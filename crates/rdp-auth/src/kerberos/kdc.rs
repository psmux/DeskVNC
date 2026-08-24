//! The AS and TGS exchanges, RFC 4120 §3.1 and §3.3.
//!
//! [`KdcClient`] is a state machine over byte slices, in the same shape as
//! [`NtlmClient`](crate::ntlm::NtlmClient) and
//! [`CredSspClient`](crate::credssp::CredSspClient): feed it the KDC's last
//! reply, get the next request back, and eventually get a
//! [`ServiceTicket`]. It opens no socket, resolves no name and reads no
//! clock. The session does all three (D12, PRDRDP/12 §2.1).
//!
//! ```text
//! C->S  AS-REQ    (no pre-authentication)
//! S->C  KRB-ERROR KDC_ERR_PREAUTH_REQUIRED, carrying PA-ETYPE-INFO2
//! C->S  AS-REQ    (with PA-ENC-TIMESTAMP under the client key)
//! S->C  AS-REP    (the TGT, and the TGS session key under the client key)
//! C->S  TGS-REQ   (PA-TGS-REQ carrying an AP-REQ against the TGT)
//! S->C  TGS-REP   (the service ticket, and the session key under the TGS key)
//! ```
//!
//! ## Why the first round trip is not skipped
//!
//! A client that guesses the salt can send the pre-authentication in the
//! first AS-REQ and save a round trip. The guess is `REALM || principal`,
//! which is right for Active Directory's default and wrong for any principal
//! with an explicit `krb5_principal_salt`, and wrong for most MIT realms that
//! have been migrated. The failure is `KDC_ERR_PREAUTH_FAILED`, which is
//! indistinguishable from a wrong password, so the user is told their
//! password is wrong when it is not. We ask, and use the salt the KDC names
//! (PRDRDP/14 §7.1 item 2 and §7.2).
//!
//! ## Transport
//!
//! TCP only. RFC 4120 §7.2.2: a four octet length in network byte order, then
//! the message. UDP is not implemented: a Windows KDC's AS-REP carries a PAC
//! and is far over any UDP datagram worth sending, so the UDP attempt fails
//! with `KRB_ERR_RESPONSE_TOO_BIG` on essentially every real connection and
//! the round trip it would save is a round trip it costs (PRDRDP/14 §7.1
//! item 10).
//!
//! [`KdcStep::SendAndExpect`] hands back the framed bytes, length prefix
//! included, and [`KdcClient::step`] expects the reply framed the same way.
//! The prefix is on both sides on purpose: the caller has to read the length
//! to know how much to read, and a contract where the caller strips a header
//! it just parsed and we re-derive it is one where the two lengths can
//! disagree. Here they are checked against each other in one place.
//!
//! ## What is not implemented, and is not a gap in silence
//!
//! * **Cross realm referrals**, RFC 6806. A `TERMSRV/host` in a different
//!   realm from the user needs the KDC's referral TGT and a second TGS
//!   exchange. The failure today is `KDC_ERR_S_PRINCIPAL_UNKNOWN` with a
//!   message naming the SPN, which is a good deal better than a hang, and it
//!   is a bounded addition on this state machine when a domain needs it.
//! * **User to user**, `ENC-TKT-IN-SKEY`. RDP does not use it.
//! * **PKINIT** and smart cards. A different pre-authentication mechanism and
//!   a different document (RFC 4556).
//! * **Ticket caching.** Every connection does both exchanges. A cache is a
//!   file, and a file is I/O this crate does not do; if it is ever wanted it
//!   belongs in the session with `ServiceTicket` as its unit.

use rand::Rng;
use zeroize::Zeroizing;

use rdp_pdu::asn1::der::{expect_tag, read_tlv, write_int, write_nested, write_tlv};
use rdp_pdu::asn1::{context, tag};

use crate::error::AuthError;
use crate::identity::Identity;

use super::asn1::{
    app, application, encode_pa_enc_ts_enc, error_code, kdc_option, kerberos_flags, msg_type,
    name_type, padata_type, read_etype_info2, write_checksum, write_encrypted_data,
    write_kerberos_string, write_kerberos_time, write_padata, write_principal_name, EncKdcRepPart,
    EtypeInfo2Entry, KdcRep, KerberosTime, KrbError, PrincipalName, Ticket, PVNO,
};
use super::crypto::{self, usage, Enctype, Key};

/// The largest KDC message we will read or write.
///
/// A Windows AS-REP carries a PAC, which grows with the number of groups the
/// user is in and is the reason the UDP path is useless. Half a megabyte is
/// far beyond any real one and far below anything that is a memory problem.
/// A KDC claiming more is not answering our question.
pub const MAX_MESSAGE_LEN: usize = 512 * 1024;

/// The default ticket lifetime asked for, ten hours, which is what Windows
/// asks for and what Active Directory's default policy grants.
pub const DEFAULT_TICKET_LIFETIME_SECS: i64 = 10 * 60 * 60;

/// What the caller does next.
#[derive(Debug)]
#[must_use]
pub enum KdcStep {
    /// Write these bytes to the KDC, read the reply, and call
    /// [`KdcClient::step`] with it. The four octet length prefix of
    /// RFC 4120 §7.2.2 is already on the front.
    SendAndExpect(Vec<u8>),
    /// Finished. The ticket is good for one `TERMSRV/<host>`.
    Done(Box<ServiceTicket>),
}

/// A service ticket and the session key that goes with it: everything
/// [`KerberosClient`](super::KerberosClient) needs and nothing else.
pub struct ServiceTicket {
    /// The `Ticket` as the KDC encoded it, for placing in an AP-REQ verbatim.
    pub ticket: Ticket,
    /// The session key shared with the service. Secret.
    pub session_key: Key,
    /// When the ticket stops being usable, so the session can decide whether
    /// a reconnect needs a new one.
    pub endtime: KerberosTime,
    /// The client realm the KDC put in the reply, which is the realm that
    /// goes in the AP-REQ authenticator's `crealm`. It is the KDC's spelling
    /// and not ours: a KDC may canonicalise a realm and the authenticator has
    /// to agree with the ticket.
    pub client_realm: String,
    /// The client principal the KDC put in the reply, for the same reason.
    pub client_name: PrincipalName,
}

impl std::fmt::Debug for ServiceTicket {
    /// PRDRDP/14 §8.3.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTicket")
            .field("ticket", &self.ticket)
            .field("session_key", &self.session_key)
            .field("endtime", &self.endtime.as_str())
            .field("client_realm", &self.client_realm)
            .field("client_name", &self.client_name.display())
            .finish()
    }
}

/// What the session hands the KDC client.
///
/// Everything is resolved before the exchange starts: no host, no socket, no
/// clock and no options struct from another crate, which is what lets the
/// whole suite run with no network (the same rule as
/// [`CredSspConfig`](crate::credssp::CredSspConfig), PRDRDP/14 §2.6).
pub struct KdcConfig {
    /// Who we are. Zeroized on drop; `Debug` redacts.
    pub identity: Identity,
    /// `"TERMSRV/<server_name>"`, from
    /// [`service_principal_name`](crate::identity::service_principal_name).
    pub spn: String,
    /// Seconds since the Unix epoch, read by the session at the moment it
    /// builds this. The crate reads no clock of its own, which is also what
    /// makes the skew handling testable.
    pub now_unix: i64,
    /// How long a ticket to ask for.
    /// [`DEFAULT_TICKET_LIFETIME_SECS`] is the value to pass.
    pub ticket_lifetime_secs: i64,
}

impl std::fmt::Debug for KdcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdcConfig")
            .field("identity", &self.identity)
            .field("spn", &self.spn)
            .field("now_unix", &self.now_unix)
            .field("ticket_lifetime_secs", &self.ticket_lifetime_secs)
            .finish()
    }
}

/// The client principal and its realm, worked out from an [`Identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPrincipal {
    /// One of [`name_type`].
    pub name_type: i64,
    /// The `name-string` components.
    pub components: Vec<String>,
    /// The realm, uppercased.
    pub realm: String,
}

/// Turn an [`Identity`] into the principal and realm an AS-REQ names
/// (RFC 4120 §5.2.2, MS-KILE 3.2.5.4).
///
/// Two spellings reach Kerberos and they take different name types:
///
/// * `DOMAIN\user`, which [`Identity`] has already split, becomes
///   `NT-PRINCIPAL` with the one component `user` in realm `DOMAIN`
///   uppercased.
/// * `user@corp.example.com`, a user principal name, becomes `NT-ENTERPRISE`
///   with the whole string as its single component, in the realm after the
///   last `@`. RFC 4120 §6.2 describes `NT-ENTERPRISE` as an "enterprise
///   name, may be mapped to principal name", which is exactly the mapping a
///   domain controller does for a UPN. Splitting the UPN into `user` and
///   `corp.example.com` and sending `NT-PRINCIPAL` is the tempting reading
///   and it is wrong: it names a different principal, and against a forest
///   where the UPN suffix is not the domain name it names one that does not
///   exist.
///
/// The realm is uppercased because Kerberos realm names are case sensitive
/// and Active Directory's are the DNS domain in upper case
/// (PRDRDP/14 §7.1 item 9). The principal name is not touched: it is case
/// sensitive too and the KDC stores it as it was created.
///
/// # Errors
///
/// [`AuthError::NoCommonMechanism`] when there is no realm to be had, which
/// is a bare local account name with no domain. That is not a failure of the
/// logon, it is Kerberos not applying to it: the account lives in the remote
/// computer's own SAM database and no KDC has heard of it. Returning it from
/// the constructor lets a caller offering both mechanisms drop Kerberos from
/// the list and go on with NTLM, which is what SPNEGO is for.
pub fn client_principal(identity: &Identity) -> Result<ClientPrincipal, AuthError> {
    if let Some((_, suffix)) = identity.user.rsplit_once('@') {
        if suffix.is_empty() {
            return Err(AuthError::NoCommonMechanism);
        }
        return Ok(ClientPrincipal {
            name_type: name_type::ENTERPRISE,
            components: vec![identity.user.clone()],
            realm: suffix.to_uppercase(),
        });
    }
    if identity.domain.is_empty() {
        return Err(AuthError::NoCommonMechanism);
    }
    Ok(ClientPrincipal {
        name_type: name_type::PRINCIPAL,
        components: vec![identity.user.clone()],
        realm: identity.domain.to_uppercase(),
    })
}

/// Split an SPN into the components of a `PrincipalName`.
///
/// `"TERMSRV/host.corp.example.com"` becomes `["TERMSRV",
/// "host.corp.example.com"]`. A name with no `/` is one component, which is
/// not an SPN this client builds but is not worth refusing here.
fn spn_components(spn: &str) -> Vec<&str> {
    spn.split('/').collect()
}

/// The default salt for a principal, used when `PA-ETYPE-INFO2` omits one.
///
/// RFC 4120 §5.2.7.5 types `salt` as OPTIONAL and RFC 3961 §4 says the
/// default is the realm followed by each component of the principal name,
/// concatenated with no separator: `ATHENA.MIT.EDU` and `raeburn` give
/// `ATHENA.MIT.EDUraeburn`, which is exactly the salt RFC 3962 appendix B's
/// own vectors use.
///
/// PRDRDP/14 §7.2 says "we use the salt from `PA-ETYPE-INFO2` and never
/// compute one". That is right about the common case and it is not enough:
/// the field is optional and MIT KDCs do omit it for a principal on the
/// default salt, so a client with no fallback fails against them with what
/// looks like a wrong password. The fallback is here, and the KDC's salt
/// still wins whenever there is one.
fn default_salt(realm: &str, components: &[String]) -> Vec<u8> {
    let mut salt = realm.as_bytes().to_vec();
    for component in components {
        salt.extend_from_slice(component.as_bytes());
    }
    salt
}

/// RFC 4120 §7.2.2's TCP framing: four octets of length, network byte order.
///
/// The top bit is reserved and must be zero for a Kerberos message; a set
/// top bit means the other TCP form of RFC 4120 §7.2.2, which nothing sends.
fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    // `MAX_MESSAGE_LEN` bounds everything we build, so the cast cannot wrap.
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The body of a framed reply, with the prefix checked against the buffer.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for a short buffer, a set top bit, a
/// length that disagrees with the buffer, or a message over
/// [`MAX_MESSAGE_LEN`].
fn unframe(buf: &[u8]) -> Result<&[u8], AuthError> {
    let bad = AuthError::MalformedMessage("KDC message framing");
    let header = buf.get(..4).ok_or(bad)?;
    let declared = u32::from_be_bytes([
        *header.first().ok_or(bad)?,
        *header.get(1).ok_or(bad)?,
        *header.get(2).ok_or(bad)?,
        *header.get(3).ok_or(bad)?,
    ]);
    if declared & 0x8000_0000 != 0 {
        return Err(bad);
    }
    let declared = declared as usize;
    if declared > MAX_MESSAGE_LEN {
        return Err(bad);
    }
    let body = buf.get(4..).ok_or(bad)?;
    if body.len() != declared {
        return Err(bad);
    }
    Ok(body)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `step(&[])` produces the first AS-REQ.
    Start,
    /// An AS-REQ is out. `preauth` says whether it carried a
    /// `PA-ENC-TIMESTAMP`, which decides what a second
    /// `KDC_ERR_PREAUTH_REQUIRED` means.
    AwaitingAsRep { preauth: bool },
    /// A TGS-REQ is out.
    AwaitingTgsRep,
    /// A [`ServiceTicket`] has been handed over.
    Done,
    /// Nothing works any more.
    Failed,
}

/// The AS and TGS exchanges of RFC 4120 §3.1 and §3.3.
pub struct KdcClient {
    config: KdcConfig,
    client: ClientPrincipal,
    state: State,
    /// The `nonce` of the request currently outstanding. RFC 4120 §5.4.2
    /// requires the reply's `EncKDCRepPart.nonce` to match it, which is what
    /// stops a reply to an older request being accepted for this one.
    nonce: i64,
    /// What `PA-ETYPE-INFO2` told us, empty until the KDC has answered once.
    etype_info: Vec<EtypeInfo2Entry>,
    /// Seconds to add to [`KdcConfig::now_unix`], set from a
    /// `KRB_AP_ERR_SKEW` reply. Positive when the KDC is ahead of us.
    clock_offset: i64,
    /// One skew retry, then the error (PRDRDP/14 §7.1 item 11).
    skew_retried: bool,
    /// The TGT and its session key, once the AS exchange has finished.
    tgt: Option<(Ticket, Key)>,
}

impl KdcClient {
    /// A client for one connection's worth of Kerberos.
    ///
    /// # Errors
    ///
    /// Whatever [`client_principal`] makes of the identity, which is
    /// [`AuthError::NoCommonMechanism`] when the account names no domain.
    pub fn new(config: KdcConfig) -> Result<Self, AuthError> {
        let client = client_principal(&config.identity)?;
        Ok(KdcClient {
            config,
            client,
            state: State::Start,
            nonce: 0,
            etype_info: Vec::new(),
            clock_offset: 0,
            skew_retried: false,
            tgt: None,
        })
    }

    /// The realm this exchange is against, uppercased.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.client.realm
    }

    /// Consume the KDC's last reply, framed as RFC 4120 §7.2.2 sends it, and
    /// produce the next request. Call with an empty slice to start.
    ///
    /// # Errors
    ///
    /// [`AuthError::KdcRefused`] when the KDC says no,
    /// [`AuthError::ClockSkew`] when the clocks disagree and the one retry
    /// did not fix it, [`AuthError::MalformedMessage`] for a reply that is
    /// not the shape RFC 4120 §5 defines, and
    /// [`AuthError::SignatureMismatch`] when a reply does not decrypt, which
    /// on the AS path is what a wrong password looks like.
    pub fn step(&mut self, input: &[u8]) -> Result<KdcStep, AuthError> {
        let result = self.step_inner(input);
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }

    fn step_inner(&mut self, input: &[u8]) -> Result<KdcStep, AuthError> {
        match self.state {
            State::Start => {
                if !input.is_empty() {
                    return Err(AuthError::UnexpectedToken);
                }
                let request = self.build_as_req(None)?;
                self.state = State::AwaitingAsRep { preauth: false };
                tracing::debug!(
                    realm = %self.client.realm,
                    len = request.len(),
                    "sending the first AS-REQ, without pre-authentication"
                );
                Ok(KdcStep::SendAndExpect(frame(&request)))
            }
            State::AwaitingAsRep { preauth } => self.on_as_reply(unframe(input)?, preauth),
            State::AwaitingTgsRep => self.on_tgs_reply(unframe(input)?),
            State::Done => Err(AuthError::UnexpectedToken),
            State::Failed => Err(AuthError::AlreadyFailed),
        }
    }

    /// The application tag on the front of a KDC reply, which is how a
    /// `KRB-ERROR` is told from a `KDC-REP` before either is parsed.
    fn reply_tag(body: &[u8]) -> Result<u8, AuthError> {
        let (tlv, _) = read_tlv(body).ok_or(AuthError::MalformedMessage("KDC reply"))?;
        Ok(tlv.tag)
    }

    fn on_as_reply(&mut self, body: &[u8], preauth: bool) -> Result<KdcStep, AuthError> {
        if Self::reply_tag(body)? == application(app::KRB_ERROR) {
            let error = KrbError::read(body)?;
            return self.on_as_error(&error, preauth);
        }

        let rep = KdcRep::read(body, app::AS_REP, msg_type::AS_REP)?;
        // A KDC that answers without pre-authentication tells us the salt in
        // the reply's own padata instead of in an error (RFC 4120 §5.2.7.5:
        // "It MAY also be sent in an AS-REP to provide information to the
        // client about which key salt to use").
        if self.etype_info.is_empty() {
            self.absorb_etype_info(&rep.padata);
        }
        let enc = self.decrypt_as_rep(&rep)?;
        if enc.nonce != self.nonce {
            // A reply to a request other than the one outstanding.
            return Err(AuthError::MessageOutOfSequence);
        }
        tracing::debug!(
            realm = %rep.crealm,
            client = %rep.cname.display(),
            tgt = %rep.ticket.sname.display(),
            "the AS exchange succeeded"
        );
        let session_key = Key::new(
            Enctype::from_etype(i32::try_from(enc.key.keytype).unwrap_or(0))
                .ok_or(AuthError::MalformedMessage("EncKDCRepPart.key.keytype"))?,
            &enc.key.keyvalue,
        )?;
        self.tgt = Some((rep.ticket, session_key));

        let request = self.build_tgs_req()?;
        self.state = State::AwaitingTgsRep;
        Ok(KdcStep::SendAndExpect(frame(&request)))
    }

    fn on_as_error(&mut self, error: &KrbError, preauth: bool) -> Result<KdcStep, AuthError> {
        match error.error_code {
            // Not a failure: the KDC is handing us the salt (RFC 4120 §3.1.1).
            error_code::KDC_ERR_PREAUTH_REQUIRED if !preauth => {
                let padata = super::asn1::read_padata_list(&error.e_data).unwrap_or_default();
                self.absorb_etype_info(&padata);
                if self.etype_info.is_empty() {
                    tracing::debug!(
                        "the domain controller asked for pre-authentication without naming a \
                         salt; using the default salt for the principal"
                    );
                }
                let choice = self.choose_enctype()?;
                let request = self.build_as_req(Some(choice))?;
                self.state = State::AwaitingAsRep { preauth: true };
                tracing::debug!(
                    etype = choice.etype(),
                    "sending the second AS-REQ, with an encrypted timestamp"
                );
                Ok(KdcStep::SendAndExpect(frame(&request)))
            }
            // The KDC's clock and ours disagree. RFC 4120 §5.4.1 puts the
            // KDC's own time in `stime`, so the fix is to send the timestamp
            // the KDC would accept rather than to change this computer's
            // clock, which is not ours to change and would break everything
            // else on it.
            error_code::KRB_AP_ERR_SKEW if !self.skew_retried => {
                self.clock_offset = error.stime.to_unix_seconds() - self.config.now_unix;
                self.skew_retried = true;
                tracing::warn!(
                    offset_seconds = self.clock_offset,
                    "this computer's clock disagrees with the domain controller's; retrying once \
                     with the corrected timestamp"
                );
                // Retry the request we were making. If we already had a salt
                // the retry carries pre-authentication, and if we did not it
                // is the first request again with a fresh nonce.
                let choice = if self.etype_info.is_empty() {
                    None
                } else {
                    Some(self.choose_enctype()?)
                };
                let request = self.build_as_req(choice)?;
                self.state = State::AwaitingAsRep {
                    preauth: choice.is_some(),
                };
                Ok(KdcStep::SendAndExpect(frame(&request)))
            }
            error_code::KRB_AP_ERR_SKEW => Err(AuthError::ClockSkew(self.clock_offset)),
            code => Err(Self::refused(code)),
        }
    }

    fn on_tgs_reply(&mut self, body: &[u8]) -> Result<KdcStep, AuthError> {
        if Self::reply_tag(body)? == application(app::KRB_ERROR) {
            let error = KrbError::read(body)?;
            if error.error_code == error_code::KDC_ERR_S_PRINCIPAL_UNKNOWN {
                // The single most useful diagnostic in the whole exchange:
                // the SPN we asked for. A missing `TERMSRV/<host>` is the
                // usual cause on a Linux host joined to a realm, and on
                // Windows it means the name the user typed is not the name
                // the computer account is registered under (PRDRDP/14 §7.2).
                tracing::warn!(
                    spn = %self.config.spn,
                    realm = %self.client.realm,
                    "the domain controller has no such service principal"
                );
            }
            return Err(Self::refused(error.error_code));
        }

        let rep = KdcRep::read(body, app::TGS_REP, msg_type::TGS_REP)?;
        let (_, tgt_key) = self.tgt.as_ref().ok_or(AuthError::ContextNotEstablished)?;

        // RFC 4120 §5.4.2: "the key usage value is 8 if the TGS session key
        // is used, or 9 if a TGS authenticator subkey is used." We send no
        // subkey in the TGS-REQ authenticator, so 8 is the answer; 9 is tried
        // second because a KDC that invents a subkey anyway is a KDC we can
        // still talk to, and the cost of trying is one key derivation.
        let plain = match crypto::decrypt(tgt_key, usage::TGS_REP_ENC_PART, &rep.enc_part.cipher) {
            Ok(plain) => plain,
            Err(AuthError::SignatureMismatch) => crypto::decrypt(
                tgt_key,
                usage::TGS_REP_ENC_PART_SUBKEY,
                &rep.enc_part.cipher,
            )?,
            Err(e) => return Err(e),
        };
        let enc = EncKdcRepPart::read(&plain)?;
        if enc.nonce != self.nonce {
            return Err(AuthError::MessageOutOfSequence);
        }

        // The ticket the KDC issued is for the service it names, and a
        // service ticket for the wrong service is one an attacker who
        // controls the KDC's answer would like us to use. RFC 4120 §3.3.3
        // makes the client check.
        let wanted = spn_components(&self.config.spn);
        if enc.sname.components != wanted {
            tracing::warn!(
                asked = %self.config.spn,
                got = %enc.sname.display(),
                "the domain controller issued a ticket for a different service"
            );
            return Err(AuthError::MalformedMessage("TGS-REP sname"));
        }

        let session_key = Key::new(
            Enctype::from_etype(i32::try_from(enc.key.keytype).unwrap_or(0))
                .ok_or(AuthError::MalformedMessage("EncKDCRepPart.key.keytype"))?,
            &enc.key.keyvalue,
        )?;
        tracing::debug!(
            spn = %self.config.spn,
            endtime = enc.endtime.as_str(),
            "the TGS exchange succeeded"
        );
        self.state = State::Done;
        Ok(KdcStep::Done(Box::new(ServiceTicket {
            ticket: rep.ticket,
            session_key,
            endtime: enc.endtime,
            client_realm: rep.crealm,
            client_name: rep.cname,
        })))
    }

    /// A `KRB-ERROR.error-code` as an [`AuthError`], with the log line the
    /// user message deliberately does not carry (PRDRDP/14 §8.4).
    fn refused(code: i64) -> AuthError {
        let code = i32::try_from(code).unwrap_or(i32::MAX);
        let error = AuthError::KdcRefused(code);
        tracing::warn!(
            code,
            symbol = error.kdc_error_symbol().unwrap_or("unknown"),
            "the domain controller refused the Kerberos request"
        );
        error
    }

    /// Take the `PA-ETYPE-INFO2` out of a padata list, ignoring everything
    /// else in it.
    ///
    /// `PA-ETYPE-INFO` (11) and `PA-PW-SALT` (3) are deliberately not read.
    /// RFC 4120 §5.2.7.5 requires a KDC that supports an enctype defined
    /// after RFC 1510 to send `PA-ETYPE-INFO2`, and both AES enctypes are, so
    /// a KDC that can give us a ticket at all has sent the one we read. A
    /// KDC that sends only the older forms is offering only the older
    /// enctypes, and that is `KDC_ERR_ETYPE_NOSUPP` with the sentence about
    /// AES rather than a salt we could use to fail more slowly.
    fn absorb_etype_info(&mut self, padata: &[super::asn1::PaData]) {
        for entry in padata {
            if entry.padata_type == padata_type::ETYPE_INFO2 {
                if let Ok(parsed) = read_etype_info2(&entry.value) {
                    self.etype_info = parsed;
                    return;
                }
                tracing::debug!("the PA-ETYPE-INFO2 in the reply did not parse");
            }
        }
    }

    /// The enctype to pre-authenticate with: the first one we offer that the
    /// KDC also named, most preferred first.
    ///
    /// # Errors
    ///
    /// [`AuthError::KdcRefused`] with `KDC_ERR_ETYPE_NOSUPP` when the KDC
    /// named none of ours. Reporting it as the KDC's own error code rather
    /// than as a parse failure is deliberate: the sentence the user reads is
    /// "the domain controller does not support AES Kerberos encryption",
    /// which is the actual situation and is actionable by an administrator.
    fn choose_enctype(&self) -> Result<Enctype, AuthError> {
        if self.etype_info.is_empty() {
            // No PA-ETYPE-INFO2 at all: the KDC wants pre-authentication and
            // did not say with what. Our first preference and the default
            // salt is the only guess available, and it is a good one.
            return Ok(Enctype::offered()[0]);
        }
        for candidate in Enctype::offered() {
            if self
                .etype_info
                .iter()
                .any(|e| i32::try_from(e.etype).unwrap_or(0) == candidate.etype())
            {
                return Ok(candidate);
            }
        }
        Err(Self::refused(error_code::KDC_ERR_ETYPE_NOSUPP))
    }

    /// The salt and iteration count for one enctype, from `PA-ETYPE-INFO2`
    /// where the KDC gave them and from the RFC 3961 §4 default where it did
    /// not.
    fn salt_and_iterations(&self, enctype: Enctype) -> (Vec<u8>, u32) {
        let entry = self
            .etype_info
            .iter()
            .find(|e| i32::try_from(e.etype).unwrap_or(0) == enctype.etype());
        let iterations = entry.map_or(crypto::DEFAULT_ITERATIONS, EtypeInfo2Entry::iterations);
        let salt = entry
            .and_then(|e| e.salt.clone())
            .unwrap_or_else(|| default_salt(&self.client.realm, &self.client.components));
        (salt, iterations)
    }

    /// The client's long term key at one enctype: RFC 3962 §4's
    /// string-to-key over the password, the KDC's salt and the KDC's
    /// iteration count.
    fn client_key(&self, enctype: Enctype) -> Result<Key, AuthError> {
        let (salt, iterations) = self.salt_and_iterations(enctype);
        crypto::string_to_key(enctype, &self.config.identity.password, &salt, iterations)
    }

    /// Decrypt an AS-REP's `enc-part` with the client's long term key at the
    /// enctype the KDC used (RFC 4120 §5.4.2: key usage 3).
    fn decrypt_as_rep(&self, rep: &KdcRep) -> Result<EncKdcRepPart, AuthError> {
        let etype = i32::try_from(rep.enc_part.etype).unwrap_or(0);
        let enctype = Enctype::from_etype(etype)
            .ok_or_else(|| Self::refused(error_code::KDC_ERR_ETYPE_NOSUPP))?;
        let key = self.client_key(enctype)?;
        let plain = crypto::decrypt(&key, usage::AS_REP_ENC_PART, &rep.enc_part.cipher)?;
        EncKdcRepPart::read(&plain)
    }

    /// The time to put in a request, this computer's clock plus whatever
    /// offset a `KRB_AP_ERR_SKEW` measured.
    fn now(&self) -> i64 {
        self.config.now_unix + self.clock_offset
    }

    /// A fresh nonce for one request (RFC 4120 §5.4.1).
    ///
    /// From `rand::rng()` and from nothing else (PRDRDP/14 §2.10). Masked to
    /// 31 bits so the DER `INTEGER` is four octets rather than five with a
    /// leading zero: `UInt32` permits the full range and a five octet
    /// positive integer is correct DER, but it is a shape some KDCs have
    /// been reported to mishandle and 31 bits of nonce is 31 bits more than
    /// enough for a value that lives for one round trip.
    fn fresh_nonce(&mut self) -> i64 {
        let mut bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut bytes);
        self.nonce = i64::from(u32::from_be_bytes(bytes) & 0x7fff_ffff);
        self.nonce
    }

    /// `KDC-REQ-BODY`, RFC 4120 §5.4.1, as its own SEQUENCE element.
    ///
    /// Returned without the `[4]` wrapper because the TGS-REQ authenticator's
    /// checksum is computed over "an encoding of the KDC-REQ-BODY sequence"
    /// (RFC 4120 §5.4.1), which is this element and not the wrapper around
    /// it. Building it once and using the same bytes for both is what stops
    /// the checksum covering a re-serialisation that differs by a length
    /// octet.
    fn build_req_body(&mut self, for_as: bool) -> Result<Vec<u8>, AuthError> {
        let till = KerberosTime::from_unix_seconds(self.now() + self.config.ticket_lifetime_secs)?;
        let nonce = self.fresh_nonce();
        let realm = self.client.realm.clone();
        let client = self.client.clone();
        let spn = self.config.spn.clone();

        let mut out = Vec::new();
        write_nested(&mut out, tag::SEQUENCE, |body| {
            // kdc-options [0] KDCOptions
            write_nested(body, context(0), |t| {
                let flags = kerberos_flags(&[
                    kdc_option::FORWARDABLE,
                    kdc_option::RENEWABLE,
                    kdc_option::RENEWABLE_OK,
                ]);
                // A BIT STRING's first content octet is the number of unused
                // bits, which for a 32 bit KerberosFlags is always zero
                // (X.690 §8.6.2, RFC 4120 §5.2.8).
                let mut bits = vec![0x00];
                bits.extend_from_slice(&flags);
                write_tlv(t, tag::BIT_STRING, &bits);
            });
            // cname [1] PrincipalName, "Used only in AS-REQ".
            if for_as {
                write_nested(body, context(1), |t| {
                    let parts: Vec<&str> = client.components.iter().map(String::as_str).collect();
                    write_principal_name(t, client.name_type, &parts);
                });
            }
            // realm [2] Realm. The server's realm, and also the client's in
            // an AS-REQ.
            write_nested(body, context(2), |t| write_kerberos_string(t, &realm));
            // sname [3] PrincipalName.
            write_nested(body, context(3), |t| {
                if for_as {
                    // The AS exchange asks for a ticket granting ticket:
                    // `krbtgt/REALM`, name type NT-SRV-INST, which RFC 4120
                    // §6.2 names for exactly this ("service and other unique
                    // instance (krbtgt)").
                    write_principal_name(t, name_type::SRV_INST, &["krbtgt", &realm]);
                } else {
                    // `TERMSRV/host`, NT-SRV-HST, "service with host name as
                    // instance" (RFC 4120 §6.2). Active Directory matches an
                    // SPN by its string and ignores the name type, so this is
                    // the RFC's answer rather than a compatibility one.
                    write_principal_name(t, name_type::SRV_HST, &spn_components(&spn));
                }
            });
            // till [5] KerberosTime. `from [4]` is omitted: a ticket valid
            // from now needs no start time and a postdated one is not
            // something an interactive logon asks for.
            write_nested(body, context(5), |t| write_kerberos_time(t, till));
            // nonce [7] UInt32.
            write_nested(body, context(7), |t| write_int(t, tag::INTEGER, nonce));
            // etype [8] SEQUENCE OF Int32, in preference order.
            write_nested(body, context(8), |t| {
                write_nested(t, tag::SEQUENCE, |list| {
                    for enctype in Enctype::offered() {
                        write_int(list, tag::INTEGER, i64::from(enctype.etype()));
                    }
                });
            });
            // addresses [9] is omitted. RFC 4120 §5.4.1 makes it optional and
            // an address list in a ticket breaks every client behind NAT,
            // which is most of them.
        });
        Ok(out)
    }

    /// An AS-REQ, with a `PA-ENC-TIMESTAMP` when `preauth` names an enctype
    /// (RFC 4120 §5.4.1 and §5.2.7.2).
    fn build_as_req(&mut self, preauth: Option<Enctype>) -> Result<Vec<u8>, AuthError> {
        let padata = match preauth {
            Some(enctype) => {
                let key = self.client_key(enctype)?;
                let timestamp = KerberosTime::from_unix_seconds(self.now())?;
                let plain = Zeroizing::new(encode_pa_enc_ts_enc(timestamp));
                let cipher = crypto::encrypt(&key, usage::AS_REQ_PA_ENC_TIMESTAMP, &plain)?;
                let mut encrypted_data = Vec::new();
                write_encrypted_data(&mut encrypted_data, enctype, &cipher);
                Some(encrypted_data)
            }
            None => None,
        };
        let body = self.build_req_body(true)?;
        Ok(Self::wrap_kdc_req(
            app::AS_REQ,
            msg_type::AS_REQ,
            padata.as_deref().map(|d| (padata_type::ENC_TIMESTAMP, d)),
            &body,
        ))
    }

    /// A TGS-REQ: the `PA-TGS-REQ` padata is an AP-REQ against the TGT, whose
    /// authenticator carries a checksum over the request body
    /// (RFC 4120 §5.4.1 and §5.5.1).
    fn build_tgs_req(&mut self) -> Result<Vec<u8>, AuthError> {
        let body = self.build_req_body(false)?;
        let ap_req = self.build_pa_tgs_req(&body)?;
        Ok(Self::wrap_kdc_req(
            app::TGS_REQ,
            msg_type::TGS_REQ,
            Some((padata_type::TGS_REQ, &ap_req)),
            &body,
        ))
    }

    /// The AP-REQ that goes in a `PA-TGS-REQ` (RFC 4120 §5.5.1).
    ///
    /// Two key usages and they are different numbers for different things:
    /// the authenticator's `cksum` is keyed at 6 and covers the request body,
    /// and the authenticator itself is encrypted at 7. RFC 4120 §5.5.1 says
    /// so in terms ("a key usage value of 10 in normal application exchanges,
    /// or 6 when used in the TGS-REQ PA-TGS-REQ AP-DATA field"), and using 10
    /// and 11 here, which are the numbers the same structure takes when it
    /// goes to a service instead of to the KDC, produces a rejection with no
    /// diagnostic.
    fn build_pa_tgs_req(&mut self, req_body: &[u8]) -> Result<Vec<u8>, AuthError> {
        let (ticket, tgt_key) = self.tgt.as_ref().ok_or(AuthError::ContextNotEstablished)?;
        let enctype = tgt_key.enctype();

        let checksum = crypto::checksum(tgt_key, usage::TGS_REQ_AUTHENTICATOR_CKSUM, req_body)?;
        let ctime = KerberosTime::from_unix_seconds(self.now())?;

        let mut authenticator = Vec::new();
        write_nested(
            &mut authenticator,
            application(app::AUTHENTICATOR),
            |outer| {
                write_nested(outer, tag::SEQUENCE, |seq| {
                    write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
                    write_nested(seq, context(1), |t| {
                        write_kerberos_string(t, &self.client.realm);
                    });
                    write_nested(seq, context(2), |t| {
                        let parts: Vec<&str> =
                            self.client.components.iter().map(String::as_str).collect();
                        write_principal_name(t, self.client.name_type, &parts);
                    });
                    write_nested(seq, context(3), |t| {
                        write_checksum(t, i64::from(enctype.checksum_type()), &checksum);
                    });
                    // cusec [4] Microseconds. Zero: RFC 4120 §5.2.4 bounds it at
                    // 0..999999 and nothing here generates two requests inside
                    // one second.
                    write_nested(seq, context(4), |t| write_int(t, tag::INTEGER, 0));
                    write_nested(seq, context(5), |t| write_kerberos_time(t, ctime));
                    // subkey [6] and seq-number [7] are omitted. A subkey would
                    // change the TGS-REP's key usage from 8 to 9 for no benefit
                    // to a client that uses the reply once.
                });
            },
        );
        let authenticator = Zeroizing::new(authenticator);
        let encrypted = crypto::encrypt(tgt_key, usage::TGS_REQ_AUTHENTICATOR, &authenticator)?;

        let mut out = Vec::new();
        write_nested(&mut out, application(app::AP_REQ), |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
                write_nested(seq, context(1), |t| {
                    write_int(t, tag::INTEGER, msg_type::AP_REQ);
                });
                // ap-options [2] APOptions, all bits clear. `mutual-required`
                // is for an application exchange, not for the KDC, and
                // `use-session-key` is the user to user case.
                write_nested(seq, context(2), |t| {
                    write_tlv(t, tag::BIT_STRING, &[0x00, 0x00, 0x00, 0x00, 0x00]);
                });
                write_nested(seq, context(3), |t| t.extend_from_slice(ticket.der()));
                write_nested(seq, context(4), |t| {
                    write_encrypted_data(t, enctype, &encrypted);
                });
            });
        });
        Ok(out)
    }

    /// The `KDC-REQ` wrapper both requests share (RFC 4120 §5.4.1).
    ///
    /// Its first tag is `[1]` and not `[0]`, which the RFC calls out inside
    /// the definition because it is one of the two structures in the document
    /// that does not start at zero.
    fn wrap_kdc_req(
        app_tag: u8,
        message_type: i64,
        padata: Option<(i64, &[u8])>,
        req_body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        write_nested(&mut out, application(app_tag), |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                write_nested(seq, context(1), |t| write_int(t, tag::INTEGER, PVNO));
                write_nested(seq, context(2), |t| {
                    write_int(t, tag::INTEGER, message_type)
                });
                if let Some((padata_kind, value)) = padata {
                    write_nested(seq, context(3), |t| {
                        write_nested(t, tag::SEQUENCE, |list| {
                            write_padata(list, padata_kind, value);
                        });
                    });
                }
                write_nested(seq, context(4), |t| t.extend_from_slice(req_body));
            });
        });
        out
    }
}

impl std::fmt::Debug for KdcClient {
    /// The state and the shapes. The config redacts itself, the TGT holds key
    /// material and is printed as a presence (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdcClient")
            .field("state", &self.state)
            .field("realm", &self.client.realm)
            .field("config", &self.config)
            .field("clock_offset", &self.clock_offset)
            .field("skew_retried", &self.skew_retried)
            .field("have_tgt", &self.tgt.is_some())
            .finish()
    }
}

/// A helper for `expect_tag` in tests and for the GSS layer, kept here so
/// there is one place that knows a KDC reply's outer shape.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] when `body` is not a `KRB-ERROR`.
pub fn read_krb_error(body: &[u8]) -> Result<KrbError, AuthError> {
    KrbError::read(body)
}

/// Whether a message is a `KRB-ERROR`, by its application tag alone.
#[must_use]
pub fn is_krb_error(body: &[u8]) -> bool {
    matches!(read_tlv(body), Some((tlv, _)) if tlv.tag == application(app::KRB_ERROR))
}

/// The DER of a `SEQUENCE` element's content, for a caller that has the
/// wrapper.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] when the element is not a `SEQUENCE`.
pub fn sequence_content(buf: &[u8]) -> Result<&[u8], AuthError> {
    expect_tag(buf, tag::SEQUENCE)
        .map(|(content, _)| content)
        .ok_or(AuthError::MalformedMessage("SEQUENCE"))
}
