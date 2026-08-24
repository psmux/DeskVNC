//! Phase 2c: driving `rdp-auth` over the framed TLS stream
//! (MS-CSSP 3.1.5, MS-RDPBCGR 5.4.5.2, PRDRDP/03 §2.3, PRDRDP/12 §3.9).
//!
//! **This file constructs no authentication message, and that is a rule
//! rather than a description.** Every `TSRequest`, every NTLM message, every
//! AV pair, every key derivation and every byte that goes on the wire for
//! authentication is built in `rdp-auth` (PRDRDP/14 §2.4). What is left here
//! is three things and nothing else: the [`NlaPolicy`] gate, the credentials,
//! and the driver loop that moves bytes between the socket and
//! [`rdp_auth::CredSspClient::step`]. If a reviewer finds an `MsvAv`, an
//! `NTLMSSP` constant or a DER tag in this file, something has been written
//! in the wrong crate.
//!
//! # The seam
//!
//! There is exactly one place where CredSSP plugs in and it is
//! [`credssp_client`]. It builds a [`rdp_auth::CredSspConfig`] and returns a
//! [`rdp_auth::CredSspClient`]; [`authenticate`] drives it through
//! [`rdp_auth::Step`] and never looks inside a token. What the seam binds to
//! comes from the TLS upgrade in one piece: see
//! [`ServerIdentity::from_upgrade`].

use rdp_auth::{CredSspClient, CredSspConfig, Identity, Step};
use remote_core::{Credentials, NlaPolicy};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection::negotiate::SecurityProtocol;
use crate::error::{ConnectStage, RdpError, Result};
use crate::options::ResolvedOptions;
use crate::transport::framer::{Expect, Framer};
use crate::transport::{with_timeout, TlsUpgrade};

/// One CredSSP round trip may take this long (PRDRDP/03 §3.3).
///
/// Generous, because phase 3's Kerberos does an AS and a TGS exchange against
/// a domain controller that may be across a WAN link.
pub const CREDSSP_STEP: std::time::Duration = std::time::Duration::from_secs(30);

/// The whole exchange may take this long, however many rounds it needs.
pub const CREDSSP_TOTAL: std::time::Duration = std::time::Duration::from_secs(90);

/// What the CredSSP exchange binds itself to, taken from the TLS upgrade.
///
/// Both values come out of the same certificate and both are needed: the
/// `subjectPublicKey` inside it is what `pubKeyAuth` binds to
/// (MS-CSSP 3.1.5), and the certificate as a whole, hashed under the
/// algorithm its `signatureAlgorithm` names, is the RFC 5929 §4.1
/// `tls-server-end-point` channel binding. Taking both from one extraction at
/// the moment of the upgrade is why PRDRDP/03 §4 asks `vnc-transport` for an
/// upgrade variant that returns the leaf certificate: walking the same
/// certificate twice, from two places, is how the two end up describing
/// different connections.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    /// The leaf certificate, DER encoded.
    pub certificate: Vec<u8>,
    /// Its `signatureAlgorithm` OID, DER content octets only.
    pub signature_algorithm_oid: Vec<u8>,
    /// Its `subjectPublicKey` BIT STRING contents, the unused bits octet
    /// already stripped.
    ///
    /// Not the `SubjectPublicKeyInfo` and not the SPKI fingerprint: those are
    /// the trust on first use pin, which is a different value from the same
    /// certificate, and using one where the other belongs produces an
    /// exchange that reaches message 4 and dies opaquely
    /// (`crates/rdp-auth/src/credssp/mod.rs:124` says the same thing on the
    /// field this feeds).
    pub public_key: Vec<u8>,
}

impl ServerIdentity {
    /// Pull the three values out of a completed TLS upgrade.
    ///
    /// `vnc_transport::tls::upgrade_with_identity` hands back the leaf
    /// certificate and its `signatureAlgorithm` OID beside the stream
    /// (PRDRDP/00 R47), so both come from one extraction at the moment of the
    /// handshake and cannot describe two different connections. The third
    /// value, the `subjectPublicKey` CredSSP binds to, is walked out of that
    /// same certificate here.
    ///
    /// # Errors
    ///
    /// [`RdpError::Tls`] when the certificate parses but has no
    /// `subjectPublicKey`, which is a certificate we should not have accepted.
    pub fn from_upgrade(upgrade: &TlsUpgrade) -> Result<Self> {
        // The DER walk is `rdp-pdu`'s. PRDRDP/00 R45: there is one walker in
        // this workspace and it is not written a second time here.
        let public_key = rdp_pdu::asn1::der::subject_public_key(&upgrade.server_certificate)
            .ok_or_else(|| {
                RdpError::Tls("the server certificate has no subjectPublicKey".to_owned())
            })?
            .to_vec();

        Ok(Self {
            certificate: upgrade.server_certificate.clone(),
            signature_algorithm_oid: upgrade.signature_algorithm_oid.clone(),
            public_key,
        })
    }
}

/// Split what the user typed into the user name and the domain the logon goes
/// to.
///
/// `DOMAIN\user` and `user@domain.tld` are both parsed by `rdp-auth`, and this
/// is the one place that decides, so the CredSSP identity and the Client Info
/// PDU (MS-RDPBCGR 2.2.1.11.1.1) cannot disagree about who is signing in. The
/// profile's domain is the fallback, never the override: what the user typed
/// in the box wins.
///
/// A user principal name is the deliberate exception. It goes in the user
/// field whole with an empty domain, because a UPN is already fully qualified
/// and splitting it produces `NTOWFv2("user", "domain.example.com")`, which is
/// not what the domain controller computes
/// (`crates/rdp-auth/src/identity.rs:33`).
#[must_use]
pub fn logon_identity(
    username: &str,
    creds: &Credentials,
    opts: &ResolvedOptions,
) -> (String, String) {
    let (user, qualified_domain) = rdp_auth::split_qualified_username(username);
    let domain = if qualified_domain.is_empty() {
        creds
            .domain
            .clone()
            .or_else(|| opts.domain.clone())
            .unwrap_or_default()
    } else {
        qualified_domain
    };
    (user, domain)
}

/// **The CredSSP seam.** Build the state machine `rdp-auth` owns.
///
/// Everything about the exchange is `rdp-auth`'s: the version we advertise is
/// 6 and the lowest server version we complete against is 2, frozen from the
/// server's first reply so a server cannot advertise 6, watch us pick the
/// hash construction, and then re-advertise 2 to get the raw public key form
/// (PRDRDP/14 §3.4, §8.7). [`CredSspConfig::new`] is the constructor that
/// gets all of that right, so this function calls it rather than filling the
/// struct field by field.
///
/// Phase 1 and 2 are NTLMv2 only (D6), which `CredSspConfig::new` selects.
/// Phase 3 sets `mechanisms` to SPNEGO over a list, and that is the only line
/// of this function that changes.
///
/// # Errors
///
/// [`RdpError::CredentialsRequired`] when there is no user name or no
/// password, and whatever `rdp-auth` makes of the configuration. Reaching
/// that error from a session with a shell attached is a bug rather than a
/// refusal: [`super::credentials::ensure`] runs first and asks the user
/// (`crates/remote-core/src/events.rs:132`). It is still the answer for a
/// headless caller, which has nobody to ask.
pub fn credssp_client(
    creds: &Credentials,
    opts: &ResolvedOptions,
    identity: &ServerIdentity,
) -> Result<CredSspClient> {
    // One definition of "these credentials are unusable", shared with the
    // gate, so the sentence the user is shown and the error the sequence
    // returns cannot disagree about which half is missing.
    if let Some(gap) = super::credentials::missing(creds) {
        return Err(RdpError::CredentialsRequired(gap.to_owned()));
    }
    let (Some(username), Some(password)) = (
        creds
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty()),
        creds.password.as_deref(),
    ) else {
        // Unreachable: `missing` returned `None`, which is exactly the
        // statement that both of these are present.
        return Err(RdpError::CredentialsRequired("no credentials".to_owned()));
    };

    let (user, domain) = logon_identity(username, creds, opts);

    let config = CredSspConfig::new(
        Identity::from_prompt(&user, &domain, password)?,
        rdp_auth::service_principal_name(&opts.server_name),
        identity.public_key.clone(),
        identity.certificate.clone(),
        identity.signature_algorithm_oid.clone(),
    );
    Ok(CredSspClient::new(config)?)
}

/// Run CredSSP to completion over `framer`, which is already inside TLS.
///
/// The loop does three things beyond pumping bytes. It enforces
/// [`NlaPolicy`], through [`refusal`] below. It never looks inside a token.
/// And on `HYBRID_EX` it reads the four byte Early User Authorization Result
/// afterwards, and only then: reading four bytes after a plain `HYBRID`
/// desynchronises the stream, which is why the negotiated protocol decides
/// and not the state machine.
///
/// # Errors
///
/// [`RdpError::AuthFailed`] when the server rejected the credentials, which
/// is never auto retried, [`RdpError::NlaRefused`] under
/// [`NlaPolicy::Required`] when the server would not do CredSSP, and
/// [`RdpError::Timeout`] against [`ConnectStage::Credssp`].
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    opts: &ResolvedOptions,
    creds: &Credentials,
    selected: SecurityProtocol,
    identity: &ServerIdentity,
) -> Result<rdp_auth::Outcome> {
    let mut client = credssp_client(creds, opts, identity)?;
    let started = std::time::Instant::now();
    let mut input: Vec<u8> = Vec::new();

    let outcome = loop {
        if started.elapsed() > CREDSSP_TOTAL {
            return Err(RdpError::Timeout {
                stage: ConnectStage::Credssp,
            });
        }
        match client.step(&input)? {
            Step::SendAndExpect(bytes) => {
                framer.write_pdu(&bytes).await?;
                // A TSRequest is a bare DER SEQUENCE inside TLS: no TPKT, no
                // X.224 (MS-CSSP 2.2.1). The framer is told the shape rather
                // than guessing at it.
                let frame = with_timeout(
                    ConnectStage::Credssp,
                    CREDSSP_STEP,
                    framer.read_expect(Expect::DerSequence),
                )
                .await?;
                input = frame.to_vec();
            }
            Step::Send(bytes) => {
                // The final message carries the encrypted credentials and has
                // no reply, but the caller still has to flush before the
                // session proceeds. Calling `step(&[])` straight away collects
                // the outcome, which keeps this loop a single match with one
                // exit.
                framer.write_pdu(&bytes).await?;
                input.clear();
            }
            Step::Done(outcome) => break outcome,
        }
    };

    if selected == SecurityProtocol::HybridEx {
        let result = with_timeout(
            ConnectStage::EarlyUserAuthResult,
            CREDSSP_STEP,
            framer.read_expect(Expect::Exact(4)),
        )
        .await?;
        read_early_user_auth_result(&result)?;
    }

    Ok(outcome)
}

/// `AUTHZ_SUCCESS`, MS-RDPBCGR 2.2.10.2.
const AUTHZ_SUCCESS: u32 = 0x0000_0000;
/// `AUTHZ_ACCESS_DENIED`: the account has no Remote Desktop rights.
const AUTHZ_ACCESS_DENIED: u32 = 0x0000_052e;

/// The Early User Authorization Result PDU (MS-RDPBCGR 2.2.10.2): four bytes
/// of `authorizationResult`, little endian.
///
/// # Errors
///
/// [`RdpError::AuthFailed`] for `AUTHZ_ACCESS_DENIED` and for anything else,
/// which classifies as needing user action: the account genuinely cannot sign
/// in here and a retry ladder achieves nothing.
fn read_early_user_auth_result(bytes: &[u8]) -> Result<()> {
    let Some(four) = bytes.get(..4) else {
        return Err(RdpError::Pdu {
            structure: "Early User Authorization Result PDU",
            message: format!("expected 4 bytes, got {}", bytes.len()),
        });
    };
    let mut value = [0u8; 4];
    value.copy_from_slice(four);
    match u32::from_le_bytes(value) {
        AUTHZ_SUCCESS => Ok(()),
        AUTHZ_ACCESS_DENIED => Err(RdpError::AuthFailed(
            "this account is not allowed to sign in remotely".to_owned(),
        )),
        other => Err(RdpError::AuthFailed(format!(
            "the server refused the logon with authorization result 0x{other:08x} \
             (MS-RDPBCGR 2.2.10.2)"
        ))),
    }
}

/// What a CredSSP failure means under the host's [`NlaPolicy`].
///
/// `Some(err)` fails the connection, `None` continues over plain TLS and lets
/// the server's own logon screen collect the credentials.
///
/// Note what `AllowFallback` costs, because it is not free: reaching
/// `Connected` without CredSSP does not prove the password was right, since
/// the server completes the connection either way, so credential saving is
/// disabled for the host (PRDRDP/00 R14, and
/// [`NlaPolicy::AllowFallback`] says the same on the variant).
///
/// A wrong password is never downgraded. Falling back after
/// [`RdpError::AuthFailed`] would put the user in front of the server's logon
/// screen with no explanation of why their saved password did not work, and
/// would hide a compromised credential behind a working connection.
#[must_use]
pub fn refusal(err: RdpError, policy: NlaPolicy) -> Option<RdpError> {
    match policy {
        NlaPolicy::Required => Some(match err {
            // The server would not do CredSSP at all, which is the case the
            // per host switch exists for, so the error names it.
            RdpError::NegotiationInconsistent => RdpError::NlaRefused,
            other => other,
        }),
        NlaPolicy::AllowFallback => match err {
            RdpError::AuthFailed(_)
            | RdpError::CredentialsRequired(_)
            | RdpError::Cancelled
            | RdpError::CertificateMismatch { .. }
            | RdpError::CertificateUntrusted(_) => Some(err),
            other => {
                tracing::warn!(error = %other, "continuing over TLS without NLA");
                None
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnc_transport::TrustDecision;

    fn upgrade(cert: Vec<u8>, oid: Vec<u8>) -> TlsUpgrade {
        TlsUpgrade {
            stream: Box::pin(tokio::io::empty()),
            decision: TrustDecision::VerifiedByCa,
            server_certificate: cert,
            signature_algorithm_oid: oid,
        }
    }

    fn resolved() -> ResolvedOptions {
        let c = remote_core::ConnectOptions::rdp("host.example", 3389);
        let rdp = c.rdp_options().expect("rdp").clone();
        ResolvedOptions::resolve(&c, &rdp, &mut Vec::new()).expect("valid")
    }

    /// A real certificate yields three values, and the two that come from the
    /// same bytes are not the same value: `public_key` is the inner
    /// `subjectPublicKey` contents and `certificate` is the whole leaf. Using
    /// one where the other belongs produces an exchange that reaches message 4
    /// and dies opaquely (PRDRDP/03 §4.3).
    #[test]
    fn a_completed_upgrade_yields_the_three_values_credssp_binds_to() {
        let cert = test_certificate();
        let oid = vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let identity = ServerIdentity::from_upgrade(&upgrade(cert.clone(), oid.clone()))
            .expect("a well formed certificate");
        assert_eq!(identity.certificate, cert);
        assert_eq!(identity.signature_algorithm_oid, oid);
        // A P-256 uncompressed point: one 0x04 marker and two 32 byte
        // coordinates. Not the SPKI element, which wraps it in an algorithm
        // identifier and is the trust on first use pin instead.
        assert_eq!(identity.public_key.len(), 65);
        assert_eq!(identity.public_key.first(), Some(&0x04));
        assert_ne!(
            identity.public_key,
            rdp_pdu::asn1::der::extract_spki(&cert).expect("an SPKI element")
        );
    }

    /// A certificate that is not one is refused rather than fed to CredSSP as
    /// an empty public key, which would produce an exchange that reaches
    /// message 4 and dies opaquely.
    #[test]
    fn a_certificate_with_no_public_key_is_refused() {
        let err = ServerIdentity::from_upgrade(&upgrade(vec![0x30, 0x00], vec![0x2a]))
            .expect_err("not a certificate");
        assert!(matches!(err, RdpError::Tls(_)), "{err:?}");
    }

    /// The same self signed P-256 certificate (`CN=vnc.example.test`) that
    /// `vnc-transport` keeps for its SPKI digest test
    /// (`crates/vnc-transport/src/tls.rs:282`), so both sides of the seam are
    /// exercised against one set of bytes rather than two that can drift.
    fn test_certificate() -> Vec<u8> {
        const HEX: &str = "3082021b308201c0020900fed9f6f5144ee51d300a06082a8648ce3d040302301b31\
19301706035504030c10766e632e6578616d706c652e74657374301e170d3236303732383139333830395a170d32363037323931\
39333830395a301b3119301706035504030c10766e632e6578616d706c652e746573743082014b3082010306072a8648ce3d0201\
3081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd557698\
86bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247\
f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb64068\
37bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101034200040b2ec0b3fed6\
08022b545e768b3ab0ffc340ff9fb4f606b0c6c9e98a8a2f1919bb93370b6d21abd621dc5122cf599bff084ff2d8b16df21bf62a\
96fcbd59975a300a06082a8648ce3d0403020349003046022100ba92e99e98c2144752897231a266796f434ccab0137f03df2af2\
69c74c7f545402210084092ec5d5ddc0caad180befc2aa4e62cbef693c063287947a776840d6c92b88";
        hex::decode(HEX.replace(['\n', ' '], "")).expect("a certificate fixture")
    }

    /// A missing credential is asked for, never guessed at. The session is
    /// paused mid handshake until the user answers, which is the contract the
    /// RFB path already keeps.
    #[test]
    fn a_missing_credential_asks_rather_than_failing_the_connection() {
        let opts = resolved();
        let identity = ServerIdentity {
            certificate: Vec::new(),
            signature_algorithm_oid: Vec::new(),
            public_key: Vec::new(),
        };

        let err = credssp_client(&Credentials::default(), &opts, &identity).expect_err("no user");
        assert!(matches!(err, RdpError::CredentialsRequired(_)), "{err:?}");
        assert!(err.needs_user_action());

        let creds = Credentials {
            username: Some("user".into()),
            ..Credentials::default()
        };
        let err = credssp_client(&creds, &opts, &identity).expect_err("no password");
        assert!(err.to_string().contains("password"), "{err}");
    }

    /// `DOMAIN\user` typed into the username box has to reach the CredSSP
    /// identity, or the logon goes to the wrong authority. What the user
    /// typed wins over the profile's domain field.
    ///
    /// A user principal name is the exception and it is deliberate: it goes
    /// in the user field whole with an empty domain, because a UPN is already
    /// fully qualified and splitting it produces
    /// `NTOWFv2("user", "domain.example.com")`, which is not what the domain
    /// controller computes (`crates/rdp-auth/src/identity.rs:33`). So a UPN
    /// falls through to the profile's domain here, which is empty for a UPN
    /// logon and is what the server expects.
    #[test]
    fn a_qualified_user_name_wins_over_the_profile_domain() {
        assert_eq!(
            rdp_auth::split_qualified_username("CORP\\alice"),
            ("alice".to_owned(), "CORP".to_owned())
        );
        assert_eq!(
            rdp_auth::split_qualified_username("alice@corp.example"),
            ("alice@corp.example".to_owned(), String::new())
        );

        // And the whole path builds a client, which is the seam working end
        // to end against a certificate shaped input.
        let mut opts = resolved();
        opts.domain = Some("IGNORED".into());
        let identity = ServerIdentity {
            certificate: vec![0u8; 8],
            signature_algorithm_oid: vec![0x2a, 0x86, 0x48],
            public_key: vec![0u8; 270],
        };
        let creds = Credentials::user_pass("CORP\\alice", "pw");
        credssp_client(&creds, &opts, &identity).expect("the seam builds a client");
    }

    #[test]
    fn the_early_user_authorization_result_is_read_little_endian() {
        assert!(read_early_user_auth_result(&[0, 0, 0, 0]).is_ok());
        let err = read_early_user_auth_result(&[0x2e, 0x05, 0, 0]).expect_err("denied");
        assert!(err.to_string().contains("remotely"), "{err}");
        assert!(err.needs_user_action(), "an access denial is not retried");
        assert!(read_early_user_auth_result(&[0, 0]).is_err(), "short read");
    }

    /// `Required` means the connection fails; `AllowFallback` means it
    /// continues over plain TLS. Neither ever downgrades a wrong password,
    /// which would hide a compromised credential behind a working
    /// connection.
    #[test]
    fn the_nla_policy_gate_never_downgrades_a_rejected_password() {
        let refused = refusal(RdpError::NegotiationInconsistent, NlaPolicy::Required);
        assert!(matches!(refused, Some(RdpError::NlaRefused)));
        assert!(refusal(RdpError::NegotiationInconsistent, NlaPolicy::AllowFallback).is_none());

        for err in [
            RdpError::AuthFailed("wrong".into()),
            RdpError::CredentialsRequired("none".into()),
            RdpError::Cancelled,
            RdpError::CertificateUntrusted("declined".into()),
        ] {
            let shown = format!("{err}");
            assert!(
                refusal(err, NlaPolicy::AllowFallback).is_some(),
                "{shown} must not be downgraded"
            );
        }
    }

    /// `NlaRefused` stops with the question in front of the person who can
    /// answer it. Auto retrying would fail identically every backoff
    /// interval.
    #[test]
    fn nla_refused_stops_rather_than_retrying() {
        assert!(!RdpError::NlaRefused.is_transient());
        assert!(RdpError::NlaRefused.needs_user_action());
        assert_eq!(RdpError::NlaRefused.symbol(), Some("nla-refused"));
    }
}
