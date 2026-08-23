//! NTLMv2, the client side, MS-NLMP.
//!
//! ```text
//! C->S  NEGOTIATE_MESSAGE       40 bytes, fixed
//! S->C  CHALLENGE_MESSAGE       ServerChallenge and the AV pair list
//! C->S  AUTHENTICATE_MESSAGE    NTProofStr, the encrypted session key, the MIC
//!       --- the context is established; wrap/unwrap are available ---
//! ```
//!
//! Two rounds, no more. A server that sends a third NTLM message is either
//! confused or probing, and gets [`AuthError::UnexpectedToken`].
//!
//! ## What we refuse
//!
//! NTLMv2 only. No LM, no NTLMv1, no session security below extended session
//! security, no anonymous authentication, no datagram mode. There is no code
//! path here that can produce an NTLMv1 response: `crypto.rs` has no
//! `NTOWFv1`, and there is no `des` in the manifest to build one with. Three
//! CHALLENGE messages are refused outright (PRDRDP/14 §8.5):
//!
//! * One with no `MsvAvTimestamp`. MS-NLMP 3.1.5.1.2 makes the MIC conditional
//!   on the timestamp being present, so a server omitting it is asking for an
//!   exchange with no MIC, which is an exchange an interceptor can rewrite.
//!   Every Windows version from Vista onwards sends it.
//! * One with `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` cleared. Without
//!   it `SIGNKEY` returns NULL (3.4.5.2) and the session security is the
//!   NTLMv1 form.
//! * One with `NTLMSSP_NEGOTIATE_UNICODE` cleared, because the OEM path uses a
//!   codepage we would have to guess.
//!
//! Interop note (D3, behaviour): the timestamp rule also refuses some old
//! Samba builds and some embedded RDP implementations. If a target we care
//! about turns out to need it, the answer is a per host opt in with a warning,
//! not a silent fallback.
//!
//! ## The order inside the second step is fixed
//!
//! The MIC needs the `ExportedSessionKey`, and the
//! `EncryptedRandomSessionKey` field is part of the message being MICed, so
//! (MS-NLMP 3.1.5.1.2):
//!
//! 1. `NTOWFv2`, `temp`, `NTProofStr`, `SessionBaseKey`, `KeyExchangeKey`.
//! 2. Generate `ExportedSessionKey`, compute `EncryptedRandomSessionKey`.
//! 3. Encode the AUTHENTICATE message with a zero MIC.
//! 4. `MIC = HMAC_MD5(ExportedSessionKey, negotiate || challenge || authenticate)`.
//! 5. Patch the MIC into bytes 72 to 87.
//! 6. Derive `SIGNKEY` and `SEALKEY` and create the handles.
//!
//! Step 6 last is not required and is how the code reads best: the message is
//! finished before the session keys exist, so nothing can accidentally sign
//! the message it is part of.
//!
//! ## Known risk
//!
//! The pure functions here are proved against MS-NLMP 4.2.4's worked example,
//! every intermediate value of it. The state machine is not: 4.2.4's CHALLENGE
//! carries no `MsvAvTimestamp`, so the vector inputs cannot be driven through
//! [`NtlmClient`] at all, and its message ordering is proved only against a
//! reading of 3.1.5.1. Until the mock server side of PRDRDP/14 §9.3 exists,
//! a failure at CredSSP message 4 against a real server points here.

pub mod av_pair;
pub mod crypto;
pub mod flags;
pub mod messages;
pub mod seal;
pub mod version;

use zeroize::Zeroizing;

use crate::bindings::ChannelBindings;
use crate::error::AuthError;
use crate::gss::{GssMechanism, GssStep};
use crate::identity::Identity;

pub use seal::NtlmSession;
use version::Version;

/// The NTLM mechanism OID, `1.3.6.1.4.1.311.2.2.10`, DER OBJECT IDENTIFIER
/// contents only (MS-SPNG 1.9, RFC 4178 mechType).
///
/// Unused in phase 1a, where CredSSP carries a raw NTLM token with no SPNEGO
/// wrapper. Present because [`GssMechanism`] needs it and because SPNEGO in
/// phase 3 will.
pub const NTLM_MECH_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// The identifier that reaches `SessionState::Authenticating` (R12).
pub const METHOD_NAME: &str = "nla-ntlm";

/// Twenty four zero bytes, the `LmChallengeResponse` we always send.
///
/// MS-NLMP 3.1.5.1.2: "If the CHALLENGE_MESSAGE TargetInfo field has an
/// MsvAvTimestamp present, the client SHOULD NOT send the
/// LmChallengeResponse and SHOULD send Z(24) instead." We require a timestamp,
/// so this is unconditional.
///
/// Interop note (D3, behaviour): there are two readings of "send Z(24)". One
/// sends twenty four zero bytes with `Len = 24`; the other sets
/// `Len = MaxLen = 0` and sends nothing. Windows accepts both and public
/// implementations are split. We send the twenty four zero bytes because it is
/// the reading the sentence supports literally, and because a zero length
/// response has been reported to fail against at least one non Windows RDP
/// server.
const LM_CHALLENGE_RESPONSE_Z24: [u8; 24] = [0u8; 24];

/// What the session hands the NTLM client.
pub struct NtlmConfig {
    /// Who we are. Zeroized on drop; `Debug` redacts.
    pub identity: Identity,
    /// `"TERMSRV/<server_name>"`, from
    /// [`service_principal_name`](crate::identity::service_principal_name).
    /// Goes in `MsvAvTargetName`.
    pub spn: String,
    /// This machine's NetBIOS name, uppercased, at most fifteen characters,
    /// ASCII only. Advisory: it appears in the server's security event log and
    /// can be matched by the `STATUS_INVALID_WORKSTATION` policy. `None` sends
    /// an empty `Workstation`, which is legal and which Windows accepts.
    ///
    /// The name comes from the shell, not from this crate: `rdp-auth` has no
    /// dependency that can read a hostname and should not acquire one. That
    /// also makes it trivially overridable by a user who does not want their
    /// laptop name in a corporate log.
    pub workstation: Option<String>,
    /// The RFC 5929 `tls-server-end-point` binding.
    ///
    /// `None` omits `MsvAvChannelBindings` entirely, which only the mock does.
    /// A default Windows installation accepts a client that sends no binding,
    /// but under the "Require" Extended Protection setting a missing binding
    /// is rejected and the failure looks like a wrong password. Sending a
    /// correct binding costs one MD5 and one AV pair and is accepted
    /// everywhere, so production always fills this.
    pub channel_bindings: Option<ChannelBindings>,
}

impl std::fmt::Debug for NtlmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtlmConfig")
            .field("identity", &self.identity)
            .field("spn", &self.spn)
            .field("workstation", &self.workstation)
            .field("channel_bindings", &self.channel_bindings.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `step(&[])` produces the NEGOTIATE message.
    Start,
    /// `step(challenge)` produces the AUTHENTICATE message.
    AwaitingChallenge,
    /// `wrap`, `unwrap`, `mic` and `verify_mic` are available.
    Complete,
    /// Nothing works any more.
    Failed,
}

/// The NTLMv2 client state machine.
///
/// Pure: it never touches a socket, never sleeps and never allocates a
/// runtime. The session reads and writes and hands the bytes back in. That is
/// the shape `crates/vnc-core/src/security/ra2.rs` would have had if it had
/// been written after the run loop instead of before it; that file imports
/// `tokio::io` at line 69, which is why its handshake cannot be unit tested
/// without a socket, which is why its module doc has to admit at line 41 that
/// the message ordering "has not been validated on the wire".
pub struct NtlmClient {
    config: NtlmConfig,
    state: State,
    /// The NEGOTIATE message exactly as sent. One of the three MIC inputs.
    negotiate: Vec<u8>,
    /// The CHALLENGE message exactly as it arrived. The second MIC input.
    challenge: Vec<u8>,
    /// The flags in the AUTHENTICATE message, which is the value the server
    /// uses for its own key derivation.
    negotiated_flags: u32,
    session: Option<NtlmSession>,
}

impl NtlmClient {
    /// A client that has not sent anything yet.
    #[must_use]
    pub fn new(config: NtlmConfig) -> Self {
        NtlmClient {
            config,
            state: State::Start,
            negotiate: Vec::new(),
            challenge: Vec::new(),
            negotiated_flags: 0,
            session: None,
        }
    }

    /// The established context, once there is one. The mock and the tests use
    /// it; the CredSSP layer goes through [`GssMechanism`].
    #[must_use]
    pub fn session(&self) -> Option<&NtlmSession> {
        self.session.as_ref()
    }

    /// The flags that went in the AUTHENTICATE message.
    #[must_use]
    pub fn negotiated_flags(&self) -> u32 {
        self.negotiated_flags
    }

    fn start(&mut self) -> Vec<u8> {
        let bytes = messages::encode_negotiate(flags::CLIENT_NEGOTIATE_FLAGS, Version::CLIENT);
        self.negotiate = bytes.clone();
        self.state = State::AwaitingChallenge;
        tracing::debug!(
            len = bytes.len(),
            flags = format_args!("{:#010x}", flags::CLIENT_NEGOTIATE_FLAGS),
            "sending the NTLM NEGOTIATE message"
        );
        bytes
    }

    /// Everything that happens on the CHALLENGE, in the order MS-NLMP
    /// 3.1.5.1.2 fixes.
    ///
    /// This is one function on purpose. The `MsvAvFlags` MIC bit and the MIC
    /// field are set here and only here, so there is no path that announces a
    /// MIC and then leaves the field zero, which a server rejects.
    fn finish_authenticate(&mut self, input: &[u8]) -> Result<Vec<u8>, AuthError> {
        let challenge = messages::decode_challenge(input)?;
        self.challenge_is_answerable(&challenge)?;

        let mut av_pairs = av_pair::AvPairs::decode(&challenge.target_info)?;
        let timestamp = av_pairs
            .get(av_pair::MSV_AV_TIMESTAMP)
            .and_then(|v| <[u8; 8]>::try_from(v).ok())
            .ok_or(AuthError::LegacyServerRefused)?;

        // Our three modifications to the server's list. Everything else is
        // copied through in the server's order (MS-NLMP 3.1.5.1.2).
        av_pairs.set_mic_present();
        av_pairs.set(
            av_pair::MSV_AV_TARGET_NAME,
            crypto::unicode(&self.config.spn),
        );
        if let Some(bindings) = &self.config.channel_bindings {
            av_pairs.set(av_pair::MSV_AV_CHANNEL_BINDINGS, bindings.value().to_vec());
        }
        let av_bytes = av_pairs.encode();

        // 1. The response.
        let response_key_nt = crypto::ntowf_v2(
            &self.config.identity.password,
            &self.config.identity.user,
            &self.config.identity.domain,
        );
        let client_challenge = crypto::client_challenge();
        let temp = crypto::temp(&timestamp, &client_challenge, &av_bytes);
        let nt_proof_str =
            crypto::nt_proof_str(&response_key_nt, &challenge.server_challenge, &temp);
        let nt_response = crypto::nt_challenge_response(&nt_proof_str, &temp);
        let session_base_key = crypto::session_base_key(&response_key_nt, &nt_proof_str);
        let key_exchange_key = crypto::key_exchange_key(&session_base_key);

        // 2. The exported session key. MS-NLMP 3.1.5.1.2: with KEY_EXCH it is
        //    ours and travels RC4 encrypted; without it, it is the key
        //    exchange key and nothing travels.
        self.negotiated_flags = negotiated_flags(challenge.flags);
        let key_exch = self.negotiated_flags & flags::NEGOTIATE_KEY_EXCH != 0;
        let (exported_session_key, encrypted_random_session_key) = if key_exch {
            let exported = crypto::exported_session_key();
            let encrypted = crypto::rc4k(&key_exchange_key, &exported);
            (exported, encrypted.to_vec())
        } else {
            (Zeroizing::new(*key_exchange_key), Vec::new())
        };

        // 3. The message, with sixteen zero bytes where the MIC goes.
        let domain = crypto::unicode(&self.config.identity.domain);
        let user = crypto::unicode(&self.config.identity.user);
        let workstation = crypto::unicode(&workstation_name(self.config.workstation.as_deref()));
        let fields = messages::AuthenticateFields {
            lm_challenge_response: &LM_CHALLENGE_RESPONSE_Z24,
            nt_challenge_response: &nt_response,
            domain_name: &domain,
            user_name: &user,
            workstation: &workstation,
            encrypted_random_session_key: &encrypted_random_session_key,
            negotiate_flags: self.negotiated_flags,
            version: Version::CLIENT,
            with_mic: true,
        };
        let (mut authenticate, mic_offset) = messages::encode_authenticate(&fields);

        // 4 and 5. The MIC over all three messages, then patched in.
        let mic = crypto::mic(
            &exported_session_key,
            &self.negotiate,
            &challenge.raw,
            &authenticate,
        );
        let offset = mic_offset.expect("with_mic was set");
        messages::patch_mic(&mut authenticate, offset, &mic);

        // 6. The session keys last, so nothing can sign the message it is in.
        self.session = Some(NtlmSession::new(
            &exported_session_key,
            self.negotiated_flags,
        ));
        self.state = State::Complete;

        // The retained messages are not secrets and there is no reason to hold
        // them once the MIC exists.
        self.negotiate = Vec::new();
        self.challenge = Vec::new();

        tracing::debug!(
            len = authenticate.len(),
            flags = format_args!("{:#010x}", self.negotiated_flags),
            av_pairs = av_pairs.len(),
            bindings = self.config.channel_bindings.is_some(),
            "sending the NTLM AUTHENTICATE message"
        );
        Ok(authenticate)
    }

    /// The three refusals of PRDRDP/14 §8.5, plus the two structural checks
    /// NTLMv2 cannot proceed without.
    fn challenge_is_answerable(
        &self,
        challenge: &messages::ChallengeMessage,
    ) -> Result<(), AuthError> {
        let missing = flags::REQUIRED_IN_CHALLENGE & !challenge.flags;
        if missing != 0 {
            tracing::warn!(
                missing = format_args!("{missing:#010x}"),
                "refusing an NTLM CHALLENGE that asks for a downgrade"
            );
            return Err(AuthError::LegacyServerRefused);
        }
        if challenge.flags & flags::NEGOTIATE_SIGN == 0 {
            // PRDRDP/11 §5.3 item 5: MS-NLMP errata 2022-07-26 corrected
            // 2.2.1.2 to say the server must echo NTLMSSP_NEGOTIATE_SIGN.
            // Logged rather than refused, so a host predating the erratum
            // still works while the deviation stays visible.
            tracing::debug!("the NTLM CHALLENGE did not echo NTLMSSP_NEGOTIATE_SIGN");
        }
        if challenge.target_info.is_empty() {
            // NTLMv2 cannot be computed without the AV pairs, because `temp`
            // embeds them (MS-NLMP 3.3.2).
            return Err(AuthError::MalformedMessage("CHALLENGE has no TargetInfo"));
        }
        Ok(())
    }

    fn session_mut(&mut self) -> Result<&mut NtlmSession, AuthError> {
        if self.state != State::Complete {
            return Err(AuthError::ContextNotEstablished);
        }
        self.session
            .as_mut()
            .ok_or(AuthError::ContextNotEstablished)
    }
}

/// The AUTHENTICATE flags: ours intersected with the server's, with
/// `NTLMSSP_NEGOTIATE_VERSION` kept because we do send a version.
///
/// This is the value that decides how the server derives its keys, so it must
/// be exactly the value `SEALKEY` and `NtlmSession` are given.
fn negotiated_flags(challenge_flags: u32) -> u32 {
    (flags::CLIENT_NEGOTIATE_FLAGS & challenge_flags) | flags::NEGOTIATE_VERSION
}

/// The `Workstation` field: uppercase, at most fifteen characters, ASCII only.
///
/// A hostname longer than fifteen characters is truncated; one containing non
/// ASCII has the offending characters dropped rather than transliterated. An
/// empty result is sent as an empty field, which is legal.
fn workstation_name(raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return String::new();
    };
    raw.chars()
        .filter(char::is_ascii)
        .flat_map(char::to_uppercase)
        .take(15)
        .collect()
}

impl GssMechanism for NtlmClient {
    fn oid(&self) -> &'static [u8] {
        NTLM_MECH_OID
    }

    fn method_name(&self) -> &'static str {
        METHOD_NAME
    }

    fn step(&mut self, input: &[u8]) -> Result<GssStep, AuthError> {
        match self.state {
            State::Start => {
                if !input.is_empty() {
                    self.state = State::Failed;
                    return Err(AuthError::UnexpectedToken);
                }
                Ok(GssStep::Token(self.start()))
            }
            State::AwaitingChallenge => match self.finish_authenticate(input) {
                Ok(bytes) => Ok(GssStep::FinalToken(bytes)),
                Err(e) => {
                    self.state = State::Failed;
                    Err(e)
                }
            },
            State::Complete => {
                if input.is_empty() {
                    Ok(GssStep::Complete)
                } else {
                    // Two rounds, no more. A third NTLM message is either a
                    // confused server or a probe.
                    self.state = State::Failed;
                    Err(AuthError::UnexpectedToken)
                }
            }
            State::Failed => Err(AuthError::AlreadyFailed),
        }
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        Ok(self.session_mut()?.wrap(plaintext))
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        self.session_mut()?.unwrap(token)
    }

    fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError> {
        Ok(self.session_mut()?.mic(message))
    }

    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), AuthError> {
        self.session_mut()?.verify_mic(message, mic)
    }
}

impl std::fmt::Debug for NtlmClient {
    /// Prints the state and the flags, which are diagnostics, and redacts
    /// everything else. The retained messages are not secrets but they carry
    /// the AV pair list and there is no reason for them to reach a log
    /// (PRDRDP/14 §8.3, §8.4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtlmClient")
            .field("state", &self.state)
            .field(
                "negotiated_flags",
                &format_args!("{:#010x}", self.negotiated_flags),
            )
            .field("config", &self.config)
            .field("session", &self.session)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NtlmConfig {
        NtlmConfig {
            identity: Identity::from_prompt("User", "Domain", "Password").unwrap(),
            spn: "TERMSRV/server.example.com".to_owned(),
            workstation: Some("computer".to_owned()),
            channel_bindings: Some(ChannelBindings::from_certificate_hash(&[0x11u8; 32])),
        }
    }

    /// A CHALLENGE shaped like a modern Windows one: the 4.2.4.3 message with
    /// an `MsvAvTimestamp` added, which is what our policy requires.
    fn modern_challenge() -> Vec<u8> {
        let mut pairs = av_pair::AvPairs::default();
        pairs.set(av_pair::MSV_AV_NB_DOMAIN_NAME, crypto::unicode("Domain"));
        pairs.set(av_pair::MSV_AV_NB_COMPUTER_NAME, crypto::unicode("Server"));
        pairs.set(av_pair::MSV_AV_TIMESTAMP, vec![0x01; 8]);
        messages::encode_challenge(&messages::ChallengeMessage {
            target_name: crypto::unicode("Server"),
            flags: flags::CLIENT_NEGOTIATE_FLAGS | flags::TARGET_TYPE_SERVER,
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_info: pairs.encode(),
            version: Some(Version::CLIENT),
            raw: Vec::new(),
        })
    }

    #[test]
    fn two_rounds_and_the_context_is_established() {
        let mut client = NtlmClient::new(config());
        let GssStep::Token(negotiate) = client.step(&[]).unwrap() else {
            panic!("the first step must produce a NEGOTIATE token");
        };
        assert_eq!(negotiate.len(), messages::NEGOTIATE_LEN);
        assert!(!client.is_complete());

        let GssStep::FinalToken(auth) = client.step(&modern_challenge()).unwrap() else {
            panic!("the second step must produce the AUTHENTICATE token");
        };
        assert!(client.is_complete());

        let parsed = messages::decode_authenticate(&auth).unwrap();
        assert_eq!(parsed.lm_challenge_response, vec![0u8; 24]);
        assert_eq!(parsed.encrypted_random_session_key.len(), 16);
        assert_eq!(parsed.user_name, crypto::unicode("User"));
        assert_eq!(parsed.domain_name, crypto::unicode("Domain"));
        assert_eq!(parsed.workstation, crypto::unicode("COMPUTER"));
        assert_eq!(parsed.version, Some(Version::CLIENT));
        assert!(parsed.mic.is_some_and(|m| m != [0u8; 16]));
        assert_eq!(parsed.negotiate_flags, client.negotiated_flags());
    }

    #[test]
    fn the_mic_flag_and_the_mic_field_are_set_together() {
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        let GssStep::FinalToken(auth) = client.step(&modern_challenge()).unwrap() else {
            panic!()
        };
        let parsed = messages::decode_authenticate(&auth).unwrap();
        // The AV pairs travel inside NtChallengeResponse, after NTProofStr and
        // the 28 byte client challenge header.
        let av = av_pair::AvPairs::decode(&parsed.nt_challenge_response[16 + 28..]).unwrap();
        let flags_value = av.get(av_pair::MSV_AV_FLAGS).unwrap();
        assert_eq!(
            u32::from_le_bytes([
                flags_value[0],
                flags_value[1],
                flags_value[2],
                flags_value[3]
            ]) & av_pair::AV_FLAG_MIC_PRESENT,
            av_pair::AV_FLAG_MIC_PRESENT
        );
        assert!(parsed.mic.is_some_and(|m| m != [0u8; 16]));
    }

    #[test]
    fn our_three_av_pairs_are_added_and_the_servers_are_copied_through() {
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        let GssStep::FinalToken(auth) = client.step(&modern_challenge()).unwrap() else {
            panic!()
        };
        let parsed = messages::decode_authenticate(&auth).unwrap();
        let av = av_pair::AvPairs::decode(&parsed.nt_challenge_response[16 + 28..]).unwrap();
        // The server's two, in the server's order, first.
        assert_eq!(av.as_slice()[0].id, av_pair::MSV_AV_NB_DOMAIN_NAME);
        assert_eq!(av.as_slice()[1].id, av_pair::MSV_AV_NB_COMPUTER_NAME);
        assert_eq!(av.as_slice()[2].id, av_pair::MSV_AV_TIMESTAMP);
        assert_eq!(
            av.get(av_pair::MSV_AV_TARGET_NAME).unwrap(),
            crypto::unicode("TERMSRV/server.example.com")
        );
        assert_eq!(
            av.get(av_pair::MSV_AV_CHANNEL_BINDINGS).unwrap(),
            ChannelBindings::from_certificate_hash(&[0x11u8; 32]).value()
        );
    }

    #[test]
    fn a_challenge_without_a_timestamp_is_refused() {
        // MS-NLMP 4.2.4.3's own CHALLENGE has no MsvAvTimestamp, which is what
        // makes it an NTLMv1 era example. Our policy refuses it, so the 4.2.4
        // vectors are proved against the pure functions and never through the
        // state machine (PRDRDP/14 §5.17, §8.5).
        let mut pairs = av_pair::AvPairs::default();
        pairs.set(av_pair::MSV_AV_NB_DOMAIN_NAME, crypto::unicode("Domain"));
        let challenge = messages::encode_challenge(&messages::ChallengeMessage {
            target_name: Vec::new(),
            flags: flags::CLIENT_NEGOTIATE_FLAGS,
            server_challenge: [0u8; 8],
            target_info: pairs.encode(),
            version: None,
            raw: Vec::new(),
        });
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        assert_eq!(
            client.step(&challenge).unwrap_err(),
            AuthError::LegacyServerRefused
        );
        // And it stays failed.
        assert_eq!(
            client.step(&challenge).unwrap_err(),
            AuthError::AlreadyFailed
        );
    }

    #[test]
    fn a_challenge_without_extended_session_security_is_refused() {
        let mut pairs = av_pair::AvPairs::default();
        pairs.set(av_pair::MSV_AV_TIMESTAMP, vec![0u8; 8]);
        let challenge = messages::encode_challenge(&messages::ChallengeMessage {
            target_name: Vec::new(),
            flags: flags::CLIENT_NEGOTIATE_FLAGS & !flags::NEGOTIATE_EXTENDED_SESSIONSECURITY,
            server_challenge: [0u8; 8],
            target_info: pairs.encode(),
            version: None,
            raw: Vec::new(),
        });
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        assert_eq!(
            client.step(&challenge).unwrap_err(),
            AuthError::LegacyServerRefused
        );
    }

    #[test]
    fn a_challenge_without_unicode_is_refused() {
        let mut pairs = av_pair::AvPairs::default();
        pairs.set(av_pair::MSV_AV_TIMESTAMP, vec![0u8; 8]);
        let challenge = messages::encode_challenge(&messages::ChallengeMessage {
            target_name: Vec::new(),
            flags: flags::CLIENT_NEGOTIATE_FLAGS & !flags::NEGOTIATE_UNICODE,
            server_challenge: [0u8; 8],
            target_info: pairs.encode(),
            version: None,
            raw: Vec::new(),
        });
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        assert_eq!(
            client.step(&challenge).unwrap_err(),
            AuthError::LegacyServerRefused
        );
    }

    #[test]
    fn wrap_before_the_context_exists_is_refused() {
        let mut client = NtlmClient::new(config());
        assert_eq!(
            client.wrap(b"pubKeyAuth").unwrap_err(),
            AuthError::ContextNotEstablished
        );
        assert_eq!(
            client.mic(b"mechList").unwrap_err(),
            AuthError::ContextNotEstablished
        );
        let _ = client.step(&[]).unwrap();
        assert_eq!(
            client.wrap(b"pubKeyAuth").unwrap_err(),
            AuthError::ContextNotEstablished
        );
    }

    #[test]
    fn a_third_ntlm_message_is_refused() {
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        let _ = client.step(&modern_challenge()).unwrap();
        assert_eq!(client.step(&[]).unwrap(), GssStep::Complete);
        assert_eq!(
            client.step(&modern_challenge()).unwrap_err(),
            AuthError::UnexpectedToken
        );
    }

    #[test]
    fn a_token_before_the_negotiate_message_is_refused() {
        let mut client = NtlmClient::new(config());
        assert_eq!(
            client.step(b"surprise").unwrap_err(),
            AuthError::UnexpectedToken
        );
    }

    #[test]
    fn two_exchanges_with_one_password_produce_different_key_material() {
        // NTLMSSP_NEGOTIATE_KEY_EXCH is what makes this true: the exported
        // session key is ours and random, so the sealing keys do not repeat.
        let wrap_once = || {
            let mut client = NtlmClient::new(config());
            let _ = client.step(&[]).unwrap();
            let _ = client.step(&modern_challenge()).unwrap();
            client.wrap(b"the same plaintext").unwrap()
        };
        assert_ne!(wrap_once(), wrap_once());
    }

    #[test]
    fn the_workstation_name_is_uppercase_ascii_and_short() {
        assert_eq!(workstation_name(None), "");
        assert_eq!(workstation_name(Some("laptop")), "LAPTOP");
        assert_eq!(
            workstation_name(Some("a-very-long-machine-name")),
            "A-VERY-LONG-MAC"
        );
        assert_eq!(workstation_name(Some("caf\u{e9}-pc")), "CAF-PC");
    }

    #[test]
    fn the_negotiated_flags_are_the_intersection_plus_version() {
        // A server that clears KEY_EXCH gets an AUTHENTICATE without it.
        let server = flags::CLIENT_NEGOTIATE_FLAGS & !flags::NEGOTIATE_KEY_EXCH;
        assert_eq!(negotiated_flags(server) & flags::NEGOTIATE_KEY_EXCH, 0);
        // And VERSION survives a server that did not echo it.
        assert_ne!(
            negotiated_flags(server & !flags::NEGOTIATE_VERSION) & flags::NEGOTIATE_VERSION,
            0
        );
        // Nothing the server asks for can add a bit we did not offer.
        assert_eq!(negotiated_flags(u32::MAX) & flags::FORBIDDEN, 0);
    }

    #[test]
    fn without_key_exch_no_session_key_travels() {
        let mut pairs = av_pair::AvPairs::default();
        pairs.set(av_pair::MSV_AV_TIMESTAMP, vec![0u8; 8]);
        let challenge = messages::encode_challenge(&messages::ChallengeMessage {
            target_name: Vec::new(),
            flags: flags::CLIENT_NEGOTIATE_FLAGS & !flags::NEGOTIATE_KEY_EXCH,
            server_challenge: [0u8; 8],
            target_info: pairs.encode(),
            version: None,
            raw: Vec::new(),
        });
        let mut client = NtlmClient::new(config());
        let _ = client.step(&[]).unwrap();
        let GssStep::FinalToken(auth) = client.step(&challenge).unwrap() else {
            panic!()
        };
        let parsed = messages::decode_authenticate(&auth).unwrap();
        assert!(parsed.encrypted_random_session_key.is_empty());
    }
}
