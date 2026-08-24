//! SPNEGO, RFC 4178 and MS-SPNG: a mechanism that negotiates mechanisms.
//!
//! ```text
//! C->S  InitialContextToken { SPNEGO OID, NegTokenInit { mechTypes, mechToken } }
//! S->C  NegTokenResp { accept-incomplete, supportedMech, responseToken }
//! C->S  NegTokenResp { responseToken, mechListMIC? }
//!       --- the inner context is established; wrap/unwrap are available ---
//! S->C  NegTokenResp { accept-completed, mechListMIC? }
//! ```
//!
//! [`SpnegoClient`] is itself a [`GssMechanism`] over a list of inner
//! mechanisms, which is what makes it a drop in replacement for raw NTLM at
//! the CredSSP layer: `CredSspClient` holds a `Box<dyn GssMechanism>` and
//! nothing in `credssp/mod.rs` mentions either NTLM or SPNEGO
//! (PRDRDP/14 §2.8, §4.1).
//!
//! ## Phase 1 does not send this
//!
//! PRDRDP/14 §4.8 decides it: phase 1 and 2 put a raw NTLM token in the
//! CredSSP `negoTokens` field, with no SPNEGO wrapper, and Windows has
//! accepted that for as long as CredSSP has existed. With one mechanism there
//! is nothing to negotiate, so the wrapper's only observable effects are more
//! bytes and more parsing of hostile input, and it adds three separate ways to
//! fail against a server we cannot debug: an extra ASN.1 layer, the
//! `mechListMIC` rules, and the `supportedMech` OID ambiguity of §4.7.
//!
//! It is written now because Kerberos in phase 3 arrives through this seam,
//! and a seam that has never been compiled is not a seam. Select it with
//! [`MechanismSet::Spnego`](crate::credssp::MechanismSet::Spnego).
//!
//! ## The two MICs are different values
//!
//! NTLM's own MIC (MS-NLMP 3.1.5.1.2) and SPNEGO's `mechListMIC`
//! (RFC 4178 §5) are different values over different data with different keys,
//! and they can appear in the same message. NTLM's is computed first, inside
//! the AUTHENTICATE message, because SPNEGO's needs the completed context that
//! the AUTHENTICATE message establishes.
//!
//! ## Known risk
//!
//! Nothing here has been exercised against a real server, because phase 1
//! does not send it. The tokens are proved against RFC 4178 §4.2's grammar and
//! against a server side written from the same text, which cannot validate our
//! reading of the message order (both sides share our assumption). The
//! `supportedMech` handling of §4.7 is written from reported Windows
//! behaviour and is the part most likely to be wrong.

pub mod oid;
pub mod token;

use zeroize::Zeroizing;

use crate::error::AuthError;
use crate::gss::{GssMechanism, GssStep};

use token::{NegState, NegTokenInit, NegTokenResp};

/// The identifier that reaches `SessionState::Authenticating` when the inner
/// mechanism has not been chosen yet (R12).
const METHOD_NAME_UNRESOLVED: &str = "nla-spnego";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `step(&[])` produces the `NegTokenInit`.
    Start,
    /// A `NegTokenResp` is out; awaiting the acceptor's.
    Negotiating,
    /// The inner context is established. `wrap` is available; the acceptor
    /// still owes us an `accept-completed`.
    Established,
    /// `accept-completed` seen and any `mechListMIC` verified.
    Done,
    /// Nothing works any more.
    Failed,
}

/// The SPNEGO initiator, RFC 4178 §4.
///
/// Holds every mechanism it offered, so that a server which picks the second
/// entry gets a mechanism starting from its own `Start` state rather than one
/// that has already produced an optimistic token (PRDRDP/14 §4.6).
pub struct SpnegoClient {
    mechanisms: Vec<Box<dyn GssMechanism>>,
    /// The `MechTypeList` element exactly as sent, tag and length included.
    /// A `mechListMIC` covers these bytes and not a re-serialisation
    /// (RFC 4178 §5), which is why it is kept rather than rebuilt.
    mech_list_der: Vec<u8>,
    /// Index into `mechanisms`. Starts at 0, the optimistic choice.
    chosen: usize,
    /// Set by an acceptor `request-mic`, or by the mechanism used not being
    /// the first one offered (RFC 4178 §5).
    mic_required: bool,
    state: State,
}

impl SpnegoClient {
    /// A client offering `mechanisms`, most preferred first.
    ///
    /// # Errors
    ///
    /// [`AuthError::NoCommonMechanism`] when the list is empty. There is
    /// nothing to negotiate and nothing to fall back to.
    pub fn new(mechanisms: Vec<Box<dyn GssMechanism>>) -> Result<Self, AuthError> {
        if mechanisms.is_empty() {
            return Err(AuthError::NoCommonMechanism);
        }
        Ok(SpnegoClient {
            mechanisms,
            mech_list_der: Vec::new(),
            chosen: 0,
            mic_required: false,
            state: State::Start,
        })
    }

    /// The mechanism currently selected.
    fn mechanism(&mut self) -> &mut Box<dyn GssMechanism> {
        let index = self.chosen.min(self.mechanisms.len() - 1);
        &mut self.mechanisms[index]
    }

    /// The first token: `mechTypes` and the optimistic `mechToken`
    /// (RFC 4178 §4.2.1).
    ///
    /// With NTLM first the optimistic token is the NEGOTIATE message and it
    /// always saves a round trip, because there is nothing else in the list to
    /// switch to. With Kerberos first it is an AP-REQ, which means a KDC round
    /// trip that a `supportedMech` of NTLM wastes.
    fn start(&mut self) -> Result<Vec<u8>, AuthError> {
        let mech_types: Vec<&'static [u8]> = self.mechanisms.iter().map(|m| m.oid()).collect();
        let optimistic = match self.mechanisms[0].step(&[])? {
            GssStep::Token(token) | GssStep::FinalToken(token) => token,
            GssStep::Complete => {
                // A mechanism with nothing to say cannot be offered
                // optimistically.
                return Err(AuthError::UnexpectedToken);
            }
        };
        let (bytes, mech_list) = NegTokenInit {
            mech_types: &mech_types,
            mech_token: Some(&optimistic),
            mech_list_mic: None,
        }
        .encode();
        self.mech_list_der = mech_list;
        self.state = State::Negotiating;
        tracing::debug!(
            mechanisms = self.mechanisms.len(),
            len = bytes.len(),
            "sending the SPNEGO NegTokenInit"
        );
        Ok(bytes)
    }

    /// Apply `supportedMech`, RFC 4178 §4.2.2 and PRDRDP/14 §4.7.
    ///
    /// Windows echoes the OID it chose even when we offered only one, and on
    /// at least Server 2019 and Windows 11 it answers Kerberos with the legacy
    /// `1.2.840.48018.1.2.2` rather than `1.2.840.113554.1.2.2`. Both are in
    /// `oid` and a mechanism that offers one is matched by the other, so a
    /// client that recognises only the modern OID does not conclude the server
    /// picked something unknown.
    fn select(&mut self, wanted: &[u8]) -> Result<(), AuthError> {
        let index = self
            .mechanisms
            .iter()
            .position(|m| same_mechanism(m.oid(), wanted));
        let Some(index) = index else {
            tracing::warn!(
                mech = ?oid::dotted(wanted),
                "the server chose a mechanism we did not offer"
            );
            return Err(AuthError::NoCommonMechanism);
        };
        if index != self.chosen {
            tracing::debug!(
                from = ?oid::dotted(self.mechanisms[self.chosen].oid()),
                to = ?oid::dotted(self.mechanisms[index].oid()),
                "the server chose a different mechanism"
            );
            self.chosen = index;
        }
        if index != 0 {
            // RFC 4178 §5: the initiator MUST send a mechListMIC when the
            // mechanism finally used is not the first one in mechTypes.
            self.mic_required = true;
        }
        Ok(())
    }

    /// The `mechListMIC` to send with the next token, if one is owed.
    ///
    /// We also send one when the list had more than one entry and the context
    /// is complete. Sending one that is not required is legal and Windows
    /// accepts it (RFC 4178 §5, PRDRDP/14 §4.5).
    fn outgoing_mic(&mut self) -> Result<Option<Vec<u8>>, AuthError> {
        if !(self.mic_required || self.mechanisms.len() > 1) {
            return Ok(None);
        }
        if !self.mechanism().is_complete() {
            return Ok(None);
        }
        let list = std::mem::take(&mut self.mech_list_der);
        let mic = self.mechanism().mic(&list);
        self.mech_list_der = list;
        Ok(Some(mic?))
    }

    /// Verify the acceptor's `mechListMIC` over the list as we sent it.
    ///
    /// A missing one on `accept-completed` is accepted with a log line:
    /// RFC 4178 §5 permits the acceptor to omit it when the first mechanism
    /// was used, and refusing would break against servers that do.
    fn check_incoming_mic(&mut self, resp: &NegTokenResp) -> Result<(), AuthError> {
        let Some(mic) = resp.mech_list_mic.clone() else {
            tracing::debug!("the acceptor sent no mechListMIC");
            return Ok(());
        };
        if !self.mechanism().is_complete() {
            return Err(AuthError::ContextNotEstablished);
        }
        let list = std::mem::take(&mut self.mech_list_der);
        let verified = self.mechanism().verify_mic(&list, &mic);
        self.mech_list_der = list;
        verified
    }

    fn advance(&mut self, input: &[u8]) -> Result<GssStep, AuthError> {
        let resp = NegTokenResp::decode(input)?;
        let state = resp.state();
        if state == NegState::Reject {
            // No mutually supported mechanism, or the mechanism failed. There
            // is no token to inspect and no error code (RFC 4178 §4.2.2).
            tracing::warn!(
                offered = self.mechanisms.len(),
                "the server rejected every mechanism we offered"
            );
            return Err(AuthError::NoCommonMechanism);
        }
        if state == NegState::RequestMic {
            self.mic_required = true;
        }
        if let Some(mech) = &resp.supported_mech {
            if self.state == State::Negotiating {
                self.select(mech)?;
            }
        }

        if self.state == State::Established {
            // We have already sent our final token. What is left is the
            // acceptor's acceptance and its MIC.
            if let Some(token) = &resp.response_token {
                // Windows sends none here. Feeding it is what tells us the
                // mechanism disagrees, rather than ignoring it silently.
                let _ = self.mechanism().step(token)?;
            }
            self.check_incoming_mic(&resp)?;
            if state != NegState::AcceptCompleted {
                tracing::warn!(?state, "the acceptor did not complete the exchange");
                return Err(AuthError::UnexpectedToken);
            }
            self.state = State::Done;
            return Ok(GssStep::Complete);
        }

        let inner_input = resp.response_token.clone().unwrap_or_default();
        match self.mechanism().step(&inner_input)? {
            GssStep::Token(token) => {
                let mic = self.outgoing_mic()?;
                Ok(GssStep::Token(
                    NegTokenResp {
                        neg_state: Some(NegState::AcceptIncomplete),
                        supported_mech: None,
                        response_token: Some(token),
                        mech_list_mic: mic,
                    }
                    .encode(),
                ))
            }
            GssStep::FinalToken(token) => {
                // The context is established by this token, so the MIC over
                // the mech list can be computed and travels with it.
                let mic = self.outgoing_mic()?;
                self.state = State::Established;
                // An empty inner token means the mechanism finished with
                // nothing left to send, which is what mutual authentication
                // Kerberos looks like once the AP-REP has been checked. The
                // `GssMechanism` seam has no way to say that (`GssStep::
                // Complete` is refused by CredSSP), so the mechanism says it
                // with an empty `FinalToken` and this is where that is turned
                // back into the absence RFC 4178 §4.2.2 describes.
                //
                // The difference is on the wire: `Some(vec![])` encodes a
                // present, zero length `responseToken [2]`, and Windows omits
                // the field. An acceptor is entitled to read a present empty
                // token as a mechanism token it should feed to the mechanism,
                // which then has nothing to make of it.
                let response_token = (!token.is_empty()).then_some(token);
                Ok(GssStep::FinalToken(
                    NegTokenResp {
                        neg_state: Some(NegState::AcceptIncomplete),
                        supported_mech: None,
                        response_token,
                        mech_list_mic: mic,
                    }
                    .encode(),
                ))
            }
            GssStep::Complete => {
                self.check_incoming_mic(&resp)?;
                self.state = State::Done;
                Ok(GssStep::Complete)
            }
        }
    }
}

/// Whether two mechanism OIDs name the same mechanism.
///
/// The only pair that differs is Kerberos: MS-SPNG 1.9's legacy
/// `1.2.840.48018.1.2.2` and RFC 4121's `1.2.840.113554.1.2.2` are the same
/// mechanism (PRDRDP/14 §4.7).
fn same_mechanism(ours: &[u8], theirs: &[u8]) -> bool {
    if ours == theirs {
        return true;
    }
    let kerberos = [oid::KRB5, oid::MS_KRB5];
    kerberos.contains(&ours) && kerberos.contains(&theirs)
}

impl GssMechanism for SpnegoClient {
    fn oid(&self) -> &'static [u8] {
        oid::SPNEGO
    }

    fn method_name(&self) -> &'static str {
        self.mechanisms
            .get(self.chosen)
            .map_or(METHOD_NAME_UNRESOLVED, |m| m.method_name())
    }

    fn step(&mut self, input: &[u8]) -> Result<GssStep, AuthError> {
        let result = match self.state {
            State::Start => {
                if input.is_empty() {
                    self.start().map(GssStep::Token)
                } else {
                    Err(AuthError::UnexpectedToken)
                }
            }
            State::Negotiating | State::Established => {
                if input.is_empty() {
                    Err(AuthError::UnexpectedToken)
                } else {
                    self.advance(input)
                }
            }
            State::Done => {
                if input.is_empty() {
                    Ok(GssStep::Complete)
                } else {
                    Err(AuthError::UnexpectedToken)
                }
            }
            State::Failed => Err(AuthError::AlreadyFailed),
        };
        if result.is_err() && self.state != State::Failed {
            self.state = State::Failed;
        }
        result
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, State::Established | State::Done)
            && self
                .mechanisms
                .get(self.chosen)
                .is_some_and(|m| m.is_complete())
    }

    fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        if !self.is_complete() {
            return Err(AuthError::ContextNotEstablished);
        }
        self.mechanism().wrap(plaintext)
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        if !self.is_complete() {
            return Err(AuthError::ContextNotEstablished);
        }
        self.mechanism().unwrap(token)
    }

    fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError> {
        if !self.is_complete() {
            return Err(AuthError::ContextNotEstablished);
        }
        self.mechanism().mic(message)
    }

    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), AuthError> {
        if !self.is_complete() {
            return Err(AuthError::ContextNotEstablished);
        }
        self.mechanism().verify_mic(message, mic)
    }
}

impl std::fmt::Debug for SpnegoClient {
    /// The state, the mechanism count and the chosen OID. The inner
    /// mechanisms hold key material and none of them renders
    /// (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpnegoClient")
            .field("state", &self.state)
            .field("mechanisms", &self.mechanisms.len())
            .field(
                "chosen",
                &self
                    .mechanisms
                    .get(self.chosen)
                    .and_then(|m| oid::dotted(m.oid())),
            )
            .field("mic_required", &self.mic_required)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::asn1::der;

    /// An inner mechanism that produces two tokens and then a MIC, with no
    /// cryptography in it. What these tests are about is the negotiation, and
    /// the mechanism underneath is proved in `nlmp_vectors.rs`.
    struct Inner {
        oid: &'static [u8],
        name: &'static str,
        rounds: u32,
        seen: u32,
        complete: bool,
    }

    impl Inner {
        fn boxed(oid: &'static [u8], name: &'static str) -> Box<dyn GssMechanism> {
            Box::new(Inner {
                oid,
                name,
                rounds: 1,
                seen: 0,
                complete: false,
            })
        }
    }

    impl GssMechanism for Inner {
        fn oid(&self) -> &'static [u8] {
            self.oid
        }

        fn method_name(&self) -> &'static str {
            self.name
        }

        fn step(&mut self, input: &[u8]) -> Result<GssStep, AuthError> {
            if self.complete {
                return if input.is_empty() {
                    Ok(GssStep::Complete)
                } else {
                    Err(AuthError::UnexpectedToken)
                };
            }
            self.seen += 1;
            if self.seen > self.rounds {
                self.complete = true;
                Ok(GssStep::FinalToken(
                    format!("{}-final", self.name).into_bytes(),
                ))
            } else {
                Ok(GssStep::Token(format!("{}-first", self.name).into_bytes()))
            }
        }

        fn is_complete(&self) -> bool {
            self.complete
        }

        fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
            if self.complete {
                Ok(plaintext.to_vec())
            } else {
                Err(AuthError::ContextNotEstablished)
            }
        }

        fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
            if self.complete {
                Ok(Zeroizing::new(token.to_vec()))
            } else {
                Err(AuthError::ContextNotEstablished)
            }
        }

        fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError> {
            if self.complete {
                let mut out = b"mic:".to_vec();
                out.extend_from_slice(message);
                Ok(out)
            } else {
                Err(AuthError::ContextNotEstablished)
            }
        }

        fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), AuthError> {
            let expected = self.mic(message)?;
            if expected == mic {
                Ok(())
            } else {
                Err(AuthError::SignatureMismatch)
            }
        }
    }

    fn client(mechs: Vec<Box<dyn GssMechanism>>) -> SpnegoClient {
        SpnegoClient::new(mechs).unwrap()
    }

    /// A mechanism that finishes with nothing left to send, which is what
    /// mutual authentication Kerberos looks like after the AP-REP is checked.
    /// The seam has no way to say "done, no token" (`GssStep::Complete` is
    /// refused by CredSSP), so it says it with an empty `FinalToken`.
    struct FinishesSilently {
        sent: bool,
    }

    impl GssMechanism for FinishesSilently {
        fn oid(&self) -> &'static [u8] {
            oid::KRB5
        }
        fn method_name(&self) -> &'static str {
            "nla-kerberos"
        }
        fn step(&mut self, _input: &[u8]) -> Result<GssStep, AuthError> {
            if self.sent {
                Ok(GssStep::FinalToken(Vec::new()))
            } else {
                self.sent = true;
                Ok(GssStep::Token(b"ap-req".to_vec()))
            }
        }
        fn is_complete(&self) -> bool {
            self.sent
        }
        fn wrap(&mut self, _: &[u8]) -> Result<Vec<u8>, AuthError> {
            Err(AuthError::UnexpectedToken)
        }
        fn unwrap(&mut self, _: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, AuthError> {
            Err(AuthError::UnexpectedToken)
        }
        fn mic(&mut self, _: &[u8]) -> Result<Vec<u8>, AuthError> {
            Ok(b"mic".to_vec())
        }
        fn verify_mic(&mut self, _: &[u8], _: &[u8]) -> Result<(), AuthError> {
            Ok(())
        }
    }

    /// A `responseToken` that is present and empty is not the same thing as an
    /// absent one, and Windows sends the absent form. An acceptor is entitled
    /// to read a present empty token as a mechanism token to feed onward, and
    /// the mechanism has nothing to make of it.
    ///
    /// This is the one wire difference the Kerberos lane flagged as the most
    /// likely source of an interop failure, so it is pinned here rather than
    /// left to a capture to discover.
    #[test]
    fn a_mechanism_that_finishes_silently_omits_the_response_token() {
        let mut spnego = client(vec![Box::new(FinishesSilently { sent: false })]);
        let GssStep::Token(_init) = spnego.step(&[]).unwrap() else {
            panic!("the first step produces the NegTokenInit")
        };

        // The acceptor answers, and the mechanism finishes with nothing to
        // say. What goes back carries the MIC and no responseToken.
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: None,
            response_token: Some(b"ap-rep".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let GssStep::FinalToken(out) = spnego.step(&reply).unwrap() else {
            panic!("the mechanism finished, so this is the final token")
        };

        let parsed = NegTokenResp::decode(&out).expect("a NegTokenResp");
        assert_eq!(
            parsed.response_token, None,
            "an empty inner token is an absent responseToken, not a present empty one"
        );
        // No MIC here, and that is right rather than a gap: RFC 4178 §5 makes
        // one required when the mechanism used was not the first offered, and
        // this exchange offered exactly one. `outgoing_mic` encodes that rule.
        // The point of this test is the token, not the MIC.
        assert_eq!(
            parsed.mech_list_mic, None,
            "one mechanism, used optimistically, needs no mechListMIC"
        );
    }

    /// The same finish, with a second mechanism offered so a MIC IS required.
    /// The `responseToken` must still be absent, and the MIC must still ride
    /// with it: omitting the token must not take the MIC with it.
    #[test]
    fn a_silent_finish_still_carries_the_mic_when_one_is_required() {
        let mut spnego = client(vec![
            Box::new(FinishesSilently { sent: false }),
            Inner::boxed(oid::NTLMSSP, "nla-ntlm"),
        ]);
        let GssStep::Token(_init) = spnego.step(&[]).unwrap() else {
            panic!("the first step produces the NegTokenInit")
        };
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: None,
            response_token: Some(b"ap-rep".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let GssStep::FinalToken(out) = spnego.step(&reply).unwrap() else {
            panic!("the mechanism finished, so this is the final token")
        };

        let parsed = NegTokenResp::decode(&out).expect("a NegTokenResp");
        assert_eq!(
            parsed.response_token, None,
            "still absent, not present empty"
        );
        assert!(
            parsed.mech_list_mic.is_some(),
            "two mechanisms were offered, so the MIC is required and must survive"
        );
    }

    #[test]
    fn the_first_token_is_an_initial_context_token_carrying_the_mech_list() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let GssStep::Token(token) = spnego.step(&[]).unwrap() else {
            panic!("the first step produces the NegTokenInit")
        };
        assert_eq!(token[0], 0x60, "[APPLICATION 0], RFC 2743 §3.1");
        assert!(!spnego.is_complete());
        // The optimistic token is the inner mechanism's first one
        // (RFC 4178 §4.2.1, PRDRDP/14 §4.6).
        assert!(token.windows(14).any(|w| w == b"nla-ntlm-first"));
    }

    #[test]
    fn the_normal_three_message_exchange_completes() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let GssStep::Token(_) = spnego.step(&[]).unwrap() else {
            panic!()
        };

        // Message 2: accept-incomplete, supportedMech, responseToken. Windows
        // echoes the OID it chose even when we offered only one
        // (PRDRDP/14 §4.7).
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(b"challenge".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let GssStep::FinalToken(token) = spnego.step(&reply).unwrap() else {
            panic!("the second step completes the inner context")
        };
        // A bare NegTokenResp, with no wrapper: a client that wraps the second
        // token gets a reject from Windows (PRDRDP/14 §4.2).
        assert_eq!(token[0], 0xa1);
        let parsed = NegTokenResp::decode(&token).unwrap();
        assert_eq!(
            parsed.response_token.as_deref(),
            Some(&b"nla-ntlm-final"[..])
        );
        assert!(
            parsed.mech_list_mic.is_none(),
            "one mechanism, so RFC 4178 §5 asks for no mechListMIC"
        );

        // The context is established, so CredSSP may wrap in this same round.
        assert!(spnego.is_complete());
        assert_eq!(spnego.wrap(b"pubKeyAuth").unwrap(), b"pubKeyAuth");
        assert_eq!(spnego.method_name(), "nla-ntlm");

        // Message 4: accept-completed with a mechListMIC and no token.
        let list = spnego.mech_list_der.clone();
        let mut mic = b"mic:".to_vec();
        mic.extend_from_slice(&list);
        let done = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: None,
            response_token: None,
            mech_list_mic: Some(mic),
        }
        .encode();
        assert_eq!(spnego.step(&done).unwrap(), GssStep::Complete);
    }

    #[test]
    fn a_mech_list_mic_covers_the_bytes_we_sent_and_not_a_reserialisation() {
        // RFC 4178 §5: over the DER encoding of the MechTypeList as the
        // initiator sent it, tag and length included.
        let mut spnego = client(vec![
            Inner::boxed(oid::MS_KRB5, "nla-kerberos"),
            Inner::boxed(oid::NTLMSSP, "nla-ntlm"),
        ]);
        let GssStep::Token(first) = spnego.step(&[]).unwrap() else {
            panic!()
        };
        let list = spnego.mech_list_der.clone();
        assert!(first.windows(list.len()).any(|w| w == list.as_slice()));

        // The server picks the second mechanism and has no token for it,
        // because we never started that one. `SpnegoClient` keeps every
        // mechanism it offered, so the chosen one runs from its own `Start`
        // state and the wasted optimistic token is simply dropped
        // (PRDRDP/14 §4.6).
        let switch = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: None,
            mech_list_mic: None,
        }
        .encode();
        let GssStep::Token(restart) = spnego.step(&switch).unwrap() else {
            panic!("the chosen mechanism starts from the beginning")
        };
        assert_eq!(spnego.method_name(), "nla-ntlm");
        assert_eq!(
            NegTokenResp::decode(&restart)
                .unwrap()
                .response_token
                .as_deref(),
            Some(&b"nla-ntlm-first"[..])
        );

        let challenge = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: None,
            response_token: Some(b"challenge".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let GssStep::FinalToken(token) = spnego.step(&challenge).unwrap() else {
            panic!()
        };
        let parsed = NegTokenResp::decode(&token).unwrap();
        let mut expected = b"mic:".to_vec();
        expected.extend_from_slice(&list);
        assert_eq!(
            parsed.mech_list_mic.as_deref(),
            Some(expected.as_slice()),
            "the mechanism used was not the first one offered, so §5 requires a MIC"
        );
        assert_eq!(
            parsed.response_token.as_deref(),
            Some(&b"nla-ntlm-final"[..])
        );
    }

    #[test]
    fn request_mic_adds_one_that_was_not_otherwise_required() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let _ = spnego.step(&[]).unwrap();
        let reply = NegTokenResp {
            neg_state: Some(NegState::RequestMic),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(b"challenge".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let GssStep::FinalToken(token) = spnego.step(&reply).unwrap() else {
            panic!()
        };
        assert!(NegTokenResp::decode(&token)
            .unwrap()
            .mech_list_mic
            .is_some());
    }

    #[test]
    fn the_legacy_kerberos_oid_names_the_same_mechanism() {
        // Windows answers supportedMech with 1.2.840.48018.1.2.2 on at least
        // Server 2019 and Windows 11, and a client that recognises only
        // 1.2.840.113554.1.2.2 concludes the server picked something unknown
        // (PRDRDP/14 §4.7).
        assert!(same_mechanism(oid::KRB5, oid::MS_KRB5));
        assert!(same_mechanism(oid::MS_KRB5, oid::KRB5));
        assert!(same_mechanism(oid::NTLMSSP, oid::NTLMSSP));
        assert!(!same_mechanism(oid::NTLMSSP, oid::KRB5));

        let mut spnego = client(vec![Inner::boxed(oid::KRB5, "nla-kerberos")]);
        let _ = spnego.step(&[]).unwrap();
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::MS_KRB5.to_vec()),
            response_token: Some(b"as-rep".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        assert!(spnego.step(&reply).is_ok());
    }

    #[test]
    fn a_reject_is_a_failure_with_no_token_to_inspect() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let _ = spnego.step(&[]).unwrap();
        let reply = NegTokenResp {
            neg_state: Some(NegState::Reject),
            ..NegTokenResp::default()
        }
        .encode();
        assert_eq!(
            spnego.step(&reply).unwrap_err(),
            AuthError::NoCommonMechanism
        );
        // And it stays failed.
        assert_eq!(spnego.step(&reply).unwrap_err(), AuthError::AlreadyFailed);
    }

    #[test]
    fn a_mechanism_we_did_not_offer_is_refused() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let _ = spnego.step(&[]).unwrap();
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::KRB5.to_vec()),
            response_token: Some(b"ap-req".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        assert_eq!(
            spnego.step(&reply).unwrap_err(),
            AuthError::NoCommonMechanism
        );
    }

    #[test]
    fn a_wrong_mech_list_mic_from_the_acceptor_is_refused() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let _ = spnego.step(&[]).unwrap();
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(b"challenge".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let _ = spnego.step(&reply).unwrap();
        let done = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            mech_list_mic: Some(b"mic:not the list we sent".to_vec()),
            ..NegTokenResp::default()
        }
        .encode();
        assert_eq!(
            spnego.step(&done).unwrap_err(),
            AuthError::SignatureMismatch
        );
    }

    #[test]
    fn an_acceptor_that_omits_the_final_mic_is_accepted() {
        // RFC 4178 §5 permits the acceptor to omit it when the first
        // mechanism was used, and refusing would break against servers that
        // do (PRDRDP/14 §4.5).
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let _ = spnego.step(&[]).unwrap();
        let reply = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(b"challenge".to_vec()),
            mech_list_mic: None,
        }
        .encode();
        let _ = spnego.step(&reply).unwrap();
        let done = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            ..NegTokenResp::default()
        }
        .encode();
        assert_eq!(spnego.step(&done).unwrap(), GssStep::Complete);
    }

    #[test]
    fn wrap_before_the_inner_context_exists_is_refused() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        assert_eq!(
            spnego.wrap(b"pubKeyAuth").unwrap_err(),
            AuthError::ContextNotEstablished
        );
        let _ = spnego.step(&[]).unwrap();
        assert_eq!(
            spnego.wrap(b"pubKeyAuth").unwrap_err(),
            AuthError::ContextNotEstablished
        );
    }

    #[test]
    fn an_empty_mechanism_list_is_refused() {
        assert_eq!(
            SpnegoClient::new(Vec::new()).unwrap_err(),
            AuthError::NoCommonMechanism
        );
    }

    #[test]
    fn every_truncation_of_a_reply_is_refused_and_none_panics() {
        let full = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(vec![0x41; 300]),
            mech_list_mic: Some(vec![0x42; 16]),
        }
        .encode();
        for n in 0..full.len() {
            let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
            let _ = spnego.step(&[]).unwrap();
            assert!(
                spnego.step(&full[..n]).is_err(),
                "a {n} byte prefix was accepted"
            );
        }
    }

    #[test]
    fn the_debug_rendering_names_the_mechanism_and_nothing_else() {
        let mut spnego = client(vec![Inner::boxed(oid::NTLMSSP, "nla-ntlm")]);
        let _ = spnego.step(&[]).unwrap();
        let rendered = format!("{spnego:?}");
        assert!(rendered.contains("1.3.6.1.4.1.311.2.2.10"), "{rendered}");
        assert!(!rendered.contains("first"), "{rendered}");
    }

    #[test]
    fn the_mech_list_is_a_sequence_of_object_identifiers_in_order() {
        let mut spnego = client(vec![
            Inner::boxed(oid::MS_KRB5, "nla-kerberos"),
            Inner::boxed(oid::KRB5, "nla-kerberos"),
            Inner::boxed(oid::NTLMSSP, "nla-ntlm"),
        ]);
        let _ = spnego.step(&[]).unwrap();
        let (list, rest) = der::read_tlv(&spnego.mech_list_der).unwrap();
        assert!(rest.is_empty());
        let mut items = list.content;
        for want in [oid::MS_KRB5, oid::KRB5, oid::NTLMSSP] {
            let (tlv, next) = der::read_tlv(items).unwrap();
            assert_eq!(tlv.content, want);
            items = next;
        }
        assert!(items.is_empty());
    }
}
