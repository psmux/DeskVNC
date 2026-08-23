//! The SPNEGO tokens: `InitialContextToken`, `NegTokenInit` and
//! `NegTokenResp` (RFC 2743 §3.1, RFC 4178 §4.2, MS-SPNG).
//!
//! ```asn1
//! InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE {
//!         thisMech          MechType,
//!         innerContextToken ANY DEFINED BY thisMech }
//!
//! NegotiationToken ::= CHOICE {
//!         negTokenInit [0] NegTokenInit,
//!         negTokenResp [1] NegTokenResp }
//!
//! NegTokenInit ::= SEQUENCE {
//!         mechTypes   [0] MechTypeList,
//!         reqFlags    [1] ContextFlags OPTIONAL,
//!         mechToken   [2] OCTET STRING OPTIONAL,
//!         mechListMIC [3] OCTET STRING OPTIONAL }
//!
//! NegTokenResp ::= SEQUENCE {
//!         negState      [0] ENUMERATED OPTIONAL,
//!         supportedMech [1] MechType    OPTIONAL,
//!         responseToken [2] OCTET STRING OPTIONAL,
//!         mechListMIC   [3] OCTET STRING OPTIONAL }
//! ```
//!
//! ## Only the first token is wrapped
//!
//! RFC 2743 §3.1 wraps the initiator's **first** token: tag `0x60`, length,
//! the SPNEGO OID `06 06 2B 06 01 05 05 02`, then the `NegotiationToken`.
//! Because the SEQUENCE is IMPLICIT inside `[APPLICATION 0]` there is no
//! `0x30` after the `0x60`, which is the layer people add and then cannot
//! find. Every subsequent token is a bare `NegTokenResp`, tag `0xA1`, with no
//! wrapper and no OID; a client that wraps the second one gets a `reject`
//! from Windows (PRDRDP/14 §4.2).
//!
//! ## `mechListMIC` covers the bytes we sent
//!
//! RFC 4178 §4.2.2 and §5: the MIC is over the DER encoding of the
//! `MechTypeList` as the initiator sent it, tag and length included, and not
//! over a re-serialisation. [`NegTokenInit::encode`] returns those bytes
//! beside the token so the caller keeps them rather than rebuilding them.

use rdp_pdu::asn1::{context, der, tag};

use crate::error::AuthError;

/// `[APPLICATION 0]`, constructed: X.690 §8.1.2.2 with class bits `01` and
/// the constructed bit set (RFC 2743 §3.1).
pub const TAG_INITIAL_CONTEXT_TOKEN: u8 = 0x60;
/// `negTokenInit [0]`, the first alternative of `NegotiationToken`.
pub const TAG_NEG_TOKEN_INIT: u8 = context(0);
/// `negTokenResp [1]`, the second alternative and every later token.
pub const TAG_NEG_TOKEN_RESP: u8 = context(1);

const TAG_MECH_TYPES: u8 = context(0);
const TAG_MECH_TOKEN: u8 = context(2);
const TAG_INIT_MECH_LIST_MIC: u8 = context(3);

const TAG_NEG_STATE: u8 = context(0);
const TAG_SUPPORTED_MECH: u8 = context(1);
const TAG_RESPONSE_TOKEN: u8 = context(2);
const TAG_RESP_MECH_LIST_MIC: u8 = context(3);

/// `negState`, RFC 4178 §4.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    /// `accept-completed`, value 0. The exchange succeeded.
    AcceptCompleted,
    /// `accept-incomplete`, value 1. More tokens are needed, and an absent
    /// `negState` means this.
    AcceptIncomplete,
    /// `reject`, value 2. No mutually supported mechanism, or the mechanism
    /// failed. There is no token to inspect and no error code.
    Reject,
    /// `request-mic`, value 3. The acceptor wants a `mechListMIC` in the next
    /// token even though RFC 4178 §5's rules would not otherwise require one.
    RequestMic,
}

impl NegState {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(NegState::AcceptCompleted),
            1 => Some(NegState::AcceptIncomplete),
            2 => Some(NegState::Reject),
            3 => Some(NegState::RequestMic),
            _ => None,
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            NegState::AcceptCompleted => 0,
            NegState::AcceptIncomplete => 1,
            NegState::Reject => 2,
            NegState::RequestMic => 3,
        }
    }
}

/// The initiator's first token, RFC 4178 §4.2.1.
pub struct NegTokenInit<'a> {
    /// The mechanism OIDs, contents only, in preference order.
    pub mech_types: &'a [&'a [u8]],
    /// The optimistic token for the first mechanism in the list
    /// (RFC 4178 §4.2.1, PRDRDP/14 §4.6).
    pub mech_token: Option<&'a [u8]>,
    /// Rarely present on a first token; sent when the acceptor asked.
    pub mech_list_mic: Option<&'a [u8]>,
}

impl NegTokenInit<'_> {
    /// The complete first token, wrapped in its `InitialContextToken`.
    ///
    /// Returns the token and the `MechTypeList` element exactly as encoded,
    /// which is what a later `mechListMIC` is computed over (RFC 4178 §5).
    ///
    /// `reqFlags` is never written. RFC 4178 §4.2.1 deprecates it and Windows
    /// ignores it.
    #[must_use]
    pub fn encode(&self) -> (Vec<u8>, Vec<u8>) {
        let mut mech_list = Vec::new();
        der::write_nested(&mut mech_list, tag::SEQUENCE, |list| {
            for oid in self.mech_types {
                der::write_tlv(list, tag::OBJECT_IDENTIFIER, oid);
            }
        });

        let mut out = Vec::new();
        der::write_nested(&mut out, TAG_INITIAL_CONTEXT_TOKEN, |wrapper| {
            // IMPLICIT inside [APPLICATION 0]: the OID and the token follow
            // the 0x60 header directly, with no SEQUENCE of their own.
            der::write_tlv(wrapper, tag::OBJECT_IDENTIFIER, super::oid::SPNEGO);
            der::write_nested(wrapper, TAG_NEG_TOKEN_INIT, |choice| {
                der::write_nested(choice, tag::SEQUENCE, |body| {
                    der::write_nested(body, TAG_MECH_TYPES, |v| {
                        v.extend_from_slice(&mech_list);
                    });
                    if let Some(token) = self.mech_token {
                        der::write_nested(body, TAG_MECH_TOKEN, |v| {
                            der::write_tlv(v, tag::OCTET_STRING, token);
                        });
                    }
                    if let Some(mic) = self.mech_list_mic {
                        der::write_nested(body, TAG_INIT_MECH_LIST_MIC, |v| {
                            der::write_tlv(v, tag::OCTET_STRING, mic);
                        });
                    }
                });
            });
        });
        (out, mech_list)
    }
}

/// Every token after the first, in both directions, RFC 4178 §4.2.2.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct NegTokenResp {
    /// Absent is read as [`NegState::AcceptIncomplete`] (RFC 4178 §4.2.2).
    pub neg_state: Option<NegState>,
    /// The mechanism the acceptor chose, contents only. Absent on later
    /// rounds, where it is unchanged from the previous one.
    pub supported_mech: Option<Vec<u8>>,
    /// The mechanism token.
    pub response_token: Option<Vec<u8>>,
    /// `GSS_GetMIC` over the `MechTypeList` as the initiator sent it.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenResp {
    /// A bare `NegTokenResp`, tag `0xA1`, with no `InitialContextToken`
    /// wrapper (RFC 4178 §4.2, PRDRDP/14 §4.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        der::write_nested(&mut out, TAG_NEG_TOKEN_RESP, |choice| {
            der::write_nested(choice, tag::SEQUENCE, |body| {
                if let Some(state) = self.neg_state {
                    der::write_nested(body, TAG_NEG_STATE, |v| {
                        der::write_tlv(v, tag::ENUMERATED, &[state.to_byte()]);
                    });
                }
                if let Some(mech) = &self.supported_mech {
                    der::write_nested(body, TAG_SUPPORTED_MECH, |v| {
                        der::write_tlv(v, tag::OBJECT_IDENTIFIER, mech);
                    });
                }
                if let Some(token) = &self.response_token {
                    der::write_nested(body, TAG_RESPONSE_TOKEN, |v| {
                        der::write_tlv(v, tag::OCTET_STRING, token);
                    });
                }
                if let Some(mic) = &self.mech_list_mic {
                    der::write_nested(body, TAG_RESP_MECH_LIST_MIC, |v| {
                        der::write_tlv(v, tag::OCTET_STRING, mic);
                    });
                }
            });
        });
        out
    }

    /// Parse one acceptor token.
    ///
    /// Accepts a bare `NegTokenResp` and, for tolerance, one still wrapped in
    /// an `InitialContextToken`: no Windows version sends that, and a client
    /// that fails on it fails with "malformed" rather than with anything a
    /// user could act on.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] naming the field, never its contents.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        let (outer, trailing) = read(bytes, "SPNEGO token")?;
        if !trailing.is_empty() {
            return Err(AuthError::MalformedMessage(
                "trailing bytes after a SPNEGO token",
            ));
        }
        let choice = if outer.tag == TAG_INITIAL_CONTEXT_TOKEN {
            let (oid, rest) = read(outer.content, "thisMech")?;
            if oid.tag != tag::OBJECT_IDENTIFIER || oid.content != super::oid::SPNEGO {
                return Err(AuthError::MalformedMessage("thisMech is not SPNEGO"));
            }
            let (choice, extra) = read(rest, "NegotiationToken")?;
            if !extra.is_empty() {
                return Err(AuthError::MalformedMessage("InitialContextToken"));
            }
            choice
        } else {
            outer
        };
        if choice.tag != TAG_NEG_TOKEN_RESP {
            return Err(AuthError::MalformedMessage("not a NegTokenResp"));
        }
        let (body, extra) = read(choice.content, "NegTokenResp")?;
        if body.tag != tag::SEQUENCE || !extra.is_empty() {
            return Err(AuthError::MalformedMessage(
                "NegTokenResp is not a SEQUENCE",
            ));
        }

        let mut out = NegTokenResp::default();
        let mut rest = body.content;
        while !rest.is_empty() {
            let (field, next) = read(rest, "NegTokenResp field")?;
            rest = next;
            match field.tag {
                TAG_NEG_STATE => {
                    let (value, extra) = der::expect_tag(field.content, tag::ENUMERATED)
                        .ok_or(AuthError::MalformedMessage("negState"))?;
                    if !extra.is_empty() || value.len() != 1 {
                        return Err(AuthError::MalformedMessage("negState"));
                    }
                    out.neg_state = Some(
                        NegState::from_byte(value[0])
                            .ok_or(AuthError::MalformedMessage("negState"))?,
                    );
                }
                TAG_SUPPORTED_MECH => {
                    let (oid, extra) = der::expect_tag(field.content, tag::OBJECT_IDENTIFIER)
                        .ok_or(AuthError::MalformedMessage("supportedMech"))?;
                    if !extra.is_empty() {
                        return Err(AuthError::MalformedMessage("supportedMech"));
                    }
                    out.supported_mech = Some(oid.to_vec());
                }
                TAG_RESPONSE_TOKEN => {
                    out.response_token = Some(octet_string(field.content, "responseToken")?);
                }
                TAG_RESP_MECH_LIST_MIC => {
                    out.mech_list_mic = Some(octet_string(field.content, "mechListMIC")?);
                }
                other => {
                    tracing::debug!(
                        tag = format_args!("{other:#04x}"),
                        "ignoring an unknown NegTokenResp field"
                    );
                }
            }
        }
        Ok(out)
    }

    /// `negState` with RFC 4178 §4.2.2's default applied.
    #[must_use]
    pub fn state(&self) -> NegState {
        self.neg_state.unwrap_or(NegState::AcceptIncomplete)
    }
}

impl std::fmt::Debug for NegTokenResp {
    /// The state and the shapes. A `responseToken` carries an NTLM
    /// AUTHENTICATE and a `mechListMIC` is a MAC, so neither prints
    /// (PRDRDP/14 §8.4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegTokenResp")
            .field("neg_state", &self.neg_state)
            .field(
                "supported_mech",
                &self.supported_mech.as_deref().and_then(super::oid::dotted),
            )
            .field(
                "response_token",
                &self.response_token.as_ref().map(Vec::len),
            )
            .field("mech_list_mic", &self.mech_list_mic.as_ref().map(Vec::len))
            .finish()
    }
}

fn octet_string(content: &[u8], what: &'static str) -> Result<Vec<u8>, AuthError> {
    let (bytes, extra) =
        der::expect_tag(content, tag::OCTET_STRING).ok_or(AuthError::MalformedMessage(what))?;
    if !extra.is_empty() {
        return Err(AuthError::MalformedMessage(what));
    }
    Ok(bytes.to_vec())
}

fn read<'a>(buf: &'a [u8], what: &'static str) -> Result<(der::Tlv<'a>, &'a [u8]), AuthError> {
    der::read_tlv(buf).ok_or(AuthError::MalformedMessage(what))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spnego::oid;

    #[test]
    fn the_first_token_is_wrapped_and_has_no_sequence_after_the_sixty() {
        let mechs: [&[u8]; 1] = [oid::NTLMSSP];
        let (token, mech_list) = NegTokenInit {
            mech_types: &mechs,
            mech_token: Some(b"NTLMSSP\0\x01\x00\x00\x00"),
            mech_list_mic: None,
        }
        .encode();

        assert_eq!(token[0], 0x60, "[APPLICATION 0]");
        // RFC 2743 §3.1: the OID follows the header directly. A 0x30 here is
        // the extra SEQUENCE people add for the IMPLICIT one.
        let (outer, rest) = der::read_tlv(&token).unwrap();
        assert!(rest.is_empty());
        assert_eq!(outer.content[0], tag::OBJECT_IDENTIFIER);
        let (this_mech, after) = der::read_tlv(outer.content).unwrap();
        assert_eq!(this_mech.content, oid::SPNEGO);
        assert_eq!(after[0], TAG_NEG_TOKEN_INIT);

        // The MechTypeList element, tag and length included, is what a MIC
        // covers (RFC 4178 §5).
        assert_eq!(mech_list[0], tag::SEQUENCE);
        assert_eq!(
            mech_list,
            vec![
                0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
            ]
        );
        // And it appears verbatim inside the token.
        assert!(token
            .windows(mech_list.len())
            .any(|w| w == mech_list.as_slice()));
    }

    #[test]
    fn a_kerberos_first_list_is_the_order_windows_uses() {
        let mechs: [&[u8]; 3] = [oid::MS_KRB5, oid::KRB5, oid::NTLMSSP];
        let (_, mech_list) = NegTokenInit {
            mech_types: &mechs,
            mech_token: None,
            mech_list_mic: None,
        }
        .encode();
        // Three OBJECT IDENTIFIER elements, in the order given.
        let (list, _) = der::read_tlv(&mech_list).unwrap();
        let mut rest = list.content;
        for want in mechs {
            let (oid_tlv, next) = der::read_tlv(rest).unwrap();
            assert_eq!(oid_tlv.tag, tag::OBJECT_IDENTIFIER);
            assert_eq!(oid_tlv.content, want);
            rest = next;
        }
        assert!(rest.is_empty());
    }

    #[test]
    fn the_normal_second_message_round_trips() {
        let resp = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(b"NTLMSSP\0\x02\x00\x00\x00challenge".to_vec()),
            mech_list_mic: None,
        };
        let bytes = resp.encode();
        assert_eq!(bytes[0], TAG_NEG_TOKEN_RESP, "bare, with no 0x60 wrapper");
        assert_eq!(NegTokenResp::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn the_final_message_round_trips() {
        let resp = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: None,
            response_token: None,
            mech_list_mic: Some(vec![0x01, 0x00, 0x00, 0x00, 0x77, 0x88]),
        };
        assert_eq!(NegTokenResp::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn an_absent_negstate_reads_as_accept_incomplete() {
        let resp = NegTokenResp {
            neg_state: None,
            response_token: Some(b"token".to_vec()),
            ..NegTokenResp::default()
        };
        let parsed = NegTokenResp::decode(&resp.encode()).unwrap();
        assert_eq!(parsed.neg_state, None);
        assert_eq!(parsed.state(), NegState::AcceptIncomplete);
    }

    #[test]
    fn every_negstate_value_round_trips_and_a_fourth_is_refused() {
        for state in [
            NegState::AcceptCompleted,
            NegState::AcceptIncomplete,
            NegState::Reject,
            NegState::RequestMic,
        ] {
            let resp = NegTokenResp {
                neg_state: Some(state),
                ..NegTokenResp::default()
            };
            assert_eq!(NegTokenResp::decode(&resp.encode()).unwrap().state(), state);
        }
        // RFC 4178 §4.2.2 defines four values. `A1 05 30 03 A0 03 0A 01 04`
        // is a fifth.
        let bogus = [0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x04];
        assert_eq!(
            NegTokenResp::decode(&bogus).unwrap_err(),
            AuthError::MalformedMessage("negState")
        );
    }

    #[test]
    fn a_wrapped_reply_is_tolerated() {
        // No Windows version sends one, and refusing costs a legible error.
        let inner = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            response_token: Some(b"token".to_vec()),
            ..NegTokenResp::default()
        };
        let mut wrapped = Vec::new();
        der::write_nested(&mut wrapped, TAG_INITIAL_CONTEXT_TOKEN, |w| {
            der::write_tlv(w, tag::OBJECT_IDENTIFIER, oid::SPNEGO);
            w.extend_from_slice(&inner.encode());
        });
        assert_eq!(NegTokenResp::decode(&wrapped).unwrap(), inner);
    }

    #[test]
    fn every_truncation_is_refused_and_none_panics() {
        let full = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(oid::NTLMSSP.to_vec()),
            response_token: Some(vec![0x41; 200]),
            mech_list_mic: Some(vec![0x42; 16]),
        }
        .encode();
        for n in 0..full.len() {
            assert!(
                NegTokenResp::decode(&full[..n]).is_err(),
                "a {n} byte prefix decoded"
            );
        }
    }

    #[test]
    fn a_negtokeninit_is_not_accepted_as_a_reply() {
        // `[0]` is the initiator's alternative. A server sending one is
        // either confused or probing.
        let mechs: [&[u8]; 1] = [oid::NTLMSSP];
        let (token, _) = NegTokenInit {
            mech_types: &mechs,
            mech_token: None,
            mech_list_mic: None,
        }
        .encode();
        assert_eq!(
            NegTokenResp::decode(&token).unwrap_err(),
            AuthError::MalformedMessage("not a NegTokenResp")
        );
    }
}
