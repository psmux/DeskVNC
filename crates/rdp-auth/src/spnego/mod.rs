//! SPNEGO, MS-SPNG and RFC 4178. Not written yet, and not needed yet.
//!
//! PRDRDP/14 §4.8 decides this: phase 1 sends a raw NTLM token in the
//! CredSSP `negoTokens` field, with no SPNEGO wrapper. Windows accepts that,
//! and every byte of SPNEGO written before there is a second mechanism to
//! multiplex is a byte written to negotiate a list of one.
//!
//! ## Why it is blocked as well as unneeded
//!
//! `NegTokenInit` and `NegTokenResp` are DER (RFC 4178 §4.2), and the DER
//! codec lives in `rdp_pdu::asn1::der` (PRDRDP/00 R45).
//!
//! ## What goes here, in phase 3
//!
//! * `mod.rs`: `SpnegoClient`, itself a
//!   [`GssMechanism`](crate::gss::GssMechanism) over a list of inner
//!   mechanisms. That is what makes SPNEGO a drop in replacement for raw NTLM
//!   at the CredSSP layer.
//! * `token.rs`: the GSS-API `InitialContextToken` wrapper (RFC 2743 §3.1),
//!   `NegTokenInit` and `NegTokenResp` (RFC 4178 §4.2), and `mechListMIC`
//!   (RFC 4178 §4.2.2), which `GssMechanism::mic` already exists to produce.
//! * `oid.rs`: the mechanism OIDs as DER constants. NTLM's,
//!   `1.3.6.1.4.1.311.2.2.10`, is already
//!   [`ntlm::NTLM_MECH_OID`](crate::ntlm::NTLM_MECH_OID).
