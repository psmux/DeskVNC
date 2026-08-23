//! CredSSP, MS-CSSP. Not written yet.
//!
//! This module is a stub with its citations, so the shape of what goes here is
//! recorded before anybody writes it. PRDRDP/14 §3 is the specification.
//!
//! ## Why it is blocked
//!
//! Every CredSSP message is a `TSRequest`, which is DER (MS-CSSP 2.2.1), and
//! the DER codec lives in `rdp_pdu::asn1::der` (PRDRDP/00 R45, PRDRDP/13 §3.5)
//! rather than here. `rdp-pdu` is being written now. Nothing in this module
//! can be written twice: a second DER walker in this crate is exactly the
//! duplication R45 exists to prevent.
//!
//! ## What goes here
//!
//! * `mod.rs`: `CredSspClient`, the state machine of PRDRDP/14 §3.13, driving
//!   a `Box<dyn GssMechanism>` and returning [`Step`](crate::Step). Nothing in
//!   it mentions NTLM.
//! * `ts_request.rs`: `TSRequest` encode and decode, MS-CSSP 2.2.1. The
//!   fields are `version`, `negoTokens`, `authInfo`, `pubKeyAuth`,
//!   `errorCode` and `clientNonce`.
//! * `ts_credentials.rs`: `TSCredentials` and `TSPasswordCreds`,
//!   MS-CSSP 2.2.1.2. Every buffer here is `Zeroizing`.
//! * `binding.rs`: `pubKeyAuth` for CredSSP versions 2 to 4 (the raw
//!   `subjectPublicKey`) and 5 to 6 (`SHA256(magic || nonce || key)`),
//!   MS-CSSP 3.1.5. Two errata land on eleven bytes of this file and each
//!   needs its own comment: PRDRDP/11 §5.3 item 3 (the magic string is ASCII
//!   with its trailing NUL, not UTF-16) and item 10 (the prose says key,
//!   magic, nonce and the pseudocode two lines below says magic, nonce, key;
//!   the pseudocode is what Windows does).
//! * `nstatus.rs`: the NTSTATUS table of PRDRDP/14 §3.10, which is what turns
//!   an `errorCode` into the sentence a user can act on.
//!
//! The version we advertise is 6 and the lowest server version we complete
//! against is 2 (PRDRDP/14 §3.4, §8.7). The version is frozen from the
//! server's first reply, so a server cannot advertise 6, watch us pick the
//! hash construction, and then re-advertise 2 to get the raw public key form.
