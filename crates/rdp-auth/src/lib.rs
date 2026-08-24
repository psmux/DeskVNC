//! # rdp-auth
//!
//! CredSSP, SPNEGO and NTLMv2, with Kerberos in phase 3. Pure state machines
//! over byte slices: feed them a token, get a token back. The session owns the
//! I/O (PRDRDP/14, PRDRDP/12 §2.2.3).
//!
//! Phase 1a is NTLMv2 only. [`ntlm`] is complete: the three messages, every key
//! derivation, the MIC, the sealing handles and the channel binding AV pair.
//! [`credssp`] wraps it in the TSRequest exchange that turns it into Network
//! Level Authentication: the DER, the public key binding of MS-CSSP 3.1.5 in
//! both of its constructions, and the delivery of the password afterwards.
//! [`spnego`] is written and is not sent in phase 1: with one mechanism there
//! is nothing to negotiate, and PRDRDP/14 §4.8 puts a raw NTLM token in
//! `negoTokens` until Kerberos arrives.
//!
//! [`kerberos`] is phase 3 and is behind the `kerberos` cargo feature: the AS
//! and TGS exchanges of RFC 4120, the AES encryption profile of RFC 3962, the
//! GSS-API framing of RFC 4121, and a [`GssMechanism`] that plugs into the
//! two modules above without either of them changing. It is what a domain
//! joined host under a Kerberos only policy needs, which NTLMv2 cannot serve
//! at all.
//!
//! ## No hand written cryptography
//!
//! This crate parses bytes controlled by a remote peer, so `#![forbid(unsafe_code)]`
//! makes memory safety the compiler's job rather than review's (PRDRDP/00 D11).
//!
//! Every cipher, hash, MAC, key derivation function, cipher mode and random
//! number generator used here is a call into a third party library named in
//! `Cargo.toml` (AGENT_BRIEF V3-A, PRDRDP/14 §2.10). What this crate owns is
//! the protocol: message layouts, state machines, string encodings, and the
//! order in which those library calls are made. It does not own a single line
//! of arithmetic that mixes, permutes, rotates or compresses secret material.
//!
//! The rule holds regardless of how small the primitive is. RC4 is forty lines
//! and it is not written here. If a construction we need has no vetted crate,
//! that is a finding for PRDRDP/11 and an escalation to the repository owner
//! (PRDRDP/14 §7.5), never a licence to write it here.
//!
//! ## Residual risk
//!
//! Calling vetted primitives removes the "we wrote a cipher" class of bug and
//! leaves the "we composed vetted primitives in the wrong order" class, which
//! is smaller and real (PRDRDP/14 §8.8). A vetted HMAC called with the wrong
//! key is a vetted HMAC producing a wrong answer, and most such failures
//! produce a working client whose security property quietly does not hold.
//! The mitigations are the MS-NLMP section 4.2 vectors in
//! `tests/nlmp_vectors.rs`, constant time comparison through `subtle`, the
//! truncation and bit flip sweeps, and fuzzing.
//!
//! ## What the client contributes against relaying
//!
//! NTLM reflection is a server side problem and a client can neither cause it
//! nor prevent it (MS-NLMP, PRDRDP/14 §8.5). What a client can do is make its
//! credentials less useful when relayed, and the two things that do that are
//! the MIC (MS-NLMP 3.1.5.1.2), which binds the three messages together so a
//! relay cannot alter the flags, and the channel binding (RFC 5929), which
//! ties the exchange to the server certificate so a relay to a different
//! endpoint fails. Both are sent, always, with no option to turn them off.
//!
//! MD4, MD5 and RC4 all appear here and all three are broken as primitives.
//! They are wire format constants in a protocol we did not design. What
//! protects the exchange is that it runs inside TLS against a pinned or CA
//! verified certificate, that the password never leaves the client until the
//! server has proved possession of the private key, and that Kerberos replaces
//! the whole thing in phase 3.
#![forbid(unsafe_code)]

pub mod bindings;
pub mod credssp;
pub mod error;
pub mod gss;
pub mod identity;
pub mod kerberos;
pub mod ntlm;
pub mod spnego;

pub use bindings::{gss_channel_bindings_struct, ChannelBindings, EndPointHash};
pub use credssp::{CredSspClient, CredSspConfig, MechanismId, MechanismSet};
pub use error::{AuthError, Class};
pub use gss::{GssMechanism, GssStep};
pub use identity::{service_principal_name, split_qualified_username, Identity};
#[cfg(feature = "kerberos")]
pub use kerberos::{KerberosClient, KerberosConfig};
pub use ntlm::{NtlmClient, NtlmConfig, NtlmSession};
pub use spnego::SpnegoClient;

/// What the caller must do next (PRDRDP/14 §2.5).
///
/// The state machine never touches a socket. The session reads and writes on
/// the TLS stream and hands the bytes back in.
///
/// Three variants, not four, and no `Expect` without a `Send`: neither CredSSP
/// nor NTLM ever wants to read twice in a row, and a variant for a case that
/// cannot occur invites a caller to handle it wrongly.
#[derive(Debug)]
#[must_use]
pub enum Step {
    /// Write these bytes to the peer, read the peer's next message, then call
    /// `step` again with it.
    SendAndExpect(Vec<u8>),
    /// Write these bytes. Do not wait for a reply; call `step(&[])` again
    /// straight away to collect the outcome.
    ///
    /// The final CredSSP message carries the encrypted credentials and has no
    /// reply, but the caller still has to flush before the session proceeds.
    /// Splitting the flush from the outcome keeps the driver loop a single
    /// `match` with one exit.
    Send(Vec<u8>),
    /// Finished. Nothing left to write.
    Done(Outcome),
}

/// What the session learns from a completed exchange (PRDRDP/14 §2.5).
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The identifier that reaches `SessionState::Authenticating` and the
    /// security label: "nla-ntlm" or "nla-kerberos" (PRDRDP/00 R12).
    pub method: &'static str,
    /// The CredSSP version actually in force, min(ours, theirs). Recorded for
    /// diagnostics and for the interop matrix; never shown to a user.
    pub credssp_version: u32,
    /// True when the server proved possession of the TLS private key through
    /// the pubKeyAuth exchange. Always true on success; kept explicit so a
    /// future mode that skips it cannot do so silently.
    pub public_key_bound: bool,
}
