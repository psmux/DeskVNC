//! The mechanism seam (PRDRDP/14 §2.8).
//!
//! CredSSP does not care which mechanism produced the token in `negoTokens`;
//! it cares that something can produce tokens, then wrap and unwrap. That is
//! the seam Kerberos has to fit through in phase 3, and it has to exist in
//! phase 1 or it will not fit later.
//!
//! [`NtlmClient`](crate::ntlm::NtlmClient) implements it now. `SpnegoClient`
//! will implement it over a list of inner mechanisms, which is what makes
//! SPNEGO a drop in replacement for raw NTLM at the CredSSP layer:
//! `CredSspClient` holds a `Box<dyn GssMechanism>` and nothing in the CredSSP
//! module mentions NTLM.

use zeroize::Zeroizing;

use crate::error::AuthError;

/// What a mechanism did with one round of input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum GssStep {
    /// A token to put in `negoTokens`. The context is not complete yet.
    Token(Vec<u8>),
    /// A final token to put in `negoTokens`, and the context is now complete,
    /// so `wrap` may be called in the same TSRequest.
    FinalToken(Vec<u8>),
    /// The context is complete and there is nothing more to send.
    Complete,
}

/// One authentication mechanism, as CredSSP uses it.
///
/// `wrap`, `unwrap`, `mic` and `verify_mic` take `&mut self` because each
/// advances a sequence number and an RC4 keystream. A `&self` signature would
/// be a lie and would let a caller reorder two wraps without a compiler
/// complaint.
pub trait GssMechanism {
    /// The DER-encoded OBJECT IDENTIFIER, contents only, for SPNEGO's
    /// mechTypes list (MS-SPNG, RFC 4178).
    fn oid(&self) -> &'static [u8];

    /// The identifier that reaches `SessionState::Authenticating` (R12).
    fn method_name(&self) -> &'static str;

    /// Consume the peer's token (empty on the first call) and produce ours.
    ///
    /// # Errors
    ///
    /// Whatever the mechanism makes of the token, and
    /// [`AuthError::UnexpectedToken`] when a token arrives in a state that has
    /// no use for one.
    fn step(&mut self, input: &[u8]) -> Result<GssStep, AuthError>;

    /// True once `wrap`, `unwrap`, `mic` and `verify_mic` may be called.
    fn is_complete(&self) -> bool;

    /// `GSS_WrapEx` with confidentiality. Used for `pubKeyAuth` and
    /// `authInfo` (MS-NLMP 3.4.6, MS-CSSP 3.1.5).
    ///
    /// # Errors
    ///
    /// [`AuthError::ContextNotEstablished`] before the context is complete.
    fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError>;

    /// `GSS_UnwrapEx`. Verifies the signature before returning plaintext.
    ///
    /// The return type is `Zeroizing` so a caller cannot forget: the
    /// plaintext of an unwrapped CredSSP blob is key material.
    ///
    /// # Errors
    ///
    /// [`AuthError::SignatureMismatch`] when the MAC does not verify,
    /// [`AuthError::MessageOutOfSequence`] when the sequence number is not the
    /// one we expected, [`AuthError::ContextNotEstablished`] before the
    /// context is complete.
    fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError>;

    /// `GSS_GetMIC` over a message, for SPNEGO's `mechListMIC`.
    ///
    /// # Errors
    ///
    /// [`AuthError::ContextNotEstablished`] before the context is complete.
    fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError>;

    /// `GSS_VerifyMIC`. Constant time (PRDRDP/14 §8.1).
    ///
    /// # Errors
    ///
    /// [`AuthError::SignatureMismatch`] when the MAC does not verify.
    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), AuthError>;
}
