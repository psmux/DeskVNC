//! CredSSP, MS-CSSP, the client side.
//!
//! ```text
//!   1. C->S  TSRequest { version=6, negoTokens=[NTLM NEGOTIATE] }
//!   2. S->C  TSRequest { version=<server>, negoTokens=[NTLM CHALLENGE] }
//!   3. C->S  TSRequest { version=6, negoTokens=[NTLM AUTHENTICATE],
//!                        pubKeyAuth=E(binding), clientNonce=<32 bytes> }
//!   4. S->C  TSRequest { version=<server>, pubKeyAuth=E(server binding) }
//!   5. C->S  TSRequest { version=6, authInfo=E(TSCredentials) }
//!            (no reply; the session proceeds to the MCS Connect Initial, or
//!             under PROTOCOL_HYBRID_EX reads the four byte Early User
//!             Authorization Result first, which is `rdp-pdu`'s)
//! ```
//!
//! Nothing in this module mentions NTLM. It drives a
//! [`GssMechanism`](crate::gss::GssMechanism), which in phase 1 is
//! [`NtlmClient`](crate::ntlm::NtlmClient) and in phase 3 is
//! [`SpnegoClient`](crate::spnego::SpnegoClient) over a list that includes
//! Kerberos (PRDRDP/14 §2.8, §4.8).
//!
//! ## Why the password is safe to send in message 5
//!
//! The password does not leave the client until message 5, which is after the
//! client has verified the server's `pubKeyAuth` in message 4, which the
//! server can produce only if it holds the private key of the certificate the
//! client saw. A relaying interceptor computes a different binding on the far
//! side and the exchange dies before any credential is sent (MS-CSSP 3.1.5
//! steps 3 to 5, PRDRDP/14 §3.5).
//!
//! An **impersonating** interceptor with its own certificate completes the
//! whole thing and gets the password. The only control for that is the trust
//! decision, which is why PRDRDP/03 makes the certificate prompt block and
//! why [`CredSspClient::new`] is not called until it has resolved
//! (PRDRDP/14 §8.6).
//!
//! ## The order inside message 3 is fixed
//!
//! 1. Ask the mechanism for its token, which as a side effect derives the
//!    session keys and creates the sealing handles.
//! 2. Only now generate `clientNonce`, if the effective version is 5 or 6.
//! 3. Compute the binding value from the nonce and the server public key.
//! 4. `wrap` the binding. This is the first use of the client to server
//!    sealing handle, so its sequence number is 0.
//! 5. Encode all of it into one TSRequest.
//!
//! Getting 1 and 4 the other way round is impossible, because there are no
//! keys yet. Getting 2 after 3 is possible and produces a binding over a
//! nonce that is not the one sent, which the server rejects with no
//! explanation. `credssp_nonce_is_the_one_sent` in `tests/credssp_der.rs`
//! pulls the nonce back out of the encoded TSRequest and recomputes the hash
//! against it (PRDRDP/14 §3.5, §8.8).
//!
//! ## Known risk
//!
//! Neither the state machine nor the wrap ordering has been seen against a
//! real server. What is proved is the DER against MS-CSSP section 4's one
//! published byte dump and against §3.2's worked example, the binding
//! constructions against the specification's own pseudocode, and the whole
//! flow against a server side written from the same text, which cannot
//! validate our reading of the message order because both sides share our
//! assumption. If CredSSP reaches message 4 and then fails, `ntlm/seal.rs`
//! and the sequence numbers are where to look.

pub mod binding;
pub mod nstatus;
pub mod ts_credentials;
pub mod ts_request;

use zeroize::Zeroizing;

use crate::bindings::ChannelBindings;
use crate::error::AuthError;
use crate::gss::{GssMechanism, GssStep};
use crate::identity::Identity;
use crate::ntlm::{NtlmClient, NtlmConfig};
use crate::spnego::SpnegoClient;
use crate::{Outcome, Step};

use binding::PublicKeyBinding;
use ts_request::TsRequest;

pub use ts_request::{CLIENT_VERSION, MIN_SERVER_VERSION, NONCE_LEN};

/// The most `negoTokens` rounds we will run before giving up.
///
/// NTLM needs 2, SPNEGO with NTLM needs 3, and Kerberos with a referral chain
/// might need 4. A server that keeps producing tokens forever is either
/// broken or trying to make us allocate (PRDRDP/14 §3.13).
pub const MAX_NEGOTIATION_ROUNDS: u32 = 8;

/// Which mechanisms may be offered, in preference order (PRDRDP/14 §4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MechanismSet {
    /// A raw NTLM token directly in `negoTokens`, with no SPNEGO wrapper.
    /// Phase 1 and 2.
    NtlmOnly,
    /// SPNEGO over the given list, most preferred first. Phase 3.
    Spnego(Vec<MechanismId>),
}

/// One mechanism SPNEGO can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MechanismId {
    /// NTLMv2, MS-NLMP.
    Ntlm,
}

/// What the session hands the CredSSP client.
///
/// Everything here has been resolved before the client is built: there is no
/// stream, no host, no port and no options struct from another crate, which
/// is what lets the whole unit suite run with no network (PRDRDP/14 §2.6).
pub struct CredSspConfig {
    /// Who we are. Zeroized on drop; `Debug` redacts.
    pub identity: Identity,
    /// `"TERMSRV/<server_name>"`, from
    /// [`service_principal_name`](crate::identity::service_principal_name).
    pub spn: String,
    /// The `subjectPublicKey` BIT STRING contents of the server certificate's
    /// SubjectPublicKeyInfo, with the unused bits octet already stripped
    /// (MS-CSSP 3.1.5, PRDRDP/14 §3.6).
    ///
    /// `rdp_pdu::asn1::der::subject_public_key` produces it. This is not the
    /// SPKI element and not the SPKI fingerprint: those are the trust on
    /// first use pin, which is a different value from the same certificate,
    /// and using one where the other belongs produces an exchange that
    /// reaches message 4 and dies opaquely.
    pub server_public_key: Vec<u8>,
    /// The leaf certificate DER, for the RFC 5929 channel binding.
    ///
    /// `None` omits `MsvAvChannelBindings` entirely, which only the mock
    /// does. A stock Windows host accepts a client that sends none; under the
    /// "Require" Extended Protection setting a missing binding is rejected and
    /// the failure looks like a wrong password (PRDRDP/14 §3.12).
    pub server_certificate: Option<Vec<u8>>,
    /// The certificate's `signatureAlgorithm` OID contents, which RFC 5929 §4
    /// uses to choose the hash.
    ///
    /// `vnc_transport::tls::upgrade_with_identity` returns it beside the
    /// certificate (PRDRDP/00 R47), so it is read once rather than by walking
    /// the same certificate a second time. An empty value, or one this client
    /// does not recognise, falls back to SHA-256 with a warning.
    pub certificate_signature_algorithm: Vec<u8>,
    /// This machine's NetBIOS name, uppercased, at most fifteen characters.
    /// `None` sends an empty `Workstation`, which Windows accepts.
    pub workstation: Option<String>,
    /// The version we advertise. 6 ([`CLIENT_VERSION`]).
    pub client_version: u32,
    /// The lowest server version we will complete against. 2
    /// ([`MIN_SERVER_VERSION`], PRDRDP/14 §8.7).
    pub min_server_version: u32,
    /// Which mechanisms may be offered.
    pub mechanisms: MechanismSet,
}

impl CredSspConfig {
    /// The phase 1 configuration: version 6 down to 2, raw NTLM.
    ///
    /// Everything a caller is likely to get wrong has one value, and this is
    /// it. `server_certificate` and `certificate_signature_algorithm` come
    /// from the same `TlsUpgrade` and are passed together so they cannot be
    /// taken from two different connections.
    #[must_use]
    pub fn new(
        identity: Identity,
        spn: String,
        server_public_key: Vec<u8>,
        server_certificate: Vec<u8>,
        certificate_signature_algorithm: Vec<u8>,
    ) -> Self {
        CredSspConfig {
            identity,
            spn,
            server_public_key,
            server_certificate: Some(server_certificate),
            certificate_signature_algorithm,
            workstation: None,
            client_version: CLIENT_VERSION,
            min_server_version: MIN_SERVER_VERSION,
            mechanisms: MechanismSet::NtlmOnly,
        }
    }

    /// The RFC 5929 `tls-server-end-point` binding for this certificate, or
    /// `None` when there is no certificate to bind to.
    fn channel_bindings(&self) -> Option<ChannelBindings> {
        self.server_certificate.as_deref().map(|der| {
            ChannelBindings::from_certificate(der, &self.certificate_signature_algorithm)
        })
    }
}

impl std::fmt::Debug for CredSspConfig {
    /// The SPN, the versions and the shapes. The identity redacts itself and
    /// the public key is not printed, because a log line that identifies the
    /// certificate is a log line that identifies the host (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredSspConfig")
            .field("identity", &self.identity)
            .field("spn", &self.spn)
            .field("server_public_key", &self.server_public_key.len())
            .field("server_certificate", &self.server_certificate.is_some())
            .field("workstation", &self.workstation)
            .field("client_version", &self.client_version)
            .field("min_server_version", &self.min_server_version)
            .field("mechanisms", &self.mechanisms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nothing sent. `step(&[])` produces message 1.
    Start,
    /// A `negoTokens` round is out; awaiting the server's.
    Negotiating,
    /// Message 3 is out; awaiting the server's `pubKeyAuth`.
    AwaitingPublicKeyAuth,
    /// Message 5 is out. `step(&[])` returns `Done`.
    SendingCredentials,
    /// A terminal error was already reported. Any further call returns it.
    Failed(AuthError),
}

/// The CredSSP client state machine (PRDRDP/14 §3.13).
///
/// Pure: it never touches a socket, never sleeps and never allocates a
/// runtime. The session reads and writes and hands the bytes back in.
///
/// `Failed` is sticky. A caller that ignores an `Err` and calls `step` again
/// gets the same error rather than a state machine that has advanced past its
/// own failure.
pub struct CredSspClient {
    config: CredSspConfig,
    mechanism: Box<dyn GssMechanism>,
    /// `min(ours, theirs)`, frozen from the server's first reply so that a
    /// server cannot advertise 6, watch us pick the hash construction, and
    /// then re-advertise 2 to get the raw public key form (PRDRDP/14 §3.4,
    /// §8.7).
    effective_version: Option<u32>,
    /// The version in the server's first reply, so a later change can be
    /// logged as the downgrade attempt it is.
    server_version: Option<u32>,
    binding: Option<PublicKeyBinding>,
    /// True when the mechanism owes one more token after its final one, which
    /// SPNEGO does and raw NTLM does not.
    expects_trailing_token: bool,
    rounds: u32,
    state: State,
}

impl CredSspClient {
    /// A client that has not sent anything yet.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnsupportedCredSspVersion`] when the configured version
    /// range is not one this implementation has a construction for, and
    /// [`AuthError::NoCommonMechanism`] when the mechanism list is empty.
    pub fn new(config: CredSspConfig) -> Result<Self, AuthError> {
        if config.client_version < config.min_server_version
            || config.min_server_version < MIN_SERVER_VERSION
            || config.client_version > CLIENT_VERSION
        {
            tracing::warn!(
                client = config.client_version,
                min_server = config.min_server_version,
                "the configured CredSSP version range has no construction"
            );
            return Err(AuthError::UnsupportedCredSspVersion);
        }
        let mechanism = build_mechanism(&config)?;
        Self::with_mechanism(config, mechanism)
    }

    /// The same, with the mechanism supplied rather than built from
    /// [`MechanismSet`].
    ///
    /// This is the seam the test suite and the mock server of PRDRDP/14 §9.3
    /// need: the CredSSP layer's contract is with [`GssMechanism`] and not
    /// with NTLM, and a state machine whose only reachable entry point builds
    /// its own collaborator cannot be tested at the layer where its bugs are
    /// (PRDRDP/14 §6.5).
    ///
    /// # Errors
    ///
    /// [`AuthError::UnsupportedCredSspVersion`] when the configured version
    /// range is not one this implementation has a construction for.
    pub fn with_mechanism(
        config: CredSspConfig,
        mechanism: Box<dyn GssMechanism>,
    ) -> Result<Self, AuthError> {
        if config.client_version < config.min_server_version
            || config.min_server_version < MIN_SERVER_VERSION
            || config.client_version > CLIENT_VERSION
        {
            tracing::warn!(
                client = config.client_version,
                min_server = config.min_server_version,
                "the configured CredSSP version range has no construction"
            );
            return Err(AuthError::UnsupportedCredSspVersion);
        }
        let expects_trailing_token = matches!(config.mechanisms, MechanismSet::Spnego(_));
        Ok(CredSspClient {
            config,
            mechanism,
            effective_version: None,
            server_version: None,
            binding: None,
            expects_trailing_token,
            rounds: 0,
            state: State::Start,
        })
    }

    /// The effective CredSSP version, once the server's first reply has
    /// frozen it.
    #[must_use]
    pub fn effective_version(&self) -> Option<u32> {
        self.effective_version
    }

    /// Consume the peer's message and produce the next thing to do.
    ///
    /// `input` is one complete TSRequest, or empty for the first call and for
    /// the call that collects the outcome after
    /// [`Step::Send`](crate::Step::Send).
    ///
    /// # Errors
    ///
    /// Everything in [`AuthError`]. The failure is sticky: a second call
    /// returns the same error rather than advancing.
    pub fn step(&mut self, input: &[u8]) -> Result<Step, AuthError> {
        if let State::Failed(error) = self.state {
            return Err(error);
        }
        match self.step_inner(input) {
            Ok(step) => Ok(step),
            Err(error) => {
                tracing::debug!(?error, state = ?self.state, "the CredSSP exchange failed");
                self.state = State::Failed(error);
                Err(error)
            }
        }
    }

    fn step_inner(&mut self, input: &[u8]) -> Result<Step, AuthError> {
        match self.state {
            State::Start => {
                if !input.is_empty() {
                    return Err(AuthError::UnexpectedToken);
                }
                self.first_message()
            }
            State::Negotiating => {
                let request = self.receive(input)?;
                self.negotiate(request)
            }
            State::AwaitingPublicKeyAuth => {
                let request = self.receive(input)?;
                self.verify_and_send_credentials(request)
            }
            State::SendingCredentials => {
                if !input.is_empty() {
                    return Err(AuthError::UnexpectedToken);
                }
                Ok(Step::Done(Outcome {
                    method: self.mechanism.method_name(),
                    credssp_version: self.effective_version.unwrap_or(MIN_SERVER_VERSION),
                    public_key_bound: true,
                }))
            }
            State::Failed(error) => Err(error),
        }
    }

    /// Everything that happens to every server message before the state
    /// specific handling.
    ///
    /// The order is fixed. MS-CSSP 3.1.5 says the client "MUST immediately
    /// fail with the provided status code and cease all further processing",
    /// so an `errorCode` is honoured before the version is even looked at: a
    /// server that has decided to refuse is telling the truth about that
    /// whatever else its message says.
    fn receive(&mut self, input: &[u8]) -> Result<TsRequest, AuthError> {
        let request = TsRequest::decode(input)?;
        self.check_error_code(&request)?;
        self.reject_server_nonce(&request)?;
        self.freeze_version(request.version)?;
        Ok(request)
    }

    /// Message 1: the mechanism's first token and nothing else.
    fn first_message(&mut self) -> Result<Step, AuthError> {
        let token = match self.mechanism.step(&[])? {
            GssStep::Token(token) => token,
            // A mechanism whose first token already completes the context
            // cannot happen for NTLM or SPNEGO and would need `pubKeyAuth` in
            // message 1, which MS-CSSP 3.1.5 step 2 does allow. It is refused
            // rather than half implemented: there is nothing to test it with.
            GssStep::FinalToken(_) | GssStep::Complete => return Err(AuthError::UnexpectedToken),
        };
        let mut request = TsRequest::new(self.config.client_version);
        request.nego_tokens = vec![token];
        self.state = State::Negotiating;
        self.rounds = 1;
        tracing::debug!(
            version = self.config.client_version,
            "sending CredSSP message 1"
        );
        Ok(Step::SendAndExpect(request.encode()))
    }

    /// A `negoTokens` round, and the transition into message 3.
    fn negotiate(&mut self, request: TsRequest) -> Result<Step, AuthError> {
        let Some(token) = request.nego_tokens.first() else {
            // A well formed TSRequest with a version and nothing else. At
            // effective version 2 that is what a server does when
            // authentication fails, because `errorCode` is only defined from
            // version 3, and it is also what some servers do when an Extended
            // Protection policy rejected the exchange (PRDRDP/14 §3.11).
            tracing::debug!("the server answered with no negoTokens and no errorCode");
            return Err(AuthError::AuthFailed);
        };

        self.rounds += 1;
        if self.rounds > MAX_NEGOTIATION_ROUNDS {
            tracing::warn!(rounds = self.rounds, "too many CredSSP negotiation rounds");
            return Err(AuthError::TooManyRounds);
        }

        match self.mechanism.step(token)? {
            GssStep::Token(next) => {
                let mut out = TsRequest::new(self.config.client_version);
                out.nego_tokens = vec![next];
                Ok(Step::SendAndExpect(out.encode()))
            }
            GssStep::FinalToken(next) => self.final_token_message(next),
            // The mechanism has nothing more to send and the context is
            // established, so there is no token to put in message 3 beside
            // the `pubKeyAuth`. MS-CSSP 3.1.5 step 3 requires both fields in
            // that message, so this is a mechanism that does not fit CredSSP.
            GssStep::Complete => Err(AuthError::UnexpectedToken),
        }
    }

    /// Message 3: the mechanism's final token, the nonce, the binding and the
    /// wrap, in that order (MS-CSSP 3.1.5 step 3).
    fn final_token_message(&mut self, token: Vec<u8>) -> Result<Step, AuthError> {
        let version = self.effective_version.unwrap_or(MIN_SERVER_VERSION);

        // 2 and 3. The nonce exists only after the mechanism produced its
        // token, and the binding is computed from that nonce and no other.
        let binding = PublicKeyBinding::new(version);
        let value = binding.client_value(&self.config.server_public_key);

        // 4. The first use of the client to server sealing handle, so the
        // sequence number in this signature is 0 and the one in message 5 is
        // 1.
        let pub_key_auth = self.mechanism.wrap(&value)?;

        let mut out = TsRequest::new(self.config.client_version);
        out.nego_tokens = vec![token];
        out.pub_key_auth = Some(pub_key_auth);
        out.client_nonce = binding.nonce().map(|n| n.to_vec());
        self.binding = Some(binding);
        self.state = State::AwaitingPublicKeyAuth;
        tracing::debug!(
            version,
            nonce = out.client_nonce.is_some(),
            "sending CredSSP message 3"
        );
        Ok(Step::SendAndExpect(out.encode()))
    }

    /// Message 4 in, message 5 out (MS-CSSP 3.1.5 steps 4 and 5).
    fn verify_and_send_credentials(&mut self, request: TsRequest) -> Result<Step, AuthError> {
        if let Some(token) = request.nego_tokens.first() {
            if self.expects_trailing_token {
                // MS-CSSP 3.1.5 step 4 says `negoTokens` is omitted from this
                // message, and a SPNEGO acceptor still has an
                // `accept-completed` with a `mechListMIC` to deliver. Windows
                // sends it here. It is consumed before the `pubKeyAuth`
                // because both use the server to client handle and the MIC is
                // the earlier of the two sequence numbers.
                let _ = self.mechanism.step(token)?;
                self.expects_trailing_token = false;
            } else {
                tracing::debug!("ignoring negoTokens in the server's pubKeyAuth message");
            }
        }

        let Some(pub_key_auth) = &request.pub_key_auth else {
            // Not a version fallback. A server at effective version 5 or 6
            // that answers with no `pubKeyAuth` and no `errorCode` has
            // rejected the sign in without saying why (PRDRDP/14 §3.8, §3.11).
            tracing::debug!("the server answered with no pubKeyAuth and no errorCode");
            return Err(AuthError::AuthFailed);
        };
        let plaintext = self.mechanism.unwrap(pub_key_auth)?;
        let binding = self
            .binding
            .as_ref()
            .ok_or(AuthError::ContextNotEstablished)?;
        binding.verify_server_value(&self.config.server_public_key, &plaintext)?;

        // The server holds the private key of the certificate we pinned, so
        // the password may now be sent.
        let credentials: Zeroizing<Vec<u8>> = ts_credentials::encode_for(&self.config.identity);
        let auth_info = self.mechanism.wrap(&credentials)?;

        let mut out = TsRequest::new(self.config.client_version);
        out.auth_info = Some(auth_info);
        self.state = State::SendingCredentials;
        tracing::debug!("the server proved possession of the private key; sending the credentials");
        Ok(Step::Send(out.encode()))
    }

    /// MS-CSSP 3.1.5: "If the client receives a TSRequest message with the
    /// errorCode present, it MUST immediately fail with the provided status
    /// code and cease all further processing."
    fn check_error_code(&self, request: &TsRequest) -> Result<(), AuthError> {
        let Some(code) = request.error_code else {
            return Ok(());
        };
        if !nstatus::is_failure(code) {
            // A value with the top bit clear is a success indication.
            // Windows does not send one; a non Microsoft server might
            // (PRDRDP/14 §3.10).
            tracing::debug!(
                code = format_args!("{code:#010x}"),
                "ignoring a successful errorCode"
            );
            return Ok(());
        }
        match nstatus::classify(code) {
            Some(row) => tracing::warn!(
                status = row.symbol,
                code = format_args!("{code:#010x}"),
                "the server refused the sign in"
            ),
            None => tracing::warn!(
                code = format_args!("{code:#010x}"),
                "the server refused the sign in with a status we do not recognise"
            ),
        }
        Err(AuthError::ServerStatus(code))
    }

    /// MS-CSSP 2.2.1 makes `clientNonce` the client's field, and 3.1.5 uses
    /// it only in the message carrying `pubKeyAuth`. A server sending one is
    /// steering our binding computation.
    fn reject_server_nonce(&self, request: &TsRequest) -> Result<(), AuthError> {
        if request.client_nonce.is_some() {
            tracing::warn!("the server sent a clientNonce, which is the client's field");
            return Err(AuthError::MalformedMessage("the server sent a clientNonce"));
        }
        Ok(())
    }

    /// Freeze the effective version from the server's first reply
    /// (PRDRDP/14 §3.4).
    ///
    /// MS-CSSP 2.2.1: "If the version received is greater than the
    /// implementation understands, treat the peer as one that is compatible
    /// with the version of the CredSSP Protocol that the implementation
    /// understands." That is the minimum, and it is taken once.
    fn freeze_version(&mut self, server_version: u32) -> Result<(), AuthError> {
        if let Some(first) = self.server_version {
            if server_version != first {
                // Changing the binding construction halfway through is a
                // downgrade primitive and there is no legitimate reason for a
                // server to do it. Logged, and the frozen value stands.
                tracing::warn!(
                    first,
                    now = server_version,
                    "the server changed its advertised CredSSP version; keeping the frozen one"
                );
            }
            return Ok(());
        }
        if server_version < self.config.min_server_version {
            tracing::warn!(
                server = server_version,
                min = self.config.min_server_version,
                "the server's CredSSP version is too old"
            );
            return Err(AuthError::UnsupportedCredSspVersion);
        }
        let effective = server_version.min(self.config.client_version);
        tracing::debug!(
            server = server_version,
            ours = self.config.client_version,
            effective,
            "froze the CredSSP version"
        );
        self.server_version = Some(server_version);
        self.effective_version = Some(effective);
        Ok(())
    }
}

/// Build the mechanism [`MechanismSet`] names.
///
/// The identity is cloned because both halves need it for the whole exchange:
/// the mechanism computes `NTOWFv2` from it in message 3 and this module
/// encodes `TSPasswordCreds` from it in message 5. Both copies are
/// `ZeroizeOnDrop`.
fn build_mechanism(config: &CredSspConfig) -> Result<Box<dyn GssMechanism>, AuthError> {
    let ntlm = || {
        NtlmClient::new(NtlmConfig {
            identity: config.identity.clone(),
            spn: config.spn.clone(),
            workstation: config.workstation.clone(),
            channel_bindings: config.channel_bindings(),
        })
    };
    match &config.mechanisms {
        MechanismSet::NtlmOnly => Ok(Box::new(ntlm())),
        MechanismSet::Spnego(ids) => {
            let mechanisms: Vec<Box<dyn GssMechanism>> = ids
                .iter()
                .map(|id| -> Box<dyn GssMechanism> {
                    match id {
                        MechanismId::Ntlm => Box::new(ntlm()),
                    }
                })
                .collect();
            Ok(Box::new(SpnegoClient::new(mechanisms)?))
        }
    }
}

impl std::fmt::Debug for CredSspClient {
    /// The state and the versions, which are diagnostics. The mechanism holds
    /// key material and the config redacts itself (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredSspClient")
            .field("state", &self.state)
            .field("effective_version", &self.effective_version)
            .field("rounds", &self.rounds)
            .field("binding", &self.binding)
            .field("config", &self.config)
            .finish()
    }
}
