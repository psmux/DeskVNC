//! [`KerberosClient`]: Kerberos as a [`GssMechanism`].
//!
//! This is the seam PRDRDP/14 §2.8 was built for. `CredSspClient` holds a
//! `Box<dyn GssMechanism>` and nothing in `credssp/mod.rs` mentions NTLM,
//! SPNEGO or Kerberos; `SpnegoClient` is itself a `GssMechanism` over a list
//! of them. So Kerberos arrives by implementing one trait, and neither of the
//! two modules that drive it changed by a line.

use zeroize::Zeroizing;

use crate::bindings::ChannelBindings;
use crate::error::AuthError;
use crate::gss::{GssMechanism, GssStep};
use crate::spnego::oid;

use super::gss::{build_ap_req, parse_ap_rep, ApReqToken, GssContext};
use super::kdc::ServiceTicket;

/// The identifier that reaches `SessionState::Authenticating` and the
/// security label (PRDRDP/00 R12). `Outcome::method` carries it.
const METHOD_NAME: &str = "nla-kerberos";

/// What [`KerberosClient`] needs, once the KDC exchanges have finished.
pub struct KerberosConfig {
    /// The ticket for `TERMSRV/<host>` and the session key that came with it,
    /// from [`KdcClient`](super::kdc::KdcClient).
    pub ticket: Box<ServiceTicket>,
    /// The RFC 5929 `tls-server-end-point` binding, or `None` when there is
    /// no certificate to bind to.
    ///
    /// The same [`ChannelBindings`] the NTLM path uses, and it goes into the
    /// same MD5 over the same RFC 2744 §3.11 structure: RFC 4121 §4.1.1.2's
    /// `Bnd` field and MS-NLMP's `MsvAvChannelBindings` AV pair are the same
    /// sixteen octets (PRDRDP/14 §7.1 item 5). That is why `bindings.rs` is a
    /// crate level module.
    pub channel_bindings: Option<ChannelBindings>,
    /// Seconds since the Unix epoch, read by the session. The crate reads no
    /// clock (D12).
    pub now_unix: i64,
}

impl std::fmt::Debug for KerberosConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KerberosConfig")
            .field("ticket", &self.ticket)
            .field("channel_bindings", &self.channel_bindings.is_some())
            .field("now_unix", &self.now_unix)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `step(&[])` produces the AP-REQ.
    Start,
    /// The AP-REQ is out; awaiting the AP-REP that mutual authentication
    /// requires.
    AwaitingApRep,
    /// The context is established. `wrap`, `unwrap`, `mic` and `verify_mic`
    /// are available.
    Complete,
    /// Nothing works any more.
    Failed,
}

/// The Kerberos initiator, RFC 4121 §4.
///
/// ## The empty final token, and why it is not a bug
///
/// With mutual authentication the client sends one token and receives one.
/// After the AP-REP the context is established and there is nothing left to
/// say, which in GSS-API terms is `GSS_S_COMPLETE` with a zero length output
/// token.
///
/// [`GssStep`] has a variant for exactly that, [`GssStep::Complete`], and
/// this mechanism does not use it on that step. It returns
/// [`GssStep::FinalToken`] with an empty token instead, because
/// `CredSspClient` refuses `GssStep::Complete` in its negotiate state: MS-CSSP
/// 3.1.5 step 3 requires message 3 to carry both a token and the
/// `pubKeyAuth`, so a mechanism that has completed with nothing to send has
/// no message 3 to be in. `SpnegoClient` passes an inner `Complete` straight
/// through to that refusal.
///
/// So an empty `FinalToken` is what makes the three layers fit, and the cost
/// is one empty `responseToken` in the SPNEGO `NegTokenResp` that carries the
/// `mechListMIC`. That is well formed DER and a legal RFC 4178 token, and it
/// is not quite what Windows sends, which omits the field. **It is the most
/// likely interop difference in this lane**, and the fix if a server objects
/// is one line in `SpnegoClient`: treat an inner `FinalToken` whose token is
/// empty as a `responseToken` of `None`. That change is in another module's
/// lane and is not made here.
pub struct KerberosClient {
    config: KerberosConfig,
    state: State,
    /// Set by `step(&[])` and consumed by the AP-REP: the subkey and the
    /// initial sequence number we asserted (RFC 4121 §2 and §4.2.1).
    request: Option<ApReqToken>,
    /// The per-message context, once the AP-REP has settled the base key.
    context: Option<GssContext>,
}

impl KerberosClient {
    /// A mechanism for one connection, over a ticket the KDC has issued.
    #[must_use]
    pub fn new(config: KerberosConfig) -> Self {
        KerberosClient {
            config,
            state: State::Start,
            request: None,
            context: None,
        }
    }

    /// The service the ticket is for, for a log line and an error message.
    #[must_use]
    pub fn service(&self) -> String {
        self.config.ticket.ticket.sname.display()
    }

    /// The AP-REQ inside its `[APPLICATION 0]` framing (RFC 4121 §4.1).
    fn start(&mut self) -> Result<Vec<u8>, AuthError> {
        let request = build_ap_req(
            &self.config.ticket,
            self.config.channel_bindings.as_ref(),
            self.config.now_unix,
            oid::KRB5,
        )?;
        let token = request.token.clone();
        self.request = Some(request);
        self.state = State::AwaitingApRep;
        tracing::debug!(
            service = %self.service(),
            len = token.len(),
            bound = self.config.channel_bindings.is_some(),
            "sending the Kerberos AP-REQ"
        );
        Ok(token)
    }

    /// Consume the AP-REP and settle the per-message keys (RFC 4121 §2).
    fn finish(&mut self, input: &[u8]) -> Result<(), AuthError> {
        let request = self
            .request
            .take()
            .ok_or(AuthError::ContextNotEstablished)?;
        let reply = parse_ap_rep(input, &self.config.ticket.session_key)?;
        tracing::debug!(
            acceptor_subkey = reply.subkey.is_some(),
            "the remote computer proved it holds the service key"
        );
        self.context = Some(GssContext::new(request, reply));
        self.state = State::Complete;
        Ok(())
    }

    /// The per-message context, or the error that says it is too early.
    fn context_mut(&mut self) -> Result<&mut GssContext, AuthError> {
        self.context
            .as_mut()
            .ok_or(AuthError::ContextNotEstablished)
    }
}

impl GssMechanism for KerberosClient {
    /// `1.2.840.113554.1.2.2` (RFC 4121 §4.1).
    ///
    /// The modern OID and not MS-SPNG's legacy `1.2.840.48018.1.2.2`.
    /// `SpnegoClient` already treats the two as the same mechanism when a
    /// server answers `supportedMech` with either, so offering the modern one
    /// is right and is matched by both (PRDRDP/14 §4.7).
    fn oid(&self) -> &'static [u8] {
        oid::KRB5
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
                match self.start() {
                    Ok(token) => Ok(GssStep::Token(token)),
                    Err(e) => {
                        self.state = State::Failed;
                        Err(e)
                    }
                }
            }
            State::AwaitingApRep => {
                if input.is_empty() {
                    // Mutual authentication was asked for and RFC 4120 §5.5.1
                    // makes the AP-REP mandatory when it is. A server that
                    // completes without one has not proved it holds the
                    // service key, which is the whole point of asking.
                    self.state = State::Failed;
                    tracing::warn!("the remote computer completed the exchange without an AP-REP");
                    return Err(AuthError::UnexpectedToken);
                }
                match self.finish(input) {
                    // The empty token is deliberate; the type comment says
                    // why. It is `FinalToken` and not `Complete` because
                    // `CredSspClient` needs a message 3 to put `pubKeyAuth`
                    // in.
                    Ok(()) => Ok(GssStep::FinalToken(Vec::new())),
                    Err(e) => {
                        self.state = State::Failed;
                        Err(e)
                    }
                }
            }
            State::Complete => {
                if input.is_empty() {
                    Ok(GssStep::Complete)
                } else {
                    // A third token when Kerberos has only ever two.
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
        self.context_mut()?.wrap(plaintext)
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        self.context_mut()?.unwrap(token)
    }

    fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.context_mut()?.mic(message)
    }

    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), AuthError> {
        self.context_mut()?.verify_mic(message, mic)
    }
}

impl std::fmt::Debug for KerberosClient {
    /// The state and the service. The config redacts itself and the context
    /// holds key material (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KerberosClient")
            .field("state", &self.state)
            .field("config", &self.config)
            .field("context", &self.context)
            .finish()
    }
}
