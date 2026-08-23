//! The error taxonomy, and the stage enum every error is reported against.
//!
//! The variant list is PRDRDP/03 §9.1's, amended by PRDRDP/12 §3.7 (PRDRDP/00
//! R46 settles that there is one definition and that this is it). The file
//! mirrors `crates/vnc-core/src/error.rs` in shape and in contract: variants
//! grouped by comment banner, then `is_transient` (that file, line 105),
//! `needs_user_action` (line 119) and `user_message`, which are the three
//! methods the reconnect supervisor reads.
//!
//! What is here and not in PRDRDP/03's list is [`RdpError::NotImplemented`].
//! The wire layer stops at the end of MCS channel connection today
//! (`crates/rdp-pdu/src/lib.rs:36`), and a session that parses remote bytes
//! may not answer that with a `todo!()`. It answers with a typed error naming
//! the [`ConnectStage`] that has no code behind it yet, so a log line and a
//! bug report both say which phase to look at.

use rdp_pdu::PduError;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, RdpError>;

// ---------------------------------------------------------------------------
// The connection sequence stages
// ---------------------------------------------------------------------------

/// One step of the connection sequence (MS-RDPBCGR 1.3.1.1).
///
/// A plain enum with a [`name`](ConnectStage::name) and a
/// [`session_state`](ConnectStage::session_state), which is what PRDRDP/06
/// §3.2 asks for: it exists to label logs and errors, not to drive a loop.
/// The sequence itself is straight line `await` code in
/// [`crate::connection`], which is PRDRDP/12 §3.9's ruling, and this enum is
/// how PRDRDP/03 §3.2's state list survives that choice. The two documents
/// disagree about which shape the sequence takes; they agree about the phases,
/// and the phases are what a reader needs.
///
/// Deliberately not `#[non_exhaustive]`: nothing outside this crate matches on
/// it, and adding a stage should break every match that has to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectStage {
    /// DNS lookup, before the socket exists. Skipped when a
    /// [`vnc_transport::StreamConnector`] is injected, because the connector
    /// resolves the endpoint on its own side.
    Resolving,
    /// TCP connect, or the injected connector's dial.
    Dialling,
    /// X.224 Connection Request with `RDP_NEG_REQ` (MS-RDPBCGR 2.2.1.1,
    /// 2.2.1.1.1).
    SendConnectionRequest,
    /// X.224 Connection Confirm with `RDP_NEG_RSP` or `RDP_NEG_FAILURE`
    /// (MS-RDPBCGR 2.2.1.2, 2.2.1.2.1, 2.2.1.2.2).
    AwaitConnectionConfirm,
    /// The TLS handshake and the trust on first use gate. MS-RDPBCGR 5.4.5.1
    /// puts it here, between the Connection Confirm and everything else, with
    /// no RDP framing in between.
    SecurityUpgrade,
    /// CredSSP: SPNEGO over NTLMv2, TSRequest rounds (MS-CSSP 3.1.5).
    Credssp,
    /// The four byte Early User Authorization Result, `HYBRID_EX` only
    /// (MS-RDPBCGR 2.2.10.2).
    EarlyUserAuthResult,
    /// MCS Connect Initial carrying the GCC Conference Create Request
    /// (MS-RDPBCGR 2.2.1.3, T.125, T.124 §8.7).
    SendMcsConnectInitial,
    /// MCS Connect Response carrying the GCC Conference Create Response
    /// (MS-RDPBCGR 2.2.1.4).
    AwaitMcsConnectResponse,
    /// Erect Domain, Attach User, Attach User Confirm and the Channel Joins
    /// (MS-RDPBCGR 2.2.1.5 to 2.2.1.9).
    ChannelConnection,
    /// The Client Info PDU (MS-RDPBCGR 2.2.1.11).
    SendClientInfo,
    /// Connect time network characteristics detection (MS-RDPBCGR 2.2.14).
    ConnectTimeAutoDetect,
    /// Licensing (MS-RDPBCGR 2.2.1.12, MS-RDPELE 2.2.2).
    Licensing,
    /// Multitransport bootstrapping, which we refuse (MS-RDPBCGR 2.2.15).
    MultitransportBootstrap,
    /// Demand Active and Confirm Active (MS-RDPBCGR 2.2.1.13).
    CapabilitiesExchange,
    /// Synchronize, Control, Font List and Font Map (MS-RDPBCGR 2.2.1.14 to
    /// 2.2.1.22). The connection is up when the Font Map arrives.
    ConnectionFinalization,
    /// The sequence is complete and the pump is running.
    Connected,
}

impl ConnectStage {
    /// Every stage, in the order MS-RDPBCGR 1.3.1.1 draws them.
    ///
    /// A slice rather than an array so adding a stage is a one line change,
    /// matching [`remote_core::ProtocolKind::ALL`].
    pub const ALL: &'static [ConnectStage] = &[
        ConnectStage::Resolving,
        ConnectStage::Dialling,
        ConnectStage::SendConnectionRequest,
        ConnectStage::AwaitConnectionConfirm,
        ConnectStage::SecurityUpgrade,
        ConnectStage::Credssp,
        ConnectStage::EarlyUserAuthResult,
        ConnectStage::SendMcsConnectInitial,
        ConnectStage::AwaitMcsConnectResponse,
        ConnectStage::ChannelConnection,
        ConnectStage::SendClientInfo,
        ConnectStage::ConnectTimeAutoDetect,
        ConnectStage::Licensing,
        ConnectStage::MultitransportBootstrap,
        ConnectStage::CapabilitiesExchange,
        ConnectStage::ConnectionFinalization,
        ConnectStage::Connected,
    ];

    /// The stage's name, as it appears in a log line and in an error message.
    /// Stable: PRDRDP/09's capture files are keyed on it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ConnectStage::Resolving => "resolving",
            ConnectStage::Dialling => "dialling",
            ConnectStage::SendConnectionRequest => "x224-connection-request",
            ConnectStage::AwaitConnectionConfirm => "x224-connection-confirm",
            ConnectStage::SecurityUpgrade => "security-upgrade",
            ConnectStage::Credssp => "credssp",
            ConnectStage::EarlyUserAuthResult => "early-user-auth-result",
            ConnectStage::SendMcsConnectInitial => "mcs-connect-initial",
            ConnectStage::AwaitMcsConnectResponse => "mcs-connect-response",
            ConnectStage::ChannelConnection => "channel-connection",
            ConnectStage::SendClientInfo => "client-info",
            ConnectStage::ConnectTimeAutoDetect => "connect-time-auto-detect",
            ConnectStage::Licensing => "licensing",
            ConnectStage::MultitransportBootstrap => "multitransport-bootstrap",
            ConnectStage::CapabilitiesExchange => "capabilities-exchange",
            ConnectStage::ConnectionFinalization => "connection-finalization",
            ConnectStage::Connected => "connected",
        }
    }

    /// The specification section that defines this stage, for the error
    /// message. Every claim about RDP in this crate cites a section, and an
    /// error a user forwards to us should carry the citation with it.
    #[must_use]
    pub const fn spec(self) -> &'static str {
        match self {
            ConnectStage::Resolving | ConnectStage::Dialling => "MS-RDPBCGR 2.2.1.1 (TCP 3389)",
            ConnectStage::SendConnectionRequest => "MS-RDPBCGR 2.2.1.1",
            ConnectStage::AwaitConnectionConfirm => "MS-RDPBCGR 2.2.1.2",
            ConnectStage::SecurityUpgrade => "MS-RDPBCGR 5.4.5.1",
            ConnectStage::Credssp => "MS-CSSP 3.1.5",
            ConnectStage::EarlyUserAuthResult => "MS-RDPBCGR 2.2.10.2",
            ConnectStage::SendMcsConnectInitial => "MS-RDPBCGR 2.2.1.3",
            ConnectStage::AwaitMcsConnectResponse => "MS-RDPBCGR 2.2.1.4",
            ConnectStage::ChannelConnection => "MS-RDPBCGR 2.2.1.5 to 2.2.1.9",
            ConnectStage::SendClientInfo => "MS-RDPBCGR 2.2.1.11",
            ConnectStage::ConnectTimeAutoDetect => "MS-RDPBCGR 2.2.14",
            ConnectStage::Licensing => "MS-RDPBCGR 2.2.1.12",
            ConnectStage::MultitransportBootstrap => "MS-RDPBCGR 2.2.15",
            ConnectStage::CapabilitiesExchange => "MS-RDPBCGR 2.2.1.13",
            ConnectStage::ConnectionFinalization => "MS-RDPBCGR 2.2.1.14 to 2.2.1.22",
            ConnectStage::Connected => "MS-RDPBCGR 1.3.1.1",
        }
    }

    /// The lifecycle state the UI shows while this stage runs.
    ///
    /// PRDRDP/00 R12 adds no `SessionState` variants for RDP, so the whole
    /// sequence folds onto the five the RFB path already emits. The X.224
    /// exchange, the TLS handshake and the certificate prompt are all
    /// `Connecting`; everything from the MCS Connect Initial onwards is
    /// `Negotiating` (PRDRDP/03 §8, PRDRDP/06 §3.2).
    #[must_use]
    pub fn session_state(self, method: &str) -> remote_core::SessionState {
        use remote_core::SessionState;
        match self {
            ConnectStage::Resolving => SessionState::Resolving,
            ConnectStage::Dialling
            | ConnectStage::SendConnectionRequest
            | ConnectStage::AwaitConnectionConfirm
            | ConnectStage::SecurityUpgrade => SessionState::Connecting,
            ConnectStage::Credssp | ConnectStage::EarlyUserAuthResult => {
                SessionState::Authenticating {
                    method: method.to_owned(),
                }
            }
            ConnectStage::SendMcsConnectInitial
            | ConnectStage::AwaitMcsConnectResponse
            | ConnectStage::ChannelConnection
            | ConnectStage::SendClientInfo
            | ConnectStage::ConnectTimeAutoDetect
            | ConnectStage::Licensing
            | ConnectStage::MultitransportBootstrap
            | ConnectStage::CapabilitiesExchange
            | ConnectStage::ConnectionFinalization => SessionState::Negotiating,
            ConnectStage::Connected => SessionState::Connected,
        }
    }
}

impl std::fmt::Display for ConnectStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// The errors
// ---------------------------------------------------------------------------

/// Error taxonomy for the RDP core (PRDRDP/03 §9.1, PRDRDP/12 §3.7).
///
/// [`is_transient`](RdpError::is_transient) and
/// [`needs_user_action`](RdpError::needs_user_action) drive the reconnect
/// supervisor, exactly as `VncError::is_transient` does today
/// (`crates/vnc-core/src/error.rs:105`). The exact variant membership of both
/// is load bearing, so both have their own unit test below.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RdpError {
    // ---- transport / transient -------------------------------------------
    /// The socket failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A clean close: the peer shut the stream down between PDUs.
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// A stage exceeded its timeout (PRDRDP/03 §3.3).
    #[error("timed out during {stage} ({spec})", spec = .stage.spec())]
    Timeout {
        /// Which stage was waiting.
        stage: ConnectStage,
    },

    /// The dial was refused.
    #[error("connection refused by {0}")]
    ConnectionRefused(String),

    /// The host name did not resolve.
    #[error("dns resolution failed for {0}")]
    ResolveFailed(String),

    // ---- negotiation -----------------------------------------------------
    /// `RDP_NEG_FAILURE` (MS-RDPBCGR 2.2.1.2.2).
    #[error("the server refused the requested security protocols: {reason}")]
    NegotiationFailed {
        /// The wire `failureCode`.
        code: u32,
        /// The sentence derived from it (PRDRDP/03 §9.2).
        reason: String,
    },

    /// The Connection Confirm named a protocol that was not in our
    /// `RDP_NEG_REQ.requestedProtocols`, or named `PROTOCOL_RDP`, which this
    /// client never negotiates because standard RDP security is RC4 (D6).
    #[error("the server selected a security protocol we did not offer")]
    NegotiationInconsistent,

    // ---- tls -------------------------------------------------------------
    /// The TLS handshake failed.
    #[error("tls error: {0}")]
    Tls(String),

    /// The pinned key changed. A hard stop, never auto retried (PRD/10 §4.3).
    #[error("server identity changed: expected {expected}, got {actual}")]
    CertificateMismatch {
        /// The stored pin.
        expected: String,
        /// What the server presented.
        actual: String,
    },

    /// The user declined the trust on first use prompt, or it was cancelled.
    #[error("server certificate not trusted: {0}")]
    CertificateUntrusted(String),

    // ---- authentication --------------------------------------------------
    /// The server rejected the credentials. Never auto retried: a stale
    /// password replayed against Active Directory locks the account out.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Credentials are needed and none were supplied.
    #[error("credentials required: {0}")]
    CredentialsRequired(String),

    /// The server refused CredSSP and [`remote_core::NlaPolicy::Required`] is
    /// in force (D6). `symbol()` reports the stable token `"nla-refused"`
    /// that PRDRDP/07 §6.15 matches on.
    #[error("the server would not accept network level authentication")]
    NlaRefused,

    // ---- protocol --------------------------------------------------------
    /// A PDU did not parse. Carries `rdp-pdu`'s message, which names the
    /// structure and the field and never the bytes (PRDRDP/12 §6.4).
    #[error("malformed {structure}: {message}")]
    Pdu {
        /// The structure's name in the specification, from
        /// [`PduError`]'s `context`.
        structure: &'static str,
        /// The parser's message.
        message: String,
    },

    /// The sequence was fine and the content was not: a channel id we never
    /// joined, a codec we never advertised, a share id that changed.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// The server ended the session and said why. MS-RDPBCGR 2.2.5.1.1 Set
    /// Error Info PDU, the `ERRINFO_*` space.
    #[error("the server ended the session: {message} (0x{code:08x})")]
    ServerError {
        /// The wire `errorInfo` value.
        code: u32,
        /// The specification's constant name, empty when unknown.
        symbol: String,
        /// The sentence derived from the code.
        message: String,
    },

    /// The server ended the session without saying why: an MCS Disconnect
    /// Provider Ultimatum with no latched `ERRINFO` code, or a clean EOF
    /// (MS-RDPBCGR 2.2.2.3, 1.3.1.4.2).
    #[error("the server ended the session")]
    ServerDisconnect {
        /// True for `rn-user-requested` (3), which is a logoff rather than a
        /// failure.
        user_requested: bool,
    },

    // ---- not written yet -------------------------------------------------
    /// This crate has no code for that stage of the sequence yet.
    ///
    /// A session that parses remote bytes may not answer an unimplemented
    /// phase with a panic, so it answers with this. The stage names itself
    /// and cites its specification section, which is what a bug report needs
    /// and what a `todo!()` destroys.
    #[error("{stage} is not implemented yet ({spec})", spec = .stage.spec())]
    NotImplemented {
        /// The stage with no code behind it.
        stage: ConnectStage,
    },

    // ---- lifecycle -------------------------------------------------------
    /// The session was cancelled, or the shell dropped the event sink.
    #[error("session cancelled by user")]
    Cancelled,

    /// The options were rejected before a socket was opened.
    #[error("configuration rejected: {0}")]
    Options(#[from] crate::options::OptionsError),
}

/// A closed event sink means the shell went away, which unwinds the session
/// through the same path a cancellation does. This is the impl that keeps
/// every `emit(..).await?` in this crate a one line call, exactly as
/// `vnc-core` does at `crates/vnc-core/src/error.rs:86`.
impl From<remote_core::EventSinkClosed> for RdpError {
    fn from(_: remote_core::EventSinkClosed) -> Self {
        RdpError::Cancelled
    }
}

/// Every [`PduError`] variant carries the `context` naming the structure that
/// failed to parse, so the conversion keeps it rather than flattening the
/// whole thing into a `String`. The structure's name is the first thing an
/// interop bug report needs (PRDRDP/12 §3.7).
impl From<PduError> for RdpError {
    fn from(e: PduError) -> Self {
        let structure = match e {
            PduError::Truncated { context, .. }
            | PduError::InvalidField { context, .. }
            | PduError::LengthMismatch { context, .. }
            | PduError::CapExceeded { context, .. }
            | PduError::Asn1Tag { context, .. }
            | PduError::Unsupported { context, .. }
            | PduError::Encode { context, .. } => context,
        };
        RdpError::Pdu {
            structure,
            message: e.to_string(),
        }
    }
}

/// `vnc-transport` classifies a dial failure into refused, timed out and
/// resolve failed, and the supervisor depends on that classification to
/// decide whether to retry. Keep it rather than collapsing it into `Io`.
impl From<vnc_transport::TransportError> for RdpError {
    fn from(e: vnc_transport::TransportError) -> Self {
        use vnc_transport::TransportError;
        match e {
            TransportError::Io(e) => RdpError::Io(e),
            TransportError::Timeout => RdpError::Timeout {
                stage: ConnectStage::Dialling,
            },
            TransportError::Refused(host) => RdpError::ConnectionRefused(host),
            TransportError::Resolve(host) => RdpError::ResolveFailed(host),
            TransportError::Tls(msg) => RdpError::Tls(msg),
            TransportError::CertificateMismatch { expected, actual } => {
                RdpError::CertificateMismatch { expected, actual }
            }
        }
    }
}

impl From<rdp_auth::AuthError> for RdpError {
    fn from(e: rdp_auth::AuthError) -> Self {
        use rdp_auth::Class;
        // `AuthError::class` already draws the line between "the password was
        // wrong" and "the exchange was malformed", and the taxonomy here is
        // the same line drawn again. Reusing it means one place decides.
        match e.class() {
            Class::User => RdpError::AuthFailed(e.user_message()),
            _ => RdpError::Protocol(e.user_message()),
        }
    }
}

impl RdpError {
    /// Whether the auto reconnect loop should retry after this error.
    ///
    /// Network shaped only. Note what is not here: [`RdpError::NlaRefused`]
    /// and [`RdpError::ServerError`] are both perfectly repeatable, and
    /// retrying them hammers a server that has already given its answer
    /// (PRDRDP/12 §3.7).
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            RdpError::Io(_)
                | RdpError::ConnectionClosed
                | RdpError::Timeout { .. }
                | RdpError::ConnectionRefused(_)
                | RdpError::ResolveFailed(_)
        )
    }

    /// Whether this error requires user interaction before any retry.
    ///
    /// Every authentication failure is here, and that is the decision that
    /// matters: a domain password replayed on a backoff ladder locks an
    /// Active Directory account after three to five attempts, and the user
    /// finds out when they cannot sign in to their own laptop.
    ///
    /// [`RdpError::NlaRefused`] is here too. The user's next step is to turn
    /// on the per host "allow connection without NLA" switch, or to discover
    /// that the server wants something we do not implement. Auto retrying
    /// would fail identically every backoff interval.
    #[must_use]
    pub fn needs_user_action(&self) -> bool {
        matches!(
            self,
            RdpError::AuthFailed(_)
                | RdpError::CredentialsRequired(_)
                | RdpError::CertificateMismatch { .. }
                | RdpError::CertificateUntrusted(_)
                | RdpError::NlaRefused
                | RdpError::NegotiationFailed { .. }
                | RdpError::NegotiationInconsistent
        )
    }

    /// The stable token PRDRDP/07 §6.15 matches on to offer the right
    /// remedy, or `None` for an error with no specific remedy.
    ///
    /// A `&'static str` rather than a `String`: these are matched, not
    /// displayed, and a typo in a match arm should be a compile error at the
    /// producing end rather than a silently unmatched string.
    #[must_use]
    pub const fn symbol(&self) -> Option<&'static str> {
        match self {
            RdpError::NlaRefused => Some("nla-refused"),
            RdpError::CertificateMismatch { .. } => Some("certificate-changed"),
            RdpError::NotImplemented { .. } => Some("not-implemented"),
            _ => None,
        }
    }

    /// The sentence the UI shows. Never carries a credential, a token or a
    /// byte of remote data (PRDRDP/12 §6.4).
    #[must_use]
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::SessionState;

    /// The membership of these two sets is what the supervisor acts on, so
    /// it is pinned here rather than left to whoever adds the next variant.
    /// `vnc-core` pins its equivalents in `session/reconnect.rs`.
    #[test]
    fn transient_and_user_action_are_disjoint() {
        let errors = [
            RdpError::ConnectionClosed,
            RdpError::Timeout {
                stage: ConnectStage::Credssp,
            },
            RdpError::ConnectionRefused("h".into()),
            RdpError::ResolveFailed("h".into()),
            RdpError::AuthFailed("no".into()),
            RdpError::NlaRefused,
            RdpError::CertificateMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            RdpError::NotImplemented {
                stage: ConnectStage::SendClientInfo,
            },
            RdpError::Cancelled,
        ];
        for e in &errors {
            assert!(
                !(e.is_transient() && e.needs_user_action()),
                "{e} is both transient and needs user action"
            );
        }
    }

    /// An authentication failure is never retried. This is the one
    /// classification with a consequence outside this program: a retry ladder
    /// against a domain controller locks the account.
    #[test]
    fn authentication_failures_are_never_retried() {
        for e in [
            RdpError::AuthFailed("wrong password".into()),
            RdpError::CredentialsRequired("no password".into()),
            RdpError::NlaRefused,
        ] {
            assert!(!e.is_transient(), "{e}");
            assert!(e.needs_user_action(), "{e}");
        }
    }

    /// A parse failure stops with a manual retry offered: it may be an
    /// interop bug of ours, and a manual retry costs the user nothing, while
    /// an automatic ladder against a PDU we will fail to parse identically
    /// every time is a loop (PRDRDP/12 §3.7).
    #[test]
    fn a_parse_failure_stops_without_demanding_the_user_do_anything() {
        let e = RdpError::Pdu {
            structure: "TS_UD_SC_NET",
            message: "short".into(),
        };
        assert!(!e.is_transient());
        assert!(!e.needs_user_action());
    }

    /// The `NotImplemented` message has to name the phase and cite the
    /// specification, because that is the whole reason it exists rather than
    /// a panic.
    #[test]
    fn not_implemented_names_the_stage_and_its_spec_section() {
        let e = RdpError::NotImplemented {
            stage: ConnectStage::SendClientInfo,
        };
        let msg = e.to_string();
        assert!(msg.contains("client-info"), "{msg}");
        assert!(msg.contains("MS-RDPBCGR 2.2.1.11"), "{msg}");
        assert_eq!(e.symbol(), Some("not-implemented"));
    }

    /// PRDRDP/00 R12 adds no lifecycle states for RDP, so every stage has to
    /// land on one of the five the RFB path already emits.
    #[test]
    fn every_stage_maps_onto_an_existing_session_state() {
        for stage in ConnectStage::ALL.iter().copied() {
            let state = stage.session_state("nla-ntlm");
            assert!(
                matches!(
                    state,
                    SessionState::Resolving
                        | SessionState::Connecting
                        | SessionState::Authenticating { .. }
                        | SessionState::Negotiating
                        | SessionState::Connected
                ),
                "{stage} produced {state:?}"
            );
            assert!(!stage.name().is_empty());
            assert!(!stage.spec().is_empty());
        }
    }

    /// The stage list is ordered, and `ALL` has to be in that order or the
    /// "which phase did we reach" reading of a log is wrong.
    #[test]
    fn the_stage_list_is_in_sequence_order() {
        let mut sorted = ConnectStage::ALL.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, ConnectStage::ALL);
        assert_eq!(ConnectStage::ALL.first(), Some(&ConnectStage::Resolving));
        assert_eq!(ConnectStage::ALL.last(), Some(&ConnectStage::Connected));
    }

    /// The conversion keeps the structure's name rather than flattening it.
    #[test]
    fn a_pdu_error_keeps_the_structure_it_failed_on() {
        let e: RdpError = PduError::Truncated {
            context: "Connect-Response",
            offset: 3,
            needed: 4,
            available: 1,
        }
        .into();
        match e {
            RdpError::Pdu { structure, message } => {
                assert_eq!(structure, "Connect-Response");
                assert!(message.contains("offset 3"), "{message}");
            }
            other => panic!("expected a Pdu error, got {other:?}"),
        }
    }
}
