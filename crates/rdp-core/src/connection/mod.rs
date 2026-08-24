//! The connection sequence, X.224 to `Connected`
//! (MS-RDPBCGR 1.3.1.1, PRDRDP/03 §2, PRDRDP/12 §3.9).
//!
//! # Shape
//!
//! Each file is a function taking the framed stream and returning what the
//! next phase needs, so the whole sequence reads top to bottom in
//! [`connect`] below. That is a deliberate choice against the shape a
//! protocol library has to take: a library cannot own the loop, so it exposes
//! a sequence with a `step` method and the caller drives it. We own the loop,
//! so the sequence is straight line `await` code, which is easier to read and
//! to get right (PRDRDP/12 §3.9).
//!
//! [`ConnectStage`] is what survives of PRDRDP/03 §3.2's state list under
//! that choice. It labels the log line and the error rather than driving the
//! loop, which is exactly what PRDRDP/06 §3.2 asks of it: "a plain enum with
//! a `name()` for logging". Where the two documents disagree about the shape
//! they agree about the phases, and the phases are what a reader needs.
//!
//! # Cancellation
//!
//! **This sequence is not cancellation safe, and does not need to be.** A
//! half written Connect Initial is a desynchronised stream, and RDP has no
//! resynchronisation point inside a TPKT unit. It is not inside a `select!`,
//! and the only thing that cancels it is the cancellation token, which drops
//! the whole attempt and the whole stream with it. Nobody should later wrap
//! it in a `select!` without changing the writes first (PRDRDP/12 §5.4).
//!
//! # The phases, and where each lives
//!
//! | Phases | File |
//! |---|---|
//! | 1, the X.224 negotiation | [`negotiate`] |
//! | 2, the TLS upgrade and CredSSP | [`crate::transport`], [`nla`] |
//! | 3 and 4, the Basic Settings Exchange and Channel Connection | [`mcs`] |
//! | 6 to 10, Client Info to the Font Map | [`activate`] |
//!
//! Phase 5, RDP Security Commencement, is skipped by construction: it exists
//! only for standard RDP security, which this client never negotiates
//! (PRDRDP/03 §2.6, D6).

pub mod activate;
pub mod credentials;
pub mod mcs;
pub mod negotiate;
pub mod nla;
pub mod prompt;
pub mod trust;

use remote_core::{Credentials, SessionEvent, SessionState};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use vnc_transport::{BoxedStream, TrustDecision};

use crate::error::{ConnectStage, RdpError, Result};
use crate::options::ResolvedOptions;
use crate::transport::framer::{Framed, Framer};
use crate::transport::{self, TlsUpgrade};

pub use activate::Activated;
pub use credentials::{Ask, MAX_CREDENTIAL_PROMPTS};
pub use mcs::{ChannelMap, McsConnected};
pub use negotiate::SecurityProtocol;
pub use nla::ServerIdentity;
pub use prompt::Prompt;

/// What the connection sequence hands the run loop, and nothing it does not.
#[derive(Debug)]
pub struct Connected {
    /// The channels, joined.
    pub channels: ChannelMap,
    /// What the X.224 negotiation settled on.
    pub selected: SecurityProtocol,
    /// The `method` string that reached
    /// [`SessionState::Authenticating`], for the stats label.
    pub method: &'static str,
    /// What the trust on first use verifier decided about the server key.
    pub trust: TrustDecision,
    /// The share id, the desktop size and the server's input capabilities.
    pub activation: Activated,
    /// Fast path updates that overtook the end of the sequence.
    ///
    /// A server is allowed to start drawing before the Font Map arrives, and a
    /// pointer or bitmap update that reaches the connection sequence belongs
    /// to the pump rather than to the bin. Dropping them is a stale region
    /// nobody can explain (PRDRDP/06 §2.2.1).
    pub pending: Vec<Framed>,
}

/// Run the X.224 negotiation, then hand the stream back for the TLS upgrade.
///
/// Split from [`after_upgrade`] rather than folded into one function, because
/// the TLS handshake needs the whole stream and not a read half, so the
/// framer has to be dismantled between the two. Splitting it here also means
/// the MCS phases can be driven over any stream in a test without a TLS
/// identity, which is what `tests/connect.rs` does.
///
/// # Errors
///
/// As [`negotiate::negotiate`], plus [`RdpError::Protocol`] when the server
/// sent anything at all before the handshake.
pub async fn negotiate_security<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    opts: &ResolvedOptions,
    creds: &Credentials,
) -> Result<SecurityProtocol> {
    let selected = negotiate::negotiate(framer, opts, creds.username.as_deref()).await?;
    tracing::debug!(?selected, "the server selected a security protocol");

    // MS-RDPBCGR 5.4.5.1 puts the handshake immediately after the Connection
    // Confirm with no RDP framing in between, so anything buffered here is
    // either a confused server or an injection. Carrying it across the
    // upgrade would mean treating pre-TLS bytes as if they had arrived inside
    // the tunnel (PRDRDP/03 §4.4).
    if framer.buffered() != 0 {
        return Err(RdpError::Protocol(format!(
            "the server sent {} bytes before the TLS handshake (MS-RDPBCGR 5.4.5.1)",
            framer.buffered()
        )));
    }
    Ok(selected)
}

/// Everything after the TLS upgrade: CredSSP when the negotiation asked for
/// it, then the MCS phases and the rest of the sequence.
///
/// `arc` is the auto reconnect cookie's client packet, when one is stored and
/// still fresh: it rides in the Client Info PDU and is what makes a reconnect
/// land in the user's existing Windows session rather than a new one
/// (MS-RDPBCGR 2.2.4.3, PRDRDP/06 §5.5).
///
/// `creds` is taken by `&mut` because the credential gate replaces it with
/// whatever the user typed, and the caller keeps that for the connection
/// after this one: see [`credentials`]. With `prompt` as `None` nothing is
/// ever written to it.
///
/// # Errors
///
/// As [`credentials::ensure`], [`nla::authenticate`], [`mcs::connect`] and
/// [`activate::activate`], plus [`RdpError::Redirected`] when a broker sent
/// us elsewhere before the share existed, which is not a failure
/// (MS-RDPBCGR 1.3.8).
#[allow(clippy::too_many_arguments)]
pub async fn after_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    opts: &ResolvedOptions,
    creds: &mut Credentials,
    selected: SecurityProtocol,
    identity: Option<&ServerIdentity>,
    trust: TrustDecision,
    arc: Option<rdp_pdu::rdp::client_info::ArcClientPrivatePacket>,
    events: &mpsc::Sender<SessionEvent>,
    prompt: Option<Prompt<'_>>,
) -> Result<Connected> {
    let mut method = selected.method();

    if selected.wants_credssp() {
        // Ask for whatever CredSSP needs and does not have, before the state
        // says `Authenticating` and long before a token goes out. Only this
        // branch asks: a plain TLS connection needs no credential at connect
        // time, because the server's own logon screen collects it
        // (MS-RDPBCGR 5.4.5.1, and `SecurityProtocol::wants_credssp`).
        credentials::ensure(creds, events, prompt).await?;

        // The method reaches the UI before the first token goes out, so a
        // user staring at a failed logon has a clue which half of the stack
        // to suspect (PRDRDP/00 R12).
        remote_core::emit_state(
            events,
            ConnectStage::Credssp.session_state(selected.method()),
        )
        .await?;

        let attempt = match identity {
            Some(identity) => nla::authenticate(framer, opts, creds, selected, identity).await,
            // A caller that upgraded the stream has an identity, because the
            // upgrade returns the certificate with it (PRDRDP/00 R47). `None`
            // reaches here only from a test driving the phases over a plain
            // socket, and a CredSSP exchange bound to nothing is not one we
            // will start.
            None => Err(RdpError::Tls(
                "there is no server certificate to bind the credentials to \
                 (MS-CSSP 3.1.5)"
                    .to_owned(),
            )),
        };
        match attempt {
            Ok(outcome) => {
                tracing::info!(
                    method = outcome.method,
                    version = outcome.credssp_version,
                    "network level authentication succeeded"
                );
                method = outcome.method;
            }
            Err(e) => {
                if let Some(fatal) = nla::refusal(e, opts.nla) {
                    return Err(fatal);
                }
                // `AllowFallback`: the server's own logon screen collects the
                // credentials, and credential saving is off for this host
                // because reaching `Connected` proves nothing about the
                // password (PRDRDP/00 R14).
                method = "tls";
            }
        }
    }

    remote_core::emit_state(events, SessionState::Negotiating).await?;
    tracing::debug!(
        method,
        ?selected,
        ?trust,
        "starting the basic settings exchange"
    );
    let connected = mcs::connect(framer, opts, selected).await?;
    tracing::info!(
        io_channel = connected.channels.io_channel_id,
        user_channel = connected.channels.user_channel_id,
        channels = connected.channels.statics.len(),
        skipped_joins = connected.skipped_channel_joins,
        "mcs channel connection complete"
    );

    // Phases 6 to 10.
    let mut pending = Vec::new();
    let activation = activate::activate(
        framer,
        opts,
        creds,
        &connected.channels,
        arc,
        events,
        &mut pending,
    )
    .await?;

    Ok(Connected {
        channels: connected.channels,
        selected,
        method,
        trust,
        activation,
        pending,
    })
}

/// The whole sequence, over a stream this function upgrades itself.
///
/// The three steps are separate functions above, so a test can drive the MCS
/// phases without a TLS identity and the production path composes all three.
///
/// # Errors
///
/// Whatever the phase that failed reports. Every error names the phase.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    stream: BoxedStream,
    opts: &ResolvedOptions,
    creds: &mut Credentials,
    pins: &remote_core::CertPins,
    arc: Option<rdp_pdu::rdp::client_info::ArcClientPrivatePacket>,
    events: &mpsc::Sender<SessionEvent>,
    mut prompt: Option<Prompt<'_>>,
) -> Result<(Connected, Framer<BoxedStream>)> {
    let received = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut framer = Framer::new(stream, received.clone());

    let selected = negotiate_security(&mut framer, opts, creds).await?;

    // The handshake wants the whole stream, so the framer is dismantled. Its
    // buffer was checked as empty above, which is why nothing is lost here.
    let (stream, _empty) = framer.into_inner();
    let upgrade = transport::upgrade_tls(stream, &opts.server_name, pins, opts.legacy_tls).await?;
    let trust = upgrade.decision.clone();
    // The certificate prompt gates CredSSP, so it happens before the identity
    // is built and long before a credential is encrypted under the server's
    // key (PRDRDP/00 R13, PRDRDP/03 §5.4). It is reborrowed rather than moved
    // because the credential gate inside `after_upgrade` asks down the same
    // channel afterwards, and there is only one receiver to lend.
    trust::approve(&trust, events, prompt.as_mut().map(Prompt::reborrow)).await?;
    let identity = ServerIdentity::from_upgrade(&upgrade)?;

    let TlsUpgrade { stream, .. } = upgrade;
    let mut framer = Framer::new(stream, received);
    let connected = after_upgrade(
        &mut framer,
        opts,
        creds,
        selected,
        Some(&identity),
        trust,
        arc,
        events,
        prompt,
    )
    .await?;
    Ok((connected, framer))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every stage of the sequence now has code behind it, so nothing in this
    /// module returns [`RdpError::NotImplemented`] any more. What is left of
    /// the variant is the run loop's fast path arms as they land; this test
    /// pins the message shape, because a phase that names itself is the whole
    /// reason the variant exists rather than a panic.
    #[test]
    fn an_unimplemented_phase_names_itself_rather_than_panicking() {
        let e = RdpError::NotImplemented {
            stage: ConnectStage::MultitransportBootstrap,
        };
        assert!(e.to_string().contains("multitransport"), "{e}");
        assert!(e.to_string().contains("MS-RDPBCGR 2.2.15"), "{e}");
        // Not transient: the same gap will be there on the next attempt, and a
        // backoff ladder against our own gap is a loop.
        assert!(!e.is_transient());
    }
}
