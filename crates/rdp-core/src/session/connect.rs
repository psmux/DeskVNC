//! One connection attempt, end to end (PRDRDP/12 §3.13).
//!
//! Resolve the options, open the stream, run the connection sequence, split
//! the stream, start the writer task, hand off to the run loop. The structure
//! copies `crates/vnc-core/src/session/connection.rs:436` (`run_once`) closely
//! enough that a reviewer can diff them mentally, and the state transitions
//! are the same five the RFB path emits, which is what the UI already renders
//! (PRDRDP/00 R12).

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use remote_core::{ClientCommand, ConnectOptions, SessionEvent, SessionState};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::connection;
use crate::error::{RdpError, Result};
use crate::options::ResolvedOptions;
use crate::session::run_loop::{Attempt, RunLoop};
use crate::session::settings::RdpSessionSettings;
use crate::session::Continuity;
use crate::transport::framer::Framer;
use crate::transport::writer::{self, WRITER_QUEUE};

/// Run one attempt to completion.
///
/// # Errors
///
/// Whatever the phase that failed reports. Every error names the phase it
/// happened in, which is what a support log needs and what a `todo!()` would
/// have destroyed.
#[allow(clippy::too_many_arguments)]
pub async fn run_once(
    options: &ConnectOptions,
    settings: &mut RdpSessionSettings,
    carry: &mut Continuity,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
    connected_at: &mut Option<std::time::Instant>,
) -> Result<Attempt> {
    let rdp = options.rdp_options().ok_or_else(|| {
        // `ConnectOptions` carries its protocol half as data, so nothing in
        // the type system stops the wrong half reaching here. `RdpDriver`
        // catches it before a task exists; this is the second gate, for the
        // integration tests that call this directly.
        RdpError::Protocol("RDP options were expected".to_owned())
    })?;

    let mut warnings = Vec::new();
    let mut opts = ResolvedOptions::resolve(options, rdp, &mut warnings)?;
    for warning in &warnings {
        tracing::warn!(warning, "the host profile was adjusted");
    }
    // A size the user asked for outlives the connection it was asked on, so
    // the desktop comes back at the size they were using rather than at the
    // profile's (PRDRDP/05 §5.4). The display control channel re-applies it
    // once the session is up; this is the connect time half.
    if let Some((width, height)) = settings.requested_size {
        opts.desktop = (width, height);
    }
    // A redirection told us to present its `LoadBalanceInfo` as the routing
    // token of the next Connection Request (MS-RDPBCGR 3.2.5.3.1). It is
    // taken rather than borrowed: a token is presented once, to the host that
    // issued it.
    opts.routing_token = carry.routing_token.take();

    // MS-RDPBCGR 5.5 step 3: the cookie goes in the Client Info PDU of the
    // attempt after the one that received it. A stale one is treated as
    // absent (PRDRDP/06 §5.5.5).
    let now = std::time::Instant::now();
    let arc = match carry.cookie.as_ref() {
        Some(cookie) if cookie.is_stale(now) => {
            tracing::info!(
                logon_id = cookie.logon_id(),
                "the auto reconnect cookie is past its rotation window: not offering it"
            );
            carry.cookie = None;
            None
        }
        Some(cookie) => {
            tracing::info!(
                logon_id = cookie.logon_id(),
                "offering the auto reconnect cookie"
            );
            Some(cookie.client_packet())
        }
        None => None,
    };

    let (connected, framer) = match establish(options, &opts, arc, events, commands, cancel).await {
        Ok(pair) => pair,
        // A broker can redirect before the session is up (MS-RDPBCGR 1.3.8),
        // in which case there is no pump to run: the attempt is over and the
        // next one goes to the machine the broker named. Not a failure, which
        // is why the supervisor is handed an outcome rather than the error.
        Err(RdpError::Redirected(redirect)) => {
            tracing::info!(%redirect, "redirected during the connection sequence");
            carry.redirect = Some(*redirect);
            return Ok(Attempt::ServerDisconnect {
                user_requested: false,
            });
        }
        Err(e) => return Err(e),
    };

    remote_core::emit_state(events, SessionState::Connected).await?;
    // What `STABLE_UPTIME` is measured from: a connection that stayed up long
    // enough proves the network is fine and resets the backoff ladder
    // (`remote_core::reconnect`).
    *connected_at = Some(std::time::Instant::now());
    run_connected(
        framer,
        connected,
        &opts,
        settings.view_only,
        carry,
        events,
        commands,
        cancel,
    )
    .await
}

/// Open a connection and run the sequence on it, asking the user for
/// credentials when the sequence needs them and re-asking when the server
/// rejects what they typed.
///
/// # Why the re-ask opens a second socket
///
/// It has to. MS-CSSP 3.1.5 has the client fail immediately on the error code
/// the server returns, and by then the server has finished with the exchange;
/// a second `TSRequest` on that TLS session goes to a peer that has stopped
/// listening, so a rejected password would turn into a dropped connection
/// rather than a second try. The credentials therefore live here, above the
/// sequence, and a rejection goes round this loop rather than round one
/// inside [`connection::connect`].
///
/// # What is not retried, and why that matters more than what is
///
/// Only credentials the *user* supplied, which is what
/// [`connection::Ask::prompted`] reports. A stored password the server
/// rejects fails once, opening exactly one TCP connection: replaying a saved
/// credential is how an Active Directory account gets locked, and the user
/// finds out when they cannot sign in to their own laptop. The count is
/// bounded by [`connection::MAX_CREDENTIAL_PROMPTS`] on top of that.
///
/// The loop lives inside a single supervisor iteration and never returns a
/// transient error, so [`RdpError::AuthFailed`] still reaches the supervisor
/// as a terminal failure. `vnc-core` draws the same two lines in the same
/// place (`crates/vnc-core/src/session/connection.rs:366`).
async fn establish(
    options: &ConnectOptions,
    opts: &ResolvedOptions,
    arc: Option<rdp_pdu::rdp::client_info::ArcClientPrivatePacket>,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<(connection::Connected, Framer<vnc_transport::BoxedStream>)> {
    // Cloned rather than borrowed because the gate replaces them with what
    // the user types, and what they type has to survive into the next turn of
    // this loop. The profile is never rewritten: a password the server
    // rejected is not one to remember, and the keychain is the shell's
    // (`crates/remote-core/src/commands.rs:64`).
    let mut creds = options.credentials.clone();
    let mut ask = connection::Ask::new();

    loop {
        let stream = crate::transport::open_stream(options, events).await?;

        // The connection sequence is straight line `await` code and is
        // deliberately not cancellation safe, so it is raced against the
        // token rather than being polled inside a `select!` alongside
        // anything else: cancelling it drops the whole attempt and the whole
        // stream with it.
        //
        // The one thing it does await on is the user. An unpinned server key
        // parks the sequence on a `ClientCommand::TrustCertificate` answer
        // and a missing password parks it on a
        // `ClientCommand::ProvideCredentials` one, which is why the command
        // receiver is lent down here rather than being read only by the pump
        // (`crate::connection::prompt`). Nothing else reads it while the
        // sequence runs.
        let result = {
            let connect = connection::connect(
                stream,
                opts,
                &mut creds,
                &options.cert_pins,
                arc,
                events,
                Some(connection::Prompt {
                    commands,
                    cancel,
                    ask: &mut ask,
                }),
            );
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(RdpError::Cancelled),
                result = connect => result,
            }
        };

        match result {
            Ok(pair) => return Ok(pair),
            Err(e @ RdpError::AuthFailed(_)) if ask.prompted() && ask.may_ask_again() => {
                tracing::info!(
                    prompts = ask.raised(),
                    "the server rejected the credentials the user supplied; asking again"
                );
                ask.refused(e.user_message());
            }
            Err(e) => return Err(e),
        }
    }
}

/// Split the stream, start the writer task, and pump.
///
/// Separate from [`run_once`] so the split and the join are in one place: the
/// writer task owns the write half from here until the session ends, and the
/// two halves are never rejoined.
#[allow(clippy::too_many_arguments)]
async fn run_connected(
    framer: Framer<vnc_transport::BoxedStream>,
    connected: connection::Connected,
    opts: &ResolvedOptions,
    view_only: bool,
    carry: &mut Continuity,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<Attempt> {
    let (stream, buffered) = framer.into_inner();
    let (read_half, write_half) = tokio::io::split(stream);

    let received = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));

    // Whatever the connection sequence read ahead of itself belongs to the
    // run loop, so the new framer starts with it rather than dropping it. A
    // server is allowed to pipeline the first update behind the last
    // finalisation PDU, and losing those bytes is a stall nobody can explain.
    let mut framer = Framer::new(read_half, received.clone());
    framer.prime(buffered);

    let (outbound, rx) = mpsc::channel(WRITER_QUEUE);
    let writer = tokio::spawn(writer::writer_task(write_half, rx, sent.clone()));

    let mut run_loop = RunLoop::new(
        framer,
        outbound,
        connected.channels,
        opts.clone(),
        connected.activation,
        view_only,
        received,
        sent,
    );
    let outcome = run_loop
        .run(connected.pending, events, commands, cancel)
        .await;

    // Whatever the pump learned that outlives this connection. Rejection
    // first and arrival second: a server that refused our cookie and then
    // minted a fresh one has given us something to keep (PRDRDP/06 §5.5.4).
    if run_loop.cookie_discarded() {
        carry.cookie = None;
    }
    if let Some(cookie) = run_loop.take_cookie() {
        carry.cookie = Some(cookie);
    }
    if let Some(redirect) = run_loop.take_redirect() {
        carry.redirect = Some(redirect);
    }

    // The teardown queued `Outbound::Shutdown`, so the writer task is either
    // finished or about to be. Joining it inside the budget is what makes the
    // close ordered rather than racing the drop.
    drop(run_loop);
    match tokio::time::timeout(TEARDOWN_BUDGET, writer).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!(error = %e, "the writer task did not finish cleanly"),
        Err(_) => tracing::debug!("the writer task did not finish inside the teardown budget"),
    }
    outcome
}

/// The whole teardown budget (PRDRDP/06 §6.4).
///
/// Three seconds, chosen to sit at the shell's `REAP_TIMEOUT` so a session
/// that will not close cleanly still releases its id before the shell gives
/// up waiting for it.
const TEARDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);
