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
use crate::session::run_loop::{RunLoop, RunOutcome};
use crate::session::settings::RdpSessionSettings;
use crate::transport::framer::Framer;
use crate::transport::writer::{self, WRITER_QUEUE};

/// Run one attempt to completion.
///
/// # Errors
///
/// Whatever the phase that failed reports. Every error names the phase it
/// happened in, which is what a support log needs and what a `todo!()` would
/// have destroyed.
pub async fn run_once(
    options: &ConnectOptions,
    settings: &mut RdpSessionSettings,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<RunOutcome> {
    let rdp = options.rdp_options().ok_or_else(|| {
        // `ConnectOptions` carries its protocol half as data, so nothing in
        // the type system stops the wrong half reaching here. `RdpDriver`
        // catches it before a task exists; this is the second gate, for the
        // integration tests that call this directly.
        RdpError::Protocol("RDP options were expected".to_owned())
    })?;

    let mut warnings = Vec::new();
    let opts = ResolvedOptions::resolve(options, rdp, &mut warnings)?;
    for warning in &warnings {
        tracing::warn!(warning, "the host profile was adjusted");
    }
    settings.apply(options);

    let stream = crate::transport::open_stream(options, events).await?;

    // The connection sequence is straight line `await` code and is
    // deliberately not cancellation safe, so it is raced against the token
    // rather than being polled inside a `select!` alongside anything else:
    // cancelling it drops the whole attempt and the whole stream with it.
    let connect = connection::connect(
        stream,
        &opts,
        &options.credentials,
        &options.cert_pins,
        events,
    );
    let (connected, framer) = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(RdpError::Cancelled),
        result = connect => result?,
    };

    remote_core::emit_state(events, SessionState::Connected).await?;
    run_connected(
        framer,
        connected,
        &opts,
        settings.view_only,
        events,
        commands,
        cancel,
    )
    .await
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
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
) -> Result<RunOutcome> {
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
