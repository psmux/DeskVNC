//! The supervised remote shell: connect, run, notice trouble, reconnect.
//!
//! ## What this fixes about plain `ssh`
//!
//! | plain `ssh` | here |
//! |---|---|
//! | link drops, you are back at a local prompt | the supervisor reconnects with backoff |
//! | link hangs, you wait minutes for TCP to admit it | keepalive probes call it in ~15s ([`Keepalive::interactive`]) |
//! | reconnecting gives you a fresh, empty shell | reattach to a remote multiplexer, work intact ([`crate::options::MultiplexerConfig`]) |
//! | a session cut inside `tmux` leaves the mouse reporting garbage | tracked modes are reset on every drop ([`crate::modes`]) |
//!
//! ## Why this loop and not `remote_core::reconnect::supervise`
//!
//! The backoff ladder, the classification of which failures are worth
//! retrying, and the "a connection that stayed up long enough resets the
//! counter" rule are all genuinely protocol-neutral, so they are reused as
//! is: [`ReconnectPolicy`], [`classify`] and [`STABLE_UPTIME`] come straight
//! from `remote-core`. The supervisor *function* there does not fit, because
//! it is written against `remote_core::SessionEvent`, whose variants are
//! framebuffer rectangles, cursor shapes and pixel formats. A terminal has
//! none of those and needs one it does not have (bytes out of a PTY), so
//! bending it to fit would mean emitting nonsense variants for a shape that
//! does not match. The policy is shared; the loop is ours.

use std::sync::Arc;
use std::time::Instant;

use remote_core::reconnect::{classify, Decision, RetryClassify, STABLE_UPTIME};
use russh::ChannelMsg;
use ssh_transport::hostkey::HostKeyVerifier;
use ssh_transport::{connect_and_authenticate_with, Keepalive};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::events::{SshCommand, SshEvent, TerminalState};
use crate::modes::ModeTracker;
use crate::options::SshTermOptions;
use crate::pty;

/// A running session. Dropping this does not stop it; call
/// [`SshSession::shutdown`] or send [`SshCommand::Disconnect`].
pub struct SshSession {
    commands: mpsc::Sender<SshCommand>,
    cancel: CancellationToken,
    endpoint: String,
}

impl SshSession {
    /// Start a supervised remote shell.
    ///
    /// Returns immediately with a handle and the event stream; everything
    /// else happens on the spawned task. The first thing the caller will see
    /// is [`TerminalState::Connecting`].
    ///
    /// Takes `impl HostKeyVerifier` rather than an `Arc<dyn …>` to match
    /// `SftpSession::connect` and `SshTunnel::connect`, and because the shape
    /// the shell actually holds, `Arc<Mutex<HostKeyStore>>`, implements the
    /// trait *as a whole* and so cannot be unsize-coerced into a trait
    /// object by the caller. Boxing it here means callers just pass the
    /// store.
    pub fn spawn(
        options: SshTermOptions,
        verifier: impl HostKeyVerifier,
    ) -> (Self, mpsc::Receiver<SshEvent>) {
        let verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static> = Arc::new(verifier);
        // 256 output chunks of buffer. A remote `cat` of a large file
        // outruns any UI, and the bound is what stops that from growing
        // memory without limit; the send is awaited, so the pressure travels
        // back down to the SSH window rather than being dropped on the floor.
        let (events_tx, events_rx) = mpsc::channel(256);
        let (commands_tx, commands_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let endpoint = options.ssh.endpoint();

        tokio::spawn(supervise(
            options,
            verifier,
            events_tx,
            commands_rx,
            cancel.clone(),
        ));

        (
            Self {
                commands: commands_tx,
                cancel,
                endpoint,
            },
            events_rx,
        )
    }

    /// `user@host:port`. Never contains secrets.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Send keystrokes to the remote PTY.
    pub async fn input(&self, bytes: Vec<u8>) -> Result<()> {
        self.send(SshCommand::Input(bytes)).await
    }

    /// Tell the remote its terminal changed size.
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.send(SshCommand::Resize { cols, rows }).await
    }

    /// Skip the remaining backoff and retry now.
    pub async fn reconnect_now(&self) -> Result<()> {
        self.send(SshCommand::ReconnectNow).await
    }

    /// Send a raw command. Used by the [`crate::driver`] adapter, which
    /// translates the shell's `ClientCommand` into these.
    pub async fn send_command(&self, cmd: SshCommand) -> Result<()> {
        self.send(cmd).await
    }

    async fn send(&self, cmd: SshCommand) -> Result<()> {
        self.commands
            .send(cmd)
            .await
            .map_err(|_| Error::Other("the session has ended".into()))
    }

    /// Stop the session. Idempotent.
    pub async fn shutdown(&self) {
        let _ = self.commands.send(SshCommand::Disconnect).await;
        self.cancel.cancel();
    }
}

async fn emit(events: &mpsc::Sender<SshEvent>, event: SshEvent) -> Result<()> {
    events.send(event).await.map_err(|_| Error::Cancelled)
}

async fn emit_state(events: &mpsc::Sender<SshEvent>, state: TerminalState) -> Result<()> {
    emit(events, SshEvent::StateChanged(state)).await
}

/// The supervisor loop.
async fn supervise(
    options: SshTermOptions,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    events: mpsc::Sender<SshEvent>,
    mut commands: mpsc::Receiver<SshCommand>,
    cancel: CancellationToken,
) {
    let mut attempts: u32 = 0;
    // Geometry is session state, not connection state: the user may resize
    // while disconnected, and the reconnected PTY must open at the size the
    // window is now, not the size it was when the link died.
    let mut terminal = options.terminal.clone();

    loop {
        let mut connected_at: Option<Instant> = None;
        let result = run_once(
            &options,
            &mut terminal,
            &verifier,
            &events,
            &mut commands,
            &cancel,
            &mut connected_at,
        )
        .await;

        // A connection that stayed up long enough proves the network
        // recovered, so the next drop starts its backoff from scratch rather
        // than inheriting a 15 second delay earned an hour ago.
        if let Some(t) = connected_at {
            if t.elapsed() >= STABLE_UPTIME {
                attempts = 0;
            }
        }

        let err = match result {
            Ok(()) => {
                let _ = emit_state(
                    &events,
                    TerminalState::Disconnected {
                        reason: "Disconnected".into(),
                        can_retry: true,
                        symbol: None,
                    },
                )
                .await;
                return;
            }
            Err(e) => e,
        };

        match classify(&err, &options.reconnect, attempts) {
            Decision::Stop { can_retry } => {
                if !err.is_cancelled() {
                    tracing::info!(endpoint = %options.ssh.endpoint(), "ssh session stopped: {err}");
                }
                let _ = emit_state(
                    &events,
                    TerminalState::Disconnected {
                        reason: err.user_message(),
                        can_retry,
                        symbol: err.symbol(),
                    },
                )
                .await;
                return;
            }
            Decision::Retry => {
                attempts += 1;
                let delay = options.reconnect.delay_for(attempts, rand::random::<f64>());
                tracing::info!(
                    endpoint = %options.ssh.endpoint(),
                    attempts,
                    "ssh session dropped ({err}); reconnecting in {delay:?}"
                );
                if emit_state(
                    &events,
                    TerminalState::Reconnecting {
                        attempt: attempts,
                        delay_ms: delay.as_millis() as u64,
                        reason: err.user_message(),
                    },
                )
                .await
                .is_err()
                {
                    return;
                }

                match wait_backoff(delay, &mut commands, &cancel, &mut terminal).await {
                    WaitOutcome::Stop => return,
                    // The user pressed "reconnect now", which is a statement
                    // that the network is back. Taking them at their word
                    // means not making them sit out a delay earned while it
                    // was down.
                    WaitOutcome::RetryNow => attempts = 0,
                    WaitOutcome::Elapsed => {}
                }
            }
        }
    }
}

enum WaitOutcome {
    Elapsed,
    RetryNow,
    Stop,
}

/// Wait out the backoff while staying responsive.
///
/// Resizes are absorbed rather than dropped: a user who reshapes the window
/// during an outage must get a correctly sized PTY when it comes back.
/// Keystrokes are deliberately discarded, there is nothing to deliver them
/// to, and replaying a buffer of them into a shell that reappears minutes
/// later is how people accidentally run half a command.
async fn wait_backoff(
    delay: std::time::Duration,
    commands: &mut mpsc::Receiver<SshCommand>,
    cancel: &CancellationToken,
    terminal: &mut crate::options::TerminalOptions,
) -> WaitOutcome {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return WaitOutcome::Stop,
            _ = &mut sleep => return WaitOutcome::Elapsed,
            cmd = commands.recv() => match cmd {
                None | Some(SshCommand::Disconnect) => return WaitOutcome::Stop,
                Some(SshCommand::ReconnectNow) => return WaitOutcome::RetryNow,
                Some(SshCommand::Resize { cols, rows }) => {
                    terminal.cols = cols;
                    terminal.rows = rows;
                }
                // Nothing is asking, so an answer arriving here is stale
                // (the dialog was answered twice, or after a timeout). Drop
                // it rather than treating it as an error.
                Some(SshCommand::Input(_))
                | Some(SshCommand::ProvideCredentials { .. })
                | Some(SshCommand::CancelCredentials) => {}
            },
        }
    }
}

/// One connection attempt, from dial to the link going away.
///
/// `Ok(())` only for a deliberate disconnect. Everything else, cancellation
/// included, is an `Err` so the supervisor can classify it.
/// `terminal` is read for the size to open at and written back with whatever
/// size the window ended up, so a resize during the session (or during the
/// backoff that follows it) survives into the next attempt.
#[allow(clippy::too_many_arguments)]
async fn run_once(
    options: &SshTermOptions,
    terminal: &mut crate::options::TerminalOptions,
    verifier: &Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    events: &mpsc::Sender<SshEvent>,
    commands: &mut mpsc::Receiver<SshCommand>,
    cancel: &CancellationToken,
    connected_at: &mut Option<Instant>,
) -> Result<()> {
    emit_state(
        events,
        TerminalState::Connecting {
            endpoint: options.ssh.endpoint(),
        },
    )
    .await?;

    // `interactive` rather than the sidecar profile: a human staring at a
    // frozen prompt must not wait 90 seconds for the transport to admit the
    // peer is gone. This is the hang detection.
    //
    // The loop exists for the ad-hoc case. A Quick Connect target has no
    // profile, so it has no stored account and no secret: without an ask, the
    // only auth that could ever succeed is an agent, and a machine with no
    // agent identities just failed. So a refused authentication asks the user
    // and tries again with what they give, exactly as the RFB handshake does.
    let mut cfg = options.ssh.clone();
    let mut attempt: u32 = 0;
    // Every method the profile has material for, in preference order. The
    // first is already on `cfg`; the rest are tried before the user is asked
    // for anything, because a client that holds a working password and asks
    // for one anyway is worse than useless.
    let mut fallbacks: std::collections::VecDeque<ssh_transport::SshAuth> =
        options.auth_methods.iter().skip(1).cloned().collect();
    let ssh = loop {
        let dialing =
            connect_and_authenticate_with(&cfg, verifier.clone(), Keepalive::interactive());
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            r = dialing => r,
        };

        match outcome {
            Ok(handle) => break handle,
            // Only an authentication refusal is worth asking about. A refused
            // dial, a timeout or a changed host key are not things a password
            // fixes, and prompting for one would be a dialog that cannot help.
            // An agent with no identities, or a refused method, is a reason
            // to try the next one rather than to give up. Only when nothing
            // is left is the user asked.
            Err(ssh_transport::Error::Auth { .. } | ssh_transport::Error::Agent(_))
                if !fallbacks.is_empty() =>
            {
                let next = fallbacks.pop_front().expect("checked non-empty");
                tracing::debug!("ssh authentication did not succeed; trying the next method");
                cfg.auth = next;
            }
            Err(e @ (ssh_transport::Error::Auth { .. } | ssh_transport::Error::Agent(_))) => {
                attempt += 1;
                let hint = (!cfg.username.is_empty()).then(|| cfg.username.clone());
                let Some((username, password)) = ask_for_credentials(
                    events,
                    commands,
                    cancel,
                    "SSH",
                    attempt,
                    Some(e.to_string()),
                    hint,
                )
                .await
                else {
                    // Asked and declined. Stopping is right: retrying would be
                    // a loop with a dialog in it.
                    return Err(Error::Transport(e));
                };
                if let Some(user) = username {
                    cfg.username = user;
                }
                cfg.auth = ssh_transport::SshAuth::Password(password);
                // The user has just told us what to use, so stop cycling
                // through the profile's other methods: retrying an agent that
                // already failed would only produce a second dialog.
                fallbacks.clear();
            }
            Err(e) => return Err(Error::Transport(e)),
        }
    };

    let found = pty::probe_multiplexer(&ssh, &options.multiplexer).await?;
    let session = pty::open(
        &ssh,
        &*terminal,
        &options.multiplexer,
        &found,
        options.startup_command.as_deref(),
    )
    .await?;
    let mut channel = session.channel;

    if session.multiplexer.is_none()
        && options.multiplexer.kind != crate::multiplexer::MultiplexerKind::None
    {
        // Say it once, quietly. The user asked for persistence and is not
        // getting it, and finding that out only after losing work would be
        // worse than a line in the log.
        //
        // The wording differs by intent. Someone who named a multiplexer
        // wants to hear that *that one* is absent; someone on Auto asked us
        // to find whatever is there, so the useful sentence names the options
        // rather than blaming a tool they never chose.
        let notice = match options.multiplexer.kind {
            crate::multiplexer::MultiplexerKind::Auto => {
                "No terminal multiplexer was found on the remote machine, so this session will \
                 not survive a disconnect. Installing tmux (or psmux on Windows) would let your \
                 work carry across reconnects."
                    .to_string()
            }
            other => format!(
                "{} is not installed on the remote machine, so this session will not survive a \
                 disconnect",
                other.binary().unwrap_or("the multiplexer")
            ),
        };
        let _ = emit(events, SshEvent::Notice(notice)).await;
    }

    *connected_at = Some(Instant::now());
    emit_state(
        events,
        TerminalState::Connected {
            endpoint: options.ssh.endpoint(),
            multiplexer: session.multiplexer,
            resumed: session.resumed,
        },
    )
    .await?;

    // From here on, every byte the remote sends is watched for the private
    // modes that would strand the local terminal if the link died. See
    // `crate::modes` for the failure this prevents.
    let mut tracker = ModeTracker::new();
    let mut geometry = (terminal.cols, terminal.rows);

    let outcome = pump(
        &mut channel,
        events,
        commands,
        cancel,
        &mut tracker,
        &mut geometry,
        session.multiplexer.map(|m| m.label()),
    )
    .await;

    // Whatever ended the session, the local terminal must be handed back in
    // a usable state. This runs on every path out: a clean exit, a dropped
    // link, a cancellation. It is the one thing plain `ssh` never does for
    // you, and the reason a killed `tmux` leaves you typing into garbage.
    let reset = tracker.reset_sequence();
    if !reset.is_empty() {
        let _ = emit(events, SshEvent::ResetTerminal(reset)).await;
    }

    // Report the geometry back so a reconnect opens its PTY at the size the
    // window actually is now.
    terminal.cols = geometry.0;
    terminal.rows = geometry.1;

    let _ = ssh
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    outcome
}

/// Ask the user for credentials and wait for the answer.
///
/// Returns `None` when the ask was declined, cancelled, or the shell went
/// away, which the caller turns into a stopped session: they were asked and
/// said no, so retrying would be a loop with a dialog in it.
///
/// Pumps `commands` directly, the same receiver the supervisor owns and that
/// nothing else reads while the session is unconnected. That is the same
/// shape `vnc-core`'s `serve_credential_ask` uses, for the same reason: the
/// handshake has to block on a human without blocking the runtime.
async fn ask_for_credentials(
    events: &mpsc::Sender<SshEvent>,
    commands: &mut mpsc::Receiver<SshCommand>,
    cancel: &CancellationToken,
    method: &str,
    attempt: u32,
    error: Option<String>,
    username_hint: Option<String>,
) -> Option<(Option<String>, String)> {
    emit(
        events,
        SshEvent::CredentialsRequired {
            method: method.to_string(),
            attempt,
            error,
            username_hint,
        },
    )
    .await
    .ok()?;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return None,
            cmd = commands.recv() => match cmd {
                None
                | Some(SshCommand::CancelCredentials)
                | Some(SshCommand::Disconnect) => return None,
                Some(SshCommand::ProvideCredentials { username, password }) => {
                    return Some((username.filter(|u| !u.trim().is_empty()), password));
                }
                // Keystrokes, resizes and reconnect requests are meaningless
                // before a shell exists. Drop them and keep waiting.
                Some(_) => continue,
            },
        }
    }
}

/// The byte pump: remote output out, keystrokes and resizes in.
async fn pump(
    channel: &mut russh::Channel<russh::client::Msg>,
    events: &mpsc::Sender<SshEvent>,
    commands: &mut mpsc::Receiver<SshCommand>,
    cancel: &CancellationToken,
    tracker: &mut ModeTracker,
    geometry: &mut (u16, u16),
    // The multiplexer that was attached, if any. Its label is what turns a
    // clean exit into a "detached" rather than an "exited": see
    // `Error::Detached`.
    multiplexer: Option<&'static str>,
) -> Result<()> {
    let mut exit_status_seen: Option<u32> = None;

    // Output coalescing. A PTY hands back many small reads: a shell prompt is
    // a handful of bytes, and a program writing line by line produces one
    // channel message per line. Emitting an event per read means one channel
    // send, one allocation and one IPC message each, and a fast-scrolling
    // build log turns that into tens of thousands per second, which the
    // renderer cannot keep up with and which starves the input path.
    //
    // So bytes accumulate here and flush when either the buffer is worth
    // sending or the stream goes quiet. `FLUSH_BYTES` is one terminal screen
    // of dense output, and `FLUSH_AFTER` is short enough that a single
    // keystroke's echo is imperceptible: a human notices around 50 ms, and
    // this is an order of magnitude under it.
    const FLUSH_BYTES: usize = 16 * 1024;
    const FLUSH_AFTER: std::time::Duration = std::time::Duration::from_millis(4);
    let mut pending: Vec<u8> = Vec::with_capacity(FLUSH_BYTES);

    loop {
        // Nothing buffered means nothing to wait out, so the timer is only
        // armed when it can actually fire. A pending sleep on every loop turn
        // would wake an idle session 250 times a second for no reason.
        let flush_due = async {
            if pending.is_empty() {
                std::future::pending::<()>().await
            } else {
                tokio::time::sleep(FLUSH_AFTER).await
            }
        };

        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),

            _ = flush_due => {
                emit(events, SshEvent::Output(std::mem::take(&mut pending))).await?;
            }

            msg = channel.wait() => {
                let Some(msg) = msg else {
                    // The channel ended without a status. That is a dropped
                    // carrier, not a shell that exited, so it is worth
                    // reconnecting through. Flush first: bytes the remote
                    // managed to send before the link died are still the
                    // user's output and must not be dropped with the buffer.
                    if !pending.is_empty() {
                        let _ = emit(events, SshEvent::Output(std::mem::take(&mut pending))).await;
                    }
                    return Err(Error::Unresponsive);
                };
                match msg {
                    ChannelMsg::Data { data } => {
                        tracker.feed(&data);
                        pending.extend_from_slice(&data);
                    }
                    // stderr of the remote command. A PTY session normally
                    // merges it, but `exec` of a multiplexer that fails to
                    // start reports here, and the user needs to see why.
                    ChannelMsg::ExtendedData { data, .. } => {
                        tracker.feed(&data);
                        pending.extend_from_slice(&data);
                    }
                    // RFC 4254 §6.10: the server sends CHANNEL_EOF, then
                    // `exit-status`, then CHANNEL_CLOSE. Returning on the EOF
                    // would therefore throw away the status that is about to
                    // arrive and report every exit as 0, so the status is
                    // recorded and the close is what ends the loop.
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_status_seen = Some(exit_status);
                    }
                    ChannelMsg::ExitSignal { signal_name, error_message, .. } => {
                        // The remote program was killed. With a multiplexer
                        // this is usually the user's own `tmux kill-server`.
                        return Err(Error::ShellRefused(format!(
                            "the remote shell was killed by {signal_name:?}: {error_message}"
                        )));
                    }
                    ChannelMsg::Eof => {}
                    ChannelMsg::Close => {
                        // The last write of a program that exits immediately
                        // after printing lands here; losing it would drop the
                        // very line the user was waiting for.
                        if !pending.is_empty() {
                            let _ = emit(events, SshEvent::Output(std::mem::take(&mut pending)))
                                .await;
                        }
                        let status = exit_status_seen.unwrap_or(0);
                        // Detaching makes the attach command exit cleanly, so
                        // at this level a detach and an `exit` are the same
                        // event. They mean opposite things to the user, and
                        // the multiplexer is what tells them apart: with one
                        // attached, a status of 0 means the session is still
                        // running on the remote and one click gets it back.
                        return Err(match (multiplexer, status) {
                            (Some(mux), 0) => Error::Detached(mux.to_string()),
                            _ => Error::ShellExited(status),
                        });
                    }
                    _ => {}
                }

                // Send early when there is already a screenful, rather than
                // waiting out the timer: bulk output should stream, not
                // arrive in 4 ms pulses.
                if pending.len() >= FLUSH_BYTES {
                    emit(events, SshEvent::Output(std::mem::take(&mut pending))).await?;
                }
            }

            cmd = commands.recv() => match cmd {
                None => return Err(Error::Cancelled),
                Some(SshCommand::Disconnect) => return Ok(()),
                Some(SshCommand::Input(bytes)) => {
                    channel.data_bytes(bytes).await.map_err(|e| {
                        Error::Transport(ssh_transport::Error::ssh(e))
                    })?;
                }
                Some(SshCommand::Resize { cols, rows }) => {
                    // Clamped for the same reason the initial request is: a
                    // webview measuring a hidden element reports 0x0, and a
                    // zero-width PTY makes remote programs misbehave.
                    let cols = cols.clamp(1, 10_000);
                    let rows = rows.clamp(1, 10_000);
                    if (cols, rows) != *geometry {
                        *geometry = (cols, rows);
                        // A failed window-change is not worth ending a
                        // session over; the size is cosmetic until the next
                        // redraw, and the read half will report a genuinely
                        // dead channel soon enough.
                        if let Err(e) = channel
                            .window_change(u32::from(cols), u32::from(rows), 0, 0)
                            .await
                        {
                            tracing::debug!("window-change was refused: {e}");
                        }
                    }
                }
                // Already connected; nothing to do. A credential answer this
                // late is stale for the same reason.
                Some(SshCommand::ReconnectNow)
                | Some(SshCommand::ProvideCredentials { .. })
                | Some(SshCommand::CancelCredentials) => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multiplexer::{MultiplexerConfig, MultiplexerKind};
    use crate::options::TerminalOptions;

    /// The backoff ladder is the one `remote-core` already ships, so a
    /// terminal reconnects on the same schedule as a VNC session rather than
    /// inventing a second set of numbers to tune.
    #[test]
    fn the_backoff_ladder_is_the_shared_one() {
        let p = remote_core::options::ReconnectPolicy::default();
        let steps: Vec<u64> = (1..=6)
            .map(|i| p.delay_for(i, 0.5).as_millis() as u64)
            .collect();
        assert_eq!(steps, vec![250, 500, 1_000, 2_000, 4_000, 8_000]);
        // And it is capped, so a long outage does not end in a ten minute wait.
        assert_eq!(p.delay_for(20, 0.5).as_millis() as u64, 15_000);
    }

    /// A resize arriving during an outage has to be remembered, otherwise the
    /// reconnected PTY opens at a stale size and every full-screen program
    /// draws into the wrong box until the user nudges the window again.
    #[tokio::test]
    async fn a_resize_during_backoff_is_applied_to_the_next_connection() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let mut terminal = TerminalOptions::default();

        tx.send(SshCommand::Resize {
            cols: 200,
            rows: 60,
        })
        .await
        .unwrap();

        let outcome = wait_backoff(
            std::time::Duration::from_millis(60),
            &mut rx,
            &cancel,
            &mut terminal,
        )
        .await;

        assert!(matches!(outcome, WaitOutcome::Elapsed));
        assert_eq!((terminal.cols, terminal.rows), (200, 60));
        drop(tx);
    }

    /// "Reconnect now" is the user saying the network is back. Making them
    /// serve out a delay earned while it was down is exactly the behaviour
    /// that makes people kill the window and start again.
    #[tokio::test]
    async fn reconnect_now_interrupts_the_backoff() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let mut terminal = TerminalOptions::default();
        tx.send(SshCommand::ReconnectNow).await.unwrap();

        let outcome = wait_backoff(
            std::time::Duration::from_secs(30),
            &mut rx,
            &cancel,
            &mut terminal,
        )
        .await;
        assert!(matches!(outcome, WaitOutcome::RetryNow));
    }

    #[tokio::test]
    async fn cancelling_ends_the_backoff_immediately() {
        let (_tx, mut rx) = mpsc::channel::<SshCommand>(4);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut terminal = TerminalOptions::default();

        let outcome = wait_backoff(
            std::time::Duration::from_secs(30),
            &mut rx,
            &cancel,
            &mut terminal,
        )
        .await;
        assert!(matches!(outcome, WaitOutcome::Stop));
    }

    /// Keystrokes typed at a dead session must not be replayed into the shell
    /// that comes back minutes later, that is how half a command gets run.
    #[tokio::test]
    async fn keystrokes_typed_during_an_outage_are_discarded() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut terminal = TerminalOptions::default();

        tx.send(SshCommand::Input(b"rm -rf /\n".to_vec()))
            .await
            .unwrap();

        let outcome = wait_backoff(
            std::time::Duration::from_millis(60),
            &mut rx,
            &cancel,
            &mut terminal,
        )
        .await;
        assert!(matches!(outcome, WaitOutcome::Elapsed));
        // Nothing was buffered anywhere for a future shell to receive.
        assert!(rx.try_recv().is_err());
        drop(tx);
    }

    /// The whole reason the multiplexer default is not a plain shell: without
    /// persistence on the far side, reconnecting is cosmetic. `Auto` is the
    /// default rather than `Tmux` so a host running psmux, zellij or screen
    /// is served too, and a host running nothing still gets a terminal.
    #[test]
    fn the_default_session_is_persistent_wherever_it_can_be() {
        let mux = MultiplexerConfig::default();
        assert_eq!(mux.kind, MultiplexerKind::Auto);
        // Auto resolves to a real command once the probe names a winner.
        for kind in MultiplexerKind::AUTO_ORDER {
            assert!(
                mux.attach_command(Some(*kind)).unwrap().is_some(),
                "{kind:?} must resolve to a command"
            );
        }
        // And a host with nothing installed still opens a shell.
        assert!(mux.attach_command(None).unwrap().is_none());
    }
}
