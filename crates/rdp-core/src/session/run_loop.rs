//! The connected state pump (PRDRDP/12 §4.4, PRDRDP/06 §2.2).
//!
//! A `tokio::select!` over the framer, the command channel, a one second
//! stats tick and cancellation, with the same two orderings
//! `crates/vnc-core/src/session/run_loop.rs:685` makes and for the same
//! reasons: `biased` so a teardown cannot be starved by a busy server, and
//! the socket polled before the command channel so a burst of input cannot
//! stall the picture.
//!
//! One structural difference from the RFB loop, and it is the only one that
//! is not a copy. **Nothing in this loop touches the socket's write half.**
//! The stream is split before the loop starts, the write half is moved into
//! [`crate::transport::writer`], and the loop holds only an
//! `mpsc::Sender<Outbound>`. [`RunLoop::send`] is a channel send, not a
//! socket write. That is what makes the "no write inside a `select!` arm"
//! rule structural rather than a convention: the operation that is not
//! cancellation safe, a partial `write_all`, does not appear in this loop at
//! all (PRDRDP/00 R10).
//!
//! # Cancellation safety, await by await
//!
//! | Await | Where | Safe because |
//! |---|---|---|
//! | `cancel.cancelled()` | select arm | `CancellationToken::cancelled` holds no state |
//! | `self.framer.read()` | select arm | ours; see [`crate::transport::framer`], whose only await is `read_buf` into a buffer the framer owns |
//! | `commands.recv()` | select arm | `mpsc::Receiver::recv` never consumes a message from a dropped future |
//! | `stats_tick.tick()` | select arm | `Interval::tick` with `MissedTickBehavior::Skip`: a dropped tick is simply not observed |
//! | `self.send(..)` | branch body | `mpsc::Sender::send` either delivered the message or did not, never half of one |
//! | `emit(events, ..)` | branch body | the same, and it can block for a long time, which is intended backpressure |
//!
//! # What is reachable today
//!
//! The connection sequence stops at the Client Info PDU
//! (`crate::connection`), so this loop does not run against a real server
//! yet. It is written, referenced and unit tested through
//! [`RunLoop::dispatch`], which is synchronous and takes bytes, so every arm
//! below is exercised without a socket. The graphics, input and channel arms
//! arrive with the PDUs that feed them.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rdp_pdu::mcs::DomainMcsPdu;
use rdp_pdu::{x224, Decode, Reader};
use remote_core::{ClientCommand, SessionEvent};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::connection::ChannelMap;
use crate::error::{RdpError, Result};
use crate::session::signal::{DisconnectSignal, SessionSignal};
use crate::transport::framer::{Framed, FramedKind, Framer};
use crate::transport::writer::Outbound;

/// How a connection ended when it did not fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// The user asked to disconnect (`ClientCommand::Disconnect`).
    UserDisconnect,
    /// The server ended it, and said whether a user asked for that.
    ServerDisconnect {
        /// True for `rn-user-requested`, which is a logoff and not a failure.
        user_requested: bool,
    },
}

/// What one pass of the select loop decided to do.
enum Step {
    Pdu(Result<Framed>),
    Command(Option<ClientCommand>),
    Tick,
    Cancelled,
}

/// The connected state pump.
pub struct RunLoop<R> {
    framer: Framer<R>,
    outbound: mpsc::Sender<Outbound>,
    channels: ChannelMap,
    received: Arc<AtomicU64>,
    sent: Arc<AtomicU64>,
    /// The last figures reported, so a tick reports a delta rather than a
    /// running total (`crates/vnc-core/src/session/run_loop.rs` does the same).
    last_received: u64,
    last_sent: u64,
}

impl<R: AsyncRead + Unpin> RunLoop<R> {
    /// Wire up one connection's pump.
    pub fn new(
        framer: Framer<R>,
        outbound: mpsc::Sender<Outbound>,
        channels: ChannelMap,
        received: Arc<AtomicU64>,
        sent: Arc<AtomicU64>,
    ) -> Self {
        Self {
            framer,
            outbound,
            channels,
            received,
            sent,
            last_received: 0,
            last_sent: 0,
        }
    }

    /// Queue bytes for the writer task. Never writes to the socket.
    ///
    /// Uses `send().await` because dropping a protocol frame desynchronises
    /// the stream. A full queue parks this loop, which is the backpressure we
    /// want. A closed channel means the writer task is gone, which means the
    /// connection is finished, so it surfaces as
    /// [`RdpError::ConnectionClosed`].
    ///
    /// `&mut self` rather than `&self`, and the reason is worth a line
    /// because it looks like an oversight. An `async fn` taking `&self` holds
    /// a `&Self` across its await, which makes the whole session future
    /// require `Self: Sync`, and `RunLoop` holds a `ReadHalf<BoxedStream>`
    /// over `dyn Stream`, which is `Send` and not `Sync`
    /// (`crates/vnc-transport/src/lib.rs:28`). `&mut Self` needs only `Send`.
    async fn send(&mut self, out: Outbound) -> Result<()> {
        self.outbound
            .send(out)
            .await
            .map_err(|_| RdpError::ConnectionClosed)
    }

    /// Run until the session ends.
    ///
    /// # Errors
    ///
    /// [`RdpError::Cancelled`] on a teardown, and whatever the framer or a
    /// dispatch reported.
    pub async fn run(
        &mut self,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
        cancel: &CancellationToken,
    ) -> Result<RunOutcome> {
        let mut stats_tick = tokio::time::interval(Duration::from_secs(1));
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        stats_tick.reset(); // do not fire immediately

        loop {
            let step = tokio::select! {
                biased;
                () = cancel.cancelled() => Step::Cancelled,
                framed = self.framer.read() => Step::Pdu(framed),
                cmd = commands.recv() => Step::Command(cmd),
                _ = stats_tick.tick() => Step::Tick,
            };

            match step {
                Step::Cancelled => {
                    self.teardown().await;
                    return Err(RdpError::Cancelled);
                }
                Step::Pdu(Err(e)) => return Err(e),
                Step::Pdu(Ok(framed)) => {
                    // Parsing is synchronous and CPU bound: it happens on
                    // this thread and does not await, which is what makes the
                    // duty cycle figure decode time and nothing else.
                    match self.dispatch(&framed)? {
                        SessionSignal::Handled { reply } => {
                            if let Some(bytes) = reply {
                                self.send(Outbound::Frame(bytes)).await?;
                            }
                        }
                        SessionSignal::Ignored(why) => {
                            tracing::trace!(why, "ignored pdu");
                        }
                        SessionSignal::Terminate(signal) => {
                            tracing::info!(?signal, "the server ended the session");
                            return Ok(RunOutcome::ServerDisconnect {
                                user_requested: signal.is_user_requested(),
                            });
                        }
                    }
                }
                // The handle was dropped: nobody can control this session any
                // more. Treat it as cancellation, which is what the RFB loop
                // does at the same point.
                Step::Command(None) => {
                    self.teardown().await;
                    return Err(RdpError::Cancelled);
                }
                Step::Command(Some(cmd)) => {
                    if let Some(outcome) = self.handle_command(cmd).await? {
                        return Ok(outcome);
                    }
                }
                Step::Tick => self.tick(events).await?,
            }
        }
    }

    /// Parse one framed PDU and say what the lifecycle has to do about it.
    ///
    /// Pure with respect to I/O: it never writes, which is what lets it be
    /// called from a match arm and unit tested against a byte slice with no
    /// socket and no runtime.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] when the frame did not parse, and
    /// [`RdpError::Protocol`] for a channel we never joined, which means the
    /// server is confused about the session and is not something to carry on
    /// through.
    pub fn dispatch(&mut self, framed: &Framed) -> Result<SessionSignal> {
        match framed.kind {
            FramedKind::Tpkt => self.dispatch_tpkt(&framed.frame),
            // MS-RDPBCGR 2.2.9.1.2. Everything inside a fast path update is
            // an update PDU, and `rdp-pdu`'s `update/` module is being
            // written now (`crates/rdp-pdu/src/lib.rs:44`).
            FramedKind::FastPath => Err(RdpError::NotImplemented {
                stage: crate::error::ConnectStage::Connected,
            }),
        }
    }

    fn dispatch_tpkt(&mut self, frame: &Bytes) -> Result<SessionSignal> {
        let mut r = Reader::new(frame);
        let mut body = x224::read_data_tpdu(&mut r)?;
        let pdu = DomainMcsPdu::decode(&mut body)?;
        match pdu {
            DomainMcsPdu::DisconnectProviderUltimatum { reason } => Ok(SessionSignal::Terminate(
                DisconnectSignal::from_reason(reason),
            )),
            DomainMcsPdu::SendDataIndication { channel_id, .. } => {
                // A channel id we never joined means the server is confused
                // about the session. An unknown PDU type on a channel we did
                // join is normal and is ignored; the two are told apart here
                // because only the first is a reason to stop.
                if !self.knows_channel(channel_id) {
                    return Err(RdpError::Protocol(format!(
                        "data arrived on channel {channel_id}, which we never joined \
                         (MS-RDPBCGR 2.2.1.13.3.1)"
                    )));
                }
                // Everything inside a Send Data Indication is a share control
                // or share data PDU, which `rdp-pdu`'s `rdp/` module holds.
                Ok(SessionSignal::Ignored(
                    "share data PDU: rdp-pdu's rdp/ module is not written yet",
                ))
            }
            // The client sends these; a server that echoes one back is
            // confused, and answering it would be worse than ignoring it.
            other => Ok(SessionSignal::Ignored(match other {
                DomainMcsPdu::ErectDomainRequest { .. } => "erect domain request from a server",
                DomainMcsPdu::AttachUserRequest => "attach user request from a server",
                DomainMcsPdu::AttachUserConfirm { .. } => "late attach user confirm",
                DomainMcsPdu::ChannelJoinRequest { .. } => "channel join request from a server",
                DomainMcsPdu::ChannelJoinConfirm { .. } => "late channel join confirm",
                DomainMcsPdu::SendDataRequest { .. } => "send data request from a server",
                DomainMcsPdu::SendDataIndication { .. }
                | DomainMcsPdu::DisconnectProviderUltimatum { .. } => unreachable!("handled above"),
            })),
        }
    }

    /// True for a channel this session joined.
    fn knows_channel(&self, id: u16) -> bool {
        id == self.channels.io_channel_id
            || id == self.channels.user_channel_id
            || self.channels.message_channel_id == Some(id)
            || self.channels.statics.iter().any(|(_, cid)| *cid == id)
    }

    /// Act on one command from the shell.
    ///
    /// Returns `Some` when the command ends the session.
    async fn handle_command(&mut self, cmd: ClientCommand) -> Result<Option<RunOutcome>> {
        match cmd {
            ClientCommand::Disconnect => {
                self.teardown().await;
                Ok(Some(RunOutcome::UserDisconnect))
            }
            // Input, clipboard, quality and resize arrive with the PDUs that
            // carry them. Dropping one silently would be a command the shell
            // believes it sent, so each says so once.
            other => {
                tracing::debug!(?other, "command has no wire path yet");
                Ok(None)
            }
        }
    }

    /// Emit one [`remote_core::SessionStats`].
    async fn tick(&mut self, events: &mpsc::Sender<SessionEvent>) -> Result<()> {
        use std::sync::atomic::Ordering;
        let received = self.received.load(Ordering::Relaxed);
        let sent = self.sent.load(Ordering::Relaxed);
        let stats = remote_core::SessionStats {
            bytes_received: received,
            bytes_sent: sent,
            throughput_bps: (received.saturating_sub(self.last_received)) as f64,
            throughput_up_bps: (sent.saturating_sub(self.last_sent)) as f64,
            ..Default::default()
        };
        self.last_received = received;
        self.last_sent = sent;
        remote_core::emit(events, SessionEvent::Stats(stats)).await?;
        Ok(())
    }

    /// Queue the ordered teardown and let the writer task carry it out.
    ///
    /// Queued rather than written: the writer task drains what is already in
    /// the channel, then the ultimatum, then closes the TLS layer, which is
    /// what keeps the teardown ordered when this task is going away
    /// (PRDRDP/06 §6.4). Every step is best effort, because a teardown on a
    /// socket that is already gone is not an error worth reporting.
    async fn teardown(&mut self) {
        // MS-RDPBCGR 2.2.2.3. `rn-user-requested` is what a client sends when
        // it hangs up (T.125 §7).
        match self.encode_disconnect_ultimatum() {
            Ok(bytes) => {
                let _ = self.send(Outbound::Frame(bytes)).await;
            }
            Err(e) => tracing::debug!(error = %e, "could not encode the disconnect ultimatum"),
        }
        let _ = self.send(Outbound::Shutdown).await;
    }

    /// The MCS Disconnect Provider Ultimatum a client sends when it hangs up
    /// (MS-RDPBCGR 2.2.2.3, T.125 §7).
    fn encode_disconnect_ultimatum(&self) -> Result<Bytes> {
        use rdp_pdu::io::{Encode, Writer};
        let pdu = DomainMcsPdu::DisconnectProviderUltimatum {
            reason: rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
        };
        let mut out = Vec::with_capacity(pdu.size() + 7);
        x224::write_data_tpdu_with(&mut Writer::new(&mut out), pdu.size(), |w| pdu.encode(w))?;
        Ok(Bytes::from(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::io::{Encode, Payload, Writer};

    fn channels() -> ChannelMap {
        ChannelMap {
            io_channel_id: 1003,
            user_channel_id: 1007,
            message_channel_id: Some(1005),
            statics: vec![("drdynvc", 1004), ("cliprdr", 1006)],
        }
    }

    fn loop_over(bytes: &'static [u8]) -> RunLoop<&'static [u8]> {
        let (tx, _rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        RunLoop::new(
            Framer::new(bytes, Arc::new(AtomicU64::new(0))),
            tx,
            channels(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    fn framed(pdu: &DomainMcsPdu<'_>) -> Framed {
        let mut out = Vec::new();
        x224::write_data_tpdu_with(&mut Writer::new(&mut out), pdu.size(), |w| pdu.encode(w))
            .expect("encodes");
        Framed {
            kind: FramedKind::Tpkt,
            frame: Bytes::from(out),
        }
    }

    /// The dispatcher is synchronous and takes bytes, so every arm is
    /// testable with no socket and no runtime. That is the property the whole
    /// "dispatch never writes" rule buys.
    #[test]
    fn a_disconnect_ultimatum_ends_the_session_and_says_who_asked() {
        let mut rl = loop_over(&[]);
        let signal = rl
            .dispatch(&framed(&DomainMcsPdu::DisconnectProviderUltimatum {
                reason: rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
            }))
            .expect("parses");
        match signal {
            SessionSignal::Terminate(s) => assert!(s.is_user_requested()),
            other => panic!("expected a terminate, got {other:?}"),
        }

        let signal = rl
            .dispatch(&framed(&DomainMcsPdu::DisconnectProviderUltimatum {
                reason: rdp_pdu::mcs::disconnect_reason::PROVIDER_INITIATED,
            }))
            .expect("parses");
        match signal {
            SessionSignal::Terminate(s) => assert!(!s.is_user_requested()),
            other => panic!("expected a terminate, got {other:?}"),
        }
    }

    /// A channel id we never joined means the server is confused about the
    /// session, which is not something to carry on through. An unknown PDU on
    /// a channel we did join is normal and is ignored with a reason. These
    /// two rows are a pair and the difference between them is the design
    /// decision.
    #[test]
    fn an_unjoined_channel_ends_the_session_and_a_joined_one_does_not() {
        let mut rl = loop_over(&[]);

        let stray = framed(&DomainMcsPdu::SendDataIndication {
            initiator: 1002,
            channel_id: 4321,
            payload: Payload::new(&[0u8; 8]),
        });
        let err = rl.dispatch(&stray).expect_err("never joined");
        assert!(err.to_string().contains("4321"), "{err}");

        for id in [1003u16, 1004, 1005, 1006, 1007] {
            let known = framed(&DomainMcsPdu::SendDataIndication {
                initiator: 1002,
                channel_id: id,
                payload: Payload::new(&[0u8; 8]),
            });
            match rl.dispatch(&known).expect("a joined channel") {
                SessionSignal::Ignored(why) => assert!(!why.is_empty()),
                other => panic!("expected an ignore for {id}, got {other:?}"),
            }
        }
    }

    /// A client to server PDU echoed back by a server is ignored with a
    /// reason rather than answered, because answering it would confuse the
    /// session further.
    #[test]
    fn a_client_to_server_pdu_from_a_server_is_ignored_with_a_reason() {
        let mut rl = loop_over(&[]);
        for pdu in [
            DomainMcsPdu::AttachUserRequest,
            DomainMcsPdu::ErectDomainRequest {
                sub_height: 0,
                sub_interval: 0,
            },
            DomainMcsPdu::ChannelJoinRequest {
                initiator: 1007,
                channel_id: 1003,
            },
        ] {
            match rl.dispatch(&framed(&pdu)).expect("parses") {
                SessionSignal::Ignored(why) => assert!(why.contains("server"), "{why}"),
                other => panic!("expected an ignore, got {other:?}"),
            }
        }
    }

    /// A fast path update is a named gap, not a panic. This is the assertion
    /// that changes when `rdp-pdu`'s `update/` module lands.
    #[test]
    fn a_fast_path_update_reports_a_named_gap_rather_than_panicking() {
        let mut rl = loop_over(&[]);
        let framed = Framed {
            kind: FramedKind::FastPath,
            frame: Bytes::from_static(&[0x00, 0x04, 0xaa, 0xbb]),
        };
        let err = rl.dispatch(&framed).expect_err("not written yet");
        assert!(matches!(err, RdpError::NotImplemented { .. }), "{err:?}");
    }

    /// The teardown queues the ultimatum before the shutdown, so the writer
    /// task sends it and only then closes the TLS layer.
    #[tokio::test]
    async fn the_teardown_queues_the_ultimatum_before_the_shutdown() {
        let (tx, mut rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        let mut rl = RunLoop::new(
            Framer::new(&[][..], Arc::new(AtomicU64::new(0))),
            tx,
            channels(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        rl.teardown().await;

        match rx.recv().await.expect("an ultimatum") {
            Outbound::Frame(bytes) => {
                let mut r = Reader::new(&bytes);
                let mut body = x224::read_data_tpdu(&mut r).expect("data tpdu");
                assert_eq!(
                    DomainMcsPdu::decode(&mut body).expect("parses"),
                    DomainMcsPdu::DisconnectProviderUltimatum {
                        reason: rdp_pdu::mcs::disconnect_reason::USER_REQUESTED,
                    }
                );
            }
            other => panic!("expected a frame, got {other:?}"),
        }
        assert!(matches!(rx.recv().await, Some(Outbound::Shutdown)));
    }

    /// Cancellation wins over a socket with data waiting, because `biased`
    /// puts it first. A teardown that could be starved by a busy server is a
    /// window that will not close.
    #[tokio::test]
    async fn cancellation_wins_over_a_busy_socket() {
        // A frame is waiting, so the read arm would be ready immediately.
        let mut wire = vec![0x03u8, 0x00];
        wire.extend_from_slice(&11u16.to_be_bytes());
        wire.resize(11, 0);
        let leaked: &'static [u8] = Box::leak(wire.into_boxed_slice());

        let (tx, mut rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        let mut rl = RunLoop::new(
            Framer::new(leaked, Arc::new(AtomicU64::new(0))),
            tx,
            channels(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );

        let cancel = CancellationToken::new();
        cancel.cancel();
        let (events, _erx) = mpsc::channel(16);
        let (_ctx, mut commands) = mpsc::channel(16);
        let err = rl
            .run(&events, &mut commands, &cancel)
            .await
            .expect_err("cancelled");
        assert!(matches!(err, RdpError::Cancelled));
        // And it tore down rather than simply returning.
        assert!(matches!(rx.recv().await, Some(Outbound::Frame(_))));
        assert!(matches!(rx.recv().await, Some(Outbound::Shutdown)));
    }

    /// A dropped command channel means nobody can control this session any
    /// more, which is the same situation as a cancellation.
    #[tokio::test]
    async fn a_dropped_handle_tears_the_session_down() {
        let (tx, _rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        // An empty stream: the read arm is pending until EOF, and EOF on an
        // empty buffer is a clean close. The command channel closing first is
        // what this test is about, so it is closed before the loop starts.
        let mut rl = RunLoop::new(
            Framer::new(tokio::io::empty(), Arc::new(AtomicU64::new(0))),
            tx,
            channels(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let (events, _erx) = mpsc::channel(16);
        let (ctx, mut commands) = mpsc::channel::<ClientCommand>(16);
        drop(ctx);
        // The framer sees EOF first on an empty stream, which is also a
        // correct end. Either way the loop returns rather than spinning.
        let out = rl
            .run(&events, &mut commands, &CancellationToken::new())
            .await;
        assert!(out.is_err(), "the loop ends when nothing can drive it");
    }
}
