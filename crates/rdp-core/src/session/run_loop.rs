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
//! Decoding is on this task and does not await, which is what makes the duty
//! cycle figure decode time and nothing else (PRDRDP/04 §10.2).

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rdp_pdu::mcs::DomainMcsPdu;
use rdp_pdu::rdp::{decode_io_pdu, IoPdu, IoPduContext, ShareDataPdu, SharePdu, SlowPathClass};
use rdp_pdu::update::fastpath::{FastPathReassembler, FastPathUpdate, FastPathUpdatePdu};
use rdp_pdu::update::slowpath::{GraphicsUpdate, PointerPdu};
use rdp_pdu::{x224, Decode, Reader};
use remote_core::{ClientCommand, DecodedRect, ProtocolEvent, RdpEvent, SessionEvent};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::channels::{ChannelCtx, Outbox, StaticChannels};
use crate::connection::activate::{self, Activated};
use crate::connection::ChannelMap;
use crate::error::{RdpError, Result};
use crate::options::ResolvedOptions;
use crate::session::graphics::Graphics;
use crate::session::input::{self, Input};
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
    /// The static virtual channels and everything under them: drdynvc, the
    /// graphics pipeline and the clipboard (`crate::channels`).
    ///
    /// The pump knows two things about this field. Data that is not on the
    /// I/O channel goes into it, and a clipboard command goes into it. Adding
    /// a channel does not change this file, which is the whole point of the
    /// registry.
    vc: StaticChannels,
    /// Events the shell had not drained at the last dispatch.
    ///
    /// Read off the event channel once per pass rather than per PDU, and
    /// handed to the channel handlers so the EGFX frame acknowledgement can
    /// report a real `queueDepth` (MS-RDPEGFX 2.2.2.13). See
    /// [`crate::channels::egfx::Egfx::frame_acknowledge`].
    event_backlog: u32,
    /// The options, kept because a Deactivate All can restart the capability
    /// exchange from inside this loop and the Confirm Active is built from
    /// them (MS-RDPBCGR 1.3.1.3, PRDRDP/06 §6.1).
    opts: ResolvedOptions,
    /// What the capability exchange settled, replaced on a reactivation.
    activated: Activated,
    /// The bitmap and pointer decoders, and the palette and cursor cache they
    /// carry between updates.
    graphics: Graphics,
    /// The keyboard and pointer state the input path needs between commands.
    input: Input,
    /// Fast path fragment reassembly (MS-RDPBCGR 2.2.9.1.2.1). The only piece
    /// of cross PDU state `rdp-pdu` owns, driven from here.
    reassembler: FastPathReassembler,
    /// The last `ERRINFO` the server latched, so the disconnect reports why
    /// rather than reporting a bare close (MS-RDPBCGR 2.2.5.1.1).
    error_info: Option<RdpError>,
    received: Arc<AtomicU64>,
    sent: Arc<AtomicU64>,
    /// The last figures reported, so a tick reports a delta rather than a
    /// running total (`crates/vnc-core/src/session/run_loop.rs` does the same).
    last_received: u64,
    last_sent: u64,
}

impl<R: AsyncRead + Unpin> RunLoop<R> {
    /// Wire up one connection's pump.
    ///
    /// Eight arguments and not a struct, because every one of them is produced
    /// exactly once by [`crate::session::connect::run_once`] and a builder
    /// would be a second place for one to go missing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        framer: Framer<R>,
        outbound: mpsc::Sender<Outbound>,
        channels: ChannelMap,
        opts: ResolvedOptions,
        activated: Activated,
        view_only: bool,
        received: Arc<AtomicU64>,
        sent: Arc<AtomicU64>,
    ) -> Self {
        Self {
            vc: StaticChannels::new(&channels),
            event_backlog: 0,
            framer,
            outbound,
            channels,
            graphics: Graphics::new(activated.desktop),
            input: Input::new(activated.desktop, activated.server_input_flags, view_only),
            reassembler: FastPathReassembler::new(),
            error_info: None,
            opts,
            activated,
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
    /// `pending` is whatever the connection sequence read ahead of itself: a
    /// server is allowed to start drawing before the Font Map arrives, and
    /// those updates belong here rather than in the bin.
    ///
    /// # Errors
    ///
    /// [`RdpError::Cancelled`] on a teardown, and whatever the framer or a
    /// dispatch reported.
    pub async fn run(
        &mut self,
        pending: Vec<Framed>,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
        cancel: &CancellationToken,
    ) -> Result<RunOutcome> {
        for framed in pending {
            let signal = self.dispatch(&framed)?;
            self.act(signal, events).await?;
        }

        let mut stats_tick = tokio::time::interval(Duration::from_secs(1));
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        stats_tick.reset(); // do not fire immediately

        loop {
            // Sampled once per pass rather than per PDU: it is the only
            // observable measure of how far behind the renderer is, and it is
            // what the graphics channel reports back as `queueDepth`.
            self.event_backlog = backlog(events);

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
                Step::Pdu(Err(e)) => return Err(self.explain(e)),
                Step::Pdu(Ok(framed)) => {
                    // Parsing and decoding are synchronous and CPU bound: they
                    // happen on this thread and do not await, which is what
                    // makes the duty cycle figure decode time and nothing
                    // else.
                    let signal = match self.dispatch(&framed) {
                        Ok(signal) => signal,
                        Err(e) => return Err(self.explain(e)),
                    };
                    if let Some(outcome) = self.act(signal, events).await? {
                        return Ok(outcome);
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

    /// Carry out one signal. Returns `Some` when the session ended.
    async fn act(
        &mut self,
        signal: SessionSignal,
        events: &mpsc::Sender<SessionEvent>,
    ) -> Result<Option<RunOutcome>> {
        match signal {
            SessionSignal::Handled { reply } => {
                if let Some(bytes) = reply {
                    self.send(Outbound::Frame(bytes)).await?;
                }
            }
            SessionSignal::Output {
                events: produced,
                reply,
            } => {
                // The reply goes first: a Confirm Active the server is waiting
                // for must not sit behind a slow webview draining the event
                // channel.
                if let Some(bytes) = reply {
                    self.send(Outbound::Frame(bytes)).await?;
                }
                for event in produced {
                    remote_core::emit(events, event).await?;
                }
            }
            SessionSignal::Channel {
                events: produced,
                frames,
            } => {
                // Same ordering rule as `Output`: what the server is waiting
                // for goes out before a slow webview gets a say. A cliprdr
                // format list response that sits behind the renderer hangs
                // copy and paste on the server for every application
                // (MS-RDPECLIP 3.1.5.2.4).
                for bytes in frames {
                    self.send(Outbound::Frame(bytes)).await?;
                }
                for event in produced {
                    remote_core::emit(events, event).await?;
                }
            }
            SessionSignal::Ignored(why) => {
                tracing::trace!(why, "ignored pdu");
            }
            SessionSignal::Terminate(signal) => {
                tracing::info!(?signal, "the server ended the session");
                // A latched `ERRINFO` is why the session ended, and it says
                // more than "the server ended it" (MS-RDPBCGR 2.2.5.1.1).
                if let Some(e) = self.error_info.take() {
                    return Err(e);
                }
                return Ok(Some(RunOutcome::ServerDisconnect {
                    user_requested: signal.is_user_requested(),
                }));
            }
        }
        Ok(None)
    }

    /// Replace a bare close with the reason the server already gave.
    ///
    /// MS-RDPBCGR 1.3.1.4.2 makes every closing PDU optional, so a server that
    /// sent a Set Error Info PDU and then hung up has told us why and we would
    /// otherwise report "connection closed by peer".
    fn explain(&mut self, e: RdpError) -> RdpError {
        match e {
            RdpError::ConnectionClosed | RdpError::Io(_) => self.error_info.take().unwrap_or(e),
            other => other,
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
            FramedKind::FastPath => self.dispatch_fastpath(&framed.frame),
        }
    }

    /// One Server Fast-Path Update PDU (MS-RDPBCGR 2.2.9.1.2).
    ///
    /// Most of a live session's bytes arrive here. One PDU carries a sequence
    /// of records, each with its own update code and its own fragmentation
    /// state, so the records are walked in place and pushed through the
    /// reassembler one at a time.
    fn dispatch_fastpath(&mut self, frame: &Bytes) -> Result<SessionSignal> {
        let pdu = FastPathUpdatePdu::decode(&mut Reader::new(frame))?;
        let mut rects: Vec<DecodedRect> = Vec::new();
        let mut events: Vec<SessionEvent> = Vec::new();

        for item in pdu.updates() {
            let update = item?;
            // Phase 1 advertises no bulk compression at all (PRDRDP/04 §4.13),
            // so this bit must never arrive. A server that compresses without
            // being asked produces garbage pixels rather than an obvious
            // failure, which is why this is an error and not a pass through.
            update.header.ensure_uncompressed()?;

            // Two disjoint field borrows: the reassembler hands out a view of
            // its own buffer and the decoders write through the other. Taking
            // them separately is what lets a `FASTPATH_FRAGMENT_LAST` be
            // decoded without copying the reassembled bytes first.
            let reassembler = &mut self.reassembler;
            let graphics = &mut self.graphics;
            let Some(complete) = reassembler.push(update.header, update.data.as_slice())? else {
                continue;
            };
            match FastPathUpdate::decode_body(complete.update_code, complete.data)? {
                FastPathUpdate::Graphics(update) => {
                    route_graphics(graphics, &update, &mut rects)?;
                }
                FastPathUpdate::Pointer(update) => {
                    if let Some(event) = graphics.pointer(&update)? {
                        // A cursor is not a frame: flushing the rectangles
                        // collected so far keeps the order the server chose,
                        // which is what makes a shape change land on the frame
                        // it belongs to.
                        flush(&mut rects, &mut events);
                        events.push(event);
                    }
                }
                FastPathUpdate::SurfaceCommands(_) => {
                    // We do not advertise the Surface Commands capability set
                    // (`crate::connection::activate::client_capabilities`
                    // removes it), so a server that sends one is drawing into
                    // a surface we never agreed to have.
                    return Err(RdpError::Protocol(
                        "the server sent a surface command after this client removed the \
                         Surface Commands capability set (MS-RDPBCGR 2.2.9.2, PRDRDP/04 §2.8)"
                            .to_owned(),
                    ));
                }
            }
        }
        flush(&mut rects, &mut events);
        Ok(SessionSignal::Output {
            events,
            reply: None,
        })
    }

    fn dispatch_tpkt(&mut self, frame: &Bytes) -> Result<SessionSignal> {
        let mut r = Reader::new(frame);
        let mut body = x224::read_data_tpdu(&mut r)?;
        let pdu = DomainMcsPdu::decode(&mut body)?;
        match pdu {
            DomainMcsPdu::DisconnectProviderUltimatum { reason } => Ok(SessionSignal::Terminate(
                DisconnectSignal::from_reason(reason),
            )),
            DomainMcsPdu::SendDataIndication {
                channel_id,
                payload,
                ..
            } => {
                // A channel id we never joined means the server is confused
                // about the session. An unknown PDU type on a channel we did
                // join is normal and is ignored; the two are told apart here
                // because only the first is a reason to stop.
                if !self.channels.knows(channel_id) {
                    return Err(RdpError::Protocol(format!(
                        "data arrived on channel {channel_id}, which we never joined \
                         (MS-RDPBCGR 2.2.1.13.3.1)"
                    )));
                }
                if channel_id != self.channels.io_channel_id {
                    if self.vc.handles(channel_id) {
                        let ctx = self.channel_ctx();
                        let mut out = Outbox::new();
                        self.vc
                            .deliver(channel_id, payload.as_slice(), ctx, &mut out)?;
                        return Ok(SessionSignal::Channel {
                            events: out.events,
                            frames: out.frames,
                        });
                    }
                    // What is left is the message channel, which carries
                    // connect time auto detect and the heartbeat. Neither is
                    // acted on, and both are length prefixed, so skipping
                    // cannot desync (MS-RDPBCGR 2.2.1.4.5, PRDRDP/05 §5.1).
                    return Ok(SessionSignal::Ignored(
                        "a pdu on the message channel, which this build does not act on",
                    ));
                }
                self.dispatch_io(payload.as_slice())
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

    /// One slow path PDU off the I/O channel.
    ///
    /// The class is [`SlowPathClass::Other`] and never anything else: after
    /// the Font Map the I/O channel carries Share Control PDUs and nothing
    /// with a security header, which is the second half of the rule
    /// [`crate::connection::activate`] documents.
    fn dispatch_io(&mut self, payload: &[u8]) -> Result<SessionSignal> {
        let mut r = Reader::new(payload);
        let IoPdu::Share(share) = decode_io_pdu(
            &mut r,
            IoPduContext::external_security(),
            SlowPathClass::Other,
        )?
        else {
            return Ok(SessionSignal::Ignored("a non share pdu on the I/O channel"));
        };

        let mut events: Vec<SessionEvent> = Vec::new();
        let mut reply = None;
        match share.as_ref() {
            SharePdu::FlowControl => {
                return Ok(SessionSignal::Ignored("a flow control pdu"));
            }
            // MS-RDPBCGR 1.3.1.3 lets a server restart the capability exchange
            // at any time, typically after a resolution change on its side.
            // The connect path and this loop answer it with the same bytes,
            // which is why `activation_reply` is where it is (PRDRDP/06 §6.1).
            SharePdu::DemandActive { pdu_source, pdu } => {
                let settled = activate::activated_from(pdu, *pdu_source, self.activated.desktop);
                tracing::info!(
                    share_id = settled.share_id,
                    width = settled.desktop.0,
                    height = settled.desktop.1,
                    "the server restarted the capability exchange"
                );
                reply = Some(activate::activation_reply(
                    &self.opts,
                    &self.channels,
                    &settled,
                )?);
                if settled.desktop != self.activated.desktop {
                    events.push(SessionEvent::DesktopResize {
                        width: settled.desktop.0,
                        height: settled.desktop.1,
                    });
                }
                self.graphics.reset(settled.desktop);
                self.input.set_desktop(settled.desktop);
                self.activated = settled;
            }
            SharePdu::DeactivateAll { .. } => {
                // The share is being torn down. A partial fragment sequence
                // belongs to the old share and must not be glued onto the new
                // one (MS-RDPBCGR 2.2.3.1), and the same is true one layer
                // out on every virtual channel (PRDRDP/05 §5.1 rule 6).
                self.reassembler.reset();
                self.vc.reset();
                tracing::info!("the server deactivated the share");
            }
            SharePdu::Data { pdu, .. } => {
                self.share_data(pdu, &mut events)?;
            }
            SharePdu::ConfirmActive { .. } | SharePdu::ServerRedirection { .. } => {
                return Ok(SessionSignal::Ignored(
                    "a confirm active or a server redirection, which this build does not act on",
                ));
            }
        }
        Ok(SessionSignal::Output { events, reply })
    }

    /// One Share Data PDU (MS-RDPBCGR 2.2.8.1.1.1.2).
    fn share_data(&mut self, pdu: &ShareDataPdu<'_>, events: &mut Vec<SessionEvent>) -> Result<()> {
        use rdp_pdu::rdp::share::pdu_type2;

        match pdu {
            ShareDataPdu::SetErrorInfo(info) => {
                // Latched rather than raised: the server sends this and then
                // the ultimatum, and the code is what the disconnect should
                // report (MS-RDPBCGR 2.2.5.1.1).
                if let Err(e) = activate::error_info(pdu) {
                    events.push(SessionEvent::Protocol(ProtocolEvent::Rdp(
                        RdpEvent::ErrorInfo {
                            code: info.error_info.to_u32(),
                            symbol: info.error_info.symbol().to_owned(),
                            message: info.error_info.describe().to_owned(),
                        },
                    )));
                    tracing::warn!(error = %e, "the server latched an error code");
                    self.error_info = Some(e);
                }
            }
            ShareDataPdu::SaveSessionInfo(info) => {
                if let Some((domain, username)) = info.logon_identity() {
                    events.push(SessionEvent::Protocol(ProtocolEvent::Rdp(
                        RdpEvent::LogonInfo {
                            domain: domain.to_owned(),
                            username: username.to_owned(),
                            session_id: session_id(info),
                        },
                    )));
                }
            }
            ShareDataPdu::Compressed(_) => {
                // Phase 1 advertises no bulk compression (PRDRDP/04 §4.13), so
                // a compressed body is a server compressing without being
                // asked, which produces garbage rather than an obvious
                // failure.
                return Err(RdpError::Protocol(
                    "the server compressed a share data pdu without being asked \
                     (MS-RDPBCGR 2.2.8.1.1.1.2)"
                        .to_owned(),
                ));
            }
            ShareDataPdu::Other { pdu_type2, body } => match *pdu_type2 {
                pdu_type2::UPDATE => {
                    let update = GraphicsUpdate::decode(&mut Reader::new(body.as_slice()))?;
                    let mut rects = Vec::new();
                    route_graphics(&mut self.graphics, &update, &mut rects)?;
                    flush(&mut rects, events);
                }
                pdu_type2::POINTER => {
                    let pointer = PointerPdu::decode(&mut Reader::new(body.as_slice()))?;
                    if let Some(event) = self.graphics.pointer(&pointer.update)? {
                        events.push(event);
                    }
                }
                other => {
                    tracing::trace!(pdu_type2 = other, "a share data pdu this build ignores");
                }
            },
            other => {
                tracing::trace!(
                    pdu_type2 = other.pdu_type2(),
                    "a share data pdu with nothing to do"
                );
            }
        }
        Ok(())
    }

    /// Act on one command from the shell.
    ///
    /// Returns `Some` when the command ends the session.
    async fn handle_command(&mut self, cmd: ClientCommand) -> Result<Option<RunOutcome>> {
        match cmd {
            ClientCommand::Disconnect => {
                // Every key the server believes is held would repeat into the
                // session forever, so they go out before the ultimatum
                // (PRDRDP/05 §2.11).
                let release = self.input.release_all();
                self.send_input(release).await?;
                self.teardown().await;
                Ok(Some(RunOutcome::UserDisconnect))
            }
            ClientCommand::Pointer { x, y, button_mask } => {
                let events = self.input.pointer(x, y, button_mask);
                self.send_input(events).await?;
                Ok(None)
            }
            ClientCommand::Key {
                keysym,
                keycode,
                down,
            } => {
                let events = self.input.key(keysym, keycode, down);
                self.send_input(events).await?;
                Ok(None)
            }
            ClientCommand::ReleaseAllKeys => {
                let events = self.input.release_all();
                self.send_input(events).await?;
                Ok(None)
            }
            ClientCommand::SetViewOnly(on) => {
                if on {
                    // Turning view only on with keys held would leave them
                    // held on the server with no way to release them.
                    let release = self.input.release_all();
                    self.send_input(release).await?;
                }
                self.input.set_view_only(on);
                Ok(None)
            }
            ClientCommand::Refresh => {
                let bytes = self.encode_refresh()?;
                self.send(Outbound::Frame(bytes)).await?;
                Ok(None)
            }
            ClientCommand::ClipboardText(text) => {
                let ctx = self.channel_ctx();
                let mut out = Outbox::new();
                self.vc.clipboard_text(&text, ctx, &mut out)?;
                self.flush_channel(out).await?;
                Ok(None)
            }
            // The format bits are ignored: this build offers and asks for
            // text and nothing else, which is what the RFB path supports too
            // (`crates/vnc-core/src/clipboard/mod.rs`).
            ClientCommand::ClipboardRequest { .. } => {
                let ctx = self.channel_ctx();
                let mut out = Outbox::new();
                self.vc.clipboard_request(ctx, &mut out)?;
                self.flush_channel(out).await?;
                Ok(None)
            }
            // Quality and resize arrive with the channels that carry them
            // (PRDRDP/05 §5.4). Dropping one silently would be a command the
            // shell believes it sent, so each says so once.
            other => {
                tracing::debug!(?other, "command has no wire path yet");
                Ok(None)
            }
        }
    }

    /// What a channel handler needs to answer one PDU.
    fn channel_ctx(&self) -> ChannelCtx {
        ChannelCtx {
            user_channel_id: self.channels.user_channel_id,
            desktop: self.activated.desktop,
            event_backlog: self.event_backlog,
        }
    }

    /// Queue everything a channel handler produced from a command.
    ///
    /// Only the frames: a command cannot produce an event, because nothing on
    /// the outbound side of a channel has news for the shell.
    async fn flush_channel(&mut self, out: Outbox) -> Result<()> {
        debug_assert!(out.events.is_empty(), "an outbound channel call emitted");
        for bytes in out.frames {
            self.send(Outbound::Frame(bytes)).await?;
        }
        Ok(())
    }

    /// Queue a batch of fast path input events, chunked so one PDU never
    /// carries more than the count field can hold (MS-RDPBCGR 2.2.8.1.2).
    async fn send_input(
        &mut self,
        events: Vec<rdp_pdu::input::fastpath::FastPathInputEvent>,
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        for chunk in events.chunks(input::MAX_EVENTS) {
            let bytes = input::encode(chunk)?;
            self.send(Outbound::Frame(bytes)).await?;
        }
        Ok(())
    }

    /// A Refresh Rect PDU over the whole desktop (MS-RDPBCGR 2.2.11.2).
    ///
    /// The RFB path's `Refresh` is a non incremental framebuffer update
    /// request, and this is the same idea: ask the server to resend everything
    /// it thinks is already on screen.
    fn encode_refresh(&self) -> Result<Bytes> {
        use rdp_pdu::io::{Encode, Writer};
        use rdp_pdu::rdp::control::{Rectangle16, RefreshRectPdu};

        let (w, h) = self.activated.desktop;
        let pdu = SharePdu::data(
            self.channels.user_channel_id,
            self.activated.share_id,
            ShareDataPdu::RefreshRect(RefreshRectPdu {
                areas: vec![Rectangle16 {
                    left: 0,
                    top: 0,
                    // `TS_RECTANGLE16` is inclusive on the right and bottom
                    // edges, like `TS_BITMAP_DATA` and unlike a surface
                    // command (MS-RDPBCGR 2.2.11.2.1).
                    right: w.saturating_sub(1),
                    bottom: h.saturating_sub(1),
                }],
            }),
        );
        let mut body = Vec::with_capacity(pdu.size());
        pdu.encode_checked(&mut Writer::new(&mut body))?;
        activate::send_data_request(
            self.channels.user_channel_id,
            self.channels.io_channel_id,
            &body,
        )
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

/// Events the shell has not taken off the channel yet.
///
/// `max_capacity` is the channel's size and `capacity` is how many slots are
/// free, so the difference is what is queued. tokio makes both cheap: they
/// are a load off the semaphore, not a lock (PRDRDP/04 §3.6).
///
/// This is the client's display backlog as well as anything can measure it,
/// and it is what the EGFX frame acknowledgement reports as `queueDepth`
/// (MS-RDPEGFX 2.2.2.13).
fn backlog(events: &mpsc::Sender<SessionEvent>) -> u32 {
    let queued = events.max_capacity().saturating_sub(events.capacity());
    u32::try_from(queued).unwrap_or(u32::MAX)
}

/// Turn the rectangles collected so far into one `FramebufferUpdate`.
///
/// The renderer presents once per event, so several bitmap records read out of
/// one fast path PDU become one event rather than one each (PRDRDP/04 §10.4).
fn flush(rects: &mut Vec<DecodedRect>, events: &mut Vec<SessionEvent>) {
    if rects.is_empty() {
        return;
    }
    events.push(crate::session::graphics::framebuffer_update(
        std::mem::take(rects),
    ));
}

/// One graphics update into rectangles, or into the palette.
fn route_graphics(
    graphics: &mut Graphics,
    update: &GraphicsUpdate<'_>,
    rects: &mut Vec<DecodedRect>,
) -> Result<()> {
    match update {
        GraphicsUpdate::Bitmap(bitmap) => {
            let (decoded, _damage) = graphics.bitmap_update(bitmap)?;
            rects.extend(decoded);
            Ok(())
        }
        GraphicsUpdate::Palette(palette) => {
            graphics.set_palette(palette);
            Ok(())
        }
        // A server sends one after a Deactivate All cycle and it means
        // nothing to a client that keeps no drawing state.
        GraphicsUpdate::Synchronize => Ok(()),
        // PRDRDP/04 §8.4: a server that sends drawing orders after being told
        // `orderSupport` is all zero is broken, and painting nothing while the
        // user watches a frozen screen is worse than saying so.
        GraphicsUpdate::Orders(_) => Err(RdpError::Protocol(
            "the server sent GDI drawing orders, which this client told it were not supported \
             (MS-RDPBCGR 2.2.7.1.3, PRDRDP/04 §8.4)"
                .to_owned(),
        )),
    }
}

/// The Terminal Services session id a Save Session Info PDU reported, or zero.
fn session_id(info: &rdp_pdu::rdp::SaveSessionInfoPdu) -> u32 {
    use rdp_pdu::rdp::SaveSessionInfoPdu as S;
    match info {
        S::Logon(info) => info.session_id,
        S::LogonLong(info) => info.session_id,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::io::{Encode, Payload, Writer};
    use rdp_pdu::update::fastpath::{
        encode_fastpath_update, update_code, FpUpdate, FpUpdateHeader,
    };
    use rdp_pdu::update::{BitmapData, BitmapUpdate, RectInclusive};
    use remote_core::{ConnectOptions, RectPayload};

    fn channels() -> ChannelMap {
        ChannelMap {
            io_channel_id: 1003,
            user_channel_id: 1007,
            message_channel_id: Some(1005),
            statics: vec![("drdynvc", 1004), ("cliprdr", 1006)],
        }
    }

    fn options() -> ResolvedOptions {
        let c = ConnectOptions::rdp("host.example", 3389);
        let rdp = c.rdp_options().expect("rdp").clone();
        ResolvedOptions::resolve(&c, &rdp, &mut Vec::new()).expect("valid")
    }

    fn activated() -> Activated {
        Activated {
            share_id: 0x0010_3ea9,
            server_pdu_source: 0x03ea,
            desktop: (64, 64),
            server_input_flags: rdp_pdu::rdp::capabilities::input_flags::MOUSEX
                | rdp_pdu::rdp::capabilities::input_flags::MOUSE_HWHEEL,
        }
    }

    fn loop_with<R: AsyncRead + Unpin>(reader: R, tx: mpsc::Sender<Outbound>) -> RunLoop<R> {
        RunLoop::new(
            Framer::new(reader, Arc::new(AtomicU64::new(0))),
            tx,
            channels(),
            options(),
            activated(),
            false,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    fn loop_over(bytes: &'static [u8]) -> RunLoop<&'static [u8]> {
        let (tx, _rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        loop_with(bytes, tx)
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

    /// Wrap an encoded share PDU the way a server does: an MCS Send Data
    /// Indication on the I/O channel inside an X.224 Data TPDU.
    fn from_server(share: &SharePdu<'_>) -> Framed {
        let mut body = Vec::new();
        share
            .encode_checked(&mut Writer::new(&mut body))
            .expect("encodes");
        framed(&DomainMcsPdu::SendDataIndication {
            initiator: 0x03ea,
            channel_id: 1003,
            payload: Payload::new(&body),
        })
    }

    /// Two rows of two pixels at 24 bits per pixel, bottom row first, which is
    /// what a DIB body is. Red on top and blue underneath, so a flip is
    /// visible.
    static BITMAP_24: &[u8] = &[
        0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, // bottom: blue
        0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, // top: red
    ];

    fn bitmap_update() -> BitmapUpdate<'static> {
        BitmapUpdate {
            rectangles: vec![BitmapData {
                dest: RectInclusive {
                    left: 2,
                    top: 4,
                    right: 3,
                    bottom: 5,
                },
                width: 2,
                height: 2,
                bits_per_pixel: 24,
                flags: 0,
                compression_header: None,
                data: Payload::new(BITMAP_24),
            }],
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

    /// Three rows, and the difference between them is the design.
    ///
    /// A channel id we never joined means the server is confused about the
    /// session and is not something to carry on through. A joined channel
    /// with a handler reaches [`crate::channels`], which is what a virtual
    /// channel PDU is now for. A joined channel with no handler, which is the
    /// message channel and the user channel, is still ignored with a reason.
    #[test]
    fn an_unjoined_channel_ends_the_session_and_a_joined_one_reaches_its_handler() {
        use rdp_pdu::io::Encode as _;
        use rdp_pdu::vc::static_vc::{channel_flags, ChannelPduHeader};

        let mut rl = loop_over(&[]);

        let stray = framed(&DomainMcsPdu::SendDataIndication {
            initiator: 1002,
            channel_id: 4321,
            payload: Payload::new(&[0u8; 8]),
        });
        let err = rl.dispatch(&stray).expect_err("never joined");
        assert!(err.to_string().contains("4321"), "{err}");

        // The message channel and the user channel have no handler, so they
        // are skipped with a reason. Both are length prefixed, so skipping
        // cannot desynchronise the stream.
        for id in [1005u16, 1007] {
            let known = framed(&DomainMcsPdu::SendDataIndication {
                initiator: 1002,
                channel_id: id,
                payload: Payload::new(&[0u8; 8]),
            });
            match rl.dispatch(&known).expect("a joined channel") {
                SessionSignal::Ignored(why) => assert!(why.contains("message channel")),
                other => panic!("expected an ignore for {id}, got {other:?}"),
            }
        }

        // `drdynvc` and `cliprdr` now go to their handlers. A chunk with no
        // `CHANNEL_FLAG_FIRST` is refused by the reassembler, which proves
        // the PDU reached the channel layer rather than the bin.
        let mut orphan = Vec::new();
        ChannelPduHeader {
            length: 16,
            flags: channel_flags::LAST,
        }
        .encode(&mut Writer::new(&mut orphan))
        .expect("encodes");
        orphan.extend_from_slice(&[0u8; 16]);
        for id in [1004u16, 1006] {
            let known = framed(&DomainMcsPdu::SendDataIndication {
                initiator: 1002,
                channel_id: id,
                payload: Payload::new(&orphan),
            });
            let err = rl.dispatch(&known).expect_err("no preceding first chunk");
            assert!(
                err.to_string().contains("CHANNEL_FLAG_FIRST"),
                "{id}: {err}"
            );
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

    /// The whole fast path graphics route, from the framing down to the
    /// pixels: a `TS_FP_UPDATE_PDU` carrying one bitmap record comes out as
    /// one `FramebufferUpdate` whose rectangle is where the server put it and
    /// whose first pixel is the top left one.
    #[test]
    fn a_fast_path_bitmap_update_becomes_a_framebuffer_update() {
        let mut body = Vec::new();
        rdp_pdu::update::slowpath::GraphicsUpdate::Bitmap(bitmap_update())
            .encode_body(&mut Writer::new(&mut body))
            .expect("encodes");
        let mut wire = Vec::new();
        encode_fastpath_update(
            &mut Writer::new(&mut wire),
            &[FpUpdate {
                header: FpUpdateHeader::single(update_code::BITMAP),
                data: Payload::new(&body),
            }],
        )
        .expect("encodes");

        let mut rl = loop_over(&[]);
        let signal = rl
            .dispatch(&Framed {
                kind: FramedKind::FastPath,
                frame: Bytes::from(wire),
            })
            .expect("decodes");
        let SessionSignal::Output { events, reply } = signal else {
            panic!("expected decoded output");
        };
        assert!(reply.is_none());
        assert_eq!(events.len(), 1);
        match &events[0] {
            SessionEvent::FramebufferUpdate { rects, damage } => {
                assert_eq!(rects.len(), 1);
                assert_eq!(rects[0].rect, remote_core::Rect::new(2, 4, 2, 2));
                assert_eq!(*damage, remote_core::Rect::new(2, 4, 2, 2));
                let RectPayload::Rgba(pixels) = &rects[0].payload else {
                    panic!("expected rgba");
                };
                assert_eq!(pixels.len(), 2 * 2 * 4);
                assert_eq!(&pixels[0..4], &[0xff, 0x00, 0x00, 0xff], "top left is red");
            }
            other => panic!("expected a framebuffer update, got {other:?}"),
        }
    }

    /// The same bytes arrive on the slow path inside a Share Data PDU, and
    /// they have to produce the same picture: MS-RDPBCGR 2.2.9.1.1.3.1.2 and
    /// 2.2.9.1.2 carry identical bodies, which is the whole reason one body
    /// decoder serves both.
    #[test]
    fn the_slow_path_carries_the_same_bitmap_to_the_same_place() {
        let mut body = Vec::new();
        rdp_pdu::update::slowpath::GraphicsUpdate::Bitmap(bitmap_update())
            .encode(&mut Writer::new(&mut body))
            .expect("encodes");
        let share = SharePdu::data(
            0x03ea,
            0x0010_3ea9,
            ShareDataPdu::Other {
                pdu_type2: rdp_pdu::rdp::share::pdu_type2::UPDATE,
                body: Payload::new(&body),
            },
        );

        let mut rl = loop_over(&[]);
        let SessionSignal::Output { events, .. } =
            rl.dispatch(&from_server(&share)).expect("decodes")
        else {
            panic!("expected decoded output");
        };
        match &events[0] {
            SessionEvent::FramebufferUpdate { rects, .. } => {
                assert_eq!(rects[0].rect, remote_core::Rect::new(2, 4, 2, 2));
            }
            other => panic!("expected a framebuffer update, got {other:?}"),
        }
    }

    /// Phase 1 advertises no bulk compression, so a compressed fast path
    /// update is a server compressing without being asked. That produces
    /// garbage pixels rather than an obvious failure, which is why it is an
    /// error and not a pass through (PRDRDP/04 §2.1).
    #[test]
    fn a_compressed_fast_path_update_is_refused() {
        let mut wire = Vec::new();
        encode_fastpath_update(
            &mut Writer::new(&mut wire),
            &[FpUpdate {
                header: FpUpdateHeader {
                    update_code: update_code::BITMAP,
                    fragmentation: rdp_pdu::update::fastpath::fragmentation::SINGLE,
                    compression: rdp_pdu::update::fastpath::compression::USED,
                    compression_flags:
                        rdp_pdu::update::fastpath::compression_flags::PACKET_COMPRESSED,
                },
                data: Payload::new(&[0xaa; 8]),
            }],
        )
        .expect("encodes");

        let mut rl = loop_over(&[]);
        let err = rl
            .dispatch(&Framed {
                kind: FramedKind::FastPath,
                frame: Bytes::from(wire),
            })
            .expect_err("never asked for compression");
        assert!(err.to_string().contains("compressionFlags"), "{err}");
    }

    /// A server that restarts the capability exchange gets the same Confirm
    /// Active and finalisation batch the connect path sends, from the same
    /// function, and the new desktop size reaches the UI
    /// (MS-RDPBCGR 1.3.1.3, PRDRDP/06 §6.1).
    #[test]
    fn a_second_demand_active_is_answered_from_the_connected_pump() {
        use rdp_pdu::rdp::capabilities::{BitmapCapabilitySet, CapabilitySet, CapabilitySets};
        use rdp_pdu::rdp::DemandActivePdu;

        let share = SharePdu::DemandActive {
            pdu_source: 0x03ea,
            pdu: Box::new(DemandActivePdu {
                share_id: 0x0010_3eaa,
                source_descriptor: b"RDP\0".to_vec(),
                capabilities: CapabilitySets {
                    sets: vec![CapabilitySet::Bitmap(BitmapCapabilitySet::client(800, 600))],
                },
                session_id: None,
            }),
        };

        let mut rl = loop_over(&[]);
        let SessionSignal::Output { events, reply } =
            rl.dispatch(&from_server(&share)).expect("decodes")
        else {
            panic!("expected decoded output");
        };
        assert!(reply.is_some(), "the confirm active has to go back");
        assert!(events.iter().any(|e| matches!(
            e,
            SessionEvent::DesktopResize {
                width: 800,
                height: 600
            }
        )));
        assert_eq!(rl.activated.share_id, 0x0010_3eaa);
        assert_eq!(rl.graphics.desktop(), (800, 600));
    }

    /// A Set Error Info PDU is the server saying why the session is about to
    /// end. It reaches the UI as protocol news, and it is latched so the
    /// disconnect that follows says why rather than reporting a bare close
    /// (MS-RDPBCGR 2.2.5.1.1).
    #[test]
    fn a_set_error_info_is_reported_and_then_explains_the_disconnect() {
        use rdp_pdu::codes::ErrInfo;
        use rdp_pdu::rdp::control::SetErrorInfoPdu;

        let share = SharePdu::data(
            0x03ea,
            0x0010_3ea9,
            ShareDataPdu::SetErrorInfo(SetErrorInfoPdu {
                error_info: ErrInfo::LogoffByUser,
            }),
        );
        let mut rl = loop_over(&[]);
        let SessionSignal::Output { events, .. } =
            rl.dispatch(&from_server(&share)).expect("parses")
        else {
            panic!("expected decoded output");
        };
        assert!(matches!(
            events[0],
            SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::ErrorInfo { .. }))
        ));

        // A close after the code has been latched reports the code.
        let explained = rl.explain(RdpError::ConnectionClosed);
        match explained {
            RdpError::ServerError { symbol, .. } => assert_eq!(symbol, "ERRINFO_LOGOFF_BY_USER"),
            other => panic!("expected the latched error, got {other:?}"),
        }
    }

    /// The teardown queues the ultimatum before the shutdown, so the writer
    /// task sends it and only then closes the TLS layer.
    #[tokio::test]
    async fn the_teardown_queues_the_ultimatum_before_the_shutdown() {
        let (tx, mut rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        let mut rl = loop_with(&[][..], tx);
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

    /// Input reaches the writer as a Fast-Path Input Event PDU and as nothing
    /// else: no TPKT, no X.224 and no MCS wrapper (MS-RDPBCGR 2.2.8.1.2).
    #[tokio::test]
    async fn a_pointer_command_reaches_the_writer_as_a_fast_path_input_pdu() {
        use rdp_pdu::input::fastpath::{FastPathInputEvent, FastPathInputPdu};
        use rdp_pdu::input::pointer_flags;

        let (tx, mut rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        let mut rl = loop_with(&[][..], tx);
        rl.handle_command(ClientCommand::Pointer {
            x: 10,
            y: 20,
            button_mask: 0b001,
        })
        .await
        .expect("queued");

        let Some(Outbound::Frame(bytes)) = rx.recv().await else {
            panic!("expected one frame");
        };
        assert_ne!(bytes[0] & 0x03, 0x03, "not a TPKT");
        let pdu =
            FastPathInputPdu::decode(&mut Reader::new(&bytes)).expect("a fast path input pdu");
        assert_eq!(
            pdu.events,
            vec![
                FastPathInputEvent::Mouse {
                    flags: pointer_flags::MOVE,
                    x: 10,
                    y: 20
                },
                FastPathInputEvent::Mouse {
                    flags: pointer_flags::DOWN | pointer_flags::BUTTON1_LEFT,
                    x: 10,
                    y: 20
                },
            ]
        );
    }

    /// A disconnect releases every held key before the ultimatum. A key the
    /// server believes is held repeats into the session forever
    /// (PRDRDP/05 §2.11).
    #[tokio::test]
    async fn a_disconnect_releases_held_keys_before_it_hangs_up() {
        use rdp_pdu::input::fastpath::{keyboard_flags, FastPathInputEvent, FastPathInputPdu};

        let (tx, mut rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        let mut rl = loop_with(&[][..], tx);
        rl.handle_command(ClientCommand::Key {
            keysym: 0,
            keycode: Some(0x1e),
            down: true,
        })
        .await
        .expect("queued");
        let _press = rx.recv().await.expect("the press");

        let outcome = rl
            .handle_command(ClientCommand::Disconnect)
            .await
            .expect("queued");
        assert_eq!(outcome, Some(RunOutcome::UserDisconnect));

        let Some(Outbound::Frame(bytes)) = rx.recv().await else {
            panic!("expected the release batch");
        };
        let pdu = FastPathInputPdu::decode(&mut Reader::new(&bytes)).expect("input pdu");
        assert_eq!(
            pdu.events,
            vec![FastPathInputEvent::Scancode {
                flags: keyboard_flags::RELEASE,
                code: 0x1e
            }]
        );
        // Then the ultimatum, then the shutdown.
        assert!(matches!(rx.recv().await, Some(Outbound::Frame(_))));
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
        let mut rl = loop_with(leaked, tx);

        let cancel = CancellationToken::new();
        cancel.cancel();
        let (events, _erx) = mpsc::channel(16);
        let (_ctx, mut commands) = mpsc::channel(16);
        let err = rl
            .run(Vec::new(), &events, &mut commands, &cancel)
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
        let mut rl = loop_with(tokio::io::empty(), tx);
        let (events, _erx) = mpsc::channel(16);
        let (ctx, mut commands) = mpsc::channel::<ClientCommand>(16);
        drop(ctx);
        // The framer sees EOF first on an empty stream, which is also a
        // correct end. Either way the loop returns rather than spinning.
        let out = rl
            .run(
                Vec::new(),
                &events,
                &mut commands,
                &CancellationToken::new(),
            )
            .await;
        assert!(out.is_err(), "the loop ends when nothing can drive it");
    }

    /// Updates that overtook the end of the connection sequence are drawn
    /// rather than dropped: a server is allowed to start painting before the
    /// Font Map arrives, and losing those pixels is a stale region nobody can
    /// explain.
    #[tokio::test]
    async fn pending_updates_from_the_connection_sequence_are_drawn_first() {
        let mut body = Vec::new();
        rdp_pdu::update::slowpath::GraphicsUpdate::Bitmap(bitmap_update())
            .encode_body(&mut Writer::new(&mut body))
            .expect("encodes");
        let mut wire = Vec::new();
        encode_fastpath_update(
            &mut Writer::new(&mut wire),
            &[FpUpdate {
                header: FpUpdateHeader::single(update_code::BITMAP),
                data: Payload::new(&body),
            }],
        )
        .expect("encodes");

        let (tx, _rx) = mpsc::channel(crate::transport::writer::WRITER_QUEUE);
        let mut rl = loop_with(tokio::io::empty(), tx);
        let (events, mut erx) = mpsc::channel(16);
        let (ctx, mut commands) = mpsc::channel::<ClientCommand>(16);
        drop(ctx);
        let _ = rl
            .run(
                vec![Framed {
                    kind: FramedKind::FastPath,
                    frame: Bytes::from(wire),
                }],
                &events,
                &mut commands,
                &CancellationToken::new(),
            )
            .await;
        drop(events);

        let first = erx.recv().await.expect("the parked update was drawn");
        assert!(matches!(first, SessionEvent::FramebufferUpdate { .. }));
    }
}
