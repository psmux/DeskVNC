//! Display control: resizing the remote desktop when the window changes
//! (MS-RDPEDISP, PRDRDP/05 §5.4, PRDRDP/12 §3.10).
//!
//! A dynamic virtual channel named [`DISPLAY_CHANNEL_NAME`]. The server opens
//! it, sends its capabilities once, and after that the client may send a
//! monitor layout whenever the window changes size. The server rebuilds its
//! session surface and restarts the capability exchange, which arrives back
//! here as a Deactivate All and a fresh Demand Active
//! (`crate::session::run_loop`).
//!
//! # Why the wire format is in this crate and not in `rdp-pdu`
//!
//! Every other PDU this crate sends is `rdp-pdu`'s, and these two should be
//! too: PRDRDP/12 §2.1 puts wire formats there and policy here. `rdp-pdu` has
//! no MS-RDPEDISP module, and this lane may not add one, so the two
//! structures are encoded here against `rdp_pdu::io::Writer` and
//! `rdp_pdu::io::Reader`, which are the same bounds checked primitives every
//! other decoder in the workspace uses. **This belongs in
//! `rdp-pdu/src/vc/display.rs` and the report says so.** Nothing else about
//! the design changes when it moves: the caps state, the validation and the
//! debounce are policy and stay here either way.
//!
//! # The rules that bite (MS-RDPEDISP 2.2.2.2.1)
//!
//! The server's failure mode for an invalid layout is to ignore the PDU
//! entirely, so the user sees "resize did nothing" with nothing in the log.
//! Every rule is therefore checked here, before anything is sent, and a
//! refusal names which rule failed:
//!
//! * `MonitorLayoutSize` MUST be 40, and each entry is exactly forty bytes.
//! * Exactly one entry carries `DISPLAYCONTROL_MONITOR_PRIMARY`, and it sits
//!   at `Left = 0, Top = 0`.
//! * `Width` is 200 to 8192 and even; `Height` is 200 to 8192.
//! * `PhysicalWidth` and `PhysicalHeight` are both zero or both in range. One
//!   of each is a validation failure, so we send zero for both: the shell
//!   cannot know the monitor's millimetres and a guessed DPI is worse than
//!   none.
//! * `DesktopScaleFactor` and `DeviceScaleFactor` are ignored **as a pair**
//!   if either is out of range, so an out of range desktop scale silently
//!   discards a valid device scale. Both are clamped and snapped here.
//!
//! PRDRDP/00 R19 adds one rule of ours on top: the width is aligned **down to
//! a multiple of 8** before clamping, not merely to an even number. RemoteFX
//! and progressive tiles are 64 wide, so an 8 aligned width avoids a partial
//! tile column on every frame, and server side encoders behave badly on
//! widths that are merely even. Losing up to seven columns of a window is
//! invisible; a codec that reallocates its tile grid every resize is not.

use std::time::{Duration, Instant};

use rdp_pdu::io::{Reader, Writer};

use crate::channels::dvc::ReplyBuf;
use crate::error::{RdpError, Result};

/// The dynamic channel's name (MS-RDPEDISP 1.5).
pub const DISPLAY_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::DisplayControl";

/// `DISPLAYCONTROL_HEADER` is two `u32` and `Length` counts it
/// (MS-RDPEDISP 2.2.1.1).
const HEADER_LEN: u32 = 8;

/// `DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT`, client to server.
const PDU_TYPE_MONITOR_LAYOUT: u32 = 0x0000_0002;
/// `DISPLAYCONTROL_PDU_TYPE_CAPS`, server to client.
const PDU_TYPE_CAPS: u32 = 0x0000_0005;

/// `DISPLAYCONTROL_MONITOR_LAYOUT_PDU.MonitorLayoutSize` MUST be 40, and it
/// is the size of one `DISPLAYCONTROL_MONITOR_LAYOUT` (2.2.2.2.1).
const MONITOR_LAYOUT_SIZE: u32 = 40;

/// `DISPLAYCONTROL_MONITOR_PRIMARY`.
const MONITOR_PRIMARY: u32 = 0x0000_0001;

/// The layout array holds at most sixteen entries (2.2.2.2).
const MAX_MONITORS: u32 = 16;

/// `Width` and `Height` bounds (2.2.2.2.1).
const MIN_EDGE: u32 = 200;
/// The upper end of the same pair.
const MAX_EDGE: u32 = 8192;

/// The alignment PRDRDP/00 R19 chose for the width. The specification asks
/// only for an even number.
const WIDTH_ALIGN: u32 = 8;

/// The shortest gap between two layouts on the wire (PRDRDP/05 §5.4).
///
/// A resize is not free: the server tears down and rebuilds its session
/// surface, which produces a Deactivate All and a full reactivation on some
/// server versions. Two of those during a window drag are two visible
/// rebuilds. The UI already debounces at 500 ms
/// (`ui/src/screens/Session.tsx:414`) and also fires one unthrottled request
/// when the user picks the mode, so the driver sees an immediate request
/// followed by a debounced one for a slightly different size; this is the
/// second, protocol side guard.
///
/// A deferred size is not lost: it is flushed by
/// [`DisplayControl::flush_pending`], which the run loop calls on its one
/// second stats tick. So the worst case added latency on a deliberate resize
/// is one second, against an operation that costs the server a screen
/// rebuild.
pub const RESIZE_DEBOUNCE: Duration = Duration::from_millis(250);

/// `DesktopScaleFactor` is 100 to 500 (2.2.2.2.1).
const MIN_DESKTOP_SCALE: u32 = 100;
/// The upper end of the same range.
const MAX_DESKTOP_SCALE: u32 = 500;

/// `DeviceScaleFactor` takes these three values and no others. They are the
/// three Windows shell scaling steps, and a value outside them causes the
/// pair rule above to discard the desktop scale as well.
const DEVICE_SCALES: [u32; 3] = [100, 140, 180];

/// What the server said it will accept (MS-RDPEDISP 2.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayCaps {
    /// `MaxNumMonitors`.
    pub max_monitors: u32,
    /// `MaxMonitorAreaFactorA`.
    pub area_factor_a: u32,
    /// `MaxMonitorAreaFactorB`.
    pub area_factor_b: u32,
}

impl DisplayCaps {
    /// The total pixel budget: the product of the three fields.
    ///
    /// `u64` because the product of three `u32` overflows a `u32` for any
    /// realistic value, and a wrapped budget would refuse every layout or
    /// accept every one depending on which way it wrapped.
    #[must_use]
    pub const fn pixel_budget(&self) -> u64 {
        (self.max_monitors as u64) * (self.area_factor_a as u64) * (self.area_factor_b as u64)
    }

    /// True when the server will accept nothing.
    ///
    /// A real configuration rather than a theoretical one: a server with
    /// dynamic resolution disabled by policy still opens the channel and
    /// still sends its capabilities, with zeros in them. Every resize is then
    /// dropped with a log line, and it must not look like a bug.
    #[must_use]
    pub const fn accepts_nothing(&self) -> bool {
        self.max_monitors == 0 || self.area_factor_a == 0 || self.area_factor_b == 0
    }
}

/// One monitor of a layout, after validation (MS-RDPEDISP 2.2.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorLayout {
    /// `Flags`.
    pub flags: u32,
    /// `Left`.
    pub left: i32,
    /// `Top`.
    pub top: i32,
    /// `Width`, aligned and clamped.
    pub width: u32,
    /// `Height`, clamped.
    pub height: u32,
    /// `DesktopScaleFactor`, clamped.
    pub desktop_scale: u32,
    /// `DeviceScaleFactor`, snapped to one of [`DEVICE_SCALES`].
    pub device_scale: u32,
}

impl MonitorLayout {
    /// The primary monitor at the origin, which is the only shape phase 2
    /// sends (PRDRDP/05 §5.5: real multi monitor is phase 3 and needs a user
    /// interface and the connect time Client Monitor Data block as well).
    ///
    /// Returns `None` when the size cannot be made legal, which is a window
    /// smaller than 200 pixels on an edge.
    #[must_use]
    pub fn primary(width: u32, height: u32, scale_percent: u32) -> Option<Self> {
        // Align down first, then clamp, so aligning cannot push the value
        // back under the minimum.
        let width = (width / WIDTH_ALIGN) * WIDTH_ALIGN;
        if width < MIN_EDGE || height < MIN_EDGE {
            return None;
        }
        Some(Self {
            flags: MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: width.min(MAX_EDGE),
            height: height.min(MAX_EDGE),
            desktop_scale: scale_percent.clamp(MIN_DESKTOP_SCALE, MAX_DESKTOP_SCALE),
            device_scale: device_scale_for(scale_percent),
        })
    }

    /// The pixel count this monitor charges against the server's budget.
    const fn area(&self) -> u64 {
        (self.width as u64) * (self.height as u64)
    }
}

/// `DeviceScaleFactor` for a percentage, snapped to the nearest legal value.
///
/// The same rule `crates/rdp-core/src/connection/mcs.rs:172` applies to
/// `TS_UD_CS_CORE.deviceScaleFactor` at connect time, and for the same
/// reason: a value outside the set of three makes the server ignore both
/// scale fields together.
fn device_scale_for(percent: u32) -> u32 {
    let mut best = DEVICE_SCALES[0];
    let mut best_gap = u32::MAX;
    for candidate in DEVICE_SCALES {
        let gap = candidate.abs_diff(percent);
        if gap < best_gap {
            best_gap = gap;
            best = candidate;
        }
    }
    best
}

/// The display control channel's state.
///
/// Two facts and no buffers: the layout it encodes is eight words long, and
/// the buffer it encodes into is [`ReplyBuf`]'s, pooled across the session
/// like every other dynamic channel reply.
#[derive(Debug, Default)]
pub struct DisplayControl {
    /// What the server said it accepts. `None` until the caps PDU arrives,
    /// and MS-RDPEDISP 1.3.1 says nothing may be sent before it.
    caps: Option<DisplayCaps>,
    /// The last layout actually sent, so an unchanged size is not sent twice.
    ///
    /// A resize costs the server a session surface rebuild and a full
    /// reactivation, so a repeat is not merely wasted bytes: it is a visible
    /// flicker (PRDRDP/05 §5.4).
    last_sent: Option<MonitorLayout>,
    /// A size that arrived and has not been sent yet, either because the
    /// caps have not arrived or because it came too soon after the last one.
    pending: Option<(u32, u32, u32)>,
    /// When the last layout went out, for the debounce.
    last_sent_at: Option<Instant>,
}

impl DisplayControl {
    /// A channel with no capabilities yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What the server said it accepts, once it has said.
    #[must_use]
    pub const fn caps(&self) -> Option<DisplayCaps> {
        self.caps
    }

    /// The last layout put on the wire.
    #[must_use]
    pub const fn last_sent(&self) -> Option<MonitorLayout> {
        self.last_sent
    }

    /// One complete message from the server.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] when the PDU did not parse or declared a length its
    /// body does not have.
    pub fn message(&mut self, message: &[u8], replies: &mut ReplyBuf) -> Result<()> {
        let mut r = Reader::new(message);
        let pdu_type = r.u32(HEADER_NAME)?;
        let length = r.u32(HEADER_NAME)?;
        if length < HEADER_LEN || length as usize > message.len() {
            return Err(RdpError::Pdu {
                structure: HEADER_NAME,
                message: format!(
                    "Length is {length} for a {} byte message (MS-RDPEDISP 2.2.1.1)",
                    message.len()
                ),
            });
        }
        match pdu_type {
            PDU_TYPE_CAPS => {
                let caps = DisplayCaps {
                    max_monitors: r.u32(CAPS_NAME)?,
                    area_factor_a: r.u32(CAPS_NAME)?,
                    area_factor_b: r.u32(CAPS_NAME)?,
                };
                tracing::info!(
                    max_monitors = caps.max_monitors,
                    budget = caps.pixel_budget(),
                    "the display control channel is ready"
                );
                self.caps = Some(caps);
                // A size the user asked for before the channel was ready, or
                // one carried across a reconnect, goes now.
                if let Some((width, height, scale)) = self.pending.take() {
                    self.resize(width, height, scale, replies)?;
                }
                Ok(())
            }
            // MS-RDPEDISP defines no other server to client PDU. Skipping it
            // by its own `Length` cannot desync the channel, and naming it is
            // better than a silent drop.
            other => {
                tracing::debug!(pdu_type = other, "a display control pdu this build ignores");
                Ok(())
            }
        }
    }

    /// The window changed size: send a layout, or remember it for later.
    ///
    /// `scale_percent` is the desktop scale as a percentage, the same figure
    /// `TS_UD_CS_CORE.desktopScaleFactor` carries at connect time.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] when the layout will not encode, which the size
    /// checks below make impossible.
    pub fn resize(
        &mut self,
        width: u32,
        height: u32,
        scale_percent: u32,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        let Some(caps) = self.caps else {
            // MS-RDPEDISP 1.3.1: nothing may be sent before the capabilities
            // arrive. Remembering it rather than dropping it is what makes a
            // resize that raced the channel opening still take effect.
            tracing::debug!("a resize arrived before the display control capabilities");
            self.pending = Some((width, height, scale_percent));
            return Ok(());
        };
        if caps.accepts_nothing() {
            tracing::debug!(
                "the server's display control capabilities accept no layout at all: \
                 dropping the resize"
            );
            return Ok(());
        }
        let Some(layout) = MonitorLayout::primary(width, height, scale_percent) else {
            tracing::debug!(
                width,
                height,
                "a resize smaller than the 200 pixel minimum edge (MS-RDPEDISP 2.2.2.2.1)"
            );
            return Ok(());
        };
        if self
            .last_sent_at
            .is_some_and(|at| at.elapsed() < RESIZE_DEBOUNCE)
        {
            // Too soon. Held rather than dropped, and flushed on the next
            // stats tick, so the last size of a drag is the one that lands.
            self.pending = Some((width, height, scale_percent));
            return Ok(());
        }
        if self.last_sent == Some(layout) {
            // The UI debounces at 500 ms and also fires one immediate request
            // when the user picks the mode, so the same size arriving twice
            // is the normal case rather than the odd one
            // (`ui/src/screens/Session.tsx:414`, PRDRDP/05 §5.4).
            tracing::trace!("a resize to the size already in effect");
            return Ok(());
        }
        if caps.max_monitors < 1 || MAX_MONITORS < 1 {
            return Ok(());
        }
        if layout.area() > caps.pixel_budget() {
            tracing::info!(
                width = layout.width,
                height = layout.height,
                budget = caps.pixel_budget(),
                "the requested size is past the server's pixel budget \
                 (MS-RDPEDISP 2.2.2.1)"
            );
            return Ok(());
        }

        tracing::info!(
            width = layout.width,
            height = layout.height,
            scale = layout.desktop_scale,
            "sending a display control monitor layout"
        );
        replies.emit(|buf| encode_layout(&[layout], buf))?;
        self.last_sent = Some(layout);
        self.last_sent_at = Some(Instant::now());
        Ok(())
    }

    /// Send a size the debounce held back, if the gap has passed.
    ///
    /// Called once a second from the run loop's stats tick, which is the
    /// timer that already exists: adding a second one to the `select!` would
    /// buy 750 ms on an operation that costs the server a screen rebuild.
    ///
    /// # Errors
    ///
    /// Whatever [`DisplayControl::resize`] reported.
    pub fn flush_pending(&mut self, replies: &mut ReplyBuf) -> Result<()> {
        let Some((width, height, scale)) = self.pending else {
            return Ok(());
        };
        if self
            .last_sent_at
            .is_some_and(|at| at.elapsed() < RESIZE_DEBOUNCE)
        {
            return Ok(());
        }
        self.pending = None;
        self.resize(width, height, scale, replies)
    }

    /// Forget everything. Called when the share is deactivated, because the
    /// server reopens its dynamic channels on the new share and its
    /// capabilities arrive again (PRDRDP/05 §5.1 rule 6).
    pub fn reset(&mut self) {
        // The last size the user asked for is kept and re-sent as soon as the
        // new channel says it is ready, which is what makes a reactivation
        // come back at the size they were using.
        self.pending = self
            .pending
            .or_else(|| self.last_sent.map(|l| (l.width, l.height, l.desktop_scale)));
        self.caps = None;
        self.last_sent = None;
        self.last_sent_at = None;
    }
}

/// `DISPLAYCONTROL_HEADER`, for an error message.
const HEADER_NAME: &str = "DISPLAYCONTROL_HEADER";
/// `DISPLAYCONTROL_CAPS_PDU`.
const CAPS_NAME: &str = "DISPLAYCONTROL_CAPS_PDU";
/// `DISPLAYCONTROL_MONITOR_LAYOUT_PDU`.
const LAYOUT_NAME: &str = "DISPLAYCONTROL_MONITOR_LAYOUT_PDU";

/// Encode a `DISPLAYCONTROL_MONITOR_LAYOUT_PDU` (MS-RDPEDISP 2.2.2.2).
///
/// # Errors
///
/// [`RdpError::Pdu`] when the monitor count is outside 1 to 16, which the
/// caller's own checks make impossible.
fn encode_layout(monitors: &[MonitorLayout], buf: &mut Vec<u8>) -> Result<()> {
    let count = u32::try_from(monitors.len()).unwrap_or(u32::MAX);
    if count == 0 || count > MAX_MONITORS {
        return Err(RdpError::Pdu {
            structure: LAYOUT_NAME,
            message: format!(
                "NumMonitors is {count}, and 1 to 16 is the range (MS-RDPEDISP 2.2.2.2)"
            ),
        });
    }
    let primaries = monitors.iter().filter(|m| m.flags & MONITOR_PRIMARY != 0);
    if primaries.count() != 1 {
        return Err(RdpError::Pdu {
            structure: LAYOUT_NAME,
            message: "exactly one monitor carries DISPLAYCONTROL_MONITOR_PRIMARY \
                      (MS-RDPEDISP 2.2.2.2.1)"
                .to_owned(),
        });
    }

    let length = HEADER_LEN + 8 + count * MONITOR_LAYOUT_SIZE;
    let mut w = Writer::new(buf);
    w.u32(PDU_TYPE_MONITOR_LAYOUT);
    w.u32(length);
    w.u32(MONITOR_LAYOUT_SIZE);
    w.u32(count);
    for monitor in monitors {
        w.u32(monitor.flags);
        w.i32(monitor.left);
        w.i32(monitor.top);
        w.u32(monitor.width);
        w.u32(monitor.height);
        // Both zero, which is the specification's "not specified": the shell
        // cannot know the monitor's millimetres, and one of each is a
        // validation failure that discards the whole layout.
        w.u32(0);
        w.u32(0);
        // Landscape. A rotation control is phase 3; the field exists mostly
        // for tablets (PRDRDP/05 §5.4).
        w.u32(0);
        w.u32(monitor.desktop_scale);
        w.u32(monitor.device_scale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_pdu(max_monitors: u32, a: u32, b: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u32(PDU_TYPE_CAPS);
        w.u32(HEADER_LEN + 12);
        w.u32(max_monitors);
        w.u32(a);
        w.u32(b);
        out
    }

    /// The one shape this build sends, byte for byte, because the server's
    /// failure mode for a wrong one is to ignore it in silence.
    #[test]
    fn a_layout_is_forty_bytes_per_monitor_behind_a_sixteen_byte_head() {
        let mut buf = Vec::new();
        let layout = MonitorLayout::primary(1920, 1080, 100).expect("a legal size");
        encode_layout(&[layout], &mut buf).expect("encodes");

        assert_eq!(buf.len(), 8 + 8 + 40, "header, layout head, one monitor");
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32("t").unwrap(), PDU_TYPE_MONITOR_LAYOUT);
        assert_eq!(
            r.u32("len").unwrap() as usize,
            buf.len(),
            "Length counts the header (MS-RDPEDISP 2.2.1.1)"
        );
        assert_eq!(r.u32("size").unwrap(), 40, "MonitorLayoutSize MUST be 40");
        assert_eq!(r.u32("count").unwrap(), 1);
        assert_eq!(r.u32("flags").unwrap(), MONITOR_PRIMARY);
        assert_eq!(r.i32("left").unwrap(), 0);
        assert_eq!(r.i32("top").unwrap(), 0);
        assert_eq!(r.u32("width").unwrap(), 1920);
        assert_eq!(r.u32("height").unwrap(), 1080);
        assert_eq!(r.u32("phys w").unwrap(), 0, "both physical fields are zero");
        assert_eq!(r.u32("phys h").unwrap(), 0);
        assert_eq!(r.u32("orientation").unwrap(), 0);
        assert_eq!(r.u32("desktop scale").unwrap(), 100);
        assert_eq!(r.u32("device scale").unwrap(), 100);
    }

    /// PRDRDP/00 R19: the width is aligned down to a multiple of eight, which
    /// is stricter than the specification's "even". The height is not
    /// aligned, only clamped.
    #[test]
    fn the_width_is_aligned_down_to_a_multiple_of_eight() {
        for (asked, expected) in [(1920, 1920), (1921, 1920), (1927, 1920), (1928, 1928)] {
            let layout = MonitorLayout::primary(asked, 1080, 100).expect("legal");
            assert_eq!(layout.width, expected, "asked for {asked}");
            assert_eq!(layout.width % 2, 0, "and it is still even");
        }
        let layout = MonitorLayout::primary(1024, 1081, 100).expect("legal");
        assert_eq!(layout.height, 1081, "the height is not aligned");
    }

    /// The bounds of 2.2.2.2.1, including the one that has no legal answer.
    #[test]
    fn a_size_outside_the_specification_is_clamped_or_refused() {
        assert!(
            MonitorLayout::primary(199, 600, 100).is_none(),
            "a width under the 200 pixel minimum has no legal layout"
        );
        assert!(MonitorLayout::primary(800, 199, 100).is_none());
        let big = MonitorLayout::primary(20_000, 20_000, 100).expect("clamped");
        assert_eq!(big.width, MAX_EDGE);
        assert_eq!(big.height, MAX_EDGE);
    }

    /// The two scale fields are ignored as a pair if either is out of range,
    /// so both are made legal or neither is worth sending.
    #[test]
    fn the_scale_factors_are_clamped_and_snapped_together() {
        for (percent, desktop, device) in [
            (100, 100, 100),
            (50, 100, 100),
            (150, 150, 140),
            (200, 200, 180),
            (600, 500, 180),
        ] {
            let layout = MonitorLayout::primary(1024, 768, percent).expect("legal");
            assert_eq!(layout.desktop_scale, desktop, "{percent}%");
            assert_eq!(layout.device_scale, device, "{percent}%");
            assert!(DEVICE_SCALES.contains(&layout.device_scale));
        }
    }

    /// MS-RDPEDISP 1.3.1: nothing goes out before the capabilities arrive,
    /// and a resize that raced the channel opening is not lost.
    #[test]
    fn a_resize_before_the_capabilities_is_held_and_sent_when_they_arrive() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();

        display.resize(1920, 1080, 100, &mut replies).expect("held");
        assert!(replies.is_empty(), "nothing may be sent before the caps");

        display
            .message(&caps_pdu(4, 8192, 8192), &mut replies)
            .expect("caps");
        assert_eq!(replies.queued().len(), 1, "the held resize went out");
        assert_eq!(
            display.last_sent().expect("sent").width,
            1920,
            "and it is the size that was asked for"
        );
    }

    /// A resize costs the server a session surface rebuild and a full
    /// reactivation, so the same size twice is dropped.
    #[test]
    fn the_same_size_is_not_sent_twice() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();
        display
            .message(&caps_pdu(4, 8192, 8192), &mut replies)
            .expect("caps");

        display.resize(1600, 900, 100, &mut replies).expect("sent");
        assert_eq!(replies.queued().len(), 1);
        replies.take();

        // Past the debounce, so what follows is the size guard and not the
        // clock.
        display.last_sent_at = None;
        display
            .resize(1600, 900, 100, &mut replies)
            .expect("dropped");
        assert!(replies.is_empty(), "the same size is already in effect");

        // And an alignment that lands on the same width is the same layout.
        display
            .resize(1607, 900, 100, &mut replies)
            .expect("dropped");
        assert!(replies.is_empty(), "1607 aligns down to 1600");

        display.resize(1608, 900, 100, &mut replies).expect("sent");
        assert_eq!(replies.queued().len(), 1, "a real change goes out");
    }

    /// A drag produces a burst of distinct sizes. Only the first goes out at
    /// once; the rest collapse into the last one, which the stats tick
    /// flushes.
    #[test]
    fn a_burst_of_resizes_collapses_into_the_last_one() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();
        display
            .message(&caps_pdu(4, 8192, 8192), &mut replies)
            .expect("caps");

        display.resize(1000, 800, 100, &mut replies).expect("sent");
        assert_eq!(replies.queued().len(), 1, "the first one goes at once");
        replies.take();

        for width in [1100, 1200, 1300, 1400] {
            display.resize(width, 800, 100, &mut replies).expect("held");
        }
        assert!(replies.is_empty(), "the burst was held by the debounce");

        // The tick fires with the gap still open: still nothing.
        display.flush_pending(&mut replies).expect("held");
        assert!(replies.is_empty());

        // The gap has passed.
        display.last_sent_at = None;
        display.flush_pending(&mut replies).expect("sent");
        assert_eq!(replies.queued().len(), 1, "one layout, not four");
        assert_eq!(
            display.last_sent().expect("sent").width,
            1400,
            "and it is the last size asked for"
        );
        assert!(display.pending.is_none(), "nothing is left over");
    }

    /// A server with dynamic resolution disabled by policy still opens the
    /// channel and still sends capabilities, with zeros in them. Every resize
    /// is dropped and it must not look like a bug.
    #[test]
    fn capabilities_of_zero_accept_nothing_and_say_so() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();
        display
            .message(&caps_pdu(0, 0, 0), &mut replies)
            .expect("caps");
        assert!(display.caps().expect("caps").accepts_nothing());
        display.resize(1920, 1080, 100, &mut replies).expect("ok");
        assert!(replies.is_empty());
    }

    /// The budget is the product of the three capability fields, and a layout
    /// past it is refused here rather than ignored by the server.
    #[test]
    fn a_layout_past_the_servers_pixel_budget_is_not_sent() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();
        // 1 * 1024 * 768 = 786,432 pixels, which 1024 by 768 exactly fills.
        display
            .message(&caps_pdu(1, 1024, 768), &mut replies)
            .expect("caps");
        assert_eq!(display.caps().expect("caps").pixel_budget(), 786_432);

        display.resize(1920, 1080, 100, &mut replies).expect("ok");
        assert!(replies.is_empty(), "2,073,600 pixels is past the budget");

        display.resize(1024, 768, 100, &mut replies).expect("ok");
        assert_eq!(replies.queued().len(), 1, "and this one exactly fits");
    }

    /// A truncated or lying header is an error rather than a partial read:
    /// the channel's next message depends on this one having been consumed
    /// whole.
    #[test]
    fn a_malformed_header_is_refused_by_name() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();
        for bad in [
            vec![],
            vec![0x05, 0x00, 0x00],
            // A `Length` of 4, which is shorter than the header it counts.
            vec![0x05, 0, 0, 0, 0x04, 0, 0, 0],
            // A `Length` longer than the message.
            vec![0x05, 0, 0, 0, 0xff, 0, 0, 0],
        ] {
            let err = display.message(&bad, &mut replies).expect_err("refused");
            assert!(matches!(err, RdpError::Pdu { .. }), "{err} for {bad:?}");
        }
    }

    /// A deactivation drops the capabilities, because the server reopens the
    /// channel on the new share. The size the user asked for survives, so the
    /// desktop comes back the way they were using it.
    #[test]
    fn a_reset_keeps_the_size_and_forgets_the_capabilities() {
        let mut display = DisplayControl::new();
        let mut replies = ReplyBuf::default();
        display
            .message(&caps_pdu(4, 8192, 8192), &mut replies)
            .expect("caps");
        display.resize(1600, 900, 100, &mut replies).expect("sent");
        replies.take();

        display.reset();
        assert!(display.caps().is_none());
        assert!(display.last_sent().is_none());

        display
            .message(&caps_pdu(4, 8192, 8192), &mut replies)
            .expect("caps again");
        assert_eq!(
            display.last_sent().expect("re-sent").width,
            1600,
            "the size the user was using came back"
        );
    }
}
