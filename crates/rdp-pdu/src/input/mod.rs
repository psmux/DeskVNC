//! Input event PDUs, slow path and fast path.
//!
//! PRDRDP/13 §5.3 and §5.4.
//!
//! The two paths carry the same seven events in two different shapes. The
//! slow path spends twelve bytes per event inside a Share Data PDU; the fast
//! path spends two to seven and replaces the whole TPKT, X.224 and MCS stack
//! with three bytes. A client uses the fast path whenever the server's Input
//! capability set advertised `INPUT_FLAG_FASTPATH_INPUT` (MS-RDPBCGR
//! 2.2.7.1.6) and falls back to the slow path otherwise, which is `rdp-core`'s
//! decision and not this module's.
//!
//! What lives here is what both shapes share: the flag words, the wheel
//! rotation packing, and the cap on how many events one PDU carries. The two
//! event types themselves are deliberately distinct, because the same three
//! keyboard flags sit at different bit positions in the two forms and one
//! enum with a single `flags` field would silently accept the wrong word
//! (MS-RDPBCGR 2.2.8.1.1.3.1.1.1 against 2.2.8.1.2.2.1).
//!
//! Neither module reaches into `crate::rdp`. A slow path input PDU is the
//! body of a Share Data PDU and this module encodes only that body, so the
//! session composes the two the way it composes a Connect Initial.

pub mod fastpath;
pub mod slowpath;

use crate::io::{PduError, PduResult};

/// The most events this crate will put in, or take out of, one input PDU
/// (MS-RDPBCGR 2.2.8.1.2).
///
/// The cap itself now lives in [`crate::io::limits`] with every other cap;
/// this name stays because `rdp-core`'s input batcher spells it
/// `rdp_pdu::input::MAX_INPUT_EVENTS`, and a batch size belongs next to the
/// PDU it bounds when read from outside the crate.
pub use crate::io::limits::MAX_INPUT_EVENTS;

/// `toggleFlags` of the slow path synchronize event and `eventFlags` of the
/// fast path one (MS-RDPBCGR 2.2.8.1.1.3.1.1.5, 2.2.8.1.2.2.5).
///
/// The event carries the absolute state of the four locks, so it is
/// idempotent and safe to resend (PRDRDP/05 §2.8).
pub mod sync_flags {
    /// `TS_SYNC_SCROLL_LOCK`.
    pub const SCROLL_LOCK: u32 = 0x0000_0001;
    /// `TS_SYNC_NUM_LOCK`.
    pub const NUM_LOCK: u32 = 0x0000_0002;
    /// `TS_SYNC_CAPS_LOCK`.
    pub const CAPS_LOCK: u32 = 0x0000_0004;
    /// `TS_SYNC_KANA_LOCK`.
    pub const KANA_LOCK: u32 = 0x0000_0008;
    /// Every bit the specification defines. The fast path form carries these
    /// in the five flag bits of its event header, so nothing above the low
    /// nibble can be represented there.
    pub const ALL: u32 = SCROLL_LOCK | NUM_LOCK | CAPS_LOCK | KANA_LOCK;
}

/// `TS_KEYBOARD_EVENT.keyboardFlags`, the slow path form
/// (MS-RDPBCGR 2.2.8.1.1.3.1.1.1).
///
/// [`fastpath::keyboard_flags`] is the same three flags at different bit
/// positions, plus the absence of a down flag. See
/// [`slowpath::SlowPathInputEvent::key`] for the constructor that stops a
/// caller having to know which is which.
pub mod keyboard_flags {
    /// `KBDFLAGS_EXTENDED`, the `E0` prefix.
    pub const EXTENDED: u16 = 0x0100;
    /// `KBDFLAGS_EXTENDED1`, the `E1` prefix, which only Pause uses.
    pub const EXTENDED1: u16 = 0x0200;
    /// `KBDFLAGS_DOWN`. Despite the name this means "the key was already
    /// down", that is, an auto repeat, and not "this is a press"
    /// (PRDRDP/13 §5.3).
    pub const DOWN: u16 = 0x4000;
    /// `KBDFLAGS_RELEASE`.
    pub const RELEASE: u16 = 0x8000;
}

/// `TS_POINTER_EVENT.pointerFlags` (MS-RDPBCGR 2.2.8.1.1.3.1.1.3), shared by
/// the fast path pointer event (2.2.8.1.2.2.3).
///
/// The button constants carry the button they actually mean in their names.
/// The specification's `PTRFLAGS_BUTTON2` is the right button and
/// `PTRFLAGS_BUTTON3` is the middle button, which reads backwards and swaps
/// middle click with right click when it is got wrong (PRDRDP/05 §3.2).
pub mod pointer_flags {
    /// `PTRFLAGS_WHEEL_NEGATIVE`. The sign bit of the nine bit rotation, not
    /// a separate negate flag. See [`super::wheel_rotation_flags`].
    pub const WHEEL_NEGATIVE: u16 = 0x0100;
    /// `PTRFLAGS_WHEEL`, vertical.
    pub const WHEEL: u16 = 0x0200;
    /// `PTRFLAGS_HWHEEL`, horizontal. Only legal when both sides advertised
    /// `TS_INPUT_FLAG_MOUSE_HWHEEL` in the Input capability set
    /// (MS-RDPBCGR 2.2.7.1.6), which `rdp-core` checks.
    pub const HWHEEL: u16 = 0x0400;
    /// `PTRFLAGS_MOVE`.
    pub const MOVE: u16 = 0x0800;
    /// `PTRFLAGS_BUTTON1`, the left button.
    pub const BUTTON1_LEFT: u16 = 0x1000;
    /// `PTRFLAGS_BUTTON2`, the **right** button.
    pub const BUTTON2_RIGHT: u16 = 0x2000;
    /// `PTRFLAGS_BUTTON3`, the **middle** button.
    pub const BUTTON3_MIDDLE: u16 = 0x4000;
    /// `PTRFLAGS_DOWN`. A press is `DOWN | BUTTONn`, a release is `BUTTONn`
    /// alone.
    pub const DOWN: u16 = 0x8000;
    /// `WheelRotationMask`, the nine bits [`WHEEL_NEGATIVE`] signs.
    pub const WHEEL_ROTATION_MASK: u16 = 0x01ff;
}

/// `TS_POINTERX_EVENT.pointerFlags` (MS-RDPBCGR 2.2.8.1.1.3.1.1.4).
///
/// The extended pointer event has no move, no wheel and no left, right or
/// middle. It is legal only when the server advertised `INPUT_FLAG_MOUSEX`
/// (MS-RDPBCGR 2.2.7.1.6).
pub mod pointer_x_flags {
    /// `PTRXFLAGS_BUTTON1`, the "back" button, X1.
    pub const BUTTON1_BACK: u16 = 0x0001;
    /// `PTRXFLAGS_BUTTON2`, the "forward" button, X2.
    pub const BUTTON2_FORWARD: u16 = 0x0002;
    /// `PTRXFLAGS_DOWN`.
    pub const DOWN: u16 = 0x8000;
}

/// One wheel detent, `WHEEL_DELTA` on Windows (PRDRDP/05 §3.3).
pub const WHEEL_DELTA: i16 = 120;

/// The range a nine bit two's complement rotation can hold.
///
/// `rdp-core` clamps to this and splits a larger flick into several events
/// (PRDRDP/05 §3.3). In practice it never fires: the webview emits one
/// press and release pair per detent.
pub const WHEEL_RANGE: std::ops::RangeInclusive<i16> = -256..=255;

/// Pack a wheel rotation into a `pointerFlags` word (MS-RDPBCGR
/// 2.2.8.1.1.3.1.1.3, PRDRDP/13 §5.3).
///
/// The rotation is a signed nine bit value sharing the flags word, where
/// [`pointer_flags::WHEEL_NEGATIVE`] is its sign bit. Masking the `i16` with
/// [`pointer_flags::WHEEL_ROTATION_MASK`] therefore does the whole job: a
/// negative delta sets the sign bit as a side effect of two's complement.
/// One detent up is `PTRFLAGS_WHEEL | 0x0078`, one detent down is
/// `PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 0x0088`, because
/// `0x88 - 0x100 = -120`.
///
/// Returns [`PduError::Encode`] outside [`WHEEL_RANGE`] rather than
/// truncating, because a truncated rotation scrolls the wrong way.
pub fn wheel_rotation_flags(delta: i16, horizontal: bool) -> PduResult<u16> {
    if !WHEEL_RANGE.contains(&delta) {
        return Err(PduError::Encode {
            context: "TS_POINTER_EVENT",
            reason: "wheel rotation outside the nine bit range",
        });
    }
    let axis = if horizontal {
        pointer_flags::HWHEEL
    } else {
        pointer_flags::WHEEL
    };
    Ok(axis | ((delta as u16) & pointer_flags::WHEEL_ROTATION_MASK))
}

/// Unpack the rotation [`wheel_rotation_flags`] packed.
///
/// Meaningless unless one of [`pointer_flags::WHEEL`] or
/// [`pointer_flags::HWHEEL`] is set in the same word, which the caller checks;
/// the rotation bits overlap nothing else, so this is a pure bit extraction.
#[must_use]
pub const fn wheel_rotation(flags: u16) -> i16 {
    let raw = flags & pointer_flags::WHEEL_ROTATION_MASK;
    if raw & pointer_flags::WHEEL_NEGATIVE != 0 {
        // `raw` is at most 0x1FF, so the cast is exact and the subtraction
        // cannot overflow: the result lands in -256..=-1.
        (raw as i16) - 0x200
    } else {
        raw as i16
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The two byte patterns PRDRDP/05 §3.3 publishes, which are the only
    /// wheel bytes any document in this project states outright.
    #[test]
    fn one_detent_up_and_down_are_the_bytes_the_document_names() {
        let up = wheel_rotation_flags(WHEEL_DELTA, false).unwrap();
        assert_eq!(up, pointer_flags::WHEEL | 0x0078);
        assert_eq!(up & pointer_flags::WHEEL_NEGATIVE, 0);

        let down = wheel_rotation_flags(-WHEEL_DELTA, false).unwrap();
        assert_eq!(
            down,
            pointer_flags::WHEEL | pointer_flags::WHEEL_NEGATIVE | 0x0088
        );
    }

    #[test]
    fn horizontal_uses_its_own_axis_bit_and_the_same_rotation_bits() {
        let right = wheel_rotation_flags(WHEEL_DELTA, true).unwrap();
        assert_eq!(right, pointer_flags::HWHEEL | 0x0078);
        assert_eq!(wheel_rotation(right), WHEEL_DELTA);
    }

    /// The sign magnitude confusion this encoding invites, checked over the
    /// whole representable range rather than at a few points.
    #[test]
    fn every_representable_rotation_round_trips() {
        for delta in WHEEL_RANGE {
            let flags = wheel_rotation_flags(delta, false).unwrap();
            assert_eq!(wheel_rotation(flags), delta, "delta {delta}");
            assert_eq!(
                flags & pointer_flags::WHEEL_NEGATIVE != 0,
                delta < 0,
                "sign bit disagrees with the sign at {delta}"
            );
        }
    }

    #[test]
    fn a_rotation_outside_nine_bits_is_refused_rather_than_truncated() {
        assert!(wheel_rotation_flags(256, false).is_err());
        assert!(wheel_rotation_flags(-257, false).is_err());
        assert!(wheel_rotation_flags(2 * WHEEL_DELTA, false).is_ok());
        assert!(wheel_rotation_flags(-2 * WHEEL_DELTA, false).is_ok());
        // Three detents do not fit, which is what makes `rdp-core`'s split
        // necessary.
        assert!(wheel_rotation_flags(3 * WHEEL_DELTA, false).is_err());
    }

    /// The five buttons of PRDRDP/05 §3.4's mapping table, asserted as masks
    /// because the specification's own names read backwards.
    #[test]
    fn each_button_produces_the_mask_the_mapping_table_states() {
        assert_eq!(pointer_flags::BUTTON1_LEFT, 0x1000);
        assert_eq!(pointer_flags::BUTTON3_MIDDLE, 0x4000);
        assert_eq!(pointer_flags::BUTTON2_RIGHT, 0x2000);
        assert_eq!(pointer_x_flags::BUTTON1_BACK, 0x0001);
        assert_eq!(pointer_x_flags::BUTTON2_FORWARD, 0x0002);
        // A press sets DOWN as well; a release is the button alone.
        assert_eq!(
            pointer_flags::DOWN | pointer_flags::BUTTON2_RIGHT,
            0xa000,
            "right button press"
        );
    }

    #[test]
    fn the_sync_flags_fit_the_fast_path_low_nibble() {
        assert_eq!(sync_flags::ALL, 0x0f);
    }
}
