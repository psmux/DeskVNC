//! Open H.264 (encoding 50), wire framing plus per-rectangle decoder-context
//! bookkeeping (PRD/02 §2.3).
//!
//! The payload is `U32 length + U32 flags + Annex-B frames`; flags bit0 is
//! `ResetContext` and bit1 is `ResetAllContexts`. A zero-length payload is a
//! pure control message (reset only, no frame).
//!
//! The actual video decode happens in the webview (WebCodecs `VideoDecoder`,
//! hardware-backed via VideoToolbox/D3D11/VAAPI), so this module owns only the
//! part that *must* live next to the protocol: which decoder each rectangle
//! belongs to, and when that decoder has to be thrown away and rebuilt.
//!
//! Contexts are keyed by rect geometry, capped at [`MAX_CONTEXTS`] (64) and
//! LRU-evicted. Context ids are slot indices in `0..MAX_CONTEXTS`, so the
//! webview's decoder map is bounded by construction: a reused slot always
//! arrives with `reset` set, which tells the frontend to tear the old decoder
//! down first.
//!
//! A decoder can only start on an IDR access unit, so a freshly created or
//! freshly reset context keeps reporting `reset = true` until a frame that
//! actually contains an IDR NAL arrives. Everything before that is
//! undecodable and the frontend drops it.

use tokio::io::{AsyncRead, AsyncReadExt};

use super::read_exact_vec;
use crate::error::Result;
use crate::types::{Rect, RectPayload};

/// Flags bit 0: drop the decoder context for this rectangle.
pub const FLAG_RESET_CONTEXT: u32 = 1 << 0;
/// Flags bit 1: drop every decoder context on the connection.
pub const FLAG_RESET_ALL_CONTEXTS: u32 = 1 << 1;

/// Maximum number of simultaneous decoder contexts (PRD/02 §2.3).
pub const MAX_CONTEXTS: usize = 64;

/// NAL unit type 5 = coded slice of an IDR picture.
const NAL_IDR_SLICE: u8 = 5;

// ---------------------------------------------------------------------------
// Context table
// ---------------------------------------------------------------------------

/// What identifies a decoder context: the rectangle's geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContextKey {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
}

impl From<Rect> for ContextKey {
    fn from(r: Rect) -> Self {
        Self {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Context {
    key: ContextKey,
    /// Monotonic tick of the last frame routed here (drives LRU eviction).
    last_used: u64,
    /// The decoder must be (re)built before this context can decode again.
    needs_reset: bool,
}

/// What the caller (and, downstream, the webview) needs to know about one
/// H.264 rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H264Meta {
    /// Decoder context slot, `0..`[`MAX_CONTEXTS`].
    pub context_id: u32,
    /// The context is new, was reset, or is still waiting for its first IDR:
    /// the frontend must (re)create the decoder for `context_id` before
    /// feeding it anything.
    pub reset: bool,
    /// The payload contains an IDR access unit, i.e. it can start a decoder.
    pub keyframe: bool,
}

/// Per-connection H.264 decoder-context table.
#[derive(Debug, Default)]
pub struct H264Contexts {
    slots: Vec<Option<Context>>,
    clock: u64,
}

impl H264Contexts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every context (reconnect, or `ResetAllContexts`).
    pub fn clear(&mut self) {
        self.slots.clear();
        self.clock = 0;
    }

    /// Number of live contexts, never more than [`MAX_CONTEXTS`].
    pub fn live(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Apply one rectangle's flags and payload to the context table.
    ///
    /// Order matters and mirrors the reference implementation: reset-all first,
    /// then the per-rect reset, then routing. `data` is inspected only to see
    /// whether it can start a decoder.
    pub fn track(&mut self, rect: Rect, flags: u32, data: &[u8]) -> H264Meta {
        if flags & FLAG_RESET_ALL_CONTEXTS != 0 {
            self.slots.fill(None);
        }
        let key = ContextKey::from(rect);
        if flags & FLAG_RESET_CONTEXT != 0 {
            if let Some(i) = self.find(key) {
                self.slots[i] = None;
            }
        }

        let keyframe = contains_idr(data);
        let idx = match self.find(key) {
            Some(i) => i,
            None => self.allocate(key),
        };

        self.clock += 1;
        let clock = self.clock;
        let ctx = self.slots[idx]
            .as_mut()
            .expect("slot was just found or allocated");
        ctx.last_used = clock;

        let reset = ctx.needs_reset;
        if !data.is_empty() {
            if keyframe {
                // From here on the decoder has a valid starting point.
                ctx.needs_reset = false;
            } else if reset {
                tracing::debug!(
                    context = idx,
                    rect = ?rect,
                    "H.264 context has no IDR yet; dropping undecodable frame"
                );
            }
        }

        H264Meta {
            context_id: idx as u32,
            reset,
            keyframe,
        }
    }

    fn find(&self, key: ContextKey) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| matches!(s, Some(c) if c.key == key))
    }

    /// Take a free slot, growing up to [`MAX_CONTEXTS`], else evict the
    /// least-recently-used one.
    fn allocate(&mut self, key: ContextKey) -> usize {
        let fresh = Context {
            key,
            last_used: self.clock,
            needs_reset: true,
        };

        if let Some(i) = self.slots.iter().position(|s| s.is_none()) {
            self.slots[i] = Some(fresh);
            return i;
        }
        if self.slots.len() < MAX_CONTEXTS {
            self.slots.push(Some(fresh));
            return self.slots.len() - 1;
        }

        let victim = self
            .slots
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.as_ref().map(|c| c.last_used).unwrap_or(0))
            .map(|(i, _)| i)
            .unwrap_or(0);
        tracing::debug!(
            context = victim,
            "evicting least-recently-used H.264 context"
        );
        self.slots[victim] = Some(fresh);
        victim
    }
}

// ---------------------------------------------------------------------------
// Annex-B inspection
// ---------------------------------------------------------------------------

/// True if the Annex-B byte stream contains an IDR slice (NAL type 5), i.e.
/// the frame a decoder is allowed to start on.
///
/// Deliberately tolerant: it scans for both 3- and 4-byte start codes and
/// ignores anything it does not recognise, because the bytes come from an
/// untrusted server and are never parsed further here.
pub fn contains_idr(data: &[u8]) -> bool {
    nal_types(data).any(|t| t == NAL_IDR_SLICE)
}

/// Iterate the NAL unit types in an Annex-B byte stream.
fn nal_types(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i + 3 <= data.len() {
            let three = data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1;
            let four = i + 4 <= data.len()
                && data[i] == 0
                && data[i + 1] == 0
                && data[i + 2] == 0
                && data[i + 3] == 1;
            if four {
                i += 4;
            } else if three {
                i += 3;
            } else {
                i += 1;
                continue;
            }
            if i < data.len() {
                let header = data[i];
                i += 1;
                // forbidden_zero_bit must be 0 for a valid NAL header.
                if header & 0x80 == 0 {
                    return Some(header & 0x1f);
                }
            }
        }
        None
    })
}

// ---------------------------------------------------------------------------
// Wire decode
// ---------------------------------------------------------------------------

/// Read one encoding-50 rectangle payload and route it to a decoder context.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    contexts: &mut H264Contexts,
) -> Result<RectPayload> {
    let len = reader.read_u32().await? as usize;
    let flags = reader.read_u32().await?;
    let data = read_exact_vec(reader, len, "h264").await?;
    let meta = contexts.track(rect, flags, &data);
    Ok(RectPayload::H264 {
        data,
        flags,
        context_id: meta.context_id,
        reset: meta.reset,
        keyframe: meta.keyframe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nal(start4: bool, header: u8, body: &[u8]) -> Vec<u8> {
        let mut v = if start4 {
            vec![0, 0, 0, 1]
        } else {
            vec![0, 0, 1]
        };
        v.push(header);
        v.extend_from_slice(body);
        v
    }

    fn idr() -> Vec<u8> {
        let mut v = nal(true, 0x67, &[0x42, 0x00, 0x1e]); // SPS
        v.extend(nal(false, 0x68, &[0xce, 0x3c, 0x80])); // PPS
        v.extend(nal(true, 0x65, &[0x88, 0x84, 0x00])); // IDR slice
        v
    }

    fn delta() -> Vec<u8> {
        nal(false, 0x41, &[0x9a, 0x00])
    }

    #[test]
    fn detects_idr_and_delta() {
        assert!(contains_idr(&idr()));
        assert!(!contains_idr(&delta()));
        assert!(!contains_idr(&[]));
        assert!(!contains_idr(&[0, 0, 1]));
        // A NAL with the forbidden bit set is not trusted.
        assert!(!contains_idr(&nal(true, 0x85, &[0x00])));
    }

    #[test]
    fn context_is_keyed_by_geometry() {
        let mut c = H264Contexts::new();
        let a = c.track(Rect::new(0, 0, 64, 64), 0, &idr());
        let b = c.track(Rect::new(0, 0, 64, 64), 0, &delta());
        let other = c.track(Rect::new(64, 0, 64, 64), 0, &idr());
        assert_eq!(a.context_id, b.context_id);
        assert_ne!(a.context_id, other.context_id);
        assert!(a.reset, "a brand new context must be reported as reset");
        assert!(!b.reset, "an established context is not reset");
        assert_eq!(c.live(), 2);
    }

    #[test]
    fn new_context_waits_for_an_idr() {
        let mut c = H264Contexts::new();
        let r = Rect::new(0, 0, 32, 32);
        let first = c.track(r, 0, &delta());
        assert!(first.reset);
        assert!(!first.keyframe, "no IDR in a delta frame");
        // Still undecodable: reset stays sticky until a keyframe shows up.
        let second = c.track(r, 0, &delta());
        assert!(second.reset);
        let third = c.track(r, 0, &idr());
        assert!(third.reset, "the IDR frame itself still starts the decoder");
        assert!(third.keyframe);
        let fourth = c.track(r, 0, &delta());
        assert!(!fourth.reset);
    }

    #[test]
    fn reset_context_only_touches_its_own() {
        let mut c = H264Contexts::new();
        let a = Rect::new(0, 0, 16, 16);
        let b = Rect::new(16, 0, 16, 16);
        c.track(a, 0, &idr());
        c.track(b, 0, &idr());
        assert!(!c.track(a, 0, &delta()).reset);
        let reset = c.track(a, FLAG_RESET_CONTEXT, &idr());
        assert!(reset.reset);
        assert!(!c.track(b, 0, &delta()).reset, "b must be untouched");
        assert_eq!(c.live(), 2);
    }

    #[test]
    fn reset_all_contexts_drops_everything() {
        let mut c = H264Contexts::new();
        let a = Rect::new(0, 0, 16, 16);
        let b = Rect::new(16, 0, 16, 16);
        c.track(a, 0, &idr());
        c.track(b, 0, &idr());
        // Zero-length control message: reset everything, decode nothing.
        let ctrl = c.track(a, FLAG_RESET_ALL_CONTEXTS, &[]);
        assert!(ctrl.reset);
        assert!(!ctrl.keyframe);
        assert!(c.track(b, 0, &delta()).reset, "b was reset too");
        assert!(c.track(a, 0, &delta()).reset);
    }

    #[test]
    fn lru_eviction_at_64_contexts() {
        let mut c = H264Contexts::new();
        let rect_at = |i: usize| Rect::new((i * 8) as u16, 0, 8, 8);

        for i in 0..MAX_CONTEXTS {
            let m = c.track(rect_at(i), 0, &idr());
            assert_eq!(m.context_id as usize, i, "slots fill in order");
        }
        assert_eq!(c.live(), MAX_CONTEXTS);

        // Touch slot 0 so slot 1 becomes the least-recently-used.
        let zero = c.track(rect_at(0), 0, &delta());
        assert_eq!(zero.context_id, 0);
        assert!(!zero.reset);

        // One geometry too many: the LRU victim (slot 1) is recycled.
        let evicting = c.track(rect_at(MAX_CONTEXTS), 0, &idr());
        assert_eq!(evicting.context_id, 1, "slot 1 was least recently used");
        assert!(evicting.reset);
        assert_eq!(c.live(), MAX_CONTEXTS, "never more than 64 live contexts");

        // The evicted geometry comes back as a brand-new context elsewhere.
        let returning = c.track(rect_at(1), 0, &idr());
        assert!(returning.reset);
        assert_ne!(returning.context_id, 1);
        assert_eq!(c.live(), MAX_CONTEXTS);

        // Slot 0 survived the whole thing.
        assert!(!c.track(rect_at(0), 0, &delta()).reset);
    }

    #[tokio::test]
    async fn decode_reads_length_flags_and_data() {
        let mut contexts = H264Contexts::new();
        let frame = idr();
        let mut wire = Vec::new();
        wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        wire.extend_from_slice(&FLAG_RESET_ALL_CONTEXTS.to_be_bytes());
        wire.extend_from_slice(&frame);

        let mut r: &[u8] = &wire;
        let payload = decode(&mut r, Rect::new(0, 0, 8, 8), &mut contexts)
            .await
            .unwrap();
        match payload {
            RectPayload::H264 {
                data,
                flags,
                context_id,
                reset,
                keyframe,
            } => {
                assert_eq!(data, frame);
                assert_eq!(flags, FLAG_RESET_ALL_CONTEXTS);
                assert_eq!(context_id, 0);
                assert!(reset);
                assert!(keyframe);
            }
            other => panic!("expected H264, got {other:?}"),
        }
        assert!(r.is_empty(), "the decoder must consume the whole payload");
    }
}
