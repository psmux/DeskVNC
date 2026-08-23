//! The EGFX bitmap cache (MS-RDPEGFX 2.2.2.6, 2.2.2.7, 2.2.2.8,
//! PRDRDP/04 §3.7).
//!
//! A server puts a rectangle it expects to draw again into a numbered slot,
//! then pastes it back from the slot as often as it likes. On a real Windows
//! desktop that is where most of the saving is: a window border, a button, a
//! piece of the taskbar, decoded once and painted a hundred times without
//! another byte on the wire.
//!
//! # What is not here
//!
//! Persistence. MS-RDPEGFX 2.2.2.16 lets a client offer a cache it saved from
//! a previous session and the server reply with the slots it accepted. We do
//! not save one, so the offer we send is empty and the reply always says zero
//! (PRDRDP/04 §3.7). Nothing in this file needs to change to add it later; a
//! persistent cache is a loader and a saver around the same slot table.
//!
//! # The budget, and why a breach is an error
//!
//! MS-RDPEGFX 2.2.3.1 makes the cache 100 MB with the default capability set
//! and 16 MB with `RDPGFX_CAPS_FLAG_SMALL_CACHE`. We advertise the default,
//! so the server knows it has 100 MB and tracks its own usage against that
//! number; a server that goes past it has lost track of the session, and the
//! next `CACHE_TO_SURFACE` will paste something other than what it thinks.
//! Evicting an entry ourselves to stay inside the budget would produce
//! exactly that outcome silently, so the breach is reported instead.

use std::collections::HashMap;

use crate::error::{RdpError, Result};

/// The cache budget with the default capability set (MS-RDPEGFX 2.2.3.1).
///
/// One hundred megabytes, the specification's own decimal figure rather than
/// mebibytes: the number is what the server is told it has, so it is written
/// the way the server reads it.
pub const MAX_CACHE_BYTES: usize = 100_000_000;

/// The most slots the default capability set allows (MS-RDPEGFX 2.2.3.1).
pub const MAX_CACHE_SLOTS: usize = 25_600;

/// One cached rectangle, packed RGBA8888 exactly as a surface stores it.
#[derive(Debug)]
pub struct CacheEntry {
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// `width * height * 4` bytes.
    pub pixels: Vec<u8>,
}

/// The slot table.
///
/// A `HashMap` and not a `Vec`, which is the opposite of the call made for
/// surfaces and channels, and for the opposite reason: `cacheSlot` runs to
/// 25,600 and a server uses the space sparsely, so a `Vec` would be 25,600
/// entries of padding to hold a few hundred rectangles.
#[derive(Debug, Default)]
pub struct BitmapCache {
    slots: HashMap<u16, CacheEntry>,
    bytes: usize,
}

impl BitmapCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Entries held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// True when nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Bytes held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drop everything.
    ///
    /// `RDPGFX_RESET_GRAPHICS` restarts the session's graphics state, and a
    /// slot filled against the old one no longer means anything
    /// (MS-RDPEGFX 3.3.5.13).
    pub fn reset(&mut self) {
        self.slots.clear();
        self.bytes = 0;
    }

    /// `RDPGFX_SURFACE_TO_CACHE_PDU`: fill a slot (MS-RDPEGFX 2.2.2.6).
    ///
    /// `pixels` is taken by value because it becomes the entry; the caller's
    /// buffer for the next read comes back out of the slot it replaced, so a
    /// steady state cache does no allocation at all.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] for a slot number outside the advertised range
    /// or a fill that would take the cache past [`MAX_CACHE_BYTES`].
    pub fn put(&mut self, slot: u16, width: u16, height: u16, pixels: Vec<u8>) -> Result<Vec<u8>> {
        if usize::from(slot) > MAX_CACHE_SLOTS || slot == 0 {
            // MS-RDPEGFX 2.2.2.6 numbers slots from 1.
            return Err(RdpError::Protocol(format!(
                "the server filled cache slot {slot}, and the default capability set \
                 has slots 1 to {MAX_CACHE_SLOTS} (MS-RDPEGFX 2.2.3.1)"
            )));
        }
        let replacing = self.slots.get(&slot).map_or(0, |e| e.pixels.len());
        let after = self.bytes - replacing + pixels.len();
        if after > MAX_CACHE_BYTES {
            return Err(RdpError::Protocol(format!(
                "the server's graphics cache reached {after} bytes, past the \
                 {MAX_CACHE_BYTES} it was offered (MS-RDPEGFX 2.2.3.1)"
            )));
        }
        self.bytes = after;
        let previous = self.slots.insert(
            slot,
            CacheEntry {
                width,
                height,
                pixels,
            },
        );
        Ok(previous.map(|e| e.pixels).unwrap_or_default())
    }

    /// `RDPGFX_CACHE_TO_SURFACE_PDU`: read a slot (MS-RDPEGFX 2.2.2.7).
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] for a slot that was never filled. That is not a
    /// tolerable miss: the server believes a rectangle is there and the only
    /// alternative to stopping is painting the wrong pixels and never saying
    /// so.
    pub fn get(&self, slot: u16) -> Result<&CacheEntry> {
        self.slots.get(&slot).ok_or_else(|| {
            RdpError::Protocol(format!(
                "the server pasted from empty cache slot {slot} (MS-RDPEGFX 2.2.2.7)"
            ))
        })
    }

    /// `RDPGFX_EVICT_CACHE_ENTRY_PDU` (MS-RDPEGFX 2.2.2.8).
    ///
    /// Evicting an empty slot is not an error: a server that reset its own
    /// cache and then tidied up is describing a state we already have.
    pub fn evict(&mut self, slot: u16) {
        if let Some(entry) = self.slots.remove(&slot) {
            self.bytes = self.bytes.saturating_sub(entry.pixels.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_filled_read_back_and_evicted() {
        let mut cache = BitmapCache::new();
        assert!(cache.is_empty());

        let spare = cache.put(7, 2, 1, vec![0xAB; 8]).expect("fills");
        assert!(spare.is_empty(), "nothing was replaced");
        assert_eq!(cache.bytes(), 8);
        assert_eq!(cache.len(), 1);

        let entry = cache.get(7).expect("reads");
        assert_eq!((entry.width, entry.height), (2, 1));
        assert_eq!(entry.pixels.len(), 8);

        cache.evict(7);
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
        // Evicting again is a no op.
        cache.evict(7);
    }

    /// Refilling a slot hands the old buffer back, which is what makes a
    /// steady state cache allocation free.
    #[test]
    fn refilling_a_slot_returns_the_buffer_it_replaced() {
        let mut cache = BitmapCache::new();
        cache.put(1, 1, 1, vec![1; 4]).expect("fills");
        let recycled = cache.put(1, 1, 1, vec![2; 4]).expect("refills");
        assert_eq!(recycled, vec![1; 4]);
        assert_eq!(cache.bytes(), 4, "the byte count did not double count");
    }

    /// A paste from a slot nobody filled is a disagreement about session
    /// state, and painting whatever happens to be nearby would hide it.
    #[test]
    fn an_empty_slot_is_an_error_rather_than_a_silent_miss() {
        let cache = BitmapCache::new();
        let err = cache.get(3).expect_err("empty");
        assert!(err.to_string().contains("empty cache slot 3"), "{err}");
    }

    /// The two bounds a hostile server would push on: the slot number and the
    /// total size.
    #[test]
    fn the_slot_range_and_the_budget_are_both_enforced() {
        let mut cache = BitmapCache::new();
        let err = cache.put(0, 1, 1, vec![0; 4]).expect_err("slot zero");
        assert!(err.to_string().contains("slot 0"), "{err}");

        let err = cache
            .put(u16::MAX, 1, 1, vec![0; 4])
            .expect_err("past the range");
        assert!(err.to_string().contains("25600"), "{err}");

        // One byte past the budget, in one go.
        let err = cache
            .put(1, 1, 1, vec![0; MAX_CACHE_BYTES + 1])
            .expect_err("budget");
        assert!(err.to_string().contains("100000000"), "{err}");
        assert!(cache.is_empty(), "the refused entry was not stored");
    }
}
