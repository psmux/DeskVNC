//! ClearCodec (MS-RDPEGFX 2.2.4.1, decode rules 3.3.8.1.3). **Phase 2, not
//! implemented.**
//!
//! `RDPGFX_CODECID_CLEARCODEC` (0x0008). Three layers over one bitmap, and a
//! glyph cache and a VBar cache that persist across calls:
//!
//! * The residual layer: run length encoded raw pixels.
//! * The bands layer: vertical bars, either literal or referenced from the
//!   VBar cache, which is where the persistent state lives.
//! * The subcodec layer: a nested RAW, NSCodec or RLEX bitmap over a
//!   sub rectangle.
//!
//! Both caches get `new`, `reset` and `bytes` per PRDRDP/04 §4.1 rule three,
//! and a cache miss or a sequence gap returns [`crate::DecodeError::StateLost`]
//! so `rdp-core` can ask for a repaint instead of failing the session
//! (PRDRDP/04 §4.8).
