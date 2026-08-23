//! AVC420 metablock parsing (MS-RDPEGFX 2.2.4.4, 2.2.4.5). **Phase 2, not
//! implemented.**
//!
//! This module never decodes video. `RDPGFX_AVC420_BITMAP_STREAM` is a
//! `RDPGFX_AVC420_METABLOCK` (a region of rectangles plus a quality value per
//! rectangle) followed by an H.264 Annex B access unit, and the access unit
//! goes to the webview's WebCodecs decoder over rect format 3, which
//! `src-tauri/FRAME_FORMAT.md` already defines (PRDRDP/04 §5.2).
//!
//! So what lands here is the metablock parse plus one `Bytes::slice`, and the
//! budget in PRDRDP/04 §11.1 is under 50 microseconds per frame for the Rust
//! side of it. AVC444 is out of scope (PRDRDP/00 R5).
