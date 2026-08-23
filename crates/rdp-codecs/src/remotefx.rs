//! RemoteFX (MS-RDPRFX). **Phase 1b, not implemented.**
//!
//! A wavelet codec over 64 by 64 tiles, carried either as
//! `RDPGFX_CODECID_CAVIDEO` (0x0003) inside EGFX or as a Bitmap Codecs codec
//! id inside legacy Surface Commands (PRDRDP/04 §2.8). Both carry the same
//! bitstream.
//!
//! What lands here, in the order PRDRDP/04 §4.6 designs it:
//!
//! * The message structure: `TS_RFX_SYNC`, `TS_RFX_CODEC_VERSIONS`,
//!   `TS_RFX_CHANNELS`, `TS_RFX_CONTEXT`, `TS_RFX_FRAME_BEGIN`,
//!   `TS_RFX_REGION` (MS-RDPRFX 2.2.2.3.3), `TS_RFX_TILESET`
//!   (MS-RDPRFX 2.2.2.3.4) and `TS_RFX_FRAME_END`. All of it is self
//!   describing inside the codec payload, so all of it is this crate's under
//!   the boundary rule in PRDRDP/12 §2.2.2.
//! * The 64 by 64 subband layout and the decode order per component
//!   (MS-RDPRFX 2.2.2.1.6, 3.1.8).
//! * RLGR1 and RLGR3 entropy decode (MS-RDPRFX 3.1.8.1), on a `BitReader`
//!   with a 64 bit MSB first window.
//! * Differential decode of the LL3 band and inverse quantization
//!   (MS-RDPRFX 3.1.8.2).
//! * The three level inverse DWT (MS-RDPRFX 3.1.8.3).
//! * YCbCr to RGB with the exact coefficients of MS-RDPRFX 3.1.8.4.
//!
//! The stage budget in PRDRDP/04 §11.2 is the reason this is four benchmarks
//! rather than one: 2.0 ms for RLGR, 0.3 ms for dequantization, 1.9 ms for the
//! inverse DWT and 1.0 ms for the colour conversion and blit, at 1080p.
