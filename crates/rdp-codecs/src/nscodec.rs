//! NSCodec (MS-RDPNSC). **Phase 2, not implemented.**
//!
//! Four planes (Y, Co, Cg, alpha), each optionally run length encoded, with
//! chroma subsampling and a colour loss level, decoded through the inverse
//! YCoCg transform of MS-RDPNSC 3.1.6.
//!
//! PRDRDP/04 §2.8 is worth reading before this is written: we implement
//! NSCodec but do not advertise `CODEC_GUID_NSCODEC`, because ClearCodec's
//! subcodec layer can carry it and a legacy server that could choose it for
//! whole bitmaps would be choosing something strictly worse than RemoteFX for
//! the content it would pick it for.
//!
//! Its plane RLE is a different encoding from planar's (PRDRDP/04 §4.5.2) and
//! sharing code between the two would be a mistake, which is why this is its
//! own module rather than a flag on [`crate::planar`].
