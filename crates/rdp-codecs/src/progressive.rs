//! Progressive RemoteFX (MS-RDPEGFX 2.2.4.2, decode rules 3.3.7).
//! **Phase 3, not implemented.** Behind the `progressive` cargo feature.
//!
//! `RDPGFX_CODECID_CAPROGRESSIVE` (0x0009). A second, larger RemoteFX decoder
//! with its own persistent tile store: the first pass carries a coarse tile
//! and later passes refine it in place, so a tile's coefficients survive
//! between frames and the store is the codec's whole memory budget
//! (12.7 MB at 1080p, 50.8 MB at 4K, PRDRDP/04 §4.9.4).
//!
//! It is feature gated rather than always compiled because that state and its
//! code are dead weight in a phase 1 binary and the fuzzer would have to cover
//! them anyway (PRDRDP/12 §2.2.2).
