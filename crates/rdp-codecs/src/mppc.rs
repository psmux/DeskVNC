//! Bulk decompression. **Phase 2, not implemented.**
//!
//! Two unrelated things share this module because they share a shape, a
//! sliding history window plus a token stream, and neither is on the EGFX
//! path:
//!
//! * MPPC at 8K and 64K, and the RDP 6.1 variant
//!   (MS-RDPBCGR 3.1.8.4.1, MS-RDPEGDI 3.1.8.2). Phase 1 does not advertise
//!   bulk compression at all (PRDRDP/04 §4.13), so this is only needed for a
//!   server that insists.
//! * RDP 8.0 bulk decompression, ZGFX (MS-RDPEGFX 3.1.8), which wraps every
//!   EGFX PDU and therefore taxes every EGFX codec at once. PRDRDP/04 §11.2
//!   puts it in the `rdp_stage` bench group for exactly that reason, with a
//!   target of 400 MB/s of output.
//!
//! The history buffer is the persistent state and gets `new`, `reset` and
//! `bytes` per PRDRDP/04 §4.1 rule three.
