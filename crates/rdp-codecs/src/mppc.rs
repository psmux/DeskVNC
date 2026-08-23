//! MPPC and the RDP 6.1 bulk compression variants. **Phase 2 tail, not
//! implemented.**
//!
//! MPPC at 8K and 64K, and the RDP 6.1 variant (MS-RDPBCGR 3.1.8.4.1,
//! MS-RDPEGDI 3.1.8.2). A sliding history window plus a token stream, the
//! same shape as [`crate::zgfx`] and a different bitstream. Phase 1 does not
//! advertise bulk compression at all (PRDRDP/04 §4.13), so this is only
//! needed for a server that insists, which is why it is last.
//!
//! The stub this replaced also claimed the RDP 8.0 bulk decompressor. That
//! now lives in [`crate::zgfx`], where PRDRDP/04 §4.12 and §4.13 put the two
//! in separate files. They share a shape and nothing else: ZGFX is on the
//! EGFX path and taxes every EGFX codec, MPPC is on the legacy path and is
//! optional. Keeping them together would have meant one module with two
//! unrelated token tables and one fuzz target for two decoders.
//!
//! The history buffer is the persistent state and gets `new`, `reset` and
//! `bytes` per PRDRDP/04 §4.1 rule three.
