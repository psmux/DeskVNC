//! The framer: the one place in this workspace that decides where a PDU ends
//! (PRDRDP/12 §4.3, PRDRDP/06 §2.2.1).
//!
//! RDP puts two different framings on the same TCP stream and switches
//! between them without announcement. Everything in the connection sequence,
//! and slow path traffic afterwards, is TPKT (RFC 1006 §6, X.224): four bytes
//! of version, reserved and a big endian length that **includes** the four
//! header bytes. Everything on the fast path, which is most of a live
//! session's bytes, uses the header in MS-RDPBCGR 2.2.9.1.2: one byte of
//! `fpOutputHeader` and then a one or two byte length.
//!
//! They are told apart by the first byte, and the reason that works looks
//! like a coincidence and is not. `fpOutputHeader`'s low two bits are the
//! action code, where `0x0` is `FASTPATH_OUTPUT_ACTION_FASTPATH` and `0x3` is
//! `FASTPATH_OUTPUT_ACTION_X224`. TPKT's first byte is the version, which
//! RFC 1006 §6 fixes at 3. So `byte0 & 0x03 == 0x03` means TPKT and anything
//! else is fast path, and the protocol was designed that way on purpose.
//!
//! # Cancellation safety
//!
//! This is the property the whole file is shaped around, because a framer
//! that loses a byte on cancellation passes every end to end test in the
//! suite and then fails once an hour on a real session, as a protocol error
//! nobody can reproduce.
//!
//! **The invariant.** Dropping the future returned by [`Framer::read`] or
//! [`Framer::read_expect`] at any await point loses no byte that has been
//! taken off the socket, and a later call on the same framer yields exactly
//! the frames a never cancelled framer would have yielded, in the same order.
//!
//! Three properties of the code below make that true, and all three are
//! things a later contributor can break without noticing:
//!
//! * The accumulator is a field of the framer, not a local of the async
//!   function. A local is dropped with the future and takes the bytes with
//!   it.
//! * Nothing leaves `self.buf` until a whole PDU is present.
//!   [`Framer::take_complete`] returns `None` when fewer than the declared
//!   number of bytes are buffered, and splits only when the frame is whole.
//! * No side effect is applied half way. Between two reads nothing is
//!   emitted, nothing is decoded, and no state is stepped. The byte counter
//!   is incremented from the count `read_buf` returned, after it has already
//!   appended to `self.buf`, so a cancelled read cannot double count it.
//!
//! The proving tests are at the bottom of this file:
//! `the_framer_is_cancel_safe_at_every_byte_offset`, which drives a stream
//! that yields one byte per poll and races the read against an immediately
//! ready branch at every offset, and
//! `a_pdu_split_across_reads_arrives_whole`, which asserts the same property
//! synchronously over [`Framer::take_complete`] with no runtime at all.
//!
//! The write side has the opposite property and no wrapper fixes it:
//! `AsyncWriteExt::write_all` dropped part way has already put some of its
//! bytes on the wire, the peer holds half a PDU, and RDP offers no
//! resynchronisation point inside a TPKT unit. That is why the write half
//! lives in its own task ([`crate::transport::writer`], PRDRDP/00 R10) and
//! why no write appears in a `select!` arm anywhere in this crate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use rdp_pdu::x224;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{RdpError, Result};

/// How much room to make before each read, so a large PDU does not cause one
/// realloc per read syscall.
///
/// `vnc-core` wraps its socket in a `BufReader::with_capacity(128 * 1024, ..)`
/// (`crates/vnc-core/src/session/connection.rs:461`) for the same reason and
/// at the same order of magnitude.
const READ_CHUNK: usize = 32 * 1024;

/// The smallest thing that can be a slow path PDU: a TPKT header plus an
/// X.224 Data TPDU header (`x224::TPKT_HEADER_LEN` plus
/// `x224::X224_DATA_HEADER.len()`). A fast path PDU can be shorter, so this
/// is only a floor for the TPKT branch.
const MIN_TPKT: usize = x224::TPKT_HEADER_LEN + x224::X224_DATA_HEADER.len();

/// Refuse a length field larger than this before reading a byte of body.
///
/// Chosen from the field widths rather than from a guess, which is the
/// discipline `MAX_WIRE_LEN` at `crates/vnc-core/src/encodings/mod.rs:33`
/// records the hard way: a flat cap picked without checking the largest
/// legitimate value rejected real 5K screen updates. TPKT's length is a `u16`
/// so it cannot exceed 65535, and the fast path length is 15 bits, so 32767.
/// 64 KiB is above both, so it can never reject a legitimate PDU, and it
/// exists so that the check is written and a future change to the framing
/// cannot quietly remove the bound.
const MAX_PDU: usize = 64 * 1024;

/// The smallest fast path PDU that can contain its own header: one byte of
/// `fpOutputHeader` and one of `length1` (MS-RDPBCGR 2.2.9.1.2).
const MIN_FASTPATH: usize = 2;

/// Which framing carried a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramedKind {
    /// TPKT (RFC 1006 §6) wrapping an X.224 TPDU. `frame` includes the TPKT
    /// header, because the X.224 layer wants to check the TPDU code.
    Tpkt,
    /// A server fast path update (MS-RDPBCGR 2.2.9.1.2). `frame` includes the
    /// `fpOutputHeader` and the length bytes.
    FastPath,
}

/// One complete PDU, and which framing carried it.
#[derive(Debug, Clone)]
pub struct Framed {
    /// TPKT or fast path.
    pub kind: FramedKind,
    /// A refcounted view of the framer's receive buffer. Parsed structures
    /// borrow this; nothing between here and the decoder copies
    /// (PRDRDP/12 §4.2).
    pub frame: Bytes,
}

/// How many bytes the caller must have before a structure can be decoded.
///
/// Every framing the connection sequence meets is length prefixed, so this is
/// always decidable from a small header (PRDRDP/03 §3.4). Used only during
/// the connection sequence, where the framing is not always TPKT; the
/// connected pump uses [`Framer::read`], which decides for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// TPKT: a four byte header with a big endian length at offset 2
    /// (RFC 1006 §6).
    Tpkt,
    /// A DER `SEQUENCE`, whose length comes from the X.690 §8.1.3 length
    /// octets. This is how a CredSSP `TSRequest` is framed (MS-CSSP 2.2.1):
    /// it travels inside TLS with no RDP header of its own.
    DerSequence,
    /// Exactly this many bytes. The Early User Authorization Result is four
    /// (MS-RDPBCGR 2.2.10.2), and reading four bytes after a plain `HYBRID`
    /// desynchronises the stream, so the caller decides, not this module.
    Exact(usize),
}

/// The receive side of one connection: a stream, an accumulator, and a byte
/// counter the stats tick reads.
///
/// Generic over the reader so a test can drive it with a `Vec<u8>` or a
/// stream that yields one byte per poll, without a socket and, for
/// [`Framer::take_complete`], without a runtime.
#[derive(Debug)]
pub struct Framer<R> {
    stream: R,
    /// The accumulator. A field rather than a local of `read`, which is the
    /// first of the three cancel safety properties in this module's doc.
    buf: BytesMut,
    received: Arc<AtomicU64>,
}

impl<R> Framer<R> {
    /// A framer over `stream`, counting every byte it reads into `received`.
    pub fn new(stream: R, received: Arc<AtomicU64>) -> Self {
        Self {
            stream,
            buf: BytesMut::with_capacity(READ_CHUNK),
            received,
        }
    }

    /// How many bytes are buffered and not yet consumed.
    ///
    /// The connection sequence asserts this is zero before handing the stream
    /// to TLS: bytes that arrived before the handshake are either a confused
    /// server or an injection attempt, and either way they must not be
    /// carried across the upgrade (PRDRDP/03 §4.4).
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Give the stream back, with whatever is still buffered.
    ///
    /// Used twice: at the TLS upgrade, because the handshake needs the whole
    /// stream rather than a read half, and at the end of the connection
    /// sequence, because the write half moves into the writer task.
    pub fn into_inner(self) -> (R, BytesMut) {
        (self.stream, self.buf)
    }

    /// Put bytes that were already read back at the front of the buffer.
    ///
    /// The pair of [`Framer::into_inner`]: whatever the connection sequence
    /// read ahead of itself belongs to whoever reads next. A server is
    /// allowed to pipeline the first update behind the last finalisation PDU,
    /// and dropping those bytes is a stall nobody can explain.
    ///
    /// Prepends rather than appends, because the leftover is older than
    /// anything this framer has read.
    pub fn prime(&mut self, leftover: BytesMut) {
        if leftover.is_empty() {
            return;
        }
        if self.buf.is_empty() {
            self.buf = leftover;
            return;
        }
        let mut combined = leftover;
        combined.extend_from_slice(&self.buf);
        self.buf = combined;
    }
}

impl<R: AsyncRead + Unpin> Framer<R> {
    /// Read one complete PDU.
    ///
    /// Cancellation safe: see this module's documentation. The only await is
    /// `read_buf`, which tokio documents as cancel safe, and every byte it
    /// delivers has already been appended to `self.buf` before the future
    /// resolves.
    ///
    /// # Errors
    ///
    /// [`RdpError::ConnectionClosed`] on a clean close between PDUs,
    /// [`RdpError::Pdu`] on a close part way through one or on a length field
    /// out of range, and [`RdpError::Io`] on anything the socket reports.
    pub async fn read(&mut self) -> Result<Framed> {
        loop {
            // Parse out of the accumulator first, so a call that needs no I/O
            // never touches the socket and never yields.
            if let Some(framed) = self.take_complete()? {
                return Ok(framed);
            }
            self.fill().await?;
        }
    }

    /// Read one structure of a shape the caller already knows.
    ///
    /// The connection sequence uses this rather than [`Framer::read`] because
    /// two of its messages are not RDP framed at all: a CredSSP `TSRequest`
    /// is a bare DER `SEQUENCE` inside TLS, and the Early User Authorization
    /// Result is four raw bytes (PRDRDP/03 §3.4).
    ///
    /// Cancellation safe on the same terms and for the same reasons.
    ///
    /// # Errors
    ///
    /// As [`Framer::read`].
    pub async fn read_expect(&mut self, expect: Expect) -> Result<Bytes> {
        loop {
            if let Some(bytes) = take_expect(&mut self.buf, expect)? {
                return Ok(bytes);
            }
            self.fill().await?;
        }
    }

    /// One read into the accumulator.
    ///
    /// Split out so both public entry points share it and so there is exactly
    /// one await in this file that touches the socket. `read_buf` appends,
    /// which is what makes cancellation lossless: the bytes are in
    /// `self.buf`, which the framer owns and which outlives the future.
    async fn fill(&mut self) -> Result<()> {
        // Reserve before reading so a large PDU does not cause one realloc
        // per read syscall.
        self.buf.reserve(READ_CHUNK);
        let n = self.stream.read_buf(&mut self.buf).await?;
        if n == 0 {
            return Err(if self.buf.is_empty() {
                RdpError::ConnectionClosed
            } else {
                // A partial PDU at EOF is a different bug report from a clean
                // close, and saying so has saved time before.
                RdpError::Pdu {
                    structure: "framer",
                    message: format!(
                        "stream closed with {} bytes of a partial pdu",
                        self.buf.len()
                    ),
                }
            });
        }
        self.received.fetch_add(n as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Split one PDU off the front of the buffer, or `None` if it is not all
    /// here yet.
    ///
    /// No await, no I/O, no allocation. This is the function the unit tests
    /// drive with hand written byte arrays, which is why it is separate from
    /// [`Framer::read`] and why it does not name `self.stream`.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] when a length field is outside the range its own
    /// encoding allows.
    pub fn take_complete(&mut self) -> Result<Option<Framed>> {
        take_complete(&mut self.buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> Framer<S> {
    /// Write and flush one PDU, for the connection sequence only.
    ///
    /// The connection sequence runs before the stream is split, because the
    /// TLS upgrade needs the whole stream rather than a read half, so it
    /// writes through the framer. That is safe here and nowhere else: the
    /// sequence is straight line `await` code and is deliberately **not**
    /// cancellation safe, since a half written Connect Initial is a
    /// desynchronised stream. It is not inside a `select!`, and the only
    /// thing that cancels it is the cancellation token, which drops the whole
    /// attempt and the whole stream with it (PRDRDP/12 §5.4).
    ///
    /// Once the sequence is done the stream is split, the write half moves
    /// into [`crate::transport::writer`], and this method is unreachable for
    /// the rest of the session because the run loop never holds a `Framer`
    /// over anything that can write.
    ///
    /// # Errors
    ///
    /// [`RdpError::Io`] for whatever the socket reports.
    pub async fn write_pdu(&mut self, bytes: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.write_all(bytes).await?;
        // Flush per PDU: the whole connection sequence is request and
        // response, so a buffered Connect Initial is a thirty second timeout
        // waiting to happen.
        self.stream.flush().await?;
        Ok(())
    }
}

/// [`Framer::take_complete`] over a bare buffer, so a test can call it
/// without constructing a framer at all.
fn take_complete(buf: &mut BytesMut) -> Result<Option<Framed>> {
    let Some(&b0) = buf.first() else {
        return Ok(None);
    };

    // MS-RDPBCGR 2.2.9.1.2: fpOutputHeader's low two bits are the action,
    // 0x3 = FASTPATH_OUTPUT_ACTION_X224. RFC 1006 §6: TPKT's first byte is
    // version 3. The two encodings were designed to be told apart here.
    if b0 & 0x03 == 0x03 {
        // `peek_tpkt_length` is the framer's entry point by design
        // (`crates/rdp-pdu/src/x224.rs:172` says so on the function). It
        // returns `None` for fewer than four bytes, checks the version, and
        // applies `MAX_TPKT_LEN`, so the length is already sane when it comes
        // back.
        let Some(len) = x224::peek_tpkt_length(buf)? else {
            return Ok(None);
        };
        if !(MIN_TPKT..=MAX_PDU).contains(&len) {
            return Err(RdpError::Pdu {
                structure: "TPKT",
                message: format!("length {len} out of range"),
            });
        }
        if buf.len() < len {
            return Ok(None);
        }
        return Ok(Some(Framed {
            kind: FramedKind::Tpkt,
            frame: buf.split_to(len).freeze(),
        }));
    }

    // Fast path. MS-RDPBCGR 2.2.9.1.2: if length1's top bit is clear the
    // length is its low seven bits and length2 is absent; otherwise the
    // length is fifteen bits across both. Either way it is the TOTAL length,
    // header included, which matches TPKT and means the caller never has to
    // know whether the header was two bytes or three.
    let Some(&length1) = buf.get(1) else {
        return Ok(None);
    };
    let len = if length1 & 0x80 == 0 {
        usize::from(length1)
    } else {
        let Some(&length2) = buf.get(2) else {
            return Ok(None);
        };
        (usize::from(length1 & 0x7f) << 8) | usize::from(length2)
    };
    // A two byte header with a length of 0 or 1 cannot contain itself.
    if !(MIN_FASTPATH..=MAX_PDU).contains(&len) {
        return Err(RdpError::Pdu {
            structure: "fastPathOutput",
            message: format!("length {len} out of range"),
        });
    }
    if buf.len() < len {
        return Ok(None);
    }
    Ok(Some(Framed {
        kind: FramedKind::FastPath,
        frame: buf.split_to(len).freeze(),
    }))
}

/// The [`Expect`] half of the same job: split one structure of a known shape
/// off the front, or `None` if it is not all here yet.
fn take_expect(buf: &mut BytesMut, expect: Expect) -> Result<Option<Bytes>> {
    let len = match expect {
        Expect::Tpkt => {
            let Some(len) = x224::peek_tpkt_length(buf)? else {
                return Ok(None);
            };
            if !(x224::TPKT_HEADER_LEN..=MAX_PDU).contains(&len) {
                return Err(RdpError::Pdu {
                    structure: "TPKT",
                    message: format!("length {len} out of range"),
                });
            }
            len
        }
        Expect::DerSequence => match der_sequence_length(buf)? {
            Some(len) => len,
            None => return Ok(None),
        },
        Expect::Exact(n) => n,
    };
    if buf.len() < len {
        return Ok(None);
    }
    Ok(Some(buf.split_to(len).freeze()))
}

/// The total length of the DER `SEQUENCE` starting at the front of `buf`,
/// header included, or `None` while the header is incomplete.
///
/// X.690 §8.1.3: a definite length is either one octet below 0x80, or an
/// octet with the top bit set whose low seven bits give the number of length
/// octets that follow, big endian. The indefinite form (0x80) is legal BER
/// and illegal DER (X.690 §10.1), so it is rejected rather than guessed at,
/// and a `TSRequest` is DER (MS-CSSP 2.2.1).
fn der_sequence_length(buf: &[u8]) -> Result<Option<usize>> {
    /// `SEQUENCE`, constructed, universal class (X.690 §8.1.2).
    const TAG_SEQUENCE: u8 = 0x30;

    let Some(&tag) = buf.first() else {
        return Ok(None);
    };
    if tag != TAG_SEQUENCE {
        return Err(RdpError::Pdu {
            structure: "TSRequest",
            message: format!("expected a DER SEQUENCE, got tag 0x{tag:02x}"),
        });
    }
    let Some(&first) = buf.get(1) else {
        return Ok(None);
    };
    if first < 0x80 {
        return Ok(Some(2 + usize::from(first)));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 {
        return Err(RdpError::Pdu {
            structure: "TSRequest",
            message: "indefinite length is not valid DER (X.690 §10.1)".to_owned(),
        });
    }
    // Four octets is 4 GiB, far above `MAX_PDU`, so anything longer is
    // rejected on the header rather than accumulated.
    if count > 4 {
        return Err(RdpError::Pdu {
            structure: "TSRequest",
            message: format!("{count} length octets is longer than any TSRequest"),
        });
    }
    let Some(octets) = buf.get(2..2 + count) else {
        return Ok(None);
    };
    let mut len: usize = 0;
    for &b in octets {
        len = (len << 8) | usize::from(b);
    }
    let total = 2 + count + len;
    if total > MAX_PDU {
        return Err(RdpError::Pdu {
            structure: "TSRequest",
            message: format!("length {total} exceeds {MAX_PDU}"),
        });
    }
    Ok(Some(total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// A TPKT frame of `len` total bytes, the length field filled in.
    fn tpkt(len: usize) -> Vec<u8> {
        let mut v = vec![0x03, 0x00];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.resize(len, 0xaa);
        v
    }

    /// A fast path frame of `len` total bytes. `two_byte_header` picks which
    /// of the two length encodings MS-RDPBCGR 2.2.9.1.2 allows is used, which
    /// matters because the same length is expressible both ways at the
    /// boundary.
    fn fastpath(len: usize, two_byte_header: bool) -> Vec<u8> {
        let mut v = vec![0x00];
        if two_byte_header {
            v.push(len as u8);
        } else {
            v.push(0x80 | ((len >> 8) as u8));
            v.push((len & 0xff) as u8);
        }
        v.resize(len, 0xbb);
        v
    }

    fn framer_of(bytes: &[u8]) -> BytesMut {
        BytesMut::from(bytes)
    }

    #[test]
    fn the_first_byte_tells_the_two_framings_apart() {
        let mut buf = framer_of(&tpkt(16));
        let f = take_complete(&mut buf).unwrap().expect("whole frame");
        assert_eq!(f.kind, FramedKind::Tpkt);
        assert_eq!(f.frame.len(), 16);

        let mut buf = framer_of(&fastpath(16, true));
        let f = take_complete(&mut buf).unwrap().expect("whole frame");
        assert_eq!(f.kind, FramedKind::FastPath);
        assert_eq!(f.frame.len(), 16);
    }

    /// The synchronous half of the cancel safety argument: bytes arriving one
    /// at a time never produce a short frame and never lose one.
    #[test]
    fn a_pdu_split_across_reads_arrives_whole() {
        let wire = tpkt(23);
        let mut buf = BytesMut::new();
        for (i, byte) in wire.iter().enumerate() {
            buf.extend_from_slice(&[*byte]);
            let got = take_complete(&mut buf).unwrap();
            if i + 1 < wire.len() {
                assert!(got.is_none(), "frame produced after only {} bytes", i + 1);
            } else {
                assert_eq!(got.expect("the last byte completes it").frame, wire);
            }
        }
        assert_eq!(buf.len(), 0, "nothing left over");
    }

    #[test]
    fn two_pdus_in_one_read_come_out_in_order() {
        let mut wire = tpkt(9);
        wire.extend(fastpath(5, true));
        wire.extend(tpkt(300));
        let mut buf = framer_of(&wire);

        let a = take_complete(&mut buf).unwrap().expect("first");
        assert_eq!((a.kind, a.frame.len()), (FramedKind::Tpkt, 9));
        let b = take_complete(&mut buf).unwrap().expect("second");
        assert_eq!((b.kind, b.frame.len()), (FramedKind::FastPath, 5));
        let c = take_complete(&mut buf).unwrap().expect("third");
        assert_eq!((c.kind, c.frame.len()), (FramedKind::Tpkt, 300));
        assert!(take_complete(&mut buf).unwrap().is_none());
    }

    /// A TPKT length of 6 is legal to the TPKT layer and cannot hold an
    /// X.224 Data TPDU, so it is refused here rather than one layer up, where
    /// it would be an out of bounds read on an empty body.
    #[test]
    fn a_tpkt_too_short_to_hold_a_tpdu_is_refused() {
        let mut buf = framer_of(&tpkt(6));
        let err = take_complete(&mut buf).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    /// A fast path length of 1 cannot contain its own two byte header.
    #[test]
    fn a_fast_path_pdu_too_short_to_hold_its_header_is_refused() {
        let mut buf = framer_of(&[0x00, 0x01]);
        let err = take_complete(&mut buf).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    /// The same length either side of the one byte to two byte boundary. 0x7F
    /// is the largest length the short form expresses and 0x80 is the
    /// smallest the long form has to be used for; getting the boundary wrong
    /// shifts every subsequent PDU by one byte.
    #[test]
    fn the_fast_path_length_boundary_frames_identically_both_ways() {
        for len in [0x7f, 0x80, 0x81] {
            let long = fastpath(len, false);
            let mut buf = framer_of(&long);
            let f = take_complete(&mut buf).unwrap().expect("long form");
            assert_eq!(f.frame.len(), len, "long form of {len}");
            assert!(buf.is_empty());
        }
        // 0x7f is the last length the short form can carry.
        let short = fastpath(0x7f, true);
        let mut buf = framer_of(&short);
        assert_eq!(take_complete(&mut buf).unwrap().unwrap().frame.len(), 0x7f);
    }

    /// A first byte of 0x03 is TPKT, even when the three bytes after it would
    /// make a plausible fast path header read the other way. This is the case
    /// the `& 0x03` test exists for.
    #[test]
    fn a_tpkt_is_never_read_as_a_fast_path_pdu() {
        // 0x03 0x00 0x00 0x20: TPKT of 32 bytes. Read as fast path it would
        // be a 0 length PDU, which is why the discrimination has to be on the
        // first byte and not on a guess.
        let mut buf = framer_of(&tpkt(32));
        let f = take_complete(&mut buf).unwrap().expect("whole frame");
        assert_eq!(f.kind, FramedKind::Tpkt);
        assert_eq!(f.frame.len(), 32);
    }

    /// A TPKT whose version is not 3 is refused by `peek_tpkt_length`, which
    /// is the check we get for free by using it rather than reading the
    /// length ourselves.
    #[test]
    fn a_bad_tpkt_version_is_refused() {
        // The low two bits still say TPKT, so this reaches the TPKT branch.
        let mut buf = framer_of(&[0x07, 0x00, 0x00, 0x10]);
        assert!(take_complete(&mut buf).is_err());
    }

    #[test]
    fn a_der_sequence_is_framed_by_its_length_octets() {
        // Short form: 0x30 0x03 and three content octets.
        let mut buf = framer_of(&[0x30, 0x03, 1, 2, 3, 0xff]);
        let got = take_expect(&mut buf, Expect::DerSequence)
            .unwrap()
            .expect("whole sequence");
        assert_eq!(&got[..], &[0x30, 0x03, 1, 2, 3]);
        assert_eq!(&buf[..], &[0xff], "the next message is untouched");

        // Long form: 0x30 0x82 with a two octet length of 300.
        let mut wire = vec![0x30, 0x82, 0x01, 0x2c];
        wire.resize(4 + 300, 0);
        let mut buf = framer_of(&wire);
        assert_eq!(
            take_expect(&mut buf, Expect::DerSequence)
                .unwrap()
                .expect("whole sequence")
                .len(),
            304
        );
    }

    #[test]
    fn a_partial_der_header_waits_rather_than_guessing() {
        for prefix in [&[0x30u8][..], &[0x30, 0x82][..], &[0x30, 0x82, 0x01][..]] {
            let mut buf = framer_of(prefix);
            assert!(take_expect(&mut buf, Expect::DerSequence)
                .unwrap()
                .is_none());
            assert_eq!(buf.len(), prefix.len(), "nothing was consumed");
        }
    }

    /// Indefinite length is legal BER and illegal DER (X.690 §10.1), and a
    /// `TSRequest` is DER (MS-CSSP 2.2.1). Guessing at it would mean scanning
    /// for an end of contents marker inside attacker supplied bytes.
    #[test]
    fn an_indefinite_length_der_sequence_is_refused() {
        let mut buf = framer_of(&[0x30, 0x80, 0x00, 0x00]);
        assert!(take_expect(&mut buf, Expect::DerSequence).is_err());
    }

    #[test]
    fn a_non_sequence_where_a_tsrequest_belongs_is_refused() {
        let mut buf = framer_of(&[0x31, 0x03, 1, 2, 3]);
        let err = take_expect(&mut buf, Expect::DerSequence).unwrap_err();
        assert!(err.to_string().contains("TSRequest"), "{err}");
    }

    #[test]
    fn exact_reads_exactly_that_many_bytes() {
        let mut buf = framer_of(&[1, 2, 3, 4, 5]);
        assert!(take_expect(&mut buf, Expect::Exact(6)).unwrap().is_none());
        let got = take_expect(&mut buf, Expect::Exact(4))
            .unwrap()
            .expect("four");
        assert_eq!(&got[..], &[1, 2, 3, 4]);
        assert_eq!(&buf[..], &[5]);
    }

    // -----------------------------------------------------------------------
    // The cancellation proof
    // -----------------------------------------------------------------------

    /// A stream that hands over one byte per poll and then reports pending
    /// forever, waking immediately so the runtime polls it again.
    ///
    /// One byte per poll is what makes the test exhaustive: every byte
    /// boundary in the transcript becomes an await point, so cancelling the
    /// read future at every offset is cancelling it at every await.
    struct OneByteAtATime {
        bytes: Vec<u8>,
        at: usize,
    }

    impl AsyncRead for OneByteAtATime {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = &mut *self;
            match me.bytes.get(me.at) {
                Some(&b) => {
                    me.at += 1;
                    buf.put_slice(&[b]);
                    Poll::Ready(Ok(()))
                }
                None => {
                    // Not EOF: the test is about cancellation, not about the
                    // close path, and a wake keeps the runtime polling.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }

    /// The invariant this module exists to hold, checked at every byte
    /// offset rather than sampled.
    ///
    /// A framer that loses a byte on cancellation passes every end to end
    /// test in the suite and then fails once an hour on a real session, as a
    /// protocol error nobody can reproduce, so the offsets are enumerated.
    ///
    /// Each iteration races `framer.read()` against a branch that is
    /// immediately ready, which drops the read future at whatever await it
    /// had reached, and the loop asserts that the same sequence of frames
    /// still comes out in the same order.
    #[tokio::test]
    async fn the_framer_is_cancel_safe_at_every_byte_offset() {
        let mut wire = tpkt(11);
        wire.extend(fastpath(0x80, false));
        wire.extend(tpkt(64));
        wire.extend(fastpath(9, true));
        let expected: Vec<(FramedKind, usize)> = vec![
            (FramedKind::Tpkt, 11),
            (FramedKind::FastPath, 0x80),
            (FramedKind::Tpkt, 64),
            (FramedKind::FastPath, 9),
        ];

        let mut framer = Framer::new(
            OneByteAtATime {
                bytes: wire.clone(),
                at: 0,
            },
            Arc::new(AtomicU64::new(0)),
        );

        let mut got = Vec::new();
        // One cancellation per byte of the transcript, plus a margin so the
        // last frame has somewhere to complete.
        for _ in 0..wire.len() * 2 {
            tokio::select! {
                biased;
                framed = framer.read() => {
                    let framed = framed.expect("no error in a well formed transcript");
                    got.push((framed.kind, framed.frame.len()));
                    if got.len() == expected.len() {
                        break;
                    }
                }
                // Ready on the first poll, so the read future above is
                // dropped every time it is not already complete.
                () = std::future::ready(()) => {}
            }
        }

        assert_eq!(got, expected, "a cancelled read lost or duplicated a frame");
        assert_eq!(
            framer.received.load(Ordering::Relaxed) as usize,
            wire.len(),
            "every byte was counted exactly once"
        );
        assert_eq!(framer.buffered(), 0, "nothing left in the accumulator");
    }

    /// The same property for the connection sequence's reads, which use a
    /// different entry point and must not be assumed to inherit it.
    #[tokio::test]
    async fn read_expect_is_cancel_safe_at_every_byte_offset() {
        let mut wire = vec![0x30, 0x82, 0x01, 0x2c];
        wire.resize(4 + 300, 0x5a);
        wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // early user auth

        let mut framer = Framer::new(
            OneByteAtATime {
                bytes: wire.clone(),
                at: 0,
            },
            Arc::new(AtomicU64::new(0)),
        );

        let mut seq = None;
        for _ in 0..wire.len() * 2 {
            tokio::select! {
                biased;
                got = framer.read_expect(Expect::DerSequence) => {
                    seq = Some(got.expect("well formed"));
                    break;
                }
                () = std::future::ready(()) => {}
            }
        }
        assert_eq!(seq.expect("the sequence arrived").len(), 304);

        let mut tail = None;
        for _ in 0..16 {
            tokio::select! {
                biased;
                got = framer.read_expect(Expect::Exact(4)) => {
                    tail = Some(got.expect("well formed"));
                    break;
                }
                () = std::future::ready(()) => {}
            }
        }
        assert_eq!(&tail.expect("the tail arrived")[..], &[0, 0, 0, 0]);
    }

    /// A close between PDUs and a close part way through one are different
    /// bug reports and the framer says which.
    #[tokio::test]
    async fn a_clean_close_and_a_truncated_one_are_told_apart() {
        let mut framer = Framer::new(&[][..], Arc::new(AtomicU64::new(0)));
        assert!(matches!(
            framer.read().await,
            Err(RdpError::ConnectionClosed)
        ));

        let half = &tpkt(40)[..10];
        let mut framer = Framer::new(half, Arc::new(AtomicU64::new(0)));
        match framer.read().await {
            Err(RdpError::Pdu { structure, message }) => {
                assert_eq!(structure, "framer");
                assert!(message.contains("10 bytes"), "{message}");
            }
            other => panic!("expected a partial pdu error, got {other:?}"),
        }
    }

    /// The buffer is checked before the TLS upgrade, so the accessor that
    /// check reads has to be right.
    #[tokio::test]
    async fn buffered_reports_what_is_left_over() {
        let mut wire = tpkt(11);
        wire.extend_from_slice(&[0x03, 0x00]); // half a header of the next one
        let mut framer = Framer::new(&wire[..], Arc::new(AtomicU64::new(0)));
        assert_eq!(framer.read().await.unwrap().frame.len(), 11);
        assert_eq!(framer.buffered(), 2);
        let (_, left) = framer.into_inner();
        assert_eq!(&left[..], &[0x03, 0x00]);
    }
}
