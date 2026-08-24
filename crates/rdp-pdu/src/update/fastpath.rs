//! Fast path update PDUs and their framing.
//!
//! MS-RDPBCGR 2.2.9.1.2, PRDRDP/13 §5.5.
//!
//! One fast path PDU carries a header byte, a one or two byte big endian
//! length and a sequence of `TS_FP_UPDATE` records. Each record has its own
//! four bit update code, two fragmentation bits and two compression bits, and
//! the two mechanisms compose: a `FASTPATH_FRAGMENT_FIRST` may be compressed
//! and the `FASTPATH_FRAGMENT_NEXT` after it uncompressed. That is where
//! implementations go wrong, so fragmentation and compression are separate
//! fields on [`FpUpdateHeader`] and neither is folded into the other.
//!
//! The length encoding is shared with the fast path input header of
//! 2.2.8.1.2, which §5.5 states as "as in §5.4", so this module calls
//! [`crate::input::fastpath::read_fastpath_length`] rather than restating it.
//!
//! [`FastPathReassembler`] is the only type in `rdp-pdu` that carries state
//! between PDUs. It is here rather than in `rdp-core` because the
//! fragmentation rules are part of the wire format and because the fuzz
//! target needs to drive it (PRDRDP/13 §5.5).
//!
//! Tail rule (PRDRDP/13 §2.5): exact. Each record's `size` bounds its data
//! and the next record starts immediately after it, so a PDU whose records do
//! not tile its body exactly is a `LengthMismatch`.

use super::slowpath::GraphicsUpdate;
use super::{system_pointer, PointerKind, PointerUpdate};
use crate::input::fastpath::{
    action, fastpath_frame, header_flags, read_fastpath_length, write_fastpath_length,
};
use crate::io::limits::MAX_FASTPATH_REASSEMBLED;
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `updateCode`, the low nibble of `updateHeader` (MS-RDPBCGR 2.2.9.1.2.1).
///
/// The first four are the same numbers as the slow path `updateType` values
/// of 2.2.9.1.1.3.1, which is why one body decoder serves both paths. The
/// rest name pointer updates that the slow path reaches through
/// `TS_POINTER_PDU.messageType` instead, with different numbers.
pub mod update_code {
    /// `FASTPATH_UPDATETYPE_ORDERS`. We never advertise order support
    /// (PRDRDP/04 §8.4).
    pub const ORDERS: u8 = 0x0;
    /// `FASTPATH_UPDATETYPE_BITMAP`.
    pub const BITMAP: u8 = 0x1;
    /// `FASTPATH_UPDATETYPE_PALETTE`.
    pub const PALETTE: u8 = 0x2;
    /// `FASTPATH_UPDATETYPE_SYNCHRONIZE`.
    pub const SYNCHRONIZE: u8 = 0x3;
    /// `FASTPATH_UPDATETYPE_SURFCMDS`.
    pub const SURFCMDS: u8 = 0x4;
    /// `FASTPATH_UPDATETYPE_PTR_NULL`: hide the pointer. No body.
    pub const PTR_NULL: u8 = 0x5;
    /// `FASTPATH_UPDATETYPE_PTR_DEFAULT`: the platform arrow. No body.
    pub const PTR_DEFAULT: u8 = 0x6;
    /// `FASTPATH_UPDATETYPE_PTR_POSITION`.
    pub const PTR_POSITION: u8 = 0x8;
    /// `FASTPATH_UPDATETYPE_COLOR`.
    pub const COLOR: u8 = 0x9;
    /// `FASTPATH_UPDATETYPE_CACHED`.
    pub const CACHED: u8 = 0xa;
    /// `FASTPATH_UPDATETYPE_POINTER`, the new pointer.
    pub const POINTER: u8 = 0xb;
    /// `FASTPATH_UPDATETYPE_LARGE_POINTER`.
    pub const LARGE_POINTER: u8 = 0xc;
    /// The mask that extracts the code from `updateHeader`.
    pub const MASK: u8 = 0x0f;
}

/// The two bit `fragmentation` field, bits 4 and 5 of `updateHeader`
/// (MS-RDPBCGR 2.2.9.1.2.1).
pub mod fragmentation {
    /// `FASTPATH_FRAGMENT_SINGLE`: the whole update is here.
    pub const SINGLE: u8 = 0x0;
    /// `FASTPATH_FRAGMENT_LAST`.
    pub const LAST: u8 = 0x1;
    /// `FASTPATH_FRAGMENT_FIRST`.
    pub const FIRST: u8 = 0x2;
    /// `FASTPATH_FRAGMENT_NEXT`.
    pub const NEXT: u8 = 0x3;
    /// Where the field sits in `updateHeader`.
    pub const SHIFT: u8 = 4;
    /// The mask that extracts it once shifted down.
    pub const MASK: u8 = 0x3;
}

/// The two bit `compression` field, bits 6 and 7 of `updateHeader`
/// (MS-RDPBCGR 2.2.9.1.2.1).
pub mod compression {
    /// No `compressionFlags` byte follows.
    pub const NONE: u8 = 0x0;
    /// `FASTPATH_OUTPUT_COMPRESSION_USED`: a `compressionFlags` byte follows
    /// the update header. As a whole byte mask this is `0x80`, which is how
    /// PRDRDP/04 §2.1 states it; as the two bit field it is 2.
    pub const USED: u8 = 0x2;
    /// Where the field sits in `updateHeader`.
    pub const SHIFT: u8 = 6;
    /// The mask that extracts it once shifted down.
    pub const MASK: u8 = 0x3;
}

/// `compressionFlags` (MS-RDPBCGR 2.2.9.1.2.1, 3.1.8.2.1).
pub mod compression_flags {
    /// `PACKET_COMPRESSED`.
    pub const PACKET_COMPRESSED: u8 = 0x20;
    /// `PACKET_AT_FRONT`.
    pub const PACKET_AT_FRONT: u8 = 0x40;
    /// `PACKET_FLUSHED`.
    pub const PACKET_FLUSHED: u8 = 0x80;
    /// `CompressionTypeMask`, the bulk compression type in the low nibble.
    pub const TYPE_MASK: u8 = 0x0f;
}

/// `TS_FP_UPDATE`'s header: the update code, the fragmentation state, the
/// compression state and the `compressionFlags` byte when there is one
/// (MS-RDPBCGR 2.2.9.1.2.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FpUpdateHeader {
    /// [`update_code`].
    pub update_code: u8,
    /// [`fragmentation`].
    pub fragmentation: u8,
    /// [`compression`], as the two bit field value rather than a byte mask.
    pub compression: u8,
    /// [`compression_flags`], meaningful only when `compression` is
    /// [`compression::USED`].
    pub compression_flags: u8,
}

impl FpUpdateHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FP_UPDATE header";

    /// A single, uncompressed update of `update_code`, which is what every
    /// update this crate writes is.
    #[must_use]
    pub const fn single(update_code: u8) -> Self {
        Self {
            update_code,
            fragmentation: fragmentation::SINGLE,
            compression: compression::NONE,
            compression_flags: 0,
        }
    }

    /// True when a `compressionFlags` byte is present and the payload is
    /// bulk compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.compression == compression::USED
    }

    /// Refuse a compressed update.
    ///
    /// Phase 1 advertises no bulk compression at all (PRDRDP/04 §4.13), so
    /// this bit must never arrive. A server that compresses without being
    /// asked produces garbage pixels rather than an obvious failure, which is
    /// why this is an error and not a pass through (PRDRDP/04 §2.1). The
    /// session calls it once per update; when compression is negotiated in
    /// phase 2 the caller decompresses instead and never calls this.
    pub fn ensure_uncompressed(&self) -> PduResult<()> {
        if self.is_compressed() {
            return Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "compressionFlags",
                value: u64::from(self.compression_flags),
                offset: 0,
            });
        }
        Ok(())
    }

    /// The header's own encoded size: `updateHeader`, the optional
    /// `compressionFlags` and the two byte `size`.
    #[must_use]
    pub const fn size(&self) -> usize {
        if self.is_compressed() {
            4
        } else {
            3
        }
    }
}

/// One `TS_FP_UPDATE` (MS-RDPBCGR 2.2.9.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpUpdate<'a> {
    /// The header, including its fragmentation and compression state.
    pub header: FpUpdateHeader,
    /// `updateData`, borrowed from the receive buffer.
    pub data: Payload<'a>,
}

impl FpUpdate<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FP_UPDATE";
}

impl<'a> Decode<'a> for FpUpdate<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let raw = r.u8(Self::NAME)?;
        let mut header = FpUpdateHeader {
            update_code: raw & update_code::MASK,
            fragmentation: (raw >> fragmentation::SHIFT) & fragmentation::MASK,
            compression: (raw >> compression::SHIFT) & compression::MASK,
            compression_flags: 0,
        };
        if header.is_compressed() {
            header.compression_flags = r.u8(Self::NAME)?;
        }
        let size = usize::from(r.u16(Self::NAME)?);
        let data = Payload::new(r.slice(size, Self::NAME)?);
        Ok(Self { header, data })
    }
}

impl Encode for FpUpdate<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        self.header.size() + self.data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let h = &self.header;
        if h.update_code > update_code::MASK
            || h.fragmentation > fragmentation::MASK
            || h.compression > compression::MASK
        {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "update header field wider than its bits",
            });
        }
        let size = u16::try_from(self.data.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "update longer than the size field",
        })?;
        w.u8(h.update_code
            | (h.fragmentation << fragmentation::SHIFT)
            | (h.compression << compression::SHIFT));
        if h.is_compressed() {
            w.u8(h.compression_flags);
        }
        w.u16(size);
        w.bytes(self.data.as_slice());
        Ok(())
    }
}

/// A whole Server Fast-Path Update PDU (MS-RDPBCGR 2.2.9.1.2).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
///
/// The updates are not decoded into a `Vec`: [`FastPathUpdatePdu::updates`]
/// walks them in place, so a PDU carrying six records costs no allocation at
/// all and the session can push each fragment into a
/// [`FastPathReassembler`] as it is read (PRDRDP/13 §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastPathUpdatePdu<'a> {
    body: Payload<'a>,
}

impl<'a> FastPathUpdatePdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FP_UPDATE_PDU";

    /// The concatenated `TS_FP_UPDATE` records, unparsed.
    #[must_use]
    pub const fn body(&self) -> Payload<'a> {
        self.body
    }

    /// Walk the records. The iterator yields a `PduResult` per record and
    /// stops at the end of the body, so a truncated final record is a
    /// `Truncated` error rather than a silent stop.
    #[must_use]
    pub const fn updates(&self) -> FpUpdateIter<'a> {
        FpUpdateIter {
            r: Reader::new(self.body.as_slice()),
            done: false,
        }
    }
}

/// The iterator [`FastPathUpdatePdu::updates`] returns.
#[derive(Debug, Clone, Copy)]
pub struct FpUpdateIter<'a> {
    r: Reader<'a>,
    done: bool,
}

impl<'a> Iterator for FpUpdateIter<'a> {
    type Item = PduResult<FpUpdate<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.r.is_empty() {
            return None;
        }
        let item = FpUpdate::decode(&mut self.r);
        if item.is_err() {
            self.done = true;
        }
        Some(item)
    }
}

impl<'a> Decode<'a> for FastPathUpdatePdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header = r.u8(Self::NAME)?;
        if header & action::MASK != action::FASTPATH {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "action",
                value: u64::from(header & action::MASK),
                offset: at,
            });
        }
        let flags = header >> header_flags::SHIFT;
        if flags != 0 {
            // `fipsInformation` and `dataSignature` would sit between the
            // length and the first record. We never negotiate the security
            // that produces them (PRDRDP/03 §13.1).
            return Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "fpOutputHeader flags",
                value: u64::from(flags),
                offset: at,
            });
        }
        let length = read_fastpath_length(r, Self::NAME)?;
        let consumed = r.offset() - at;
        let body_len = length
            .checked_sub(consumed)
            .ok_or(PduError::LengthMismatch {
                context: Self::NAME,
                declared: length,
                actual: consumed,
                offset: at,
            })?;
        Ok(Self {
            body: Payload::new(r.slice(body_len, Self::NAME)?),
        })
    }
}

/// The encoded size of a PDU carrying `updates`.
pub fn fastpath_update_size(updates: &[FpUpdate<'_>]) -> PduResult<usize> {
    let body: usize = updates.iter().map(Encode::size).sum();
    Ok(fastpath_frame(1 + body, FastPathUpdatePdu::NAME)?.0)
}

/// Write a whole Server Fast-Path Update PDU (MS-RDPBCGR 2.2.9.1.2).
///
/// The client never sends one. This exists for the round trip tests of
/// PRDRDP/13 §9.1 and for `rdp-core`'s mock server (R18).
pub fn encode_fastpath_update(w: &mut Writer<'_>, updates: &[FpUpdate<'_>]) -> PduResult<()> {
    const NAME: &str = FastPathUpdatePdu::NAME;
    let body: usize = updates.iter().map(Encode::size).sum();
    let (total, prefix_len) = fastpath_frame(1 + body, NAME)?;
    // action FASTPATH, reserved zero, flags clear.
    w.u8(0);
    write_fastpath_length(w, total, prefix_len, NAME)?;
    for update in updates {
        update.encode(w)?;
    }
    Ok(())
}

/// One reassembled update, ready for a body decoder
/// (MS-RDPBCGR 2.2.9.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteUpdate<'a> {
    /// The [`update_code`] every fragment agreed on.
    pub update_code: u8,
    /// The concatenated data. For a `FASTPATH_FRAGMENT_SINGLE` this borrows
    /// the caller's own slice and nothing was copied.
    pub data: &'a [u8],
}

/// Reassembles fragmented fast path updates.
///
/// This is the only type in `rdp-pdu` that carries state between PDUs
/// (PRDRDP/13 §5.5). It holds at most [`MAX_FASTPATH_REASSEMBLED`] bytes and
/// errors past it. That constant is also what the Multifragment Update
/// capability set advertises as `MaxRequestSize` (MS-RDPBCGR 2.2.7.2.6), so
/// the budget we ask for and the budget we accept cannot drift apart.
///
/// Decompression of a compressed fragment happens in `rdp-codecs` between
/// [`FastPathReassembler::push`] calls, which is why `push` takes a slice
/// rather than reading from a [`Reader`].
#[derive(Debug, Default)]
pub struct FastPathReassembler {
    buf: Vec<u8>,
    code: Option<u8>,
}

impl FastPathReassembler {
    /// The name errors from this type carry.
    pub const NAME: &'static str = "FASTPATH_FRAGMENT";

    /// An empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True while a `FASTPATH_FRAGMENT_FIRST` has been seen and its `_LAST`
    /// has not.
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.code.is_some()
    }

    /// Drop any partial reassembly. The session calls this on a Deactivate
    /// All, where the server is entitled to abandon a fragment sequence.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.code = None;
    }

    /// Feed one fragment, returning the update when it is complete.
    ///
    /// The rules, each of which has a test: a `NEXT` or `LAST` without a
    /// preceding `FIRST` is [`PduError::InvalidField`]; a `FIRST` while a
    /// reassembly is in progress is the same; the update code must be
    /// identical across every fragment of one update; and a `SINGLE` never
    /// touches the buffer, so the common case copies nothing and returns a
    /// borrow of `data`.
    ///
    /// A `SINGLE` arriving mid sequence is also an error. The specification
    /// does not name that case, and the alternative is to drop a partial
    /// frame silently and paint the next one over the hole.
    pub fn push<'a>(
        &'a mut self,
        header: FpUpdateHeader,
        data: &'a [u8],
    ) -> PduResult<Option<CompleteUpdate<'a>>> {
        match header.fragmentation {
            fragmentation::SINGLE => {
                self.expect_idle(header)?;
                Ok(Some(CompleteUpdate {
                    update_code: header.update_code,
                    data,
                }))
            }
            fragmentation::FIRST => {
                self.expect_idle(header)?;
                self.buf.clear();
                self.reserve(data)?;
                self.buf.extend_from_slice(data);
                self.code = Some(header.update_code);
                Ok(None)
            }
            fragmentation::NEXT => {
                self.expect_code(header)?;
                self.reserve(data)?;
                self.buf.extend_from_slice(data);
                Ok(None)
            }
            fragmentation::LAST => {
                self.expect_code(header)?;
                self.reserve(data)?;
                self.buf.extend_from_slice(data);
                self.code = None;
                Ok(Some(CompleteUpdate {
                    update_code: header.update_code,
                    data: &self.buf,
                }))
            }
            other => Err(PduError::InvalidField {
                context: Self::NAME,
                field: "fragmentation",
                value: u64::from(other),
                offset: self.buf.len(),
            }),
        }
    }

    /// A fragment that may only arrive when nothing is in progress.
    fn expect_idle(&self, header: FpUpdateHeader) -> PduResult<()> {
        if self.in_progress() {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "fragmentation while a reassembly is in progress",
                value: u64::from(header.fragmentation),
                offset: self.buf.len(),
            });
        }
        Ok(())
    }

    /// A fragment that may only arrive mid sequence, and only for the update
    /// the sequence started with.
    fn expect_code(&self, header: FpUpdateHeader) -> PduResult<()> {
        match self.code {
            None => Err(PduError::InvalidField {
                context: Self::NAME,
                field: "fragmentation without a preceding FIRST",
                value: u64::from(header.fragmentation),
                offset: self.buf.len(),
            }),
            Some(code) if code != header.update_code => Err(PduError::InvalidField {
                context: Self::NAME,
                field: "updateCode changed mid reassembly",
                value: u64::from(header.update_code),
                offset: self.buf.len(),
            }),
            Some(_) => Ok(()),
        }
    }

    /// Check the cap before growing, so a hostile fragment sequence cannot
    /// walk the buffer up to the address space.
    fn reserve(&mut self, data: &[u8]) -> PduResult<()> {
        let total = self.buf.len() + data.len();
        if total > MAX_FASTPATH_REASSEMBLED {
            // The reassembler has no reader, so the offset reported is how
            // far into the reassembled update the overflow happened.
            return Err(PduError::CapExceeded {
                context: Self::NAME,
                declared: total,
                cap: MAX_FASTPATH_REASSEMBLED,
                limit_name: "MAX_FASTPATH_REASSEMBLED",
                offset: self.buf.len(),
            });
        }
        self.buf.reserve(data.len());
        Ok(())
    }
}

/// A decoded fast path update body, normalised onto the slow path's types
/// (MS-RDPBCGR 2.2.9.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastPathUpdate<'a> {
    /// Codes 0x0 to 0x3, whose bodies are the slow path's
    /// (2.2.9.1.1.3.1).
    Graphics(GraphicsUpdate<'a>),
    /// Code 0x4: a sequence of `TS_SURFCMD`, which
    /// [`crate::update::surface::SurfaceCommandIter`] walks.
    SurfaceCommands(Payload<'a>),
    /// Codes 0x5, 0x6 and 0x8 to 0xC (2.2.9.1.1.4). The two system pointer
    /// codes have no body and arrive as [`PointerUpdate::System`].
    Pointer(PointerUpdate<'a>),
}

impl<'a> FastPathUpdate<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FP_UPDATE body";

    /// Decode one reassembled update body.
    ///
    /// The caller has the update code from [`FpUpdateHeader`] or from
    /// [`CompleteUpdate`], and the data with any bulk compression already
    /// undone.
    pub fn decode_body(update_code: u8, data: &'a [u8]) -> PduResult<Self> {
        let mut r = Reader::new(data);
        let update = match update_code {
            update_code::ORDERS | update_code::BITMAP | update_code::PALETTE => {
                // The fast path body still carries its own two octet
                // `updateType`, even though the four bit update code in the
                // header already said the same thing (MS-RDPBCGR 2.2.9.1.2.1.1
                // to 2.2.9.1.2.1.3: the body is the slow path structure minus
                // its share data header, and `updateType` is not part of that
                // header).
                //
                // It was skipped here, on the argument that the update codes
                // and the update types are numerically identical so the field
                // only looked doubled. The identity is real and the field is
                // on the wire anyway. A Windows 11 host's first bitmap update
                // (DESKTOP-H21K47C, 2026-08-24) begins `01 00 a2 00`, which is
                // `UPDATETYPE_BITMAP` and then 162 rectangles; reading it as
                // 1 rectangle at `destLeft = 162` made the first tile of every
                // session a malformed one. `docs/RDP_SPEC_NOTES.md` §1.4
                // recorded the two readings and this is the capture that
                // settles it.
                let at = r.offset();
                let declared = r.u16(Self::NAME)?;
                if declared != u16::from(update_code) {
                    return Err(PduError::InvalidField {
                        context: Self::NAME,
                        field: "updateType",
                        value: u64::from(declared),
                        offset: at,
                    });
                }
                Self::Graphics(GraphicsUpdate::decode_body(&mut r, declared, false)?)
            }
            // The synchronize body is empty or two pad octets, and
            // `GraphicsUpdate::decode_body` already tolerates both, so there
            // is nothing to read a type from.
            update_code::SYNCHRONIZE => Self::Graphics(GraphicsUpdate::decode_body(
                &mut r,
                u16::from(update_code),
                false,
            )?),
            update_code::SURFCMDS => Self::SurfaceCommands(Payload::new(r.rest())),
            update_code::PTR_NULL => Self::Pointer(PointerUpdate::System(system_pointer::NULL)),
            update_code::PTR_DEFAULT => {
                Self::Pointer(PointerUpdate::System(system_pointer::DEFAULT))
            }
            update_code::PTR_POSITION => {
                Self::Pointer(PointerUpdate::decode_body(&mut r, PointerKind::Position)?)
            }
            update_code::COLOR => {
                Self::Pointer(PointerUpdate::decode_body(&mut r, PointerKind::Color)?)
            }
            update_code::CACHED => {
                Self::Pointer(PointerUpdate::decode_body(&mut r, PointerKind::Cached)?)
            }
            update_code::POINTER => {
                Self::Pointer(PointerUpdate::decode_body(&mut r, PointerKind::New)?)
            }
            update_code::LARGE_POINTER => {
                Self::Pointer(PointerUpdate::decode_body(&mut r, PointerKind::Large)?)
            }
            other => {
                return Err(PduError::Unsupported {
                    context: Self::NAME,
                    kind: "updateCode",
                    value: u64::from(other),
                    offset: 0,
                })
            }
        };
        // A body that does not consume its declared `size` means we
        // mis-parsed it. The two system pointer codes are the exception:
        // their body is empty and any bytes there belong to nobody.
        if !matches!(update, Self::Pointer(PointerUpdate::System(_))) {
            r.expect_empty(Self::NAME)?;
        }
        Ok(update)
    }

    /// The `updateCode` that names this body.
    pub fn update_code(&self) -> PduResult<u8> {
        Ok(match self {
            Self::Graphics(update) => update.update_type() as u8,
            Self::SurfaceCommands(_) => update_code::SURFCMDS,
            Self::Pointer(pointer) => match pointer {
                PointerUpdate::System(system_pointer::NULL) => update_code::PTR_NULL,
                PointerUpdate::System(system_pointer::DEFAULT) => update_code::PTR_DEFAULT,
                PointerUpdate::System(_) => {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "the fast path has a code for each system pointer and no other",
                    })
                }
                PointerUpdate::Position(_) => update_code::PTR_POSITION,
                PointerUpdate::Color(_) => update_code::COLOR,
                PointerUpdate::Cached(_) => update_code::CACHED,
                PointerUpdate::New { .. } => update_code::POINTER,
                PointerUpdate::Large { .. } => update_code::LARGE_POINTER,
            },
        })
    }

    /// The encoded size of the body.
    #[must_use]
    pub fn body_size(&self) -> usize {
        match self {
            // A fast path synchronize update has a zero length body: the
            // update code has already said everything the slow path's two
            // pad bytes say.
            Self::Graphics(GraphicsUpdate::Synchronize) => 0,
            // Two for the `updateType` the body carries, which `encode_body`
            // writes and `decode_body` reads.
            Self::Graphics(update) => 2 + update.body_size(),
            Self::SurfaceCommands(payload) => payload.len(),
            Self::Pointer(PointerUpdate::System(_)) => 0,
            Self::Pointer(pointer) => pointer.body_size(),
        }
    }

    /// Write the body, without the update header that names it.
    pub fn encode_body(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::Graphics(GraphicsUpdate::Synchronize) => Ok(()),
            Self::Graphics(update) => {
                // Symmetric with `decode_body`: the two octet `updateType`
                // is part of the fast path body, so a mock server that omits
                // it does not encode what a real one sends.
                w.u16(update.update_type());
                update.encode_body(w)
            }
            Self::SurfaceCommands(payload) => {
                w.bytes(payload.as_slice());
                Ok(())
            }
            Self::Pointer(PointerUpdate::System(_)) => Ok(()),
            Self::Pointer(pointer) => pointer.encode_body(w),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::update::tests::{bitmap_update, color_pointer};
    use crate::update::{PaletteUpdate, Point16};

    fn bodies() -> Vec<FastPathUpdate<'static>> {
        vec![
            FastPathUpdate::Graphics(GraphicsUpdate::Bitmap(bitmap_update())),
            FastPathUpdate::Graphics(GraphicsUpdate::Palette(Box::<PaletteUpdate>::default())),
            FastPathUpdate::Graphics(GraphicsUpdate::Synchronize),
            FastPathUpdate::SurfaceCommands(Payload::new(&[1, 2, 3, 4])),
            FastPathUpdate::Pointer(PointerUpdate::System(system_pointer::NULL)),
            FastPathUpdate::Pointer(PointerUpdate::System(system_pointer::DEFAULT)),
            FastPathUpdate::Pointer(PointerUpdate::Position(Point16 { x: 9, y: 10 })),
            FastPathUpdate::Pointer(PointerUpdate::Cached(4)),
            FastPathUpdate::Pointer(PointerUpdate::Color(color_pointer())),
            FastPathUpdate::Pointer(PointerUpdate::New {
                xor_bpp: 32,
                pointer: color_pointer(),
            }),
            FastPathUpdate::Pointer(PointerUpdate::Large {
                xor_bpp: 24,
                pointer: color_pointer(),
            }),
        ]
    }

    /// Encode a body into an owned buffer so the record can borrow it.
    fn body_bytes(update: &FastPathUpdate<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        update.encode_body(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), update.body_size());
        buf
    }

    /// The first bitmap update a real Windows 11 host sends, header included,
    /// transcribed from the frame that broke this decoder
    /// (DESKTOP-H21K47C, 2026-08-24).
    ///
    /// It is `01 00` then `a2 00`: the two octet `updateType` the fast path
    /// body was assumed not to carry, then 162 rectangles. Read without the
    /// type field the first rectangle is `destLeft = 162, destRight = 0`,
    /// which is inverted, so every session died on its first tile.
    #[test]
    fn a_real_fast_path_bitmap_update_carries_its_update_type() {
        // The first twelve octets exactly as they arrived. This is the
        // evidence: `01 00` is the `updateType` this decoder used to skip.
        let real_prefix = hex::decode("0100a200000000003f003f00").expect("valid hex");
        assert_eq!(
            &real_prefix[..2],
            &[0x01, 0x00],
            "updateType = UPDATETYPE_BITMAP"
        );
        assert_eq!(&real_prefix[2..4], &[0xa2, 0x00], "numberRectangles = 162");

        // The same bytes with the count reduced to one, so the vector can be
        // one tile rather than the 162 the host actually sent. Everything
        // before and after the count is untouched.
        let body = hex::decode(concat!(
            "0100",     // updateType = UPDATETYPE_BITMAP, as sent
            "0100",     // numberRectangles, 162 in the capture, 1 here
            "0000",     // destLeft   = 0,  as sent
            "0000",     // destTop    = 0,  as sent
            "3f00",     // destRight  = 63, as sent, inclusive
            "3f00",     // destBottom = 63, as sent, inclusive
            "4000",     // width  = 64,     as sent
            "4000",     // height = 64,     as sent
            "2000",     // bitsPerPixel = 32, as sent
            "0104",     // flags, as sent
            "0400",     // bitmapLength, 385 in the capture, 4 here
            "00000000", // four payload octets standing in for the tile
        ))
        .expect("valid hex");

        let update = FastPathUpdate::decode_body(update_code::BITMAP, &body)
            .expect("a real bitmap update decodes");
        let FastPathUpdate::Graphics(GraphicsUpdate::Bitmap(bitmap)) = update else {
            panic!("update code 1 is a bitmap update")
        };
        assert_eq!(bitmap.rectangles.len(), 1);
        let first = &bitmap.rectangles[0];
        assert_eq!(first.dest.left, 0);
        assert_eq!(first.dest.right, 63, "inclusive, so a 64 pixel wide tile");
        assert_eq!(first.dest.width(), Some(64));
        assert_eq!(first.width, 64);
        assert_eq!(first.height, 64);
        assert_eq!(first.bits_per_pixel, 32);
    }

    #[test]
    fn every_body_round_trips_through_its_update_code() {
        for update in bodies() {
            let code = update.update_code().unwrap();
            let bytes = body_bytes(&update);
            let back = FastPathUpdate::decode_body(code, &bytes).unwrap();
            assert_eq!(back, update, "code {code:#x}");
        }
    }

    #[test]
    fn a_whole_pdu_round_trips_with_several_records() {
        let bitmap = body_bytes(&FastPathUpdate::Graphics(GraphicsUpdate::Bitmap(
            bitmap_update(),
        )));
        let position = body_bytes(&FastPathUpdate::Pointer(PointerUpdate::Position(Point16 {
            x: 1,
            y: 2,
        })));
        let updates = [
            FpUpdate {
                header: FpUpdateHeader::single(update_code::BITMAP),
                data: Payload::new(&bitmap),
            },
            FpUpdate {
                header: FpUpdateHeader::single(update_code::PTR_POSITION),
                data: Payload::new(&position),
            },
            FpUpdate {
                header: FpUpdateHeader::single(update_code::PTR_NULL),
                data: Payload::new(&[]),
            },
        ];
        let mut buf = Vec::new();
        encode_fastpath_update(&mut Writer::new(&mut buf), &updates).unwrap();
        assert_eq!(buf.len(), fastpath_update_size(&updates).unwrap());

        let pdu = FastPathUpdatePdu::decode(&mut Reader::new(&buf)).unwrap();
        let decoded: Vec<FpUpdate<'_>> = pdu.updates().collect::<PduResult<_>>().unwrap();
        assert_eq!(decoded.len(), 3);
        for (got, want) in decoded.iter().zip(updates.iter()) {
            assert_eq!(got, want);
        }
    }

    /// A layout vector computed from the field table of PRDRDP/13 §5.5: a
    /// header byte of zero, a short length, then one single uncompressed
    /// `FASTPATH_UPDATETYPE_PTR_NULL` record with no data.
    #[test]
    fn golden_hide_the_pointer() {
        let updates = [FpUpdate {
            header: FpUpdateHeader::single(update_code::PTR_NULL),
            data: Payload::new(&[]),
        }];
        let mut buf = Vec::new();
        encode_fastpath_update(&mut Writer::new(&mut buf), &updates).unwrap();
        // fpOutputHeader 0x00, length 0x05, updateHeader 0x05, size 0x0000.
        assert_eq!(buf, hex::decode("0005050000").unwrap());

        let pdu = FastPathUpdatePdu::decode(&mut Reader::new(&buf)).unwrap();
        let record = pdu.updates().next().unwrap().unwrap();
        assert_eq!(record.header.update_code, update_code::PTR_NULL);
        assert_eq!(
            FastPathUpdate::decode_body(record.header.update_code, record.data.as_slice()).unwrap(),
            FastPathUpdate::Pointer(PointerUpdate::System(system_pointer::NULL))
        );
    }

    #[test]
    fn the_header_packs_all_three_fields_into_one_byte() {
        let header = FpUpdateHeader {
            update_code: update_code::SURFCMDS,
            fragmentation: fragmentation::FIRST,
            compression: compression::USED,
            compression_flags: compression_flags::PACKET_COMPRESSED,
        };
        let update = FpUpdate {
            header,
            data: Payload::new(&[0xaa, 0xbb]),
        };
        let mut buf = Vec::new();
        update.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        // 0x4 code, FIRST at bit 4, COMPRESSION_USED at bit 6: 0x80 | 0x20 | 4.
        assert_eq!(buf[0], 0xa4);
        assert_eq!(buf[1], compression_flags::PACKET_COMPRESSED);
        assert_eq!(FpUpdate::decode(&mut Reader::new(&buf)).unwrap(), update);
    }

    /// A header that claims compression the session never negotiated
    /// (PRDRDP/13 §5.5, PRDRDP/04 §2.1).
    #[test]
    fn a_compressed_update_is_refused_when_compression_was_not_negotiated() {
        let plain = FpUpdateHeader::single(update_code::BITMAP);
        assert!(plain.ensure_uncompressed().is_ok());

        let compressed = FpUpdateHeader {
            compression: compression::USED,
            compression_flags: compression_flags::PACKET_COMPRESSED,
            ..FpUpdateHeader::single(update_code::BITMAP)
        };
        assert!(compressed.is_compressed());
        assert!(matches!(
            compressed.ensure_uncompressed().unwrap_err(),
            PduError::Unsupported {
                kind: "compressionFlags",
                ..
            }
        ));
        // The compression field is two bits at bit 6, so as a whole byte
        // mask it is 0x80, which is how PRDRDP/04 §2.1 names it.
        assert_eq!(compression::USED << compression::SHIFT, 0x80);
    }

    /// One logical update split across three PDUs and put back together
    /// (PRDRDP/13 §5.5).
    #[test]
    fn a_fragmented_update_is_reassembled_across_three_pdus() {
        let whole = body_bytes(&FastPathUpdate::Graphics(GraphicsUpdate::Bitmap(
            bitmap_update(),
        )));
        let third = whole.len() / 3;
        let parts: [&[u8]; 3] = [
            &whole[..third],
            &whole[third..2 * third],
            &whole[2 * third..],
        ];
        let stages = [
            fragmentation::FIRST,
            fragmentation::NEXT,
            fragmentation::LAST,
        ];

        let mut reassembler = FastPathReassembler::new();
        let mut finished = None;
        for (stage, part) in stages.iter().zip(parts) {
            let header = FpUpdateHeader {
                fragmentation: *stage,
                ..FpUpdateHeader::single(update_code::BITMAP)
            };
            if let Some(complete) = reassembler.push(header, part).unwrap() {
                assert_eq!(complete.update_code, update_code::BITMAP);
                finished = Some(complete.data.to_vec());
            }
        }
        let finished = finished.expect("the LAST fragment completed the update");
        assert_eq!(finished, whole);
        assert!(!reassembler.in_progress());
        assert_eq!(
            FastPathUpdate::decode_body(update_code::BITMAP, &finished).unwrap(),
            FastPathUpdate::Graphics(GraphicsUpdate::Bitmap(bitmap_update()))
        );
    }

    /// A single fragment never touches the buffer, so the common case copies
    /// nothing (PRDRDP/13 §10.1 statement 3).
    #[test]
    fn a_single_fragment_borrows_the_callers_slice() {
        let data = [1u8, 2, 3, 4];
        let mut reassembler = FastPathReassembler::new();
        let complete = reassembler
            .push(FpUpdateHeader::single(update_code::BITMAP), &data)
            .unwrap()
            .expect("a single fragment completes immediately");
        assert_eq!(complete.data.as_ptr(), data.as_ptr(), "the data was copied");
    }

    #[test]
    fn a_next_without_a_first_is_rejected() {
        let mut reassembler = FastPathReassembler::new();
        for stage in [fragmentation::NEXT, fragmentation::LAST] {
            let header = FpUpdateHeader {
                fragmentation: stage,
                ..FpUpdateHeader::single(update_code::BITMAP)
            };
            assert!(matches!(
                reassembler.push(header, &[0u8]).unwrap_err(),
                PduError::InvalidField { .. }
            ));
        }
    }

    #[test]
    fn a_first_while_a_reassembly_is_in_progress_is_rejected() {
        let first = FpUpdateHeader {
            fragmentation: fragmentation::FIRST,
            ..FpUpdateHeader::single(update_code::BITMAP)
        };
        let mut reassembler = FastPathReassembler::new();
        assert!(reassembler.push(first, &[0u8]).unwrap().is_none());
        assert!(matches!(
            reassembler.push(first, &[0u8]).unwrap_err(),
            PduError::InvalidField { .. }
        ));
        // And so is a single, which would silently drop the partial update.
        reassembler.reset();
        assert!(reassembler.push(first, &[0u8]).unwrap().is_none());
        assert!(reassembler
            .push(FpUpdateHeader::single(update_code::BITMAP), &[0u8])
            .is_err());
    }

    #[test]
    fn the_update_code_must_be_identical_across_fragments() {
        let mut reassembler = FastPathReassembler::new();
        let first = FpUpdateHeader {
            fragmentation: fragmentation::FIRST,
            ..FpUpdateHeader::single(update_code::BITMAP)
        };
        let wrong_last = FpUpdateHeader {
            fragmentation: fragmentation::LAST,
            ..FpUpdateHeader::single(update_code::SURFCMDS)
        };
        assert!(reassembler.push(first, &[0u8]).unwrap().is_none());
        assert!(matches!(
            reassembler.push(wrong_last, &[0u8]).unwrap_err(),
            PduError::InvalidField {
                field: "updateCode changed mid reassembly",
                ..
            }
        ));
    }

    #[test]
    fn reassembly_stops_at_the_cap() {
        let mut reassembler = FastPathReassembler::new();
        let first = FpUpdateHeader {
            fragmentation: fragmentation::FIRST,
            ..FpUpdateHeader::single(update_code::BITMAP)
        };
        let next = FpUpdateHeader {
            fragmentation: fragmentation::NEXT,
            ..FpUpdateHeader::single(update_code::BITMAP)
        };
        let chunk = vec![0u8; 1 << 20];
        assert!(reassembler.push(first, &chunk).unwrap().is_none());
        let mut pushed = 1usize;
        loop {
            match reassembler.push(next, &chunk) {
                Ok(_) => pushed += 1,
                Err(PduError::CapExceeded {
                    limit_name: "MAX_FASTPATH_REASSEMBLED",
                    ..
                }) => break,
                Err(other) => panic!("{other}"),
            }
            assert!(pushed < 64, "the cap never fired");
        }
        assert_eq!(pushed, MAX_FASTPATH_REASSEMBLED >> 20);
    }

    #[test]
    fn an_unknown_update_code_is_unsupported_rather_than_skipped() {
        assert!(matches!(
            FastPathUpdate::decode_body(0x7, &[]).unwrap_err(),
            PduError::Unsupported {
                kind: "updateCode",
                ..
            }
        ));
    }

    #[test]
    fn a_body_with_bytes_left_over_is_a_length_mismatch() {
        let mut bytes = body_bytes(&FastPathUpdate::Pointer(PointerUpdate::Cached(3)));
        bytes.push(0xff);
        assert!(matches!(
            FastPathUpdate::decode_body(update_code::CACHED, &bytes).unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn a_pdu_claiming_encryption_is_refused() {
        let buf = [header_flags::ENCRYPTED << header_flags::SHIFT, 0x03, 0x00];
        assert!(matches!(
            FastPathUpdatePdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Unsupported {
                kind: "fpOutputHeader flags",
                ..
            }
        ));
    }

    #[test]
    fn truncating_at_every_offset_errors_without_panicking() {
        let bitmap = body_bytes(&FastPathUpdate::Graphics(GraphicsUpdate::Bitmap(
            bitmap_update(),
        )));
        let updates = [FpUpdate {
            header: FpUpdateHeader::single(update_code::BITMAP),
            data: Payload::new(&bitmap),
        }];
        let mut buf = Vec::new();
        encode_fastpath_update(&mut Writer::new(&mut buf), &updates).unwrap();
        for cut in 0..buf.len() {
            let short = &buf[..cut];
            let outcome = FastPathUpdatePdu::decode(&mut Reader::new(short))
                .and_then(|pdu| pdu.updates().collect::<PduResult<Vec<_>>>());
            assert!(outcome.is_err(), "decoded a PDU truncated to {cut} bytes");
        }
    }
}
