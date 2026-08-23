//! The EGFX PDUs.
//!
//! MS-RDPEGFX 2.2, PRDRDP/13 §6.3.
//!
//! EGFX is the graphics path every modern Windows host prefers, and it rides
//! the dynamic virtual channel `Microsoft::Windows::RDS::Graphics`. The whole
//! layering on receive is four steps and missing any one of them produces a
//! `cmdId` that looks like garbage (PRDRDP/13 §6.3):
//!
//! ```text
//! static channel chunks   -> vc::static_vc, one drdynvc message
//! DYNVC_DATA_FIRST/DATA   -> vc::dvc, one EGFX message
//! RDP_SEGMENTED_DATA      -> vc::segment, one or more bulk segments
//! rdp-codecs decompresses -> a concatenation of RDPGFX_HEADER PDUs
//! ```
//!
//! Several PDUs may be concatenated in that last step, so
//! [`EgfxPdu::iter`] loops while the reader is non empty and takes
//! `pduLength - 8` per command, the same shape as the surface command
//! iterator of §5.7.
//!
//! # Where this module stops
//!
//! PRDRDP/12 §2.2.2: this crate parses down to the first byte of a codec's
//! own bitstream and stops. [`EgfxPdu::WireToSurface1`] owns its `codecId`
//! and its `bitmapDataLength` and hands on a borrowed
//! [`Payload`]. What is inside that bitstream is `rdp-codecs`: no RemoteFX
//! tiles, no ClearCodec bands, no ZGFX. The one exception the specification
//! forces is [`Avc420Metablock`], which is a framing structure that sits
//! between the codec id and the H.264 Annex B stream (MS-RDPEGFX 2.2.4.4),
//! and even there the stream itself comes out as a `Payload`.
//!
//! Tail rule (PRDRDP/13 §2.5): exact at the PDU boundary, tolerant inside
//! it. `pduLength` is authoritative and the dispatcher advances by it however
//! much a body decoder read, so a newer server that extends a fixed command
//! cannot desynchronise the stream. A body that runs past `pduLength` is
//! [`PduError::Truncated`] because the sub reader ends there.

use crate::gcc::client::MonitorDef;
use crate::io::limits::{
    MAX_AVC420_REGION_RECTS, MAX_CACHE_IMPORT_ENTRIES, MAX_EGFX_CAPSETS, MAX_EGFX_CAPSET_LEN,
    MAX_EGFX_PDU, MAX_EGFX_RECTS, MAX_MONITORS,
};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `RDPGFX_POINT16` (MS-RDPEGFX 2.2.1.1): two unsigned 16 bit coordinates,
/// the same layout as `TS_POINT16` (MS-RDPBCGR 2.2.9.1.1.4.1), so it is the
/// same type (D13).
pub type Point16 = crate::update::Point16;

/// `RDPGFX_RECT16` (MS-RDPEGFX 2.2.1.2): left, top, right and bottom as `u16`
/// with the right and bottom edges **exclusive**, which is the surface
/// command convention and not the bitmap update one
/// (PRDRDP/13 §5.7).
pub type Rect16 = crate::update::RectExclusive;

/// `RDPGFX_HEADER.cmdId` (MS-RDPEGFX 2.2.1.5).
///
/// There is no 0x0014: the numbering skips it between `CAPS_CONFIRM` and
/// `MAP_SURFACE_TO_WINDOW`.
pub mod cmd_id {
    /// `RDPGFX_CMDID_WIRETOSURFACE_1` (2.2.2.1).
    pub const WIRE_TO_SURFACE_1: u16 = 0x0001;
    /// `RDPGFX_CMDID_WIRETOSURFACE_2` (2.2.2.2).
    pub const WIRE_TO_SURFACE_2: u16 = 0x0002;
    /// `RDPGFX_CMDID_DELETEENCODINGCONTEXT` (2.2.2.3).
    pub const DELETE_ENCODING_CONTEXT: u16 = 0x0003;
    /// `RDPGFX_CMDID_SOLIDFILL` (2.2.2.4).
    pub const SOLID_FILL: u16 = 0x0004;
    /// `RDPGFX_CMDID_SURFACETOSURFACE` (2.2.2.5).
    pub const SURFACE_TO_SURFACE: u16 = 0x0005;
    /// `RDPGFX_CMDID_SURFACETOCACHE` (2.2.2.6).
    pub const SURFACE_TO_CACHE: u16 = 0x0006;
    /// `RDPGFX_CMDID_CACHETOSURFACE` (2.2.2.7).
    pub const CACHE_TO_SURFACE: u16 = 0x0007;
    /// `RDPGFX_CMDID_EVICTCACHEENTRY` (2.2.2.8).
    pub const EVICT_CACHE_ENTRY: u16 = 0x0008;
    /// `RDPGFX_CMDID_CREATESURFACE` (2.2.2.9).
    pub const CREATE_SURFACE: u16 = 0x0009;
    /// `RDPGFX_CMDID_DELETESURFACE` (2.2.2.10).
    pub const DELETE_SURFACE: u16 = 0x000A;
    /// `RDPGFX_CMDID_STARTFRAME` (2.2.2.11).
    pub const START_FRAME: u16 = 0x000B;
    /// `RDPGFX_CMDID_ENDFRAME` (2.2.2.12).
    pub const END_FRAME: u16 = 0x000C;
    /// `RDPGFX_CMDID_FRAMEACKNOWLEDGE` (2.2.2.13), client to server.
    pub const FRAME_ACKNOWLEDGE: u16 = 0x000D;
    /// `RDPGFX_CMDID_RESETGRAPHICS` (2.2.2.14).
    pub const RESET_GRAPHICS: u16 = 0x000E;
    /// `RDPGFX_CMDID_MAPSURFACETOOUTPUT` (2.2.2.15).
    pub const MAP_SURFACE_TO_OUTPUT: u16 = 0x000F;
    /// `RDPGFX_CMDID_CACHEIMPORTOFFER` (2.2.2.16), client to server.
    pub const CACHE_IMPORT_OFFER: u16 = 0x0010;
    /// `RDPGFX_CMDID_CACHEIMPORTREPLY` (2.2.2.17).
    pub const CACHE_IMPORT_REPLY: u16 = 0x0011;
    /// `RDPGFX_CMDID_CAPSADVERTISE` (2.2.2.18), client to server.
    pub const CAPS_ADVERTISE: u16 = 0x0012;
    /// `RDPGFX_CMDID_CAPSCONFIRM` (2.2.2.19).
    pub const CAPS_CONFIRM: u16 = 0x0013;
    /// `RDPGFX_CMDID_MAPSURFACETOWINDOW` (2.2.2.20). RemoteApp only; we do
    /// not advertise RAIL, so it cannot legitimately arrive (PRDRDP/04 §3.1).
    pub const MAP_SURFACE_TO_WINDOW: u16 = 0x0015;
    /// `RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE` (2.2.2.21), client to server. We
    /// never send it (PRDRDP/04 §3.6).
    pub const QOE_FRAME_ACKNOWLEDGE: u16 = 0x0016;
    /// `RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT` (2.2.2.22).
    pub const MAP_SURFACE_TO_SCALED_OUTPUT: u16 = 0x0017;
    /// `RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW` (2.2.2.23). RemoteApp only.
    pub const MAP_SURFACE_TO_SCALED_WINDOW: u16 = 0x0018;
}

/// The pixel format of a surface or a wire to surface command
/// (MS-RDPEGFX 2.2.1.4).
pub mod pixel_format {
    /// `GFX_PIXEL_FORMAT_XRGB_8888`: 32 bits per pixel, the alpha byte
    /// ignored.
    pub const XRGB_8888: u8 = 0x20;
    /// `GFX_PIXEL_FORMAT_ARGB_8888`: 32 bits per pixel with alpha.
    pub const ARGB_8888: u8 = 0x21;
}

/// `codecId` of a wire to surface command (MS-RDPEGFX 2.2.4.1).
///
/// This crate reads the id and stops. Which of these `rdp-codecs` implements,
/// and which we advertise, is PRDRDP/04 §4's business.
pub mod codec_id {
    /// `RDPGFX_CODECID_UNCOMPRESSED`.
    pub const UNCOMPRESSED: u16 = 0x0000;
    /// `RDPGFX_CODECID_CAVIDEO`, which is RemoteFX (MS-RDPRFX).
    pub const CAVIDEO: u16 = 0x0003;
    /// `RDPGFX_CODECID_CLEARCODEC`.
    pub const CLEARCODEC: u16 = 0x0008;
    /// `RDPGFX_CODECID_PLANAR`.
    pub const PLANAR: u16 = 0x000A;
    /// `RDPGFX_CODECID_AVC420`. The `bitmapData` begins with
    /// [`Avc420Metablock`](super::Avc420Metablock).
    pub const AVC420: u16 = 0x000B;
    /// `RDPGFX_CODECID_ALPHA`.
    pub const ALPHA: u16 = 0x000C;
    /// `RDPGFX_CODECID_AVC444`.
    pub const AVC444: u16 = 0x000E;
    /// `RDPGFX_CODECID_AVC444V2`.
    pub const AVC444V2: u16 = 0x000F;
}

/// `RDPGFX_CAPSET.version` (MS-RDPEGFX 2.2.1.6, 2.2.3.1 to 2.2.3.11).
pub mod caps_version {
    /// `RDPGFX_CAPVERSION_8` (2.2.3.1).
    pub const V8: u32 = 0x0008_0004;
    /// `RDPGFX_CAPVERSION_8_1` (2.2.3.2). The highest version at which "AVC420
    /// and nothing beyond it" is expressible, which is why PRDRDP/04 §3.2
    /// fixes the advertisement here.
    pub const V8_1: u32 = 0x0008_0105;
    /// `RDPGFX_CAPVERSION_10` (2.2.3.3).
    pub const V10: u32 = 0x000A_0002;
    /// `RDPGFX_CAPVERSION_10_1` (2.2.3.4). Advertising it is itself the
    /// AVC444v2 opt in (MS-RDPEGFX 1.7), so we do not.
    pub const V10_1: u32 = 0x000A_0100;
    /// `RDPGFX_CAPVERSION_10_2` (2.2.3.5).
    pub const V10_2: u32 = 0x000A_0200;
    /// `RDPGFX_CAPVERSION_10_3` (2.2.3.6).
    pub const V10_3: u32 = 0x000A_0301;
    /// `RDPGFX_CAPVERSION_10_4` (2.2.3.7).
    pub const V10_4: u32 = 0x000A_0400;
    /// `RDPGFX_CAPVERSION_10_5` (2.2.3.8).
    pub const V10_5: u32 = 0x000A_0502;
    /// `RDPGFX_CAPVERSION_10_6` (2.2.3.9), the corrected value.
    pub const V10_6: u32 = 0x000A_0600;
    /// The erroneous `RDPGFX_CAPVERSION_10_6`.
    ///
    /// PRDRDP/11 §5.3 item 1: MS-RDPEGFX published `0x000A0601` in sections
    /// 2.2.1.6 and 2.2.3.9 for years and the erratum of 2018-12-10 corrected
    /// both to `0x000A0600`. Servers and clients built against the
    /// uncorrected text use the erroneous value, so both are in the wild. We
    /// accept this one in a `CAPS_CONFIRM` as meaning version 10.6 and never
    /// send it (PRDRDP/04 §3.2).
    pub const V10_6_ERRATUM: u32 = 0x000A_0601;
    /// `RDPGFX_CAPVERSION_10_7` (2.2.3.10).
    pub const V10_7: u32 = 0x000A_0701;

    /// True when `version` names capability version 10.6, in either the
    /// corrected or the erroneous spelling (PRDRDP/11 §5.3 item 1).
    #[must_use]
    pub const fn is_v10_6(version: u32) -> bool {
        version == V10_6 || version == V10_6_ERRATUM
    }
}

/// The flags in an `RDPGFX_CAPSET.capsData` (MS-RDPEGFX 2.2.3.1 onward).
///
/// The polarity flips at version 10: AVC is opt in below it
/// (`AVC420_ENABLED`) and opt out at and above it (`AVC_DISABLED`), and there
/// is no "AVC420 yes, AVC444 no" flag at version 10 (PRDRDP/04 §3.2). That is
/// why the decoder returns the version and the raw `u32` and interprets
/// neither.
pub mod caps_flags {
    /// `RDPGFX_CAPS_FLAG_THINCLIENT`.
    pub const THINCLIENT: u32 = 0x0000_0001;
    /// `RDPGFX_CAPS_FLAG_SMALL_CACHE`.
    pub const SMALL_CACHE: u32 = 0x0000_0002;
    /// `RDPGFX_CAPS_FLAG_AVC420_ENABLED`. Version 8.1 only.
    pub const AVC420_ENABLED: u32 = 0x0000_0010;
    /// `RDPGFX_CAPS_FLAG_AVC_DISABLED`. Version 10 and above.
    pub const AVC_DISABLED: u32 = 0x0000_0020;
    /// `RDPGFX_CAPS_FLAG_AVC_THINCLIENT`, a preference for YUV444. Version
    /// 10.3 and above.
    pub const AVC_THINCLIENT: u32 = 0x0000_0040;
}

/// `RDPGFX_HEADER` (MS-RDPEGFX 2.2.1.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgfxHeader {
    /// [`cmd_id`].
    pub cmd_id: u16,
    /// `flags`. Every defined command sets it to zero; a non zero value is
    /// carried rather than rejected (PRDRDP/13 §2.7 rule 3).
    pub flags: u16,
    /// `pduLength`, **including** these eight header bytes.
    pub pdu_length: u32,
}

impl EgfxHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDPGFX_HEADER";

    /// Eight bytes, always, and the number `pduLength` counts on top of the
    /// body.
    pub const LEN: usize = 8;
}

impl Decode<'_> for EgfxHeader {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            cmd_id: r.u16(Self::NAME)?,
            flags: r.u16(Self::NAME)?,
            pdu_length: r.u32(Self::NAME)?,
        })
    }
}

impl Encode for EgfxHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.cmd_id);
        w.u16(self.flags);
        w.u32(self.pdu_length);
        Ok(())
    }
}

/// `RDPGFX_COLOR32` (MS-RDPEGFX 2.2.1.3): blue, green, red, then the alpha
/// byte, in that order on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Color32 {
    /// `B`.
    pub b: u8,
    /// `G`.
    pub g: u8,
    /// `R`.
    pub r: u8,
    /// `XA`, the alpha byte, ignored for an `XRGB` surface.
    pub xa: u8,
}

impl Color32 {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDPGFX_COLOR32";

    /// Four bytes, always.
    pub const LEN: usize = 4;
}

impl Decode<'_> for Color32 {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            b: r.u8(Self::NAME)?,
            g: r.u8(Self::NAME)?,
            r: r.u8(Self::NAME)?,
            xa: r.u8(Self::NAME)?,
        })
    }
}

impl Encode for Color32 {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u8(self.b);
        w.u8(self.g);
        w.u8(self.r);
        w.u8(self.xa);
        Ok(())
    }
}

/// One `RDPGFX_CAPSET` (MS-RDPEGFX 2.2.1.6).
///
/// The body stays a [`Payload`] because its meaning is version dependent:
/// versions 8 and 8.1 hold a single `u32` of flags, version 10.1 holds
/// sixteen reserved zero bytes, and from version 10.2 the flags return with
/// different bits. The decoder returns the version and the raw bytes and
/// PRDRDP/04 §3.2 interprets them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capset<'a> {
    /// [`caps_version`].
    pub version: u32,
    /// `capsData`, `capsDataLength` bytes long.
    pub caps_data: Payload<'a>,
}

impl<'a> Capset<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDPGFX_CAPSET";

    /// The four byte `version` and the four byte `capsDataLength`.
    pub const FIXED_LEN: usize = 8;

    /// A capability set whose body is one `u32` of [`caps_flags`], which is
    /// what versions 8 and 8.1 carry and therefore what we advertise
    /// (PRDRDP/04 §3.2).
    ///
    /// The bytes are the caller's, because a [`Payload`] borrows and this
    /// crate never allocates one.
    #[must_use]
    pub const fn new(version: u32, caps_data: &'a [u8]) -> Self {
        Self {
            version,
            caps_data: Payload::new(caps_data),
        }
    }

    /// The first four bytes of `capsData` as the flags word, for the versions
    /// that have one.
    ///
    /// Version 10.1's sixteen reserved zero bytes read back as zero, which is
    /// the right answer for a capset that has no flags.
    pub fn flags(&self) -> PduResult<u32> {
        Reader::new(self.caps_data.as_slice()).u32("RDPGFX_CAPSET capsData")
    }
}

impl<'a> Decode<'a> for Capset<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let version = r.u32(Self::NAME)?;
        let len = r.u32(Self::NAME)? as usize;
        r.ensure_cap(len, MAX_EGFX_CAPSET_LEN, "MAX_EGFX_CAPSET_LEN", Self::NAME)?;
        Ok(Self {
            version,
            caps_data: Payload::new(r.slice(len, Self::NAME)?),
        })
    }
}

impl Encode for Capset<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::FIXED_LEN + self.caps_data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.version);
        let len = u32::try_from(self.caps_data.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "capsData longer than its u32 length prefix",
        })?;
        w.u32(len);
        w.bytes(self.caps_data.as_slice());
        Ok(())
    }
}

/// `RDPGFX_CACHE_ENTRY_METADATA` (MS-RDPEGFX 2.2.2.16).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheEntryMetadata {
    /// `cacheKey`.
    pub cache_key: u64,
    /// `bitmapLength`.
    pub bitmap_length: u32,
}

impl CacheEntryMetadata {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDPGFX_CACHE_ENTRY_METADATA";

    /// Twelve bytes, always.
    pub const LEN: usize = 12;
}

impl Decode<'_> for CacheEntryMetadata {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            cache_key: r.u64(Self::NAME)?,
            bitmap_length: r.u32(Self::NAME)?,
        })
    }
}

impl Encode for CacheEntryMetadata {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u64(self.cache_key);
        w.u32(self.bitmap_length);
        Ok(())
    }
}

/// `RDPGFX_H264_QUANT_QUALITY` (MS-RDPEGFX 2.2.4.4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H264QuantQuality {
    /// `qpVal`, the whole byte. The quantization parameter is bits 0 to 5,
    /// `r` is bit 6 and `p` is bit 7.
    pub qp_val: u8,
    /// `qualityVal`, 0 to 100.
    pub quality_val: u8,
}

impl H264QuantQuality {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDPGFX_H264_QUANT_QUALITY";

    /// Two bytes, always.
    pub const LEN: usize = 2;

    /// The quantization parameter, bits 0 to 5 of `qpVal`.
    #[must_use]
    pub const fn qp(&self) -> u8 {
        self.qp_val & 0x3f
    }

    /// `r`, bit 6 of `qpVal`.
    #[must_use]
    pub const fn r(&self) -> bool {
        self.qp_val & 0x40 != 0
    }

    /// `p`, bit 7 of `qpVal`.
    #[must_use]
    pub const fn p(&self) -> bool {
        self.qp_val & 0x80 != 0
    }
}

/// `RFX_AVC420_METABLOCK` (MS-RDPEGFX 2.2.4.4).
///
/// The framing that sits between an AVC420 `codecId` and the H.264 Annex B
/// stream. The stream itself is a [`Payload`] that goes to the WebCodecs path
/// unchanged (PRDRDP/04 §5.2); nothing here reads a bit of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avc420Metablock<'a> {
    /// `regionRects`, `numRegionRects` of them.
    pub region_rects: Vec<Rect16>,
    /// `quantQualityVals`, exactly as many as there are rectangles.
    pub quant_quality_vals: Vec<H264QuantQuality>,
    /// The Annex B stream that follows the metablock.
    pub stream: Payload<'a>,
}

impl Avc420Metablock<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RFX_AVC420_METABLOCK";
}

impl<'a> Decode<'a> for Avc420Metablock<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let count = r.u32(Self::NAME)? as usize;
        r.ensure_cap(
            count,
            MAX_AVC420_REGION_RECTS,
            "MAX_AVC420_REGION_RECTS",
            Self::NAME,
        )?;
        // Each rectangle costs eight bytes and each quant pair two, so a
        // count larger than the bytes left cannot force a reservation
        // (PRDRDP/13 §10.1).
        let room = r.remaining() / (Rect16::LEN + H264QuantQuality::LEN) + 1;
        let mut region_rects = Vec::with_capacity(count.min(room));
        for _ in 0..count {
            region_rects.push(Rect16::decode(r)?);
        }
        let mut quant_quality_vals = Vec::with_capacity(count.min(room));
        for _ in 0..count {
            quant_quality_vals.push(H264QuantQuality {
                qp_val: r.u8(H264QuantQuality::NAME)?,
                quality_val: r.u8(H264QuantQuality::NAME)?,
            });
        }
        Ok(Self {
            region_rects,
            quant_quality_vals,
            stream: Payload::new(r.rest()),
        })
    }
}

impl Encode for Avc420Metablock<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + self.region_rects.len() * Rect16::LEN
            + self.quant_quality_vals.len() * H264QuantQuality::LEN
            + self.stream.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.region_rects.len() != self.quant_quality_vals.len() {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "numRegionRects counts both arrays and they differ",
            });
        }
        let count = u32::try_from(self.region_rects.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "more region rectangles than numRegionRects can hold",
        })?;
        w.u32(count);
        for rect in &self.region_rects {
            rect.encode(w)?;
        }
        for q in &self.quant_quality_vals {
            w.u8(q.qp_val);
            w.u8(q.quality_val);
        }
        w.bytes(self.stream.as_slice());
        Ok(())
    }
}

/// One EGFX PDU: the header's `cmdId` and the body that follows it
/// (MS-RDPEGFX 2.2.2).
///
/// Every payload borrows the decompressed EGFX message, so decoding a whole
/// frame's worth of commands copies nothing (PRDRDP/13 §10.1). The only
/// allocations are the `Vec`s of genuinely repeated structures, each bounded
/// by a constant from [`crate::io::limits`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgfxPdu<'a> {
    /// `RDPGFX_WIRE_TO_SURFACE_PDU_1` (MS-RDPEGFX 2.2.2.1), server to client.
    WireToSurface1 {
        /// `surfaceId`.
        surface_id: u16,
        /// [`codec_id`].
        codec_id: u16,
        /// [`pixel_format`].
        pixel_format: u8,
        /// `destRect`, exclusive edges.
        dest_rect: Rect16,
        /// `bitmapData`, `bitmapDataLength` bytes of a codec's own bitstream.
        /// This crate stops here (PRDRDP/12 §2.2.2).
        bitmap_data: Payload<'a>,
    },
    /// `RDPGFX_WIRE_TO_SURFACE_PDU_2` (MS-RDPEGFX 2.2.2.2), server to client.
    ///
    /// No `bitmapDataLength`: the payload runs to the end of the PDU as
    /// `pduLength` declared it. That asymmetry with `_1` is why the
    /// dispatcher takes `pduLength - 8` before calling a body decoder rather
    /// than letting one read from the outer reader.
    WireToSurface2 {
        /// `surfaceId`.
        surface_id: u16,
        /// [`codec_id`].
        codec_id: u16,
        /// `codecContextId`.
        codec_context_id: u32,
        /// [`pixel_format`].
        pixel_format: u8,
        /// `bitmapData`, running to the end of the PDU.
        bitmap_data: Payload<'a>,
    },
    /// `RDPGFX_DELETE_ENCODING_CONTEXT_PDU` (MS-RDPEGFX 2.2.2.3).
    DeleteEncodingContext {
        /// `surfaceId`.
        surface_id: u16,
        /// `codecContextId`.
        codec_context_id: u32,
    },
    /// `RDPGFX_SOLIDFILL_PDU` (MS-RDPEGFX 2.2.2.4).
    SolidFill {
        /// `surfaceId`.
        surface_id: u16,
        /// `fillPixel`.
        fill_pixel: Color32,
        /// `fillRectList`, `rectCount` of them.
        fill_rects: Vec<Rect16>,
    },
    /// `RDPGFX_SURFACE_TO_SURFACE_PDU` (MS-RDPEGFX 2.2.2.5).
    SurfaceToSurface {
        /// `surfaceIdSrc`.
        surface_id_src: u16,
        /// `surfaceIdDest`.
        surface_id_dest: u16,
        /// `rectSrc`.
        rect_src: Rect16,
        /// `destPts`, `destPtsCount` of them.
        dest_pts: Vec<Point16>,
    },
    /// `RDPGFX_SURFACE_TO_CACHE_PDU` (MS-RDPEGFX 2.2.2.6).
    SurfaceToCache {
        /// `surfaceId`.
        surface_id: u16,
        /// `cacheKey`.
        cache_key: u64,
        /// `cacheSlot`.
        cache_slot: u16,
        /// `rectSrc`.
        rect_src: Rect16,
    },
    /// `RDPGFX_CACHE_TO_SURFACE_PDU` (MS-RDPEGFX 2.2.2.7).
    CacheToSurface {
        /// `cacheSlot`.
        cache_slot: u16,
        /// `surfaceId`.
        surface_id: u16,
        /// `destPts`, `destPtsCount` of them.
        dest_pts: Vec<Point16>,
    },
    /// `RDPGFX_EVICT_CACHE_ENTRY_PDU` (MS-RDPEGFX 2.2.2.8).
    EvictCacheEntry {
        /// `cacheSlot`.
        cache_slot: u16,
    },
    /// `RDPGFX_CREATE_SURFACE_PDU` (MS-RDPEGFX 2.2.2.9).
    CreateSurface {
        /// `surfaceId`.
        surface_id: u16,
        /// `width`.
        width: u16,
        /// `height`.
        height: u16,
        /// [`pixel_format`].
        pixel_format: u8,
    },
    /// `RDPGFX_DELETE_SURFACE_PDU` (MS-RDPEGFX 2.2.2.10).
    DeleteSurface {
        /// `surfaceId`.
        surface_id: u16,
    },
    /// `RDPGFX_START_FRAME_PDU` (MS-RDPEGFX 2.2.2.11).
    StartFrame {
        /// `timestamp`.
        timestamp: u32,
        /// `frameId`.
        frame_id: u32,
    },
    /// `RDPGFX_END_FRAME_PDU` (MS-RDPEGFX 2.2.2.12).
    EndFrame {
        /// `frameId`.
        frame_id: u32,
    },
    /// `RDPGFX_FRAME_ACKNOWLEDGE_PDU` (MS-RDPEGFX 2.2.2.13), client to
    /// server. The only flow control an RDP client has (PRDRDP/04 §3.6).
    FrameAcknowledge {
        /// `queueDepth`, either a real depth,
        /// [`QUEUE_DEPTH_UNAVAILABLE`](EgfxPdu::QUEUE_DEPTH_UNAVAILABLE), or
        /// [`SUSPEND_FRAME_ACKNOWLEDGEMENT`](EgfxPdu::SUSPEND_FRAME_ACKNOWLEDGEMENT).
        queue_depth: u32,
        /// `frameId`, the frame being acknowledged.
        frame_id: u32,
        /// `totalFramesDecoded`.
        total_frames_decoded: u32,
    },
    /// `RDPGFX_RESET_GRAPHICS_PDU` (MS-RDPEGFX 2.2.2.14).
    ///
    /// The PDU is padded to 340 bytes whatever the monitor count, so the body
    /// is always [`EgfxPdu::RESET_GRAPHICS_BODY_LEN`] bytes. A parser that
    /// does not consume the padding desynchronises the channel
    /// (PRDRDP/04 §3.9).
    ResetGraphics {
        /// `width`.
        width: u32,
        /// `height`.
        height: u32,
        /// `monitorDefArray`, `monitorCount` of them.
        monitors: Vec<MonitorDef>,
    },
    /// `RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU` (MS-RDPEGFX 2.2.2.15).
    MapSurfaceToOutput {
        /// `surfaceId`.
        surface_id: u16,
        /// `reserved`.
        reserved: u16,
        /// `outputOriginX`.
        output_origin_x: u32,
        /// `outputOriginY`.
        output_origin_y: u32,
    },
    /// `RDPGFX_CACHE_IMPORT_OFFER_PDU` (MS-RDPEGFX 2.2.2.16), client to
    /// server. We send one with zero entries (PRDRDP/04 §3.7).
    CacheImportOffer {
        /// `cacheEntries`, at most
        /// [`MAX_CACHE_IMPORT_ENTRIES`].
        entries: Vec<CacheEntryMetadata>,
    },
    /// `RDPGFX_CACHE_IMPORT_REPLY_PDU` (MS-RDPEGFX 2.2.2.17).
    CacheImportReply {
        /// `cacheSlots`, `importedEntriesCount` of them.
        cache_slots: Vec<u16>,
    },
    /// `RDPGFX_CAPS_ADVERTISE_PDU` (MS-RDPEGFX 2.2.2.18), client to server.
    CapsAdvertise {
        /// `capsSets`, `capsSetCount` of them.
        capsets: Vec<Capset<'a>>,
    },
    /// `RDPGFX_CAPS_CONFIRM_PDU` (MS-RDPEGFX 2.2.2.19). The server confirms
    /// exactly one capability set and only that set's flags apply
    /// (PRDRDP/04 §3.2).
    CapsConfirm {
        /// The confirmed set.
        capset: Capset<'a>,
    },
    /// `RDPGFX_MAP_SURFACE_TO_WINDOW_PDU` (MS-RDPEGFX 2.2.2.20).
    MapSurfaceToWindow {
        /// `surfaceId`.
        surface_id: u16,
        /// `windowId`.
        window_id: u64,
        /// `mappedWidth`.
        mapped_width: u32,
        /// `mappedHeight`.
        mapped_height: u32,
    },
    /// `RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU` (MS-RDPEGFX 2.2.2.21), client to
    /// server. Decoded for the mock server; we never send one, because the
    /// present time it wants is not observable from Rust (PRDRDP/04 §3.6).
    QoeFrameAcknowledge {
        /// `frameId`.
        frame_id: u32,
        /// `timestamp`.
        timestamp: u32,
        /// `timeDiffSE`.
        time_diff_se: u16,
        /// `timeDiffEDR`.
        time_diff_edr: u16,
    },
    /// `RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU` (MS-RDPEGFX 2.2.2.22).
    MapSurfaceToScaledOutput {
        /// `surfaceId`.
        surface_id: u16,
        /// `reserved`.
        reserved: u16,
        /// `outputOriginX`.
        output_origin_x: u32,
        /// `outputOriginY`.
        output_origin_y: u32,
        /// `targetWidth`.
        target_width: u32,
        /// `targetHeight`.
        target_height: u32,
    },
    /// `RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU` (MS-RDPEGFX 2.2.2.23).
    MapSurfaceToScaledWindow {
        /// `surfaceId`.
        surface_id: u16,
        /// `windowId`.
        window_id: u64,
        /// `mappedWidth`.
        mapped_width: u32,
        /// `mappedHeight`.
        mapped_height: u32,
        /// `targetWidth`.
        target_width: u32,
        /// `targetHeight`.
        target_height: u32,
    },
    /// A `cmdId` this crate does not know, preserved rather than rejected.
    ///
    /// `pduLength` tells us exactly how long it is, so skipping it cannot
    /// desynchronise the stream, which is the condition PRDRDP/13 §2.7 rule 3
    /// sets for preserving an unknown enumerant. Refusing it is `rdp-core`'s
    /// decision, not the parser's.
    Unknown {
        /// The `cmdId` that was there.
        cmd_id: u16,
        /// The header's `flags`.
        flags: u16,
        /// Everything after the eight header bytes.
        body: Payload<'a>,
    },
}

impl<'a> EgfxPdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDPGFX PDU";

    /// `SUSPEND_FRAME_ACKNOWLEDGEMENT` (MS-RDPEGFX 2.2.2.13): stop expecting
    /// acknowledgements. PRDRDP/04 §3.6 forbids us from sending it, because a
    /// client that does not bound its own demand starves every other session
    /// on the server.
    pub const SUSPEND_FRAME_ACKNOWLEDGEMENT: u32 = 0xFFFF_FFFF;

    /// `QUEUE_DEPTH_UNAVAILABLE` (MS-RDPEGFX 2.2.2.13): acknowledged, with no
    /// depth reported.
    pub const QUEUE_DEPTH_UNAVAILABLE: u32 = 0x0000_0000;

    /// The body length of a `RDPGFX_RESET_GRAPHICS_PDU`: the whole PDU is 340
    /// bytes including [`EgfxHeader::LEN`] (MS-RDPEGFX 2.2.2.14).
    pub const RESET_GRAPHICS_BODY_LEN: usize = 340 - EgfxHeader::LEN;

    /// Walk a concatenation of EGFX PDUs, which is what one decompressed EGFX
    /// message holds (MS-RDPEGFX 2.2.1.5).
    ///
    /// The iterator yields a `PduResult` per command and stops after the
    /// first error, so a truncated final command is an error rather than a
    /// silent stop.
    #[must_use]
    pub const fn iter(message: &'a [u8]) -> EgfxPduIter<'a> {
        EgfxPduIter {
            r: Reader::new(message),
            done: false,
        }
    }

    /// The `cmdId` this PDU encodes as.
    #[must_use]
    pub const fn cmd_id(&self) -> u16 {
        match self {
            Self::WireToSurface1 { .. } => cmd_id::WIRE_TO_SURFACE_1,
            Self::WireToSurface2 { .. } => cmd_id::WIRE_TO_SURFACE_2,
            Self::DeleteEncodingContext { .. } => cmd_id::DELETE_ENCODING_CONTEXT,
            Self::SolidFill { .. } => cmd_id::SOLID_FILL,
            Self::SurfaceToSurface { .. } => cmd_id::SURFACE_TO_SURFACE,
            Self::SurfaceToCache { .. } => cmd_id::SURFACE_TO_CACHE,
            Self::CacheToSurface { .. } => cmd_id::CACHE_TO_SURFACE,
            Self::EvictCacheEntry { .. } => cmd_id::EVICT_CACHE_ENTRY,
            Self::CreateSurface { .. } => cmd_id::CREATE_SURFACE,
            Self::DeleteSurface { .. } => cmd_id::DELETE_SURFACE,
            Self::StartFrame { .. } => cmd_id::START_FRAME,
            Self::EndFrame { .. } => cmd_id::END_FRAME,
            Self::FrameAcknowledge { .. } => cmd_id::FRAME_ACKNOWLEDGE,
            Self::ResetGraphics { .. } => cmd_id::RESET_GRAPHICS,
            Self::MapSurfaceToOutput { .. } => cmd_id::MAP_SURFACE_TO_OUTPUT,
            Self::CacheImportOffer { .. } => cmd_id::CACHE_IMPORT_OFFER,
            Self::CacheImportReply { .. } => cmd_id::CACHE_IMPORT_REPLY,
            Self::CapsAdvertise { .. } => cmd_id::CAPS_ADVERTISE,
            Self::CapsConfirm { .. } => cmd_id::CAPS_CONFIRM,
            Self::MapSurfaceToWindow { .. } => cmd_id::MAP_SURFACE_TO_WINDOW,
            Self::QoeFrameAcknowledge { .. } => cmd_id::QOE_FRAME_ACKNOWLEDGE,
            Self::MapSurfaceToScaledOutput { .. } => cmd_id::MAP_SURFACE_TO_SCALED_OUTPUT,
            Self::MapSurfaceToScaledWindow { .. } => cmd_id::MAP_SURFACE_TO_SCALED_WINDOW,
            Self::Unknown { cmd_id, .. } => *cmd_id,
        }
    }

    /// The header's `flags`, which is zero for every defined command.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        match self {
            Self::Unknown { flags, .. } => *flags,
            _ => 0,
        }
    }

    /// The encoded length of the body, without the eight header bytes.
    fn body_size(&self) -> usize {
        match self {
            Self::WireToSurface1 {
                dest_rect,
                bitmap_data,
                ..
            } => 2 + 2 + 1 + dest_rect.size() + 4 + bitmap_data.len(),
            Self::WireToSurface2 { bitmap_data, .. } => 2 + 2 + 4 + 1 + bitmap_data.len(),
            Self::DeleteEncodingContext { .. } => 2 + 4,
            Self::SolidFill { fill_rects, .. } => {
                2 + Color32::LEN + 2 + fill_rects.len() * Rect16::LEN
            }
            Self::SurfaceToSurface { dest_pts, .. } => {
                2 + 2 + Rect16::LEN + 2 + dest_pts.len() * Point16::LEN
            }
            Self::SurfaceToCache { .. } => 2 + 8 + 2 + Rect16::LEN,
            Self::CacheToSurface { dest_pts, .. } => 2 + 2 + 2 + dest_pts.len() * Point16::LEN,
            Self::EvictCacheEntry { .. } | Self::DeleteSurface { .. } => 2,
            Self::CreateSurface { .. } => 2 + 2 + 2 + 1,
            Self::StartFrame { .. } => 8,
            Self::EndFrame { .. } => 4,
            Self::FrameAcknowledge { .. } => 12,
            Self::ResetGraphics { .. } => Self::RESET_GRAPHICS_BODY_LEN,
            Self::MapSurfaceToOutput { .. } => 2 + 2 + 4 + 4,
            Self::CacheImportOffer { entries } => 2 + entries.len() * CacheEntryMetadata::LEN,
            Self::CacheImportReply { cache_slots } => 2 + cache_slots.len() * 2,
            Self::CapsAdvertise { capsets } => 2 + capsets.iter().map(Encode::size).sum::<usize>(),
            Self::CapsConfirm { capset } => capset.size(),
            Self::MapSurfaceToWindow { .. } => 2 + 8 + 4 + 4,
            Self::QoeFrameAcknowledge { .. } => 4 + 4 + 2 + 2,
            Self::MapSurfaceToScaledOutput { .. } => 2 + 2 + 4 + 4 + 4 + 4,
            Self::MapSurfaceToScaledWindow { .. } => 2 + 8 + 4 + 4 + 4 + 4,
            Self::Unknown { body, .. } => body.len(),
        }
    }
}

/// The iterator [`EgfxPdu::iter`] returns.
#[derive(Debug, Clone, Copy)]
pub struct EgfxPduIter<'a> {
    r: Reader<'a>,
    done: bool,
}

impl<'a> Iterator for EgfxPduIter<'a> {
    type Item = PduResult<EgfxPdu<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.r.is_empty() {
            return None;
        }
        let item = EgfxPdu::decode(&mut self.r);
        if item.is_err() {
            self.done = true;
        }
        Some(item)
    }
}

/// Read a `u16` count, refuse it past `cap`, and read that many structures.
fn decode_vec<'a, T: Decode<'a>>(
    r: &mut Reader<'a>,
    cap: usize,
    limit_name: &'static str,
    context: &'static str,
    item_len: usize,
) -> PduResult<Vec<T>> {
    let count = usize::from(r.u16(context)?);
    r.ensure_cap(count, cap, limit_name, context)?;
    // A count larger than the bytes left cannot force a reservation
    // (PRDRDP/13 §10.1); the decode fails on the first missing item.
    let room = r.remaining() / item_len.max(1) + 1;
    let mut out = Vec::with_capacity(count.min(room));
    for _ in 0..count {
        out.push(T::decode(r)?);
    }
    Ok(out)
}

impl<'a> Decode<'a> for EgfxPdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header = EgfxHeader::decode(r)?;
        let declared = header.pdu_length as usize;
        if declared < EgfxHeader::LEN {
            return Err(PduError::LengthMismatch {
                context: Self::NAME,
                declared,
                actual: EgfxHeader::LEN,
                offset: at,
            });
        }
        r.ensure_cap(declared, MAX_EGFX_PDU, "MAX_EGFX_PDU", Self::NAME)?;
        let mut b = r.take(declared - EgfxHeader::LEN, Self::NAME)?;
        decode_body(&mut b, header)
    }
}

/// Decode one command body from a reader bounded by `pduLength`.
fn decode_body<'a>(b: &mut Reader<'a>, header: EgfxHeader) -> PduResult<EgfxPdu<'a>> {
    const NAME: &str = EgfxPdu::NAME;
    match header.cmd_id {
        cmd_id::WIRE_TO_SURFACE_1 => {
            let surface_id = b.u16("RDPGFX_WIRE_TO_SURFACE_PDU_1")?;
            let codec_id = b.u16("RDPGFX_WIRE_TO_SURFACE_PDU_1")?;
            let pixel_format = b.u8("RDPGFX_WIRE_TO_SURFACE_PDU_1")?;
            let dest_rect = Rect16::decode(b)?;
            let len = b.u32("RDPGFX_WIRE_TO_SURFACE_PDU_1")? as usize;
            let bitmap_data = Payload::new(b.slice(len, "RDPGFX_WIRE_TO_SURFACE_PDU_1")?);
            Ok(EgfxPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                dest_rect,
                bitmap_data,
            })
        }
        cmd_id::WIRE_TO_SURFACE_2 => Ok(EgfxPdu::WireToSurface2 {
            surface_id: b.u16("RDPGFX_WIRE_TO_SURFACE_PDU_2")?,
            codec_id: b.u16("RDPGFX_WIRE_TO_SURFACE_PDU_2")?,
            codec_context_id: b.u32("RDPGFX_WIRE_TO_SURFACE_PDU_2")?,
            pixel_format: b.u8("RDPGFX_WIRE_TO_SURFACE_PDU_2")?,
            bitmap_data: Payload::new(b.rest()),
        }),
        cmd_id::DELETE_ENCODING_CONTEXT => Ok(EgfxPdu::DeleteEncodingContext {
            surface_id: b.u16("RDPGFX_DELETE_ENCODING_CONTEXT_PDU")?,
            codec_context_id: b.u32("RDPGFX_DELETE_ENCODING_CONTEXT_PDU")?,
        }),
        cmd_id::SOLID_FILL => Ok(EgfxPdu::SolidFill {
            surface_id: b.u16("RDPGFX_SOLIDFILL_PDU")?,
            fill_pixel: Color32::decode(b)?,
            fill_rects: decode_vec(
                b,
                MAX_EGFX_RECTS,
                "MAX_EGFX_RECTS",
                "RDPGFX_SOLIDFILL_PDU",
                Rect16::LEN,
            )?,
        }),
        cmd_id::SURFACE_TO_SURFACE => Ok(EgfxPdu::SurfaceToSurface {
            surface_id_src: b.u16("RDPGFX_SURFACE_TO_SURFACE_PDU")?,
            surface_id_dest: b.u16("RDPGFX_SURFACE_TO_SURFACE_PDU")?,
            rect_src: Rect16::decode(b)?,
            dest_pts: decode_vec(
                b,
                MAX_EGFX_RECTS,
                "MAX_EGFX_RECTS",
                "RDPGFX_SURFACE_TO_SURFACE_PDU",
                Point16::LEN,
            )?,
        }),
        cmd_id::SURFACE_TO_CACHE => Ok(EgfxPdu::SurfaceToCache {
            surface_id: b.u16("RDPGFX_SURFACE_TO_CACHE_PDU")?,
            cache_key: b.u64("RDPGFX_SURFACE_TO_CACHE_PDU")?,
            cache_slot: b.u16("RDPGFX_SURFACE_TO_CACHE_PDU")?,
            rect_src: Rect16::decode(b)?,
        }),
        cmd_id::CACHE_TO_SURFACE => Ok(EgfxPdu::CacheToSurface {
            cache_slot: b.u16("RDPGFX_CACHE_TO_SURFACE_PDU")?,
            surface_id: b.u16("RDPGFX_CACHE_TO_SURFACE_PDU")?,
            dest_pts: decode_vec(
                b,
                MAX_EGFX_RECTS,
                "MAX_EGFX_RECTS",
                "RDPGFX_CACHE_TO_SURFACE_PDU",
                Point16::LEN,
            )?,
        }),
        cmd_id::EVICT_CACHE_ENTRY => Ok(EgfxPdu::EvictCacheEntry {
            cache_slot: b.u16("RDPGFX_EVICT_CACHE_ENTRY_PDU")?,
        }),
        cmd_id::CREATE_SURFACE => Ok(EgfxPdu::CreateSurface {
            surface_id: b.u16("RDPGFX_CREATE_SURFACE_PDU")?,
            width: b.u16("RDPGFX_CREATE_SURFACE_PDU")?,
            height: b.u16("RDPGFX_CREATE_SURFACE_PDU")?,
            pixel_format: b.u8("RDPGFX_CREATE_SURFACE_PDU")?,
        }),
        cmd_id::DELETE_SURFACE => Ok(EgfxPdu::DeleteSurface {
            surface_id: b.u16("RDPGFX_DELETE_SURFACE_PDU")?,
        }),
        cmd_id::START_FRAME => Ok(EgfxPdu::StartFrame {
            timestamp: b.u32("RDPGFX_START_FRAME_PDU")?,
            frame_id: b.u32("RDPGFX_START_FRAME_PDU")?,
        }),
        cmd_id::END_FRAME => Ok(EgfxPdu::EndFrame {
            frame_id: b.u32("RDPGFX_END_FRAME_PDU")?,
        }),
        cmd_id::FRAME_ACKNOWLEDGE => Ok(EgfxPdu::FrameAcknowledge {
            queue_depth: b.u32("RDPGFX_FRAME_ACKNOWLEDGE_PDU")?,
            frame_id: b.u32("RDPGFX_FRAME_ACKNOWLEDGE_PDU")?,
            total_frames_decoded: b.u32("RDPGFX_FRAME_ACKNOWLEDGE_PDU")?,
        }),
        cmd_id::RESET_GRAPHICS => {
            const RG: &str = "RDPGFX_RESET_GRAPHICS_PDU";
            let width = b.u32(RG)?;
            let height = b.u32(RG)?;
            let count = b.u32(RG)? as usize;
            b.ensure_cap(count, MAX_MONITORS, "MAX_MONITORS", RG)?;
            let mut monitors = Vec::with_capacity(count.min(MAX_MONITORS));
            for _ in 0..count {
                monitors.push(MonitorDef {
                    left: b.i32(MonitorDef::NAME)?,
                    top: b.i32(MonitorDef::NAME)?,
                    right: b.i32(MonitorDef::NAME)?,
                    bottom: b.i32(MonitorDef::NAME)?,
                    flags: b.u32(MonitorDef::NAME)?,
                });
            }
            // The padding out to 340 bytes. Consuming it is the whole point:
            // a parser that leaves it desynchronises the channel
            // (PRDRDP/04 §3.9).
            let _ = b.rest();
            Ok(EgfxPdu::ResetGraphics {
                width,
                height,
                monitors,
            })
        }
        cmd_id::MAP_SURFACE_TO_OUTPUT => Ok(EgfxPdu::MapSurfaceToOutput {
            surface_id: b.u16("RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU")?,
            reserved: b.u16("RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU")?,
            output_origin_x: b.u32("RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU")?,
            output_origin_y: b.u32("RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU")?,
        }),
        cmd_id::CACHE_IMPORT_OFFER => Ok(EgfxPdu::CacheImportOffer {
            entries: decode_vec(
                b,
                MAX_CACHE_IMPORT_ENTRIES,
                "MAX_CACHE_IMPORT_ENTRIES",
                "RDPGFX_CACHE_IMPORT_OFFER_PDU",
                CacheEntryMetadata::LEN,
            )?,
        }),
        cmd_id::CACHE_IMPORT_REPLY => {
            const CIR: &str = "RDPGFX_CACHE_IMPORT_REPLY_PDU";
            let count = usize::from(b.u16(CIR)?);
            b.ensure_cap(
                count,
                MAX_CACHE_IMPORT_ENTRIES,
                "MAX_CACHE_IMPORT_ENTRIES",
                CIR,
            )?;
            let mut cache_slots = Vec::with_capacity(count.min(b.remaining() / 2 + 1));
            for _ in 0..count {
                cache_slots.push(b.u16(CIR)?);
            }
            Ok(EgfxPdu::CacheImportReply { cache_slots })
        }
        cmd_id::CAPS_ADVERTISE => Ok(EgfxPdu::CapsAdvertise {
            capsets: decode_vec(
                b,
                MAX_EGFX_CAPSETS,
                "MAX_EGFX_CAPSETS",
                "RDPGFX_CAPS_ADVERTISE_PDU",
                Capset::FIXED_LEN,
            )?,
        }),
        cmd_id::CAPS_CONFIRM => Ok(EgfxPdu::CapsConfirm {
            capset: Capset::decode(b)?,
        }),
        cmd_id::MAP_SURFACE_TO_WINDOW => Ok(EgfxPdu::MapSurfaceToWindow {
            surface_id: b.u16("RDPGFX_MAP_SURFACE_TO_WINDOW_PDU")?,
            window_id: b.u64("RDPGFX_MAP_SURFACE_TO_WINDOW_PDU")?,
            mapped_width: b.u32("RDPGFX_MAP_SURFACE_TO_WINDOW_PDU")?,
            mapped_height: b.u32("RDPGFX_MAP_SURFACE_TO_WINDOW_PDU")?,
        }),
        cmd_id::QOE_FRAME_ACKNOWLEDGE => Ok(EgfxPdu::QoeFrameAcknowledge {
            frame_id: b.u32("RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU")?,
            timestamp: b.u32("RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU")?,
            time_diff_se: b.u16("RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU")?,
            time_diff_edr: b.u16("RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU")?,
        }),
        cmd_id::MAP_SURFACE_TO_SCALED_OUTPUT => Ok(EgfxPdu::MapSurfaceToScaledOutput {
            surface_id: b.u16("RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU")?,
            reserved: b.u16("RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU")?,
            output_origin_x: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU")?,
            output_origin_y: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU")?,
            target_width: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU")?,
            target_height: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU")?,
        }),
        cmd_id::MAP_SURFACE_TO_SCALED_WINDOW => Ok(EgfxPdu::MapSurfaceToScaledWindow {
            surface_id: b.u16("RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU")?,
            window_id: b.u64("RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU")?,
            mapped_width: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU")?,
            mapped_height: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU")?,
            target_width: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU")?,
            target_height: b.u32("RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU")?,
        }),
        other => {
            #[cfg(feature = "trace-pdu")]
            tracing::trace!(cmd_id = other, "unknown RDPGFX cmdId, preserved");
            let _ = NAME;
            Ok(EgfxPdu::Unknown {
                cmd_id: other,
                flags: header.flags,
                body: Payload::new(b.rest()),
            })
        }
    }
}

impl Encode for EgfxPdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        EgfxHeader::LEN + self.body_size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        // `pduLength` counts the eight header bytes and sits after two of
        // them, so `Writer::with_len_u32` cannot express it: that helper adds
        // its own four bytes and never the two in front of it. `size()` is
        // exact for every variant and `encode_checked` asserts it in debug
        // builds, which is the check that would otherwise be missing.
        let total = u32::try_from(self.size()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "PDU longer than pduLength can hold",
        })?;
        EgfxHeader {
            cmd_id: self.cmd_id(),
            flags: self.flags(),
            pdu_length: total,
        }
        .encode(w)?;
        match self {
            Self::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                dest_rect,
                bitmap_data,
            } => {
                w.u16(*surface_id);
                w.u16(*codec_id);
                w.u8(*pixel_format);
                dest_rect.encode(w)?;
                let len = u32::try_from(bitmap_data.len()).map_err(|_| PduError::Encode {
                    context: "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                    reason: "bitmapData longer than bitmapDataLength can hold",
                })?;
                w.u32(len);
                w.bytes(bitmap_data.as_slice());
            }
            Self::WireToSurface2 {
                surface_id,
                codec_id,
                codec_context_id,
                pixel_format,
                bitmap_data,
            } => {
                w.u16(*surface_id);
                w.u16(*codec_id);
                w.u32(*codec_context_id);
                w.u8(*pixel_format);
                w.bytes(bitmap_data.as_slice());
            }
            Self::DeleteEncodingContext {
                surface_id,
                codec_context_id,
            } => {
                w.u16(*surface_id);
                w.u32(*codec_context_id);
            }
            Self::SolidFill {
                surface_id,
                fill_pixel,
                fill_rects,
            } => {
                w.u16(*surface_id);
                fill_pixel.encode(w)?;
                encode_count(w, fill_rects.len(), "RDPGFX_SOLIDFILL_PDU")?;
                for rect in fill_rects {
                    rect.encode(w)?;
                }
            }
            Self::SurfaceToSurface {
                surface_id_src,
                surface_id_dest,
                rect_src,
                dest_pts,
            } => {
                w.u16(*surface_id_src);
                w.u16(*surface_id_dest);
                rect_src.encode(w)?;
                encode_count(w, dest_pts.len(), "RDPGFX_SURFACE_TO_SURFACE_PDU")?;
                for pt in dest_pts {
                    pt.encode(w)?;
                }
            }
            Self::SurfaceToCache {
                surface_id,
                cache_key,
                cache_slot,
                rect_src,
            } => {
                w.u16(*surface_id);
                w.u64(*cache_key);
                w.u16(*cache_slot);
                rect_src.encode(w)?;
            }
            Self::CacheToSurface {
                cache_slot,
                surface_id,
                dest_pts,
            } => {
                w.u16(*cache_slot);
                w.u16(*surface_id);
                encode_count(w, dest_pts.len(), "RDPGFX_CACHE_TO_SURFACE_PDU")?;
                for pt in dest_pts {
                    pt.encode(w)?;
                }
            }
            Self::EvictCacheEntry { cache_slot } => w.u16(*cache_slot),
            Self::CreateSurface {
                surface_id,
                width,
                height,
                pixel_format,
            } => {
                w.u16(*surface_id);
                w.u16(*width);
                w.u16(*height);
                w.u8(*pixel_format);
            }
            Self::DeleteSurface { surface_id } => w.u16(*surface_id),
            Self::StartFrame {
                timestamp,
                frame_id,
            } => {
                w.u32(*timestamp);
                w.u32(*frame_id);
            }
            Self::EndFrame { frame_id } => w.u32(*frame_id),
            Self::FrameAcknowledge {
                queue_depth,
                frame_id,
                total_frames_decoded,
            } => {
                w.u32(*queue_depth);
                w.u32(*frame_id);
                w.u32(*total_frames_decoded);
            }
            Self::ResetGraphics {
                width,
                height,
                monitors,
            } => {
                if monitors.len() > MAX_MONITORS {
                    return Err(PduError::Encode {
                        context: "RDPGFX_RESET_GRAPHICS_PDU",
                        reason: "more monitors than the 340 byte PDU holds",
                    });
                }
                let before = w.len();
                w.u32(*width);
                w.u32(*height);
                w.u32(monitors.len() as u32);
                for m in monitors {
                    w.i32(m.left);
                    w.i32(m.top);
                    w.i32(m.right);
                    w.i32(m.bottom);
                    w.u32(m.flags);
                }
                // Sixteen monitors fill the body exactly, so this is the
                // padding and never a truncation.
                let written = w.len() - before;
                w.zeros(Self::RESET_GRAPHICS_BODY_LEN.saturating_sub(written));
            }
            Self::MapSurfaceToOutput {
                surface_id,
                reserved,
                output_origin_x,
                output_origin_y,
            } => {
                w.u16(*surface_id);
                w.u16(*reserved);
                w.u32(*output_origin_x);
                w.u32(*output_origin_y);
            }
            Self::CacheImportOffer { entries } => {
                if entries.len() > MAX_CACHE_IMPORT_ENTRIES {
                    return Err(PduError::Encode {
                        context: "RDPGFX_CACHE_IMPORT_OFFER_PDU",
                        reason: "more entries than the specification's 5462",
                    });
                }
                encode_count(w, entries.len(), "RDPGFX_CACHE_IMPORT_OFFER_PDU")?;
                for entry in entries {
                    entry.encode(w)?;
                }
            }
            Self::CacheImportReply { cache_slots } => {
                encode_count(w, cache_slots.len(), "RDPGFX_CACHE_IMPORT_REPLY_PDU")?;
                for slot in cache_slots {
                    w.u16(*slot);
                }
            }
            Self::CapsAdvertise { capsets } => {
                encode_count(w, capsets.len(), "RDPGFX_CAPS_ADVERTISE_PDU")?;
                for capset in capsets {
                    capset.encode(w)?;
                }
            }
            Self::CapsConfirm { capset } => capset.encode(w)?,
            Self::MapSurfaceToWindow {
                surface_id,
                window_id,
                mapped_width,
                mapped_height,
            } => {
                w.u16(*surface_id);
                w.u64(*window_id);
                w.u32(*mapped_width);
                w.u32(*mapped_height);
            }
            Self::QoeFrameAcknowledge {
                frame_id,
                timestamp,
                time_diff_se,
                time_diff_edr,
            } => {
                w.u32(*frame_id);
                w.u32(*timestamp);
                w.u16(*time_diff_se);
                w.u16(*time_diff_edr);
            }
            Self::MapSurfaceToScaledOutput {
                surface_id,
                reserved,
                output_origin_x,
                output_origin_y,
                target_width,
                target_height,
            } => {
                w.u16(*surface_id);
                w.u16(*reserved);
                w.u32(*output_origin_x);
                w.u32(*output_origin_y);
                w.u32(*target_width);
                w.u32(*target_height);
            }
            Self::MapSurfaceToScaledWindow {
                surface_id,
                window_id,
                mapped_width,
                mapped_height,
                target_width,
                target_height,
            } => {
                w.u16(*surface_id);
                w.u64(*window_id);
                w.u32(*mapped_width);
                w.u32(*mapped_height);
                w.u32(*target_width);
                w.u32(*target_height);
            }
            Self::Unknown { body, .. } => w.bytes(body.as_slice()),
        }
        Ok(())
    }
}

/// Write a `u16` count, refusing one that does not fit.
fn encode_count(w: &mut Writer<'_>, count: usize, context: &'static str) -> PduResult<()> {
    let n = u16::try_from(count).map_err(|_| PduError::Encode {
        context,
        reason: "more entries than the u16 count field can hold",
    })?;
    w.u16(n);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn encoded(pdu: &EgfxPdu<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), pdu.size(), "size() disagrees with encode()");
        assert_eq!(
            u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize,
            buf.len(),
            "pduLength does not count the whole PDU"
        );
        buf
    }

    fn round_trip(pdu: EgfxPdu<'_>) {
        let buf = encoded(&pdu);
        assert_eq!(EgfxPdu::decode(&mut Reader::new(&buf)).unwrap(), pdu);
    }

    fn truncates(pdu: &EgfxPdu<'_>) {
        let buf = encoded(pdu);
        for cut in 0..buf.len() {
            assert!(
                EgfxPdu::decode(&mut Reader::new(&buf[..cut])).is_err(),
                "{:#06x} truncated to {cut} bytes decoded",
                pdu.cmd_id()
            );
        }
    }

    fn samples() -> Vec<EgfxPdu<'static>> {
        vec![
            EgfxPdu::WireToSurface1 {
                surface_id: 1,
                codec_id: codec_id::CAVIDEO,
                pixel_format: pixel_format::XRGB_8888,
                dest_rect: Rect16 {
                    left: 0,
                    top: 0,
                    right: 64,
                    bottom: 64,
                },
                bitmap_data: Payload::new(&[0xde, 0xad, 0xbe, 0xef]),
            },
            EgfxPdu::WireToSurface2 {
                surface_id: 1,
                codec_id: codec_id::CLEARCODEC,
                codec_context_id: 7,
                pixel_format: pixel_format::ARGB_8888,
                bitmap_data: Payload::new(&[1, 2, 3]),
            },
            EgfxPdu::DeleteEncodingContext {
                surface_id: 1,
                codec_context_id: 7,
            },
            EgfxPdu::SolidFill {
                surface_id: 2,
                fill_pixel: Color32 {
                    b: 0x11,
                    g: 0x22,
                    r: 0x33,
                    xa: 0xff,
                },
                fill_rects: vec![
                    Rect16 {
                        left: 1,
                        top: 2,
                        right: 3,
                        bottom: 4,
                    },
                    Rect16 {
                        left: 5,
                        top: 6,
                        right: 7,
                        bottom: 8,
                    },
                ],
            },
            EgfxPdu::SurfaceToSurface {
                surface_id_src: 1,
                surface_id_dest: 2,
                rect_src: Rect16 {
                    left: 0,
                    top: 0,
                    right: 16,
                    bottom: 16,
                },
                dest_pts: vec![Point16 { x: 32, y: 48 }],
            },
            EgfxPdu::SurfaceToCache {
                surface_id: 1,
                cache_key: 0x0102_0304_0506_0708,
                cache_slot: 9,
                rect_src: Rect16 {
                    left: 0,
                    top: 0,
                    right: 8,
                    bottom: 8,
                },
            },
            EgfxPdu::CacheToSurface {
                cache_slot: 9,
                surface_id: 1,
                dest_pts: vec![Point16 { x: 1, y: 2 }, Point16 { x: 3, y: 4 }],
            },
            EgfxPdu::EvictCacheEntry { cache_slot: 9 },
            EgfxPdu::CreateSurface {
                surface_id: 1,
                width: 1920,
                height: 1080,
                pixel_format: pixel_format::XRGB_8888,
            },
            EgfxPdu::DeleteSurface { surface_id: 1 },
            EgfxPdu::StartFrame {
                timestamp: 0x1234_5678,
                frame_id: 42,
            },
            EgfxPdu::EndFrame { frame_id: 42 },
            EgfxPdu::FrameAcknowledge {
                queue_depth: 2,
                frame_id: 42,
                total_frames_decoded: 100,
            },
            EgfxPdu::ResetGraphics {
                width: 1920,
                height: 1080,
                monitors: vec![MonitorDef {
                    left: 0,
                    top: 0,
                    right: 1919,
                    bottom: 1079,
                    flags: MonitorDef::PRIMARY,
                }],
            },
            EgfxPdu::MapSurfaceToOutput {
                surface_id: 1,
                reserved: 0,
                output_origin_x: 0,
                output_origin_y: 0,
            },
            EgfxPdu::CacheImportOffer { entries: vec![] },
            EgfxPdu::CacheImportOffer {
                entries: vec![CacheEntryMetadata {
                    cache_key: 7,
                    bitmap_length: 4096,
                }],
            },
            EgfxPdu::CacheImportReply {
                cache_slots: vec![1, 2, 3],
            },
            EgfxPdu::CapsAdvertise {
                capsets: vec![
                    Capset::new(caps_version::V8_1, &[0x10, 0x00, 0x00, 0x00]),
                    Capset::new(caps_version::V8, &[0x00, 0x00, 0x00, 0x00]),
                ],
            },
            EgfxPdu::CapsConfirm {
                capset: Capset::new(caps_version::V8_1, &[0x10, 0x00, 0x00, 0x00]),
            },
            EgfxPdu::MapSurfaceToWindow {
                surface_id: 1,
                window_id: 0x0102_0304_0506_0708,
                mapped_width: 800,
                mapped_height: 600,
            },
            EgfxPdu::QoeFrameAcknowledge {
                frame_id: 42,
                timestamp: 7,
                time_diff_se: 1,
                time_diff_edr: 2,
            },
            EgfxPdu::MapSurfaceToScaledOutput {
                surface_id: 1,
                reserved: 0,
                output_origin_x: 0,
                output_origin_y: 0,
                target_width: 3840,
                target_height: 2160,
            },
            EgfxPdu::MapSurfaceToScaledWindow {
                surface_id: 1,
                window_id: 5,
                mapped_width: 800,
                mapped_height: 600,
                target_width: 1600,
                target_height: 1200,
            },
            EgfxPdu::Unknown {
                cmd_id: 0x0014,
                flags: 0,
                body: Payload::new(&[0xaa, 0xbb]),
            },
        ]
    }

    #[test]
    fn every_pdu_round_trips() {
        for pdu in samples() {
            round_trip(pdu);
        }
    }

    #[test]
    fn every_pdu_truncated_at_every_prefix_errors_without_panicking() {
        for pdu in samples() {
            truncates(&pdu);
        }
    }

    /// The sample set must cover every `cmdId` the specification defines, or
    /// the two tests above quietly stop testing a command somebody added.
    #[test]
    fn the_sample_set_covers_every_command() {
        let mut seen: Vec<u16> = samples().iter().map(EgfxPdu::cmd_id).collect();
        seen.sort_unstable();
        seen.dedup();
        let defined = [
            0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B,
            0x000C, 0x000D, 0x000E, 0x000F, 0x0010, 0x0011, 0x0012, 0x0013, 0x0015, 0x0016, 0x0017,
            0x0018,
        ];
        for cmd in defined {
            assert!(seen.contains(&cmd), "no sample for cmdId {cmd:#06x}");
        }
    }

    /// MS-RDPEGFX 2.2.1.5 and 2.2.2.12: an End Frame is twelve bytes, of
    /// which eight are the header. `pduLength` counts them.
    #[test]
    fn end_frame_golden() {
        let bytes = encoded(&EgfxPdu::EndFrame { frame_id: 42 });
        assert_eq!(
            bytes,
            [0x0c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00]
        );
    }

    /// MS-RDPEGFX 2.2.2.13. The frame acknowledgement PRDRDP/04 §3.6 sends:
    /// a real queue depth, never `SUSPEND_FRAME_ACKNOWLEDGEMENT`.
    #[test]
    fn frame_acknowledge_golden() {
        let bytes = encoded(&EgfxPdu::FrameAcknowledge {
            queue_depth: 1,
            frame_id: 0x0000_002a,
            total_frames_decoded: 0x0000_0064,
        });
        assert_eq!(
            bytes,
            [
                0x0d, 0x00, 0x00, 0x00, // cmdId, flags
                0x14, 0x00, 0x00, 0x00, // pduLength = 20
                0x01, 0x00, 0x00, 0x00, // queueDepth
                0x2a, 0x00, 0x00, 0x00, // frameId
                0x64, 0x00, 0x00, 0x00, // totalFramesDecoded
            ]
        );
    }

    /// MS-RDPEGFX 2.2.2.18 with the two capability sets PRDRDP/04 §3.2 fixes
    /// for phase 2: version 8.1 with `AVC420_ENABLED`, then version 8 with no
    /// flags.
    #[test]
    fn caps_advertise_golden() {
        let avc420 = caps_flags::AVC420_ENABLED.to_le_bytes();
        let none = 0u32.to_le_bytes();
        let bytes = encoded(&EgfxPdu::CapsAdvertise {
            capsets: vec![
                Capset::new(caps_version::V8_1, &avc420),
                Capset::new(caps_version::V8, &none),
            ],
        });
        assert_eq!(
            bytes,
            [
                0x12, 0x00, 0x00, 0x00, // cmdId, flags
                0x22, 0x00, 0x00, 0x00, // pduLength = 8 + 2 + 12 + 12 = 34
                0x02, 0x00, // capsSetCount
                0x05, 0x01, 0x08, 0x00, // RDPGFX_CAPVERSION_8_1
                0x04, 0x00, 0x00, 0x00, // capsDataLength
                0x10, 0x00, 0x00, 0x00, // AVC420_ENABLED
                0x04, 0x00, 0x08, 0x00, // RDPGFX_CAPVERSION_8
                0x04, 0x00, 0x00, 0x00, // capsDataLength
                0x00, 0x00, 0x00, 0x00, // no flags
            ]
        );
    }

    #[test]
    fn a_capset_reads_its_flags_word() {
        let avc420 = caps_flags::AVC420_ENABLED.to_le_bytes();
        let capset = Capset::new(caps_version::V8_1, &avc420);
        assert_eq!(capset.flags().unwrap(), caps_flags::AVC420_ENABLED);
        // Version 10.1's sixteen reserved bytes read back as no flags.
        let v101 = Capset::new(caps_version::V10_1, &[0u8; 16]);
        assert_eq!(v101.flags().unwrap(), 0);
        // A body too short for a flags word errors rather than reading past.
        assert!(Capset::new(caps_version::V8, &[0x01]).flags().is_err());
    }

    /// PRDRDP/11 §5.3 item 1: both spellings of capability version 10.6 are
    /// in the wild and both mean the same version.
    #[test]
    fn both_spellings_of_capability_version_10_6_are_recognised() {
        assert!(caps_version::is_v10_6(caps_version::V10_6));
        assert!(caps_version::is_v10_6(caps_version::V10_6_ERRATUM));
        assert_ne!(caps_version::V10_6, caps_version::V10_6_ERRATUM);
        assert!(!caps_version::is_v10_6(caps_version::V10_7));
    }

    /// MS-RDPEGFX 2.2.2.14: the PDU is 340 bytes whatever the monitor count,
    /// and sixteen monitors fill it exactly.
    #[test]
    fn reset_graphics_is_always_340_bytes() {
        for count in [0usize, 1, 2, 16] {
            let monitors: Vec<MonitorDef> = (0..count)
                .map(|i| MonitorDef {
                    left: i as i32 * 100,
                    top: 0,
                    right: i as i32 * 100 + 99,
                    bottom: 99,
                    flags: u32::from(i == 0),
                })
                .collect();
            let pdu = EgfxPdu::ResetGraphics {
                width: 1920,
                height: 1080,
                monitors: monitors.clone(),
            };
            let bytes = encoded(&pdu);
            assert_eq!(bytes.len(), 340, "{count} monitors");
            let back = EgfxPdu::decode(&mut Reader::new(&bytes)).unwrap();
            assert_eq!(back, pdu);
        }
        // Twelve bytes of fixed fields plus sixteen twenty byte monitors is
        // the body exactly.
        assert_eq!(12 + 16 * MonitorDef::SIZE, EgfxPdu::RESET_GRAPHICS_BODY_LEN);
    }

    #[test]
    fn a_reset_graphics_with_too_many_monitors_is_refused_both_ways() {
        let mut buf = Vec::new();
        let too_many = EgfxPdu::ResetGraphics {
            width: 1,
            height: 1,
            monitors: vec![MonitorDef::default(); MAX_MONITORS + 1],
        };
        assert!(too_many.encode(&mut Writer::new(&mut buf)).is_err());

        let mut wire = vec![0x0e, 0x00, 0x00, 0x00];
        wire.extend_from_slice(&340u32.to_le_bytes());
        wire.extend_from_slice(&1u32.to_le_bytes());
        wire.extend_from_slice(&1u32.to_le_bytes());
        wire.extend_from_slice(&99u32.to_le_bytes());
        wire.resize(340, 0);
        assert!(matches!(
            EgfxPdu::decode(&mut Reader::new(&wire)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_MONITORS",
                ..
            }
        ));
    }

    /// The dispatcher takes `pduLength - 8` before the body decoder runs, so
    /// a Wire To Surface 2's payload stops at the PDU boundary and the next
    /// command starts where it should.
    #[test]
    fn several_pdus_concatenated_in_one_message_are_walked_in_order() {
        let mut buf = Vec::new();
        for pdu in [
            EgfxPdu::StartFrame {
                timestamp: 1,
                frame_id: 7,
            },
            EgfxPdu::WireToSurface2 {
                surface_id: 1,
                codec_id: codec_id::PLANAR,
                codec_context_id: 0,
                pixel_format: pixel_format::XRGB_8888,
                bitmap_data: Payload::new(&[9, 9, 9, 9]),
            },
            EgfxPdu::EndFrame { frame_id: 7 },
        ] {
            pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        }
        let got: Vec<_> = EgfxPdu::iter(&buf).map(Result::unwrap).collect();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].cmd_id(), cmd_id::START_FRAME);
        assert!(matches!(
            got[1],
            EgfxPdu::WireToSurface2 {
                ref bitmap_data, ..
            } if bitmap_data.as_slice() == [9, 9, 9, 9]
        ));
        assert_eq!(got[2], EgfxPdu::EndFrame { frame_id: 7 });
    }

    #[test]
    fn the_iterator_stops_at_the_first_error_rather_than_desyncing() {
        // A header claiming a PDU longer than the message.
        let mut buf = Vec::new();
        EgfxPdu::EndFrame { frame_id: 1 }
            .encode_checked(&mut Writer::new(&mut buf))
            .unwrap();
        buf.extend_from_slice(&[0x0c, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
        let got: Vec<_> = EgfxPdu::iter(&buf).collect();
        assert_eq!(got.len(), 2);
        assert!(got[0].is_ok());
        assert!(got[1].is_err());
    }

    #[test]
    fn a_pdu_length_below_the_header_is_a_length_mismatch() {
        let bytes = [0x0c, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00];
        assert!(matches!(
            EgfxPdu::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn a_pdu_length_past_the_cap_is_refused_before_the_take() {
        let mut bytes = vec![0x0c, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&((MAX_EGFX_PDU + 1) as u32).to_le_bytes());
        assert!(matches!(
            EgfxPdu::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_EGFX_PDU",
                ..
            }
        ));
    }

    /// A body longer than the command needs is tolerated: `pduLength` is
    /// authoritative and the outer reader advances by it, so a newer server
    /// that extends a fixed command cannot desynchronise us.
    #[test]
    fn a_longer_body_than_the_command_needs_does_not_desync_the_stream() {
        let mut buf = vec![0x0c, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&7u32.to_le_bytes());
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        EgfxPdu::StartFrame {
            timestamp: 1,
            frame_id: 8,
        }
        .encode_checked(&mut Writer::new(&mut buf))
        .unwrap();
        let got: Vec<_> = EgfxPdu::iter(&buf).map(Result::unwrap).collect();
        assert_eq!(got[0], EgfxPdu::EndFrame { frame_id: 7 });
        assert_eq!(got[1].cmd_id(), cmd_id::START_FRAME);
    }

    #[test]
    fn a_wire_to_surface_1_bitmap_length_past_its_body_is_truncated() {
        let mut buf = vec![0x01, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&(8u32 + 17).to_le_bytes());
        buf.extend_from_slice(&[0x01, 0x00]); // surfaceId
        buf.extend_from_slice(&[0x03, 0x00]); // codecId
        buf.push(pixel_format::XRGB_8888);
        buf.extend_from_slice(&[0, 0, 0, 0, 0x40, 0, 0x40, 0]); // destRect
        buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // bitmapDataLength
        assert!(matches!(
            EgfxPdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Truncated { .. }
        ));
    }

    #[test]
    fn a_rectangle_count_past_the_cap_is_refused() {
        let mut buf = vec![0x04, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&(8u32 + 8).to_le_bytes());
        buf.extend_from_slice(&[0x01, 0x00]); // surfaceId
        buf.extend_from_slice(&[0, 0, 0, 0xff]); // fillPixel
        buf.extend_from_slice(&(MAX_EGFX_RECTS as u16 + 1).to_le_bytes());
        assert!(matches!(
            EgfxPdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_EGFX_RECTS",
                ..
            }
        ));
    }

    /// A hostile count with no bytes behind it must fail the decode rather
    /// than reserve for the count it claimed (PRDRDP/13 §10.1).
    #[test]
    fn a_count_larger_than_the_bytes_left_fails_rather_than_reserving() {
        let mut buf = vec![0x04, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&(8u32 + 8).to_le_bytes());
        buf.extend_from_slice(&[0x01, 0x00]);
        buf.extend_from_slice(&[0, 0, 0, 0xff]);
        buf.extend_from_slice(&4000u16.to_le_bytes());
        assert!(matches!(
            EgfxPdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Truncated { .. }
        ));
    }

    #[test]
    fn an_unknown_command_is_preserved_and_re_encoded_unchanged() {
        let bytes = [0x99, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xaa, 0xbb];
        let pdu = EgfxPdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            pdu,
            EgfxPdu::Unknown {
                cmd_id: 0x0099,
                flags: 0x0001,
                body: Payload::new(&[0xaa, 0xbb]),
            }
        );
        assert_eq!(encoded(&pdu), bytes);
    }

    #[test]
    fn a_wire_to_surface_1_hands_on_a_borrow_of_the_frame() {
        let frame = bytes::Bytes::from(encoded(&EgfxPdu::WireToSurface1 {
            surface_id: 1,
            codec_id: codec_id::AVC420,
            pixel_format: pixel_format::XRGB_8888,
            dest_rect: Rect16::default(),
            bitmap_data: Payload::new(&[1, 2, 3, 4]),
        }));
        let EgfxPdu::WireToSurface1 { bitmap_data, .. } =
            EgfxPdu::decode(&mut Reader::new(&frame)).unwrap()
        else {
            panic!("wrong command");
        };
        let owned = bitmap_data.to_bytes(&frame);
        assert_eq!(&owned[..], &[1, 2, 3, 4]);
        // Header 8, surfaceId 2, codecId 2, pixelFormat 1, destRect 8,
        // bitmapDataLength 4.
        assert_eq!(owned.as_ptr() as usize - frame.as_ptr() as usize, 25);
    }

    /// MS-RDPEGFX 2.2.4.4: the metablock is framing, the Annex B stream that
    /// follows it is not this crate's business (PRDRDP/12 §2.2.2).
    #[test]
    fn the_avc420_metablock_round_trips_and_stops_at_the_bitstream() {
        let value = Avc420Metablock {
            region_rects: vec![
                Rect16 {
                    left: 0,
                    top: 0,
                    right: 16,
                    bottom: 16,
                },
                Rect16 {
                    left: 16,
                    top: 0,
                    right: 32,
                    bottom: 16,
                },
            ],
            quant_quality_vals: vec![
                H264QuantQuality {
                    qp_val: 0x80 | 22,
                    quality_val: 100,
                },
                H264QuantQuality {
                    qp_val: 0x40 | 30,
                    quality_val: 90,
                },
            ],
            stream: Payload::new(&[0x00, 0x00, 0x00, 0x01, 0x65]),
        };
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size());
        let back = Avc420Metablock::decode(&mut Reader::new(&buf)).unwrap();
        assert_eq!(back, value);
        assert_eq!(back.quant_quality_vals[0].qp(), 22);
        assert!(back.quant_quality_vals[0].p());
        assert!(!back.quant_quality_vals[0].r());
        assert_eq!(back.quant_quality_vals[1].qp(), 30);
        assert!(back.quant_quality_vals[1].r());
        assert_eq!(back.stream.as_slice(), [0x00, 0x00, 0x00, 0x01, 0x65]);

        for cut in 0..buf.len() {
            // Everything up to the end of the quant array must fail; a cut
            // inside the Annex B stream is a shorter stream.
            let _ = Avc420Metablock::decode(&mut Reader::new(&buf[..cut]));
        }
        for cut in 0..4 + 2 * Rect16::LEN + 2 * H264QuantQuality::LEN {
            assert!(Avc420Metablock::decode(&mut Reader::new(&buf[..cut])).is_err());
        }
    }

    #[test]
    fn an_avc420_rect_count_past_the_cap_is_refused() {
        let bytes = (MAX_AVC420_REGION_RECTS as u32 + 1).to_le_bytes();
        assert!(matches!(
            Avc420Metablock::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_AVC420_REGION_RECTS",
                ..
            }
        ));
    }

    #[test]
    fn a_metablock_whose_arrays_disagree_cannot_be_encoded() {
        let value = Avc420Metablock {
            region_rects: vec![Rect16::default()],
            quant_quality_vals: vec![],
            stream: Payload::new(&[]),
        };
        let mut buf = Vec::new();
        assert!(matches!(
            value.encode(&mut Writer::new(&mut buf)).unwrap_err(),
            PduError::Encode { .. }
        ));
    }

    #[test]
    fn the_frame_acknowledge_sentinels_are_the_specified_values() {
        assert_eq!(EgfxPdu::SUSPEND_FRAME_ACKNOWLEDGEMENT, 0xFFFF_FFFF);
        assert_eq!(EgfxPdu::QUEUE_DEPTH_UNAVAILABLE, 0);
    }

    #[test]
    fn a_cache_import_offer_past_the_specified_count_is_refused() {
        let entries = vec![CacheEntryMetadata::default(); MAX_CACHE_IMPORT_ENTRIES + 1];
        let mut buf = Vec::new();
        assert!(EgfxPdu::CacheImportOffer { entries }
            .encode(&mut Writer::new(&mut buf))
            .is_err());
    }
}
