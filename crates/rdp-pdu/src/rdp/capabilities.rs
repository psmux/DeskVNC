//! The capability sets, both directions (MS-RDPBCGR 2.2.7, PRDRDP/13 §4.8).
//!
//! Every set is `capabilitySetType` (`u16 le`), `lengthCapability` (`u16 le`,
//! including those four header bytes), then a body. The dispatcher takes
//! `lengthCapability - 4` into a bounded sub reader and matches the type; a
//! type it does not know is **skipped and kept**, not rejected, because the
//! length is explicit so skipping cannot desync. That is the opposite of the
//! rule `vnc-core/src/encodings/mod.rs` arrived at for RFB encodings, and it
//! is right here for the same underlying reason: there, the length was not
//! known and a silent skip desynced every rect that followed.
//!
//! Every set is classified extensible under PRDRDP/13 §2.5, so no decoder
//! here calls `expect_empty`. `TS_VIRTUALCHANNEL_CAPABILITYSET` is the
//! classic case: its `VCChunkSize` is absent from RDP 4.0 servers, and a
//! client that rejects the short form cannot talk to one.
//!
//! # Two places this file disagrees with PRDRDP/13 §4.8.3
//!
//! `compressionTypes` and `compressionLevel` of the General set are written
//! there as `u32 le`. They are `u16` in MS-RDPBCGR 2.2.7.1.1, and the whole
//! set is 24 bytes including its header; making them `u32` would produce a 32
//! byte set that a server rejects with `ERRINFO_CAPABILITYSETTOOLARGE`. The
//! sizes here are the specification's.
//!
//! The Window List set is 11 bytes, not 12: `NumIconCaches` is one byte and
//! `NumIconCacheEntries` is two, with no padding after them
//! (MS-RDPERP 2.2.1.1.2).

use crate::io::limits::{MAX_BITMAP_CODECS, MAX_CAPABILITY_SETS, MAX_CAPSET_LEN};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `capabilitySetType` and `lengthCapability` (MS-RDPBCGR 2.2.7.1.1).
pub const CAPSET_HEADER_LEN: usize = 4;

/// `capabilitySetType` (MS-RDPBCGR 2.2.7).
pub mod capability_set_type {
    /// `CAPSTYPE_GENERAL` (2.2.7.1.1).
    pub const GENERAL: u16 = 0x0001;
    /// `CAPSTYPE_BITMAP` (2.2.7.1.2).
    pub const BITMAP: u16 = 0x0002;
    /// `CAPSTYPE_ORDER` (2.2.7.1.3).
    pub const ORDER: u16 = 0x0003;
    /// `CAPSTYPE_BITMAPCACHE` (2.2.7.1.4.1).
    pub const BITMAP_CACHE: u16 = 0x0004;
    /// `CAPSTYPE_CONTROL` (2.2.7.2.2).
    pub const CONTROL: u16 = 0x0005;
    /// `CAPSTYPE_ACTIVATION` (2.2.7.2.3).
    pub const ACTIVATION: u16 = 0x0007;
    /// `CAPSTYPE_POINTER` (2.2.7.1.5).
    pub const POINTER: u16 = 0x0008;
    /// `CAPSTYPE_SHARE` (2.2.7.2.4).
    pub const SHARE: u16 = 0x0009;
    /// `CAPSTYPE_COLORCACHE` (2.2.7.2.1).
    pub const COLOR_CACHE: u16 = 0x000a;
    /// `CAPSTYPE_SOUND` (2.2.7.1.11).
    pub const SOUND: u16 = 0x000c;
    /// `CAPSTYPE_INPUT` (2.2.7.1.6).
    pub const INPUT: u16 = 0x000d;
    /// `CAPSTYPE_FONT` (2.2.7.2.5).
    pub const FONT: u16 = 0x000e;
    /// `CAPSTYPE_BRUSH` (2.2.7.1.7).
    pub const BRUSH: u16 = 0x000f;
    /// `CAPSTYPE_GLYPHCACHE` (2.2.7.1.8).
    pub const GLYPH_CACHE: u16 = 0x0010;
    /// `CAPSTYPE_OFFSCREENCACHE` (2.2.7.1.9).
    pub const OFFSCREEN_CACHE: u16 = 0x0011;
    /// `CAPSTYPE_BITMAPCACHE_HOSTSUPPORT` (2.2.7.1.4.3), server to client.
    pub const BITMAP_CACHE_HOST_SUPPORT: u16 = 0x0012;
    /// `CAPSTYPE_BITMAPCACHE_REV2` (2.2.7.1.4.2).
    pub const BITMAP_CACHE_REV2: u16 = 0x0013;
    /// `CAPSTYPE_VIRTUALCHANNEL` (2.2.7.1.10).
    pub const VIRTUAL_CHANNEL: u16 = 0x0014;
    /// `CAPSTYPE_DRAWNINEGRIDCACHE` (2.2.7.1.12), which we skip.
    pub const DRAW_NINE_GRID_CACHE: u16 = 0x0015;
    /// `CAPSTYPE_DRAWGDIPLUS` (2.2.7.1.13), which we skip.
    pub const DRAW_GDI_PLUS: u16 = 0x0016;
    /// `CAPSTYPE_RAIL` (MS-RDPERP 2.2.1.1.1), which we skip.
    pub const RAIL: u16 = 0x0017;
    /// `CAPSTYPE_WINDOW` (MS-RDPERP 2.2.1.1.2).
    pub const WINDOW: u16 = 0x0018;
    /// `CAPSETTYPE_COMPDESK` (2.2.7.2.8).
    pub const COMP_DESK: u16 = 0x0019;
    /// `CAPSETTYPE_MULTIFRAGMENTUPDATE` (2.2.7.2.6).
    pub const MULTIFRAGMENT_UPDATE: u16 = 0x001a;
    /// `CAPSETTYPE_LARGE_POINTER` (2.2.7.2.7).
    pub const LARGE_POINTER: u16 = 0x001b;
    /// `CAPSETTYPE_SURFACE_COMMANDS` (2.2.7.2.9).
    pub const SURFACE_COMMANDS: u16 = 0x001c;
    /// `CAPSETTYPE_BITMAP_CODECS` (2.2.7.2.10).
    pub const BITMAP_CODECS: u16 = 0x001d;
    /// `CAPSSETTYPE_FRAME_ACKNOWLEDGE`, spelled with the doubled S the
    /// specification uses.
    pub const FRAME_ACKNOWLEDGE: u16 = 0x001e;
}

/// Read a capability set header and return a bounded reader over the body.
fn read_capset<'a>(
    r: &mut Reader<'a>,
    expected: u16,
    context: &'static str,
) -> PduResult<Reader<'a>> {
    let at = r.offset();
    let set_type = r.u16(context)?;
    if set_type != expected {
        return Err(PduError::InvalidField {
            context,
            field: "capabilitySetType",
            value: u64::from(set_type),
            offset: at,
        });
    }
    read_capset_body(r, context)
}

/// Read `lengthCapability` and take the body it declares.
fn read_capset_body<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<Reader<'a>> {
    let at = r.offset();
    let length = usize::from(r.u16(context)?);
    if length < CAPSET_HEADER_LEN {
        return Err(PduError::InvalidField {
            context,
            field: "lengthCapability",
            value: length as u64,
            offset: at,
        });
    }
    let body_len = length - CAPSET_HEADER_LEN;
    r.ensure_cap(body_len, MAX_CAPSET_LEN, "MAX_CAPSET_LEN", context)?;
    r.take(body_len, context)
}

/// Write a capability set header whose `lengthCapability` counts itself.
fn write_capset_header(
    w: &mut Writer<'_>,
    set_type: u16,
    total_len: usize,
    context: &'static str,
) -> PduResult<()> {
    let length = u16::try_from(total_len).map_err(|_| PduError::Encode {
        context,
        reason: "capability set longer than its lengthCapability field",
    })?;
    w.u16(set_type);
    w.u16(length);
    Ok(())
}

/// Read an optional trailing `u16`, the extensible tail rule of §2.5.
fn opt_u16(r: &mut Reader<'_>, context: &'static str) -> PduResult<Option<u16>> {
    if r.remaining() < 2 {
        return Ok(None);
    }
    Ok(Some(r.u16(context)?))
}

/// Read an optional trailing `u32`.
fn opt_u32(r: &mut Reader<'_>, context: &'static str) -> PduResult<Option<u32>> {
    if r.remaining() < 4 {
        return Ok(None);
    }
    Ok(Some(r.u32(context)?))
}

/// `TS_GENERAL_CAPABILITYSET.osMajorType` (MS-RDPBCGR 2.2.7.1.1).
pub mod os_major_type {
    /// `OSMAJORTYPE_WINDOWS`.
    pub const WINDOWS: u16 = 0x0001;
    /// `OSMAJORTYPE_OS2`.
    pub const OS2: u16 = 0x0002;
    /// `OSMAJORTYPE_MACINTOSH`.
    pub const MACINTOSH: u16 = 0x0003;
    /// `OSMAJORTYPE_UNIX`, which is what we send because it is honest and no
    /// server branches on it (PRDRDP/13 §4.8.3).
    pub const UNIX: u16 = 0x0004;
    /// `OSMAJORTYPE_IOS`.
    pub const IOS: u16 = 0x0005;
    /// `OSMAJORTYPE_OSX`.
    pub const OSX: u16 = 0x0006;
    /// `OSMAJORTYPE_ANDROID`.
    pub const ANDROID: u16 = 0x0007;
}

/// `TS_GENERAL_CAPABILITYSET.osMinorType` (MS-RDPBCGR 2.2.7.1.1).
pub mod os_minor_type {
    /// `OSMINORTYPE_NATIVE_XSERVER`.
    pub const NATIVE_XSERVER: u16 = 0x0007;
}

/// `TS_GENERAL_CAPABILITYSET.extraFlags` (MS-RDPBCGR 2.2.7.1.1).
pub mod general_extra_flags {
    /// `FASTPATH_OUTPUT_SUPPORTED`, the flag that makes the server use the
    /// fast path output header of 2.2.9.1.2.
    pub const FASTPATH_OUTPUT_SUPPORTED: u16 = 0x0001;
    /// `NO_BITMAP_COMPRESSION_HDR`, which drops the eight byte
    /// `TS_CD_HEADER` from every compressed bitmap.
    pub const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;
    /// `LONG_CREDENTIALS_SUPPORTED`.
    pub const LONG_CREDENTIALS_SUPPORTED: u16 = 0x0004;
    /// `AUTORECONNECT_SUPPORTED`, which the phase 2 cookie needs.
    pub const AUTORECONNECT_SUPPORTED: u16 = 0x0008;
    /// `ENC_SALTED_CHECKSUM`, standard security only, so clear.
    pub const ENC_SALTED_CHECKSUM: u16 = 0x0010;
}

/// `TS_GENERAL_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.1), 24 bytes with its
/// header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeneralCapabilitySet {
    /// `osMajorType`.
    pub os_major_type: u16,
    /// `osMinorType`.
    pub os_minor_type: u16,
    /// `protocolVersion`, `TS_CAPS_PROTOCOLVERSION` 0x0200 and nothing else.
    pub protocol_version: u16,
    /// `compressionTypes`, zero: phase 1 advertises no compression.
    pub compression_types: u16,
    /// `extraFlags`, from [`general_extra_flags`].
    pub extra_flags: u16,
    /// `updateCapabilityFlag`, zero.
    pub update_capability_flag: u16,
    /// `remoteUnshareFlag`, zero.
    pub remote_unshare_flag: u16,
    /// `compressionLevel`, zero.
    pub compression_level: u16,
    /// `refreshRectSupport`, 1, which is what lets us send 2.2.11.2.
    pub refresh_rect_support: u8,
    /// `suppressOutputSupport`, 1, which is what lets us send 2.2.11.3.
    pub suppress_output_support: u8,
}

impl GeneralCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_GENERAL_CAPABILITYSET";

    /// `TS_CAPS_PROTOCOLVERSION`, the only value `protocolVersion` takes.
    pub const PROTOCOL_VERSION: u16 = 0x0200;

    /// The set this client sends (PRDRDP/13 §4.8.3).
    #[must_use]
    pub const fn client() -> Self {
        Self {
            os_major_type: os_major_type::UNIX,
            os_minor_type: os_minor_type::NATIVE_XSERVER,
            protocol_version: Self::PROTOCOL_VERSION,
            compression_types: 0,
            extra_flags: general_extra_flags::FASTPATH_OUTPUT_SUPPORTED
                | general_extra_flags::NO_BITMAP_COMPRESSION_HDR
                | general_extra_flags::LONG_CREDENTIALS_SUPPORTED
                | general_extra_flags::AUTORECONNECT_SUPPORTED,
            update_capability_flag: 0,
            remote_unshare_flag: 0,
            compression_level: 0,
            refresh_rect_support: 1,
            suppress_output_support: 1,
        }
    }

    /// True when the server will use the fast path output header.
    #[must_use]
    pub const fn fastpath_output(&self) -> bool {
        self.extra_flags & general_extra_flags::FASTPATH_OUTPUT_SUPPORTED != 0
    }

    /// True when compressed bitmaps arrive without their `TS_CD_HEADER`.
    #[must_use]
    pub const fn no_bitmap_compression_header(&self) -> bool {
        self.extra_flags & general_extra_flags::NO_BITMAP_COMPRESSION_HDR != 0
    }
}

impl Encode for GeneralCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 20
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::GENERAL, self.size(), Self::NAME)?;
        w.u16(self.os_major_type);
        w.u16(self.os_minor_type);
        w.u16(self.protocol_version);
        // `pad2octetsA`.
        w.u16(0);
        w.u16(self.compression_types);
        w.u16(self.extra_flags);
        w.u16(self.update_capability_flag);
        w.u16(self.remote_unshare_flag);
        w.u16(self.compression_level);
        w.u8(self.refresh_rect_support);
        w.u8(self.suppress_output_support);
        Ok(())
    }
}

impl Decode<'_> for GeneralCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::GENERAL, Self::NAME)?;
        let os_major_type = b.u16(Self::NAME)?;
        let os_minor_type = b.u16(Self::NAME)?;
        let at = b.offset();
        let protocol_version = b.u16(Self::NAME)?;
        if protocol_version != Self::PROTOCOL_VERSION {
            // The specification names one value and a server sending another
            // is not a server we understand (PRDRDP/13 §4.8.3).
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "protocolVersion",
                value: u64::from(protocol_version),
                offset: at,
            });
        }
        b.skip(2, Self::NAME)?;
        Ok(Self {
            os_major_type,
            os_minor_type,
            protocol_version,
            compression_types: b.u16(Self::NAME)?,
            extra_flags: b.u16(Self::NAME)?,
            update_capability_flag: b.u16(Self::NAME)?,
            remote_unshare_flag: b.u16(Self::NAME)?,
            compression_level: b.u16(Self::NAME)?,
            refresh_rect_support: b.u8(Self::NAME)?,
            suppress_output_support: b.u8(Self::NAME)?,
        })
    }
}

/// `TS_BITMAP_CAPABILITYSET.drawingFlags` (MS-RDPBCGR 2.2.7.1.2).
pub mod bitmap_drawing_flags {
    /// `DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY`.
    pub const ALLOW_DYNAMIC_COLOR_FIDELITY: u8 = 0x02;
    /// `DRAW_ALLOW_COLOR_SUBSAMPLING`, clear: chroma subsampled bitmaps are
    /// not something the phase 1 decoders handle.
    pub const ALLOW_COLOR_SUBSAMPLING: u8 = 0x04;
    /// `DRAW_ALLOW_SKIP_ALPHA`, which says the server may send 32bpp bitmaps
    /// whose alpha byte is garbage. It does that anyway; setting the flag
    /// makes the contract explicit and lets the planar decoder skip the alpha
    /// plane (PRDRDP/13 §4.8.3).
    pub const ALLOW_SKIP_ALPHA: u8 = 0x08;
}

/// `TS_BITMAP_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.2), 28 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BitmapCapabilitySet {
    /// `preferredBitsPerPixel`, 32.
    pub preferred_bits_per_pixel: u16,
    /// `receive1BitPerPixel`, ignored by every server.
    pub receive_1_bit_per_pixel: u16,
    /// `receive4BitsPerPixel`, ignored.
    pub receive_4_bits_per_pixel: u16,
    /// `receive8BitsPerPixel`, ignored.
    pub receive_8_bits_per_pixel: u16,
    /// `desktopWidth`.
    pub desktop_width: u16,
    /// `desktopHeight`.
    pub desktop_height: u16,
    /// `desktopResizeFlag`.
    pub desktop_resize_flag: u16,
    /// `bitmapCompressionFlag`, which the specification says must be 1.
    pub bitmap_compression_flag: u16,
    /// `highColorFlags`, zero.
    pub high_color_flags: u8,
    /// `drawingFlags`, from [`bitmap_drawing_flags`].
    pub drawing_flags: u8,
    /// `multipleRectangleSupport`, which must be 1.
    pub multiple_rectangle_support: u16,
}

impl BitmapCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAP_CAPABILITYSET";

    /// The set this client sends for a desktop of the given size.
    #[must_use]
    pub const fn client(desktop_width: u16, desktop_height: u16) -> Self {
        Self {
            preferred_bits_per_pixel: 32,
            receive_1_bit_per_pixel: 1,
            receive_4_bits_per_pixel: 1,
            receive_8_bits_per_pixel: 1,
            desktop_width,
            desktop_height,
            desktop_resize_flag: 1,
            bitmap_compression_flag: 1,
            high_color_flags: 0,
            drawing_flags: bitmap_drawing_flags::ALLOW_DYNAMIC_COLOR_FIDELITY
                | bitmap_drawing_flags::ALLOW_SKIP_ALPHA,
            multiple_rectangle_support: 1,
        }
    }
}

impl Encode for BitmapCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 24
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::BITMAP, self.size(), Self::NAME)?;
        w.u16(self.preferred_bits_per_pixel);
        w.u16(self.receive_1_bit_per_pixel);
        w.u16(self.receive_4_bits_per_pixel);
        w.u16(self.receive_8_bits_per_pixel);
        w.u16(self.desktop_width);
        w.u16(self.desktop_height);
        // `pad2octets`.
        w.u16(0);
        w.u16(self.desktop_resize_flag);
        w.u16(self.bitmap_compression_flag);
        w.u8(self.high_color_flags);
        w.u8(self.drawing_flags);
        w.u16(self.multiple_rectangle_support);
        // `pad2octetsB`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for BitmapCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::BITMAP, Self::NAME)?;
        let preferred_bits_per_pixel = b.u16(Self::NAME)?;
        let receive_1_bit_per_pixel = b.u16(Self::NAME)?;
        let receive_4_bits_per_pixel = b.u16(Self::NAME)?;
        let receive_8_bits_per_pixel = b.u16(Self::NAME)?;
        let desktop_width = b.u16(Self::NAME)?;
        let desktop_height = b.u16(Self::NAME)?;
        b.skip(2, Self::NAME)?;
        Ok(Self {
            preferred_bits_per_pixel,
            receive_1_bit_per_pixel,
            receive_4_bits_per_pixel,
            receive_8_bits_per_pixel,
            desktop_width,
            desktop_height,
            desktop_resize_flag: b.u16(Self::NAME)?,
            bitmap_compression_flag: b.u16(Self::NAME)?,
            high_color_flags: b.u8(Self::NAME)?,
            drawing_flags: b.u8(Self::NAME)?,
            multiple_rectangle_support: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_ORDER_CAPABILITYSET.orderFlags` (MS-RDPBCGR 2.2.7.1.3).
pub mod order_flags {
    /// `NEGOTIATEORDERSUPPORT`: "read my `orderSupport` array". Without it
    /// the array is ignored and the server assumes a default set, which is
    /// the failure mode where a server starts sending `MemBlt` at a client
    /// that cannot draw it (PRDRDP/13 §4.8.3).
    pub const NEGOTIATE_ORDER_SUPPORT: u16 = 0x0002;
    /// `ZEROBOUNDSDELTASSUPPORT`, required of any client that negotiates
    /// orders at all and free when the array is empty.
    pub const ZERO_BOUNDS_DELTAS_SUPPORT: u16 = 0x0008;
    /// `COLORINDEXSUPPORT`.
    pub const COLOR_INDEX_SUPPORT: u16 = 0x0020;
    /// `SOLIDPATTERNBRUSHONLY`.
    pub const SOLID_PATTERN_BRUSH_ONLY: u16 = 0x0040;
    /// `ORDERFLAGS_EXTRA_FLAGS`, which makes `orderSupportExFlags` readable.
    pub const EXTRA_FLAGS: u16 = 0x0080;
}

/// The `orderSupport` array is thirty two bytes, one per order
/// (MS-RDPBCGR 2.2.7.1.3).
pub const ORDER_SUPPORT_LEN: usize = 32;

/// Indices into `orderSupport` (MS-RDPBCGR 2.2.7.1.3).
///
/// Declared so the test that every index is zero can name what it is
/// asserting. PRDRDP/04 §8.2 decides that this client implements no GDI
/// drawing orders; this module states the encoding that carries the decision.
pub mod order_index {
    /// `TS_NEG_DSTBLT_INDEX`.
    pub const DSTBLT: usize = 0x00;
    /// `TS_NEG_PATBLT_INDEX`.
    pub const PATBLT: usize = 0x01;
    /// `TS_NEG_SCRBLT_INDEX`.
    pub const SCRBLT: usize = 0x02;
    /// `TS_NEG_MEMBLT_INDEX`.
    pub const MEMBLT: usize = 0x03;
    /// `TS_NEG_MEM3BLT_INDEX`.
    pub const MEM3BLT: usize = 0x04;
    /// `TS_NEG_DRAWNINEGRID_INDEX`.
    pub const DRAWNINEGRID: usize = 0x07;
    /// `TS_NEG_LINETO_INDEX`.
    pub const LINETO: usize = 0x08;
    /// `TS_NEG_MULTI_DRAWNINEGRID_INDEX`.
    pub const MULTI_DRAWNINEGRID: usize = 0x09;
    /// `TS_NEG_SAVEBITMAP_INDEX`.
    pub const SAVEBITMAP: usize = 0x0b;
    /// `TS_NEG_MULTIDSTBLT_INDEX`.
    pub const MULTIDSTBLT: usize = 0x0f;
    /// `TS_NEG_MULTIPATBLT_INDEX`.
    pub const MULTIPATBLT: usize = 0x10;
    /// `TS_NEG_MULTISCRBLT_INDEX`.
    pub const MULTISCRBLT: usize = 0x11;
    /// `TS_NEG_MULTIOPAQUERECT_INDEX`.
    pub const MULTIOPAQUERECT: usize = 0x12;
    /// `TS_NEG_FAST_INDEX_INDEX`.
    pub const FAST_INDEX: usize = 0x13;
    /// `TS_NEG_POLYGON_SC_INDEX`.
    pub const POLYGON_SC: usize = 0x14;
    /// `TS_NEG_POLYGON_CB_INDEX`.
    pub const POLYGON_CB: usize = 0x15;
    /// `TS_NEG_POLYLINE_INDEX`.
    pub const POLYLINE: usize = 0x16;
    /// `TS_NEG_FAST_GLYPH_INDEX`.
    pub const FAST_GLYPH: usize = 0x18;
    /// `TS_NEG_ELLIPSE_SC_INDEX`.
    pub const ELLIPSE_SC: usize = 0x19;
    /// `TS_NEG_ELLIPSE_CB_INDEX`.
    pub const ELLIPSE_CB: usize = 0x1a;
    /// `TS_NEG_GLYPH_INDEX`.
    pub const GLYPH: usize = 0x1b;
}

/// `TS_ORDER_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.3), 88 bytes.
///
/// The set that commits us to decoding no GDI at all: `orderSupport` is
/// thirty two zero bytes and `NEGOTIATEORDERSUPPORT` is set, which together
/// say "I support no orders" rather than "assume the default set".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderCapabilitySet {
    /// `desktopSaveXGranularity`, 1.
    pub desktop_save_x_granularity: u16,
    /// `desktopSaveYGranularity`, 20.
    pub desktop_save_y_granularity: u16,
    /// `maximumOrderLevel`, `ORD_LEVEL_1_ORDERS`.
    pub maximum_order_level: u16,
    /// `numberFonts`, zero.
    pub number_fonts: u16,
    /// `orderFlags`, from [`order_flags`].
    pub order_flags: u16,
    /// `orderSupport`, one byte per order index.
    pub order_support: [u8; ORDER_SUPPORT_LEN],
    /// `textFlags`, zero.
    pub text_flags: u16,
    /// `orderSupportExFlags`, zero.
    pub order_support_ex_flags: u16,
    /// `desktopSaveSize`, zero.
    pub desktop_save_size: u32,
    /// `textANSICodePage`, zero.
    pub text_ansi_code_page: u16,
}

impl Default for OrderCapabilitySet {
    fn default() -> Self {
        Self {
            desktop_save_x_granularity: 0,
            desktop_save_y_granularity: 0,
            maximum_order_level: 0,
            number_fonts: 0,
            order_flags: 0,
            order_support: [0u8; ORDER_SUPPORT_LEN],
            text_flags: 0,
            order_support_ex_flags: 0,
            desktop_save_size: 0,
            text_ansi_code_page: 0,
        }
    }
}

impl OrderCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_ORDER_CAPABILITYSET";

    /// `ORD_LEVEL_1_ORDERS`.
    pub const ORD_LEVEL_1_ORDERS: u16 = 1;

    /// The set this client sends: no order supported, and the flag that makes
    /// the server believe it (PRDRDP/13 §4.8.3).
    #[must_use]
    pub const fn client() -> Self {
        Self {
            desktop_save_x_granularity: 1,
            desktop_save_y_granularity: 20,
            maximum_order_level: Self::ORD_LEVEL_1_ORDERS,
            number_fonts: 0,
            order_flags: order_flags::NEGOTIATE_ORDER_SUPPORT
                | order_flags::ZERO_BOUNDS_DELTAS_SUPPORT,
            order_support: [0u8; ORDER_SUPPORT_LEN],
            text_flags: 0,
            order_support_ex_flags: 0,
            desktop_save_size: 0,
            text_ansi_code_page: 0,
        }
    }

    /// True when no order index is set, which is what this client advertises.
    #[must_use]
    pub fn supports_no_orders(&self) -> bool {
        self.order_support.iter().all(|b| *b == 0)
    }
}

impl Encode for OrderCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 84
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::ORDER, self.size(), Self::NAME)?;
        // `terminalDescriptor`, sixteen zero bytes.
        w.zeros(16);
        // `pad4octetsA`.
        w.zeros(4);
        w.u16(self.desktop_save_x_granularity);
        w.u16(self.desktop_save_y_granularity);
        // `pad2octetsA`.
        w.u16(0);
        w.u16(self.maximum_order_level);
        w.u16(self.number_fonts);
        w.u16(self.order_flags);
        w.bytes(&self.order_support);
        w.u16(self.text_flags);
        w.u16(self.order_support_ex_flags);
        // `pad4octetsB`.
        w.zeros(4);
        w.u32(self.desktop_save_size);
        // `pad2octetsC`, `pad2octetsD`.
        w.zeros(4);
        w.u16(self.text_ansi_code_page);
        // `pad2octetsE`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for OrderCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::ORDER, Self::NAME)?;
        b.skip(16, Self::NAME)?;
        b.skip(4, Self::NAME)?;
        let desktop_save_x_granularity = b.u16(Self::NAME)?;
        let desktop_save_y_granularity = b.u16(Self::NAME)?;
        b.skip(2, Self::NAME)?;
        let maximum_order_level = b.u16(Self::NAME)?;
        let number_fonts = b.u16(Self::NAME)?;
        let order_flags = b.u16(Self::NAME)?;
        let order_support = b.array::<ORDER_SUPPORT_LEN>(Self::NAME)?;
        let text_flags = b.u16(Self::NAME)?;
        let order_support_ex_flags = b.u16(Self::NAME)?;
        b.skip(4, Self::NAME)?;
        let desktop_save_size = b.u32(Self::NAME)?;
        b.skip(4, Self::NAME)?;
        let text_ansi_code_page = b.u16(Self::NAME)?;
        Ok(Self {
            desktop_save_x_granularity,
            desktop_save_y_granularity,
            maximum_order_level,
            number_fonts,
            order_flags,
            order_support,
            text_flags,
            order_support_ex_flags,
            desktop_save_size,
            text_ansi_code_page,
        })
    }
}

/// One cell of `TS_BITMAPCACHE_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BitmapCacheCell {
    /// `CacheNEntries`.
    pub entries: u16,
    /// `CacheNMaximumCellSize`.
    pub maximum_cell_size: u16,
}

/// `TS_BITMAPCACHE_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.4.1), 40 bytes.
///
/// Twenty four bytes of reserved fields and three cells. We send it empty:
/// a server that sees neither cache set may assume a default cache, and both
/// present and empty is unambiguous (PRDRDP/13 §4.8.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BitmapCacheCapabilitySet {
    /// The three cells, all zero for us.
    pub cells: [BitmapCacheCell; 3],
}

impl BitmapCacheCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAPCACHE_CAPABILITYSET";
}

impl Encode for BitmapCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 36
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::BITMAP_CACHE,
            self.size(),
            Self::NAME,
        )?;
        // `pad1` to `pad6`.
        w.zeros(24);
        for cell in &self.cells {
            w.u16(cell.entries);
            w.u16(cell.maximum_cell_size);
        }
        Ok(())
    }
}

impl Decode<'_> for BitmapCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::BITMAP_CACHE, Self::NAME)?;
        b.skip(24, Self::NAME)?;
        let mut cells = [BitmapCacheCell::default(); 3];
        for cell in &mut cells {
            cell.entries = b.u16(Self::NAME)?;
            cell.maximum_cell_size = b.u16(Self::NAME)?;
        }
        Ok(Self { cells })
    }
}

/// `TS_BITMAPCACHE_CAPABILITYSET_REV2.CacheFlags` (MS-RDPBCGR 2.2.7.1.4.2).
pub mod bitmap_cache_rev2_flags {
    /// `PERSISTENT_KEYS_EXPECTED_FLAG`.
    pub const PERSISTENT_KEYS_EXPECTED: u16 = 0x0001;
    /// `ALLOW_CACHE_WAITING_LIST_FLAG`.
    pub const ALLOW_CACHE_WAITING_LIST: u16 = 0x0002;
}

/// `TS_BITMAPCACHE_CAPABILITYSET_REV2` (MS-RDPBCGR 2.2.7.1.4.2), 40 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BitmapCacheRev2CapabilitySet {
    /// `CacheFlags`, from [`bitmap_cache_rev2_flags`].
    pub cache_flags: u16,
    /// `NumCellCaches`, zero for us.
    pub num_cell_caches: u8,
    /// The five `BitmapCacheNCellInfo` words: bits 0 to 30 the entry count,
    /// bit 31 the persistent flag.
    pub cell_info: [u32; 5],
}

impl BitmapCacheRev2CapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAPCACHE_CAPABILITYSET_REV2";

    /// `BitmapCacheNCellInfo`'s persistent bit.
    pub const PERSISTENT_FLAG: u32 = 0x8000_0000;
}

impl Encode for BitmapCacheRev2CapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 36
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::BITMAP_CACHE_REV2,
            self.size(),
            Self::NAME,
        )?;
        w.u16(self.cache_flags);
        // `Pad2`.
        w.u8(0);
        w.u8(self.num_cell_caches);
        for info in &self.cell_info {
            w.u32(*info);
        }
        // `Pad3`.
        w.zeros(12);
        Ok(())
    }
}

impl Decode<'_> for BitmapCacheRev2CapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::BITMAP_CACHE_REV2, Self::NAME)?;
        let cache_flags = b.u16(Self::NAME)?;
        b.skip(1, Self::NAME)?;
        let num_cell_caches = b.u8(Self::NAME)?;
        let mut cell_info = [0u32; 5];
        for info in &mut cell_info {
            *info = b.u32(Self::NAME)?;
        }
        Ok(Self {
            cache_flags,
            num_cell_caches,
            cell_info,
        })
    }
}

/// `TS_BITMAPCACHE_HOSTSUPPORT_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.4.3), 8
/// bytes, server to client only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BitmapCacheHostSupportCapabilitySet {
    /// `CacheVersion`, `BITMAPCACHE_REV2` 1.
    pub cache_version: u8,
}

impl BitmapCacheHostSupportCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAPCACHE_HOSTSUPPORT_CAPABILITYSET";
}

impl Encode for BitmapCacheHostSupportCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::BITMAP_CACHE_HOST_SUPPORT,
            self.size(),
            Self::NAME,
        )?;
        w.u8(self.cache_version);
        // `Pad1`, `Pad2`.
        w.zeros(3);
        Ok(())
    }
}

impl Decode<'_> for BitmapCacheHostSupportCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(
            r,
            capability_set_type::BITMAP_CACHE_HOST_SUPPORT,
            Self::NAME,
        )?;
        Ok(Self {
            cache_version: b.u8(Self::NAME)?,
        })
    }
}

/// `TS_POINTER_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.5), 10 bytes.
///
/// `pointerCacheSize` is the extensible tail: a server that sees zero there
/// never sends `TS_PTRMSGTYPE_POINTER` and falls back to the 24bpp colour
/// form, so its absence and a zero mean the same thing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PointerCapabilitySet {
    /// `colorPointerFlag`.
    pub color_pointer_flag: u16,
    /// `colorPointerCacheSize`, the legacy colour pointer cache.
    pub color_pointer_cache_size: u16,
    /// `pointerCacheSize`, the new pointer cache.
    pub pointer_cache_size: Option<u16>,
}

impl PointerCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_POINTER_CAPABILITYSET";

    /// The set this client sends (PRDRDP/13 §4.8.3).
    #[must_use]
    pub const fn client() -> Self {
        Self {
            color_pointer_flag: 1,
            color_pointer_cache_size: 25,
            pointer_cache_size: Some(25),
        }
    }
}

impl Encode for PointerCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN
            + 4
            + if self.pointer_cache_size.is_some() {
                2
            } else {
                0
            }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::POINTER, self.size(), Self::NAME)?;
        w.u16(self.color_pointer_flag);
        w.u16(self.color_pointer_cache_size);
        if let Some(size) = self.pointer_cache_size {
            w.u16(size);
        }
        Ok(())
    }
}

impl Decode<'_> for PointerCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::POINTER, Self::NAME)?;
        Ok(Self {
            color_pointer_flag: b.u16(Self::NAME)?,
            color_pointer_cache_size: b.u16(Self::NAME)?,
            pointer_cache_size: opt_u16(&mut b, Self::NAME)?,
        })
    }
}

/// `TS_INPUT_CAPABILITYSET.inputFlags` (MS-RDPBCGR 2.2.7.1.6).
pub mod input_flags {
    /// `INPUT_FLAG_SCANCODES`.
    pub const SCANCODES: u16 = 0x0001;
    /// `INPUT_FLAG_MOUSEX`, buttons 4 and 5.
    pub const MOUSEX: u16 = 0x0004;
    /// `INPUT_FLAG_FASTPATH_INPUT`.
    pub const FASTPATH_INPUT: u16 = 0x0008;
    /// `INPUT_FLAG_UNICODE`.
    pub const UNICODE: u16 = 0x0010;
    /// `INPUT_FLAG_FASTPATH_INPUT2`. The one that matters: without it
    /// Windows accepts fast path input and ignores the `numberEvents` byte
    /// extension, so only clients setting both flags get reliable fast path
    /// input on every server version (PRDRDP/13 §4.8.3).
    pub const FASTPATH_INPUT2: u16 = 0x0020;
    /// `INPUT_FLAG_UNUSED1`.
    pub const UNUSED1: u16 = 0x0040;
    /// `INPUT_FLAG_MOUSE_RELATIVE`.
    pub const MOUSE_RELATIVE: u16 = 0x0080;
    /// `TS_INPUT_FLAG_MOUSE_HWHEEL`.
    pub const MOUSE_HWHEEL: u16 = 0x0100;
    /// `TS_INPUT_FLAG_QOE_TIMESTAMPS`, phase 2, which feeds `rtt_ms`.
    pub const QOE_TIMESTAMPS: u16 = 0x0200;
}

/// The fixed width of `imeFileName`, in bytes (MS-RDPBCGR 2.2.7.1.6).
pub const IME_FILE_NAME_LEN: usize = 64;

/// `TS_INPUT_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.6), 88 bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputCapabilitySet {
    /// `inputFlags`, from [`input_flags`].
    pub input_flags: u16,
    /// `keyboardLayout`, echoing `TS_UD_CS_CORE`.
    pub keyboard_layout: u32,
    /// `keyboardType`.
    pub keyboard_type: u32,
    /// `keyboardSubType`.
    pub keyboard_sub_type: u32,
    /// `keyboardFunctionKey`.
    pub keyboard_function_key: u32,
    /// `imeFileName`, empty for every layout we support.
    pub ime_file_name: String,
}

impl InputCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_INPUT_CAPABILITYSET";

    /// The flags this client sends in phase 1 (PRDRDP/13 §4.8.3).
    pub const CLIENT_FLAGS: u16 = input_flags::SCANCODES
        | input_flags::MOUSEX
        | input_flags::FASTPATH_INPUT
        | input_flags::UNICODE
        | input_flags::FASTPATH_INPUT2
        | input_flags::MOUSE_HWHEEL;

    /// The set this client sends, echoing the keyboard fields of
    /// `TS_UD_CS_CORE`.
    #[must_use]
    pub fn client(
        keyboard_layout: u32,
        keyboard_type: u32,
        keyboard_sub_type: u32,
        keyboard_function_key: u32,
    ) -> Self {
        Self {
            input_flags: Self::CLIENT_FLAGS,
            keyboard_layout,
            keyboard_type,
            keyboard_sub_type,
            keyboard_function_key,
            ime_file_name: String::new(),
        }
    }
}

impl Encode for InputCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 20 + IME_FILE_NAME_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::INPUT, self.size(), Self::NAME)?;
        w.u16(self.input_flags);
        // `pad2octetsA`.
        w.u16(0);
        w.u32(self.keyboard_layout);
        w.u32(self.keyboard_type);
        w.u32(self.keyboard_sub_type);
        w.u32(self.keyboard_function_key);
        w.utf16_fixed(&self.ime_file_name, IME_FILE_NAME_LEN, Self::NAME)
    }
}

impl Decode<'_> for InputCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::INPUT, Self::NAME)?;
        let input_flags = b.u16(Self::NAME)?;
        b.skip(2, Self::NAME)?;
        Ok(Self {
            input_flags,
            keyboard_layout: b.u32(Self::NAME)?,
            keyboard_type: b.u32(Self::NAME)?,
            keyboard_sub_type: b.u32(Self::NAME)?,
            keyboard_function_key: b.u32(Self::NAME)?,
            ime_file_name: b.utf16_fixed(IME_FILE_NAME_LEN, Self::NAME)?,
        })
    }
}

/// `TS_BRUSH_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.7), 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BrushCapabilitySet {
    /// `brushSupportLevel`, `BRUSH_DEFAULT` 0.
    pub brush_support_level: u32,
}

impl BrushCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BRUSH_CAPABILITYSET";
}

impl Encode for BrushCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::BRUSH, self.size(), Self::NAME)?;
        w.u32(self.brush_support_level);
        Ok(())
    }
}

impl Decode<'_> for BrushCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::BRUSH, Self::NAME)?;
        Ok(Self {
            brush_support_level: b.u32(Self::NAME)?,
        })
    }
}

/// One `TS_CACHE_DEFINITION` of the glyph cache (MS-RDPBCGR 2.2.7.1.8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlyphCacheDefinition {
    /// `CacheEntries`.
    pub cache_entries: u16,
    /// `CacheMaximumCellSize`.
    pub cache_maximum_cell_size: u16,
}

/// `TS_GLYPHCACHE_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.8), 52 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlyphCacheCapabilitySet {
    /// The ten `GlyphCache` definitions, all zero for us.
    pub glyph_cache: [GlyphCacheDefinition; 10],
    /// `FragCache`.
    pub frag_cache: u32,
    /// `GlyphSupportLevel`, `GLYPH_SUPPORT_NONE` 0.
    pub glyph_support_level: u16,
}

impl GlyphCacheCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_GLYPHCACHE_CAPABILITYSET";

    /// `GLYPH_SUPPORT_NONE`, which is what a client that draws no glyphs
    /// advertises.
    pub const GLYPH_SUPPORT_NONE: u16 = 0x0000;
}

impl Encode for GlyphCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 48
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::GLYPH_CACHE, self.size(), Self::NAME)?;
        for cache in &self.glyph_cache {
            w.u16(cache.cache_entries);
            w.u16(cache.cache_maximum_cell_size);
        }
        w.u32(self.frag_cache);
        w.u16(self.glyph_support_level);
        // `pad2octets`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for GlyphCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::GLYPH_CACHE, Self::NAME)?;
        let mut glyph_cache = [GlyphCacheDefinition::default(); 10];
        for cache in &mut glyph_cache {
            cache.cache_entries = b.u16(Self::NAME)?;
            cache.cache_maximum_cell_size = b.u16(Self::NAME)?;
        }
        Ok(Self {
            glyph_cache,
            frag_cache: b.u32(Self::NAME)?,
            glyph_support_level: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_OFFSCREEN_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.9), 12 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OffscreenCacheCapabilitySet {
    /// `offscreenSupportLevel`, zero: we implement no offscreen cache.
    pub offscreen_support_level: u32,
    /// `offscreenCacheSize`, in kilobytes.
    pub offscreen_cache_size: u16,
    /// `offscreenCacheEntries`.
    pub offscreen_cache_entries: u16,
}

impl OffscreenCacheCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_OFFSCREEN_CAPABILITYSET";
}

impl Encode for OffscreenCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::OFFSCREEN_CACHE,
            self.size(),
            Self::NAME,
        )?;
        w.u32(self.offscreen_support_level);
        w.u16(self.offscreen_cache_size);
        w.u16(self.offscreen_cache_entries);
        Ok(())
    }
}

impl Decode<'_> for OffscreenCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::OFFSCREEN_CACHE, Self::NAME)?;
        Ok(Self {
            offscreen_support_level: b.u32(Self::NAME)?,
            offscreen_cache_size: b.u16(Self::NAME)?,
            offscreen_cache_entries: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_VIRTUALCHANNEL_CAPABILITYSET.flags` (MS-RDPBCGR 2.2.7.1.10).
pub mod virtual_channel_flags {
    /// `VCCAPS_NO_COMPR`, what phase 1 sends.
    pub const NO_COMPR: u32 = 0x0000_0000;
    /// `VCCAPS_COMPR_SC`.
    pub const COMPR_SC: u32 = 0x0000_0001;
    /// `VCCAPS_COMPR_CS_8K`.
    pub const COMPR_CS_8K: u32 = 0x0000_0002;
}

/// `CHANNEL_CHUNK_LENGTH`, the default and the value we advertise
/// (MS-RDPBCGR 2.2.7.1.10).
pub const CHANNEL_CHUNK_LENGTH: u32 = 1600;

/// `TS_VIRTUALCHANNEL_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.10), 8 or 12 bytes.
///
/// The classic extensible tail: `VCChunkSize` is absent from RDP 4.0 servers
/// and a missing field means [`CHANNEL_CHUNK_LENGTH`] (PRDRDP/13 §2.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtualChannelCapabilitySet {
    /// `flags`, from [`virtual_channel_flags`].
    pub flags: u32,
    /// `VCChunkSize`, the chunk size the sender will use.
    pub chunk_size: Option<u32>,
}

impl VirtualChannelCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_VIRTUALCHANNEL_CAPABILITYSET";

    /// The set this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            flags: virtual_channel_flags::NO_COMPR,
            chunk_size: Some(CHANNEL_CHUNK_LENGTH),
        }
    }

    /// The chunk size to use, which is [`CHANNEL_CHUNK_LENGTH`] when the
    /// field was absent.
    #[must_use]
    pub const fn effective_chunk_size(&self) -> u32 {
        match self.chunk_size {
            Some(size) => size,
            None => CHANNEL_CHUNK_LENGTH,
        }
    }
}

impl Encode for VirtualChannelCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4 + if self.chunk_size.is_some() { 4 } else { 0 }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::VIRTUAL_CHANNEL,
            self.size(),
            Self::NAME,
        )?;
        w.u32(self.flags);
        if let Some(size) = self.chunk_size {
            w.u32(size);
        }
        Ok(())
    }
}

impl Decode<'_> for VirtualChannelCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::VIRTUAL_CHANNEL, Self::NAME)?;
        Ok(Self {
            flags: b.u32(Self::NAME)?,
            chunk_size: opt_u32(&mut b, Self::NAME)?,
        })
    }
}

/// `TS_SOUND_CAPABILITYSET` (MS-RDPBCGR 2.2.7.1.11), 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SoundCapabilitySet {
    /// `soundFlags`: `SOUND_BEEPS_FLAG` 0x0001. We clear it, so the server
    /// does not send `PDUTYPE2_PLAY_SOUND`.
    pub sound_flags: u16,
}

impl SoundCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SOUND_CAPABILITYSET";

    /// `SOUND_BEEPS_FLAG`.
    pub const BEEPS: u16 = 0x0001;
}

impl Encode for SoundCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::SOUND, self.size(), Self::NAME)?;
        w.u16(self.sound_flags);
        // `pad2octetsA`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for SoundCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::SOUND, Self::NAME)?;
        Ok(Self {
            sound_flags: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_CONTROL_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.2), 12 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlCapabilitySet {
    /// `controlFlags`, zero.
    pub control_flags: u16,
    /// `remoteDetachFlag`, zero.
    pub remote_detach_flag: u16,
    /// `controlInterest`, `CONTROLPRIORITY_NEVER`.
    pub control_interest: u16,
    /// `detachInterest`, `CONTROLPRIORITY_NEVER`.
    pub detach_interest: u16,
}

impl ControlCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_CONTROL_CAPABILITYSET";

    /// `CONTROLPRIORITY_NEVER`.
    pub const CONTROLPRIORITY_NEVER: u16 = 0x0002;

    /// The set this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            control_flags: 0,
            remote_detach_flag: 0,
            control_interest: Self::CONTROLPRIORITY_NEVER,
            detach_interest: Self::CONTROLPRIORITY_NEVER,
        }
    }
}

impl Encode for ControlCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::CONTROL, self.size(), Self::NAME)?;
        w.u16(self.control_flags);
        w.u16(self.remote_detach_flag);
        w.u16(self.control_interest);
        w.u16(self.detach_interest);
        Ok(())
    }
}

impl Decode<'_> for ControlCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::CONTROL, Self::NAME)?;
        Ok(Self {
            control_flags: b.u16(Self::NAME)?,
            remote_detach_flag: b.u16(Self::NAME)?,
            control_interest: b.u16(Self::NAME)?,
            detach_interest: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_WINDOWACTIVATION_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.3), 12 bytes, all
/// four fields zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowActivationCapabilitySet {
    /// `helpKeyFlag`.
    pub help_key_flag: u16,
    /// `helpKeyIndexFlag`.
    pub help_key_index_flag: u16,
    /// `helpExtendedKeyFlag`.
    pub help_extended_key_flag: u16,
    /// `windowManagerKeyFlag`.
    pub window_manager_key_flag: u16,
}

impl WindowActivationCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_WINDOWACTIVATION_CAPABILITYSET";
}

impl Encode for WindowActivationCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::ACTIVATION, self.size(), Self::NAME)?;
        w.u16(self.help_key_flag);
        w.u16(self.help_key_index_flag);
        w.u16(self.help_extended_key_flag);
        w.u16(self.window_manager_key_flag);
        Ok(())
    }
}

impl Decode<'_> for WindowActivationCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::ACTIVATION, Self::NAME)?;
        Ok(Self {
            help_key_flag: b.u16(Self::NAME)?,
            help_key_index_flag: b.u16(Self::NAME)?,
            help_extended_key_flag: b.u16(Self::NAME)?,
            window_manager_key_flag: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_SHARE_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.4), 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShareCapabilitySet {
    /// `nodeId`: our user channel id in a Confirm Active, zero in a Demand
    /// Active.
    pub node_id: u16,
}

impl ShareCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SHARE_CAPABILITYSET";
}

impl Encode for ShareCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::SHARE, self.size(), Self::NAME)?;
        w.u16(self.node_id);
        // `pad2octets`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for ShareCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::SHARE, Self::NAME)?;
        Ok(Self {
            node_id: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_FONT_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.5), 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FontCapabilitySet {
    /// `fontSupportFlags`, `FONTSUPPORT_FONTLIST` 1.
    pub font_support_flags: u16,
}

impl FontCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FONT_CAPABILITYSET";

    /// `FONTSUPPORT_FONTLIST`.
    pub const FONTSUPPORT_FONTLIST: u16 = 0x0001;

    /// The set this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            font_support_flags: Self::FONTSUPPORT_FONTLIST,
        }
    }
}

impl Encode for FontCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::FONT, self.size(), Self::NAME)?;
        w.u16(self.font_support_flags);
        // `pad2octets`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for FontCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::FONT, Self::NAME)?;
        // Both fields are optional on an old server, which is the extensible
        // tail rule again (PRDRDP/13 §2.5).
        Ok(Self {
            font_support_flags: opt_u16(&mut b, Self::NAME)?.unwrap_or(0),
        })
    }
}

/// `TS_COLORTABLE_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.1), 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ColorCacheCapabilitySet {
    /// `colorTableCacheSize`, 6, the value the specification says to send and
    /// which every server ignores.
    pub color_table_cache_size: u16,
}

impl ColorCacheCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_COLORTABLE_CAPABILITYSET";

    /// The set this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            color_table_cache_size: 6,
        }
    }
}

impl Encode for ColorCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::COLOR_CACHE, self.size(), Self::NAME)?;
        w.u16(self.color_table_cache_size);
        // `pad2octets`.
        w.u16(0);
        Ok(())
    }
}

impl Decode<'_> for ColorCacheCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::COLOR_CACHE, Self::NAME)?;
        Ok(Self {
            color_table_cache_size: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_WINDOW_CAPABILITYSET` (MS-RDPERP 2.2.1.1.2), 11 bytes.
///
/// Sent with level zero so a server does not infer RemoteApp support from the
/// set's absence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowListCapabilitySet {
    /// `WndSupportLevel`, `TS_WINDOW_LEVEL_NOT_SUPPORTED` 0.
    pub wnd_support_level: u32,
    /// `NumIconCaches`.
    pub num_icon_caches: u8,
    /// `NumIconCacheEntries`.
    pub num_icon_cache_entries: u16,
}

impl WindowListCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_WINDOW_CAPABILITYSET";
}

impl Encode for WindowListCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 7
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::WINDOW, self.size(), Self::NAME)?;
        w.u32(self.wnd_support_level);
        w.u8(self.num_icon_caches);
        w.u16(self.num_icon_cache_entries);
        Ok(())
    }
}

impl Decode<'_> for WindowListCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::WINDOW, Self::NAME)?;
        Ok(Self {
            wnd_support_level: b.u32(Self::NAME)?,
            num_icon_caches: b.u8(Self::NAME)?,
            num_icon_cache_entries: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_COMPDESK_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.8), 6 bytes.
///
/// Sent as supported only when the performance flags enable desktop
/// composition: the two disagreeing is a documented way to get a black
/// desktop (PRDRDP/13 §4.8.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DesktopCompositionCapabilitySet {
    /// `CompDeskSupportLevel`.
    pub comp_desk_support_level: u16,
}

impl DesktopCompositionCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_COMPDESK_CAPABILITYSET";

    /// `COMPDESK_NOT_SUPPORTED`.
    pub const NOT_SUPPORTED: u16 = 0x0000;
    /// `COMPDESK_SUPPORTED`.
    pub const SUPPORTED: u16 = 0x0001;

    /// The set this client sends, given whether the performance flags asked
    /// for desktop composition.
    #[must_use]
    pub const fn client(enabled: bool) -> Self {
        Self {
            comp_desk_support_level: if enabled {
                Self::SUPPORTED
            } else {
                Self::NOT_SUPPORTED
            },
        }
    }
}

impl Encode for DesktopCompositionCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 2
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(w, capability_set_type::COMP_DESK, self.size(), Self::NAME)?;
        w.u16(self.comp_desk_support_level);
        Ok(())
    }
}

impl Decode<'_> for DesktopCompositionCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::COMP_DESK, Self::NAME)?;
        Ok(Self {
            comp_desk_support_level: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_MULTIFRAGMENTUPDATE_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.6), 8 bytes.
///
/// `MaxRequestSize` is the reassembly budget for fragmented fast path updates
/// and for EGFX, and a large value is what lets a server send a whole 4K
/// surface as one logical update.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MultifragmentUpdateCapabilitySet {
    /// `MaxRequestSize`.
    pub max_request_size: u32,
}

impl MultifragmentUpdateCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_MULTIFRAGMENTUPDATE_CAPABILITYSET";

    /// The set this client sends.
    ///
    /// PRDRDP/13 §4.8.3 says two things about this number that cannot both
    /// hold: "we send 8 * 1024 * 1024" and "the value we advertise is the
    /// value `MAX_VC_REASSEMBLED` enforces", where that cap is 16 MiB. The
    /// second is the one that matters, because advertising a budget larger
    /// than the one we enforce invites an update we then refuse, so this is
    /// [`MAX_VC_REASSEMBLED`](crate::io::limits::MAX_VC_REASSEMBLED).
    #[must_use]
    pub const fn client() -> Self {
        Self {
            max_request_size: crate::io::limits::MAX_VC_REASSEMBLED as u32,
        }
    }
}

impl Encode for MultifragmentUpdateCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::MULTIFRAGMENT_UPDATE,
            self.size(),
            Self::NAME,
        )?;
        w.u32(self.max_request_size);
        Ok(())
    }
}

impl Decode<'_> for MultifragmentUpdateCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::MULTIFRAGMENT_UPDATE, Self::NAME)?;
        Ok(Self {
            max_request_size: b.u32(Self::NAME)?,
        })
    }
}

/// `TS_LARGE_POINTER_CAPABILITYSET.largePointerSupportFlags` (MS-RDPBCGR
/// 2.2.7.2.7).
pub mod large_pointer_flags {
    /// `LARGE_POINTER_FLAG_96x96`.
    pub const SUPPORT_96X96: u16 = 0x0001;
    /// `LARGE_POINTER_FLAG_384x384`, which requires a multifragment
    /// `MaxRequestSize` of at least 38055.
    pub const SUPPORT_384X384: u16 = 0x0002;
}

/// The `MaxRequestSize` that `LARGE_POINTER_FLAG_384x384` requires
/// (MS-RDPBCGR 2.2.7.2.7).
pub const LARGE_POINTER_384_MIN_REQUEST_SIZE: u32 = 38055;

/// `TS_LARGE_POINTER_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.7), 6 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LargePointerCapabilitySet {
    /// `largePointerSupportFlags`, from [`large_pointer_flags`].
    pub large_pointer_support_flags: u16,
}

impl LargePointerCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_LARGE_POINTER_CAPABILITYSET";

    /// The set this client sends: both sizes, which our multifragment budget
    /// covers.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            large_pointer_support_flags: large_pointer_flags::SUPPORT_96X96
                | large_pointer_flags::SUPPORT_384X384,
        }
    }
}

impl Encode for LargePointerCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 2
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::LARGE_POINTER,
            self.size(),
            Self::NAME,
        )?;
        w.u16(self.large_pointer_support_flags);
        Ok(())
    }
}

impl Decode<'_> for LargePointerCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::LARGE_POINTER, Self::NAME)?;
        Ok(Self {
            large_pointer_support_flags: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_SURFCMDS_CAPABILITYSET.cmdFlags` (MS-RDPBCGR 2.2.7.2.9).
pub mod surface_command_flags {
    /// `SURFCMDS_SETSURFACEBITS`.
    pub const SET_SURFACE_BITS: u32 = 0x0000_0002;
    /// `SURFCMDS_FRAMEMARKER`.
    pub const FRAME_MARKER: u32 = 0x0000_0010;
    /// `SURFCMDS_STREAMSURFACEBITS`.
    pub const STREAM_SURFACE_BITS: u32 = 0x0000_0040;
}

/// `TS_SURFCMDS_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.9), 12 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SurfaceCommandsCapabilitySet {
    /// `cmdFlags`, from [`surface_command_flags`].
    pub cmd_flags: u32,
}

impl SurfaceCommandsCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SURFCMDS_CAPABILITYSET";

    /// The set this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            cmd_flags: surface_command_flags::SET_SURFACE_BITS
                | surface_command_flags::FRAME_MARKER
                | surface_command_flags::STREAM_SURFACE_BITS,
        }
    }
}

impl Encode for SurfaceCommandsCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::SURFACE_COMMANDS,
            self.size(),
            Self::NAME,
        )?;
        w.u32(self.cmd_flags);
        // `reserved`.
        w.u32(0);
        Ok(())
    }
}

impl Decode<'_> for SurfaceCommandsCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::SURFACE_COMMANDS, Self::NAME)?;
        Ok(Self {
            cmd_flags: b.u32(Self::NAME)?,
        })
    }
}

/// `CAPSSETTYPE_FRAME_ACKNOWLEDGE` (MS-RDPBCGR 2.2.7.2), 8 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameAcknowledgeCapabilitySet {
    /// `maxUnacknowledgedFrameCount`.
    pub max_unacknowledged_frame_count: u32,
}

impl FrameAcknowledgeCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FRAME_ACKNOWLEDGE_CAPABILITYSET";

    /// `MAX_IN_FLIGHT_FRAMES` (PRDRDP/04 §3.6, PRDRDP/12 §5.3): the
    /// advertised depth and the enforced depth are one constant.
    pub const MAX_IN_FLIGHT_FRAMES: u32 = 3;

    /// The set this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            max_unacknowledged_frame_count: Self::MAX_IN_FLIGHT_FRAMES,
        }
    }
}

impl Encode for FrameAcknowledgeCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_capset_header(
            w,
            capability_set_type::FRAME_ACKNOWLEDGE,
            self.size(),
            Self::NAME,
        )?;
        w.u32(self.max_unacknowledged_frame_count);
        Ok(())
    }
}

impl Decode<'_> for FrameAcknowledgeCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::FRAME_ACKNOWLEDGE, Self::NAME)?;
        Ok(Self {
            max_unacknowledged_frame_count: b.u32(Self::NAME)?,
        })
    }
}

/// The codec GUIDs of `TS_BITMAPCODEC` as the wire carries them
/// (MS-RDPBCGR 2.2.7.2.10).
///
/// The usual GUID trap applies: the first three groups are little endian on
/// the wire and the last two are big endian, so the byte sequence does not
/// read like the braced form. Each constant below is the byte sequence, and
/// its doc comment is the braced form it corresponds to.
pub mod codec_guid {
    /// `{CA8D1BB9-000F-154F-589F-AE2D1A87E2D6}`, NSCodec.
    pub const NSCODEC: [u8; 16] = [
        0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9f, 0xae, 0x2d, 0x1a, 0x87, 0xe2,
        0xd6,
    ];
    /// `{76772F12-BD72-4463-AFB3-B73C9C6F7886}`, RemoteFX.
    pub const REMOTEFX: [u8; 16] = [
        0x12, 0x2f, 0x77, 0x76, 0x72, 0xbd, 0x63, 0x44, 0xaf, 0xb3, 0xb7, 0x3c, 0x9c, 0x6f, 0x78,
        0x86,
    ];
    /// `{2744CCD4-9D8A-4E74-803C-0ECBEEA19C54}`, image mode RemoteFX.
    pub const IMAGE_REMOTEFX: [u8; 16] = [
        0xd4, 0xcc, 0x44, 0x27, 0x8a, 0x9d, 0x74, 0x4e, 0x80, 0x3c, 0x0e, 0xcb, 0xee, 0xa1, 0x9c,
        0x54,
    ];
    /// `{9C4351A6-3535-42AE-910C-CDFCE5760B58}`, the ignore codec.
    pub const IGNORE: [u8; 16] = [
        0xa6, 0x51, 0x43, 0x9c, 0x35, 0x35, 0xae, 0x42, 0x91, 0x0c, 0xcd, 0xfc, 0xe5, 0x76, 0x0b,
        0x58,
    ];
}

/// `TS_RFX_ICAP.entropyBits` (MS-RDPRFX 2.2.1.1.1.1.1).
pub mod rfx_entropy {
    /// `CLW_ENTROPY_RLGR1`.
    pub const RLGR1: u8 = 0x01;
    /// `CLW_ENTROPY_RLGR3`.
    pub const RLGR3: u8 = 0x04;
}

/// `TS_RFX_ICAP` (MS-RDPRFX 2.2.1.1.1.1.1), 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfxICap {
    /// `version`, `CLW_VERSION_1_0` 0x0100.
    pub version: u16,
    /// `tileSize`, `CT_TILE_64x64` 0x0040.
    pub tile_size: u16,
    /// `flags`: `CODEC_MODE` 0x02 selects video mode, which we clear.
    pub flags: u8,
    /// `colConvBits`, `CLW_COL_CONV_ICT` 1.
    pub col_conv_bits: u8,
    /// `transformBits`, `CLW_XFORM_DWT_53_A` 1.
    pub transform_bits: u8,
    /// `entropyBits`, from [`rfx_entropy`].
    pub entropy_bits: u8,
}

impl RfxICap {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_RFX_ICAP";
    /// `CLW_VERSION_1_0`.
    pub const VERSION_1_0: u16 = 0x0100;
    /// `CT_TILE_64x64`.
    pub const TILE_64X64: u16 = 0x0040;
    /// `CODEC_MODE`, video mode, which we clear.
    pub const CODEC_MODE: u8 = 0x02;
    /// Eight bytes, which is `icapLen`.
    pub const SIZE: usize = 8;

    /// One entry for the given entropy coder, image mode.
    #[must_use]
    pub const fn client(entropy_bits: u8) -> Self {
        Self {
            version: Self::VERSION_1_0,
            tile_size: Self::TILE_64X64,
            flags: 0,
            col_conv_bits: 1,
            transform_bits: 1,
            entropy_bits,
        }
    }
}

/// `TS_RFX_CLNT_CAPS_CONTAINER` (MS-RDPRFX 2.2.1.1), the `codecProperties` of
/// the RemoteFX and image RemoteFX codecs.
///
/// The nesting is `TS_RFX_CLNT_CAPS_CONTAINER` holding `TS_RFX_CAPS` holding
/// one `TS_RFX_CAPSET` holding the `TS_RFX_ICAP` entries. MS-RDPRFX fixes
/// `numCapsets` at one, so the decoder requires that and the encoder writes
/// one; a container claiming more is refused rather than half read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxClientCapsContainer {
    /// `captureFlags`: `CARDP_CAPS_CAPTURE_NON_CAC` 0x01.
    pub capture_flags: u32,
    /// `TS_RFX_CAPSET.codecId`, which MS-RDPRFX fixes at 1.
    pub codec_id: u8,
    /// One entry per entropy coder we accept.
    pub icaps: Vec<RfxICap>,
}

impl RfxClientCapsContainer {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_RFX_CLNT_CAPS_CONTAINER";
    /// `CBY_CAPS`, `TS_RFX_CAPS.blockType`.
    pub const CAPS_BLOCK_TYPE: u16 = 0xcbc0;
    /// `CBY_CAPSET`, `TS_RFX_CAPSET.blockType`.
    pub const CAPSET_BLOCK_TYPE: u16 = 0xcbc1;
    /// `CLY_CAPSET`, `TS_RFX_CAPSET.capsetType`.
    pub const CAPSET_TYPE: u16 = 0xcfc0;
    /// `CARDP_CAPS_CAPTURE_NON_CAC`.
    pub const CAPTURE_NON_CAC: u32 = 0x0000_0001;
    /// `TS_RFX_CAPS` is eight bytes and its `blockLen` says so.
    const CAPS_LEN: usize = 8;
    /// `TS_RFX_CAPSET` without its icaps.
    const CAPSET_FIXED_LEN: usize = 13;

    /// The properties this client sends: both entropy coders, because
    /// PRDRDP/04 wants both decoders and a server that implements only RLGR1
    /// exists (PRDRDP/13 §4.8.4).
    #[must_use]
    pub fn client() -> Self {
        Self {
            capture_flags: Self::CAPTURE_NON_CAC,
            codec_id: 1,
            icaps: vec![
                RfxICap::client(rfx_entropy::RLGR1),
                RfxICap::client(rfx_entropy::RLGR3),
            ],
        }
    }

    /// The `blockLen` of the single capset.
    fn capset_len(&self) -> usize {
        Self::CAPSET_FIXED_LEN + self.icaps.len() * RfxICap::SIZE
    }

    /// `capsLength`, which counts `TS_RFX_CAPS` and the capset.
    fn caps_length(&self) -> usize {
        Self::CAPS_LEN + self.capset_len()
    }

    /// Decode one from a codec's property blob.
    pub fn read(r: &mut Reader<'_>) -> PduResult<Self> {
        // `length` covers the whole container; the two inner lengths are
        // checked against what they actually contain rather than trusted.
        let _length = r.u32(Self::NAME)?;
        let capture_flags = r.u32(Self::NAME)?;
        let _caps_length = r.u32(Self::NAME)?;
        let at = r.offset();
        let block_type = r.u16(Self::NAME)?;
        if block_type != Self::CAPS_BLOCK_TYPE {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "TS_RFX_CAPS.blockType",
                value: u64::from(block_type),
                offset: at,
            });
        }
        r.skip(4, Self::NAME)?;
        let at = r.offset();
        let num_capsets = r.u16(Self::NAME)?;
        if num_capsets != 1 {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "TS_RFX_CAPS.numCapsets",
                value: u64::from(num_capsets),
                offset: at,
            });
        }
        let at = r.offset();
        let capset_block_type = r.u16(Self::NAME)?;
        if capset_block_type != Self::CAPSET_BLOCK_TYPE {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "TS_RFX_CAPSET.blockType",
                value: u64::from(capset_block_type),
                offset: at,
            });
        }
        r.skip(4, Self::NAME)?;
        let codec_id = r.u8(Self::NAME)?;
        r.skip(2, Self::NAME)?;
        let num_icaps = usize::from(r.u16(Self::NAME)?);
        let at = r.offset();
        let icap_len = usize::from(r.u16(Self::NAME)?);
        if icap_len != RfxICap::SIZE {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "TS_RFX_CAPSET.icapLen",
                value: icap_len as u64,
                offset: at,
            });
        }
        r.ensure_cap(
            num_icaps,
            MAX_CAPSET_LEN / RfxICap::SIZE,
            "MAX_CAPSET_LEN",
            Self::NAME,
        )?;
        let mut icaps = Vec::with_capacity(num_icaps);
        for _ in 0..num_icaps {
            icaps.push(RfxICap {
                version: r.u16(RfxICap::NAME)?,
                tile_size: r.u16(RfxICap::NAME)?,
                flags: r.u8(RfxICap::NAME)?,
                col_conv_bits: r.u8(RfxICap::NAME)?,
                transform_bits: r.u8(RfxICap::NAME)?,
                entropy_bits: r.u8(RfxICap::NAME)?,
            });
        }
        Ok(Self {
            capture_flags,
            codec_id,
            icaps,
        })
    }
}

impl Encode for RfxClientCapsContainer {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        12 + self.caps_length()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.size() as u32);
        w.u32(self.capture_flags);
        w.u32(self.caps_length() as u32);
        // TS_RFX_CAPS.
        w.u16(Self::CAPS_BLOCK_TYPE);
        w.u32(Self::CAPS_LEN as u32);
        w.u16(1);
        // TS_RFX_CAPSET.
        w.u16(Self::CAPSET_BLOCK_TYPE);
        w.u32(self.capset_len() as u32);
        w.u8(self.codec_id);
        w.u16(Self::CAPSET_TYPE);
        w.u16(
            u16::try_from(self.icaps.len()).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "more icaps than numIcaps can count",
            })?,
        );
        w.u16(RfxICap::SIZE as u16);
        for icap in &self.icaps {
            w.u16(icap.version);
            w.u16(icap.tile_size);
            w.u8(icap.flags);
            w.u8(icap.col_conv_bits);
            w.u8(icap.transform_bits);
            w.u8(icap.entropy_bits);
        }
        Ok(())
    }
}

/// `NSCODEC_CAPABILITYSET` (MS-RDPNSC 2.2.1), the NSCodec property blob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NsCodecCapabilitySet {
    /// `fAllowDynamicFidelity`.
    pub allow_dynamic_fidelity: u8,
    /// `fAllowSubsampling`.
    pub allow_subsampling: u8,
    /// `colorLossLevel`, 1 to 7.
    pub color_loss_level: u8,
}

impl NsCodecCapabilitySet {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "NSCODEC_CAPABILITYSET";

    /// The properties this client sends (PRDRDP/13 §4.8.4).
    #[must_use]
    pub const fn client() -> Self {
        Self {
            allow_dynamic_fidelity: 1,
            allow_subsampling: 1,
            color_loss_level: 3,
        }
    }
}

impl Encode for NsCodecCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        3
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u8(self.allow_dynamic_fidelity);
        w.u8(self.allow_subsampling);
        w.u8(self.color_loss_level);
        Ok(())
    }
}

impl Decode<'_> for NsCodecCapabilitySet {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            allow_dynamic_fidelity: r.u8(Self::NAME)?,
            allow_subsampling: r.u8(Self::NAME)?,
            color_loss_level: r.u8(Self::NAME)?,
        })
    }
}

/// One `TS_BITMAPCODEC` (MS-RDPBCGR 2.2.7.2.10).
///
/// `codecProperties` stays a borrowed view. The typed forms are
/// [`RfxClientCapsContainer`] and [`NsCodecCapabilitySet`], and which one
/// applies is decided by `codecGUID`, which is PRDRDP/04's allow list to
/// apply rather than ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapCodec<'a> {
    /// `codecGUID`, one of [`codec_guid`].
    pub codec_guid: [u8; 16],
    /// `codecID`, assigned by whoever sends the set.
    pub codec_id: u8,
    /// `codecProperties`.
    pub properties: Payload<'a>,
}

impl BitmapCodec<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAPCODEC";

    /// The encoded size of this codec entry.
    #[must_use]
    pub fn size(&self) -> usize {
        16 + 1 + 2 + self.properties.len()
    }
}

/// `TS_BITMAPCODECS_CAPABILITYSET` (MS-RDPBCGR 2.2.7.2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapCodecsCapabilitySet<'a> {
    /// One entry per codec.
    pub codecs: Vec<BitmapCodec<'a>>,
}

impl BitmapCodecsCapabilitySet<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAPCODECS_CAPABILITYSET";
}

impl Encode for BitmapCodecsCapabilitySet<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        CAPSET_HEADER_LEN + 1 + self.codecs.iter().map(BitmapCodec::size).sum::<usize>()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let count = u8::try_from(self.codecs.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "more codecs than bitmapCodecCount can count",
        })?;
        write_capset_header(
            w,
            capability_set_type::BITMAP_CODECS,
            self.size(),
            Self::NAME,
        )?;
        w.u8(count);
        for codec in &self.codecs {
            w.bytes(&codec.codec_guid);
            w.u8(codec.codec_id);
            let len = u16::try_from(codec.properties.len()).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "codec properties longer than codecPropertiesLength",
            })?;
            w.u16(len);
            w.bytes(codec.properties.as_slice());
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for BitmapCodecsCapabilitySet<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut b = read_capset(r, capability_set_type::BITMAP_CODECS, Self::NAME)?;
        let count = usize::from(b.u8(Self::NAME)?);
        b.ensure_cap(count, MAX_BITMAP_CODECS, "MAX_BITMAP_CODECS", Self::NAME)?;
        let mut codecs: Vec<BitmapCodec<'a>> = Vec::with_capacity(count);
        for _ in 0..count {
            let codec_guid = b.array::<16>(Self::NAME)?;
            let at = b.offset();
            let codec_id = b.u8(Self::NAME)?;
            if codecs.iter().any(|c| c.codec_id == codec_id) {
                // Two codecs sharing an id is unrecoverable: every
                // `TS_BITMAP_DATA_EX.codecID` after it is ambiguous
                // (PRDRDP/13 §4.8.4).
                return Err(PduError::InvalidField {
                    context: Self::NAME,
                    field: "codecID",
                    value: u64::from(codec_id),
                    offset: at,
                });
            }
            let len = usize::from(b.u16(Self::NAME)?);
            codecs.push(BitmapCodec {
                codec_guid,
                codec_id,
                properties: Payload::new(b.slice(len, Self::NAME)?),
            });
        }
        Ok(Self { codecs })
    }
}

/// One capability set, whichever it turned out to be (MS-RDPBCGR 2.2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySet<'a> {
    /// `CAPSTYPE_GENERAL`.
    General(GeneralCapabilitySet),
    /// `CAPSTYPE_BITMAP`.
    Bitmap(BitmapCapabilitySet),
    /// `CAPSTYPE_ORDER`.
    Order(Box<OrderCapabilitySet>),
    /// `CAPSTYPE_BITMAPCACHE`.
    BitmapCache(BitmapCacheCapabilitySet),
    /// `CAPSTYPE_BITMAPCACHE_REV2`.
    BitmapCacheRev2(BitmapCacheRev2CapabilitySet),
    /// `CAPSTYPE_BITMAPCACHE_HOSTSUPPORT`.
    BitmapCacheHostSupport(BitmapCacheHostSupportCapabilitySet),
    /// `CAPSTYPE_CONTROL`.
    Control(ControlCapabilitySet),
    /// `CAPSTYPE_ACTIVATION`.
    WindowActivation(WindowActivationCapabilitySet),
    /// `CAPSTYPE_POINTER`.
    Pointer(PointerCapabilitySet),
    /// `CAPSTYPE_SHARE`.
    Share(ShareCapabilitySet),
    /// `CAPSTYPE_COLORCACHE`.
    ColorCache(ColorCacheCapabilitySet),
    /// `CAPSTYPE_SOUND`.
    Sound(SoundCapabilitySet),
    /// `CAPSTYPE_INPUT`.
    Input(Box<InputCapabilitySet>),
    /// `CAPSTYPE_FONT`.
    Font(FontCapabilitySet),
    /// `CAPSTYPE_BRUSH`.
    Brush(BrushCapabilitySet),
    /// `CAPSTYPE_GLYPHCACHE`.
    GlyphCache(GlyphCacheCapabilitySet),
    /// `CAPSTYPE_OFFSCREENCACHE`.
    OffscreenCache(OffscreenCacheCapabilitySet),
    /// `CAPSTYPE_VIRTUALCHANNEL`.
    VirtualChannel(VirtualChannelCapabilitySet),
    /// `CAPSTYPE_WINDOW`.
    WindowList(WindowListCapabilitySet),
    /// `CAPSETTYPE_COMPDESK`.
    DesktopComposition(DesktopCompositionCapabilitySet),
    /// `CAPSETTYPE_MULTIFRAGMENTUPDATE`.
    MultifragmentUpdate(MultifragmentUpdateCapabilitySet),
    /// `CAPSETTYPE_LARGE_POINTER`.
    LargePointer(LargePointerCapabilitySet),
    /// `CAPSETTYPE_SURFACE_COMMANDS`.
    SurfaceCommands(SurfaceCommandsCapabilitySet),
    /// `CAPSETTYPE_BITMAP_CODECS`.
    BitmapCodecs(BitmapCodecsCapabilitySet<'a>),
    /// `CAPSSETTYPE_FRAME_ACKNOWLEDGE`.
    FrameAcknowledge(FrameAcknowledgeCapabilitySet),
    /// A set this build does not implement, kept whole.
    ///
    /// The length was explicit, so skipping cannot desync and preserving
    /// costs nothing. A round trip test can then prove we did not lose it,
    /// and a trace can show what a server offered (PRDRDP/13 §4.8.2).
    Unknown {
        /// `capabilitySetType`.
        capability_set_type: u16,
        /// The body, `lengthCapability - 4` bytes.
        body: Payload<'a>,
    },
}

impl CapabilitySet<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_CAPS_SET";

    /// This set's `capabilitySetType`.
    #[must_use]
    pub const fn capability_set_type(&self) -> u16 {
        match self {
            Self::General(_) => capability_set_type::GENERAL,
            Self::Bitmap(_) => capability_set_type::BITMAP,
            Self::Order(_) => capability_set_type::ORDER,
            Self::BitmapCache(_) => capability_set_type::BITMAP_CACHE,
            Self::BitmapCacheRev2(_) => capability_set_type::BITMAP_CACHE_REV2,
            Self::BitmapCacheHostSupport(_) => capability_set_type::BITMAP_CACHE_HOST_SUPPORT,
            Self::Control(_) => capability_set_type::CONTROL,
            Self::WindowActivation(_) => capability_set_type::ACTIVATION,
            Self::Pointer(_) => capability_set_type::POINTER,
            Self::Share(_) => capability_set_type::SHARE,
            Self::ColorCache(_) => capability_set_type::COLOR_CACHE,
            Self::Sound(_) => capability_set_type::SOUND,
            Self::Input(_) => capability_set_type::INPUT,
            Self::Font(_) => capability_set_type::FONT,
            Self::Brush(_) => capability_set_type::BRUSH,
            Self::GlyphCache(_) => capability_set_type::GLYPH_CACHE,
            Self::OffscreenCache(_) => capability_set_type::OFFSCREEN_CACHE,
            Self::VirtualChannel(_) => capability_set_type::VIRTUAL_CHANNEL,
            Self::WindowList(_) => capability_set_type::WINDOW,
            Self::DesktopComposition(_) => capability_set_type::COMP_DESK,
            Self::MultifragmentUpdate(_) => capability_set_type::MULTIFRAGMENT_UPDATE,
            Self::LargePointer(_) => capability_set_type::LARGE_POINTER,
            Self::SurfaceCommands(_) => capability_set_type::SURFACE_COMMANDS,
            Self::BitmapCodecs(_) => capability_set_type::BITMAP_CODECS,
            Self::FrameAcknowledge(_) => capability_set_type::FRAME_ACKNOWLEDGE,
            Self::Unknown {
                capability_set_type,
                ..
            } => *capability_set_type,
        }
    }
}

impl Encode for CapabilitySet<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        match self {
            Self::General(set) => set.size(),
            Self::Bitmap(set) => set.size(),
            Self::Order(set) => set.size(),
            Self::BitmapCache(set) => set.size(),
            Self::BitmapCacheRev2(set) => set.size(),
            Self::BitmapCacheHostSupport(set) => set.size(),
            Self::Control(set) => set.size(),
            Self::WindowActivation(set) => set.size(),
            Self::Pointer(set) => set.size(),
            Self::Share(set) => set.size(),
            Self::ColorCache(set) => set.size(),
            Self::Sound(set) => set.size(),
            Self::Input(set) => set.size(),
            Self::Font(set) => set.size(),
            Self::Brush(set) => set.size(),
            Self::GlyphCache(set) => set.size(),
            Self::OffscreenCache(set) => set.size(),
            Self::VirtualChannel(set) => set.size(),
            Self::WindowList(set) => set.size(),
            Self::DesktopComposition(set) => set.size(),
            Self::MultifragmentUpdate(set) => set.size(),
            Self::LargePointer(set) => set.size(),
            Self::SurfaceCommands(set) => set.size(),
            Self::BitmapCodecs(set) => set.size(),
            Self::FrameAcknowledge(set) => set.size(),
            Self::Unknown { body, .. } => CAPSET_HEADER_LEN + body.len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::General(set) => set.encode(w),
            Self::Bitmap(set) => set.encode(w),
            Self::Order(set) => set.encode(w),
            Self::BitmapCache(set) => set.encode(w),
            Self::BitmapCacheRev2(set) => set.encode(w),
            Self::BitmapCacheHostSupport(set) => set.encode(w),
            Self::Control(set) => set.encode(w),
            Self::WindowActivation(set) => set.encode(w),
            Self::Pointer(set) => set.encode(w),
            Self::Share(set) => set.encode(w),
            Self::ColorCache(set) => set.encode(w),
            Self::Sound(set) => set.encode(w),
            Self::Input(set) => set.encode(w),
            Self::Font(set) => set.encode(w),
            Self::Brush(set) => set.encode(w),
            Self::GlyphCache(set) => set.encode(w),
            Self::OffscreenCache(set) => set.encode(w),
            Self::VirtualChannel(set) => set.encode(w),
            Self::WindowList(set) => set.encode(w),
            Self::DesktopComposition(set) => set.encode(w),
            Self::MultifragmentUpdate(set) => set.encode(w),
            Self::LargePointer(set) => set.encode(w),
            Self::SurfaceCommands(set) => set.encode(w),
            Self::BitmapCodecs(set) => set.encode(w),
            Self::FrameAcknowledge(set) => set.encode(w),
            Self::Unknown {
                capability_set_type,
                body,
            } => {
                write_capset_header(w, *capability_set_type, self.size(), Self::NAME)?;
                w.bytes(body.as_slice());
                Ok(())
            }
        }
    }
}

impl<'a> Decode<'a> for CapabilitySet<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let set_type = {
            let mut probe = *r;
            probe.u16(Self::NAME)?
        };
        Ok(match set_type {
            capability_set_type::GENERAL => Self::General(GeneralCapabilitySet::decode(r)?),
            capability_set_type::BITMAP => Self::Bitmap(BitmapCapabilitySet::decode(r)?),
            capability_set_type::ORDER => Self::Order(Box::new(OrderCapabilitySet::decode(r)?)),
            capability_set_type::BITMAP_CACHE => {
                Self::BitmapCache(BitmapCacheCapabilitySet::decode(r)?)
            }
            capability_set_type::BITMAP_CACHE_REV2 => {
                Self::BitmapCacheRev2(BitmapCacheRev2CapabilitySet::decode(r)?)
            }
            capability_set_type::BITMAP_CACHE_HOST_SUPPORT => {
                Self::BitmapCacheHostSupport(BitmapCacheHostSupportCapabilitySet::decode(r)?)
            }
            capability_set_type::CONTROL => Self::Control(ControlCapabilitySet::decode(r)?),
            capability_set_type::ACTIVATION => {
                Self::WindowActivation(WindowActivationCapabilitySet::decode(r)?)
            }
            capability_set_type::POINTER => Self::Pointer(PointerCapabilitySet::decode(r)?),
            capability_set_type::SHARE => Self::Share(ShareCapabilitySet::decode(r)?),
            capability_set_type::COLOR_CACHE => {
                Self::ColorCache(ColorCacheCapabilitySet::decode(r)?)
            }
            capability_set_type::SOUND => Self::Sound(SoundCapabilitySet::decode(r)?),
            capability_set_type::INPUT => Self::Input(Box::new(InputCapabilitySet::decode(r)?)),
            capability_set_type::FONT => Self::Font(FontCapabilitySet::decode(r)?),
            capability_set_type::BRUSH => Self::Brush(BrushCapabilitySet::decode(r)?),
            capability_set_type::GLYPH_CACHE => {
                Self::GlyphCache(GlyphCacheCapabilitySet::decode(r)?)
            }
            capability_set_type::OFFSCREEN_CACHE => {
                Self::OffscreenCache(OffscreenCacheCapabilitySet::decode(r)?)
            }
            capability_set_type::VIRTUAL_CHANNEL => {
                Self::VirtualChannel(VirtualChannelCapabilitySet::decode(r)?)
            }
            capability_set_type::WINDOW => Self::WindowList(WindowListCapabilitySet::decode(r)?),
            capability_set_type::COMP_DESK => {
                Self::DesktopComposition(DesktopCompositionCapabilitySet::decode(r)?)
            }
            capability_set_type::MULTIFRAGMENT_UPDATE => {
                Self::MultifragmentUpdate(MultifragmentUpdateCapabilitySet::decode(r)?)
            }
            capability_set_type::LARGE_POINTER => {
                Self::LargePointer(LargePointerCapabilitySet::decode(r)?)
            }
            capability_set_type::SURFACE_COMMANDS => {
                Self::SurfaceCommands(SurfaceCommandsCapabilitySet::decode(r)?)
            }
            capability_set_type::BITMAP_CODECS => {
                Self::BitmapCodecs(BitmapCodecsCapabilitySet::decode(r)?)
            }
            capability_set_type::FRAME_ACKNOWLEDGE => {
                Self::FrameAcknowledge(FrameAcknowledgeCapabilitySet::decode(r)?)
            }
            other => {
                r.skip(2, Self::NAME)?;
                let mut body = read_capset_body(r, Self::NAME)?;
                tracing::trace!(
                    capability_set_type = other,
                    "keeping an unrecognised capability set"
                );
                Self::Unknown {
                    capability_set_type: other,
                    body: Payload::new(body.rest()),
                }
            }
        })
    }
}

/// The capability sets of one Demand Active or Confirm Active PDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySets<'a> {
    /// The sets, in the order they arrived or will be sent.
    pub sets: Vec<CapabilitySet<'a>>,
}

impl<'a> CapabilitySets<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "capabilitySets";

    /// Read `count` sets, capped by
    /// [`MAX_CAPABILITY_SETS`](crate::io::limits::MAX_CAPABILITY_SETS).
    ///
    /// The count comes from `numberCapabilities` in the enclosing PDU, which
    /// is why this is not a plain [`Decode`].
    pub fn read(r: &mut Reader<'a>, count: usize) -> PduResult<Self> {
        r.ensure_cap(
            count,
            MAX_CAPABILITY_SETS,
            "MAX_CAPABILITY_SETS",
            Self::NAME,
        )?;
        let mut sets = Vec::with_capacity(count);
        for _ in 0..count {
            sets.push(CapabilitySet::decode(r)?);
        }
        Ok(Self { sets })
    }

    /// The total encoded size of every set.
    #[must_use]
    pub fn size(&self) -> usize {
        self.sets.iter().map(Encode::size).sum()
    }

    /// Write every set, in order.
    pub fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        for set in &self.sets {
            set.encode(w)?;
        }
        Ok(())
    }

    /// The first set of the given `capabilitySetType`.
    #[must_use]
    pub fn find(&self, set_type: u16) -> Option<&CapabilitySet<'a>> {
        self.sets
            .iter()
            .find(|set| set.capability_set_type() == set_type)
    }

    /// The General set, which carries the fast path output flag the update
    /// path depends on.
    #[must_use]
    pub fn general(&self) -> Option<&GeneralCapabilitySet> {
        match self.find(capability_set_type::GENERAL)? {
            CapabilitySet::General(set) => Some(set),
            _ => None,
        }
    }

    /// The Bitmap set, which carries the desktop size the server chose.
    #[must_use]
    pub fn bitmap(&self) -> Option<&BitmapCapabilitySet> {
        match self.find(capability_set_type::BITMAP)? {
            CapabilitySet::Bitmap(set) => Some(set),
            _ => None,
        }
    }

    /// The Virtual Channel set, which carries the chunk size the server will
    /// use.
    #[must_use]
    pub fn virtual_channel(&self) -> Option<&VirtualChannelCapabilitySet> {
        match self.find(capability_set_type::VIRTUAL_CHANNEL)? {
            CapabilitySet::VirtualChannel(set) => Some(set),
            _ => None,
        }
    }

    /// The Multifragment Update set, which carries the reassembly budget.
    #[must_use]
    pub fn multifragment_update(&self) -> Option<&MultifragmentUpdateCapabilitySet> {
        match self.find(capability_set_type::MULTIFRAGMENT_UPDATE)? {
            CapabilitySet::MultifragmentUpdate(set) => Some(set),
            _ => None,
        }
    }

    /// The Surface Commands set, which says whether surface bits are usable.
    #[must_use]
    pub fn surface_commands(&self) -> Option<&SurfaceCommandsCapabilitySet> {
        match self.find(capability_set_type::SURFACE_COMMANDS)? {
            CapabilitySet::SurfaceCommands(set) => Some(set),
            _ => None,
        }
    }

    /// The Bitmap Codecs set, which carries the codec list and its property
    /// blobs.
    #[must_use]
    pub fn bitmap_codecs(&self) -> Option<&BitmapCodecsCapabilitySet<'a>> {
        match self.find(capability_set_type::BITMAP_CODECS)? {
            CapabilitySet::BitmapCodecs(set) => Some(set),
            _ => None,
        }
    }

    /// The sets a Confirm Active carries in phase 1 (PRDRDP/13 §4.8.3).
    ///
    /// `input` is a parameter rather than four keyboard words because the
    /// Input set echoes `TS_UD_CS_CORE` and the session already holds that
    /// block; [`InputCapabilitySet::client`] builds it.
    ///
    /// PRDRDP/04 §8.2 owns the policy and may replace any of these before the
    /// PDU is sent; this is the list that matches what §4.8.3 states, in the
    /// order mstsc sends it. Bitmap Codecs is not here: it is phase 2 and its
    /// property blobs have to outlive this call, so the session appends it.
    #[must_use]
    pub fn client_defaults(
        desktop_width: u16,
        desktop_height: u16,
        node_id: u16,
        input: InputCapabilitySet,
        desktop_composition: bool,
    ) -> Self {
        Self {
            sets: vec![
                CapabilitySet::General(GeneralCapabilitySet::client()),
                CapabilitySet::Bitmap(BitmapCapabilitySet::client(desktop_width, desktop_height)),
                CapabilitySet::Order(Box::new(OrderCapabilitySet::client())),
                CapabilitySet::BitmapCache(BitmapCacheCapabilitySet::default()),
                CapabilitySet::BitmapCacheRev2(BitmapCacheRev2CapabilitySet::default()),
                CapabilitySet::Pointer(PointerCapabilitySet::client()),
                CapabilitySet::Input(Box::new(input)),
                CapabilitySet::Brush(BrushCapabilitySet::default()),
                CapabilitySet::GlyphCache(GlyphCacheCapabilitySet::default()),
                CapabilitySet::OffscreenCache(OffscreenCacheCapabilitySet::default()),
                CapabilitySet::VirtualChannel(VirtualChannelCapabilitySet::client()),
                CapabilitySet::Sound(SoundCapabilitySet::default()),
                CapabilitySet::Control(ControlCapabilitySet::client()),
                CapabilitySet::WindowActivation(WindowActivationCapabilitySet::default()),
                CapabilitySet::Share(ShareCapabilitySet { node_id }),
                CapabilitySet::Font(FontCapabilitySet::client()),
                CapabilitySet::ColorCache(ColorCacheCapabilitySet::client()),
                CapabilitySet::WindowList(WindowListCapabilitySet::default()),
                CapabilitySet::DesktopComposition(DesktopCompositionCapabilitySet::client(
                    desktop_composition,
                )),
                CapabilitySet::MultifragmentUpdate(MultifragmentUpdateCapabilitySet::client()),
                CapabilitySet::LargePointer(LargePointerCapabilitySet::client()),
                CapabilitySet::SurfaceCommands(SurfaceCommandsCapabilitySet::client()),
                CapabilitySet::FrameAcknowledge(FrameAcknowledgeCapabilitySet::client()),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    fn client_sets() -> CapabilitySets<'static> {
        CapabilitySets::client_defaults(
            1920,
            1080,
            0x03ea,
            InputCapabilitySet::client(0x0409, 4, 0, 12),
            true,
        )
    }

    /// Each set's encoded length against the number MS-RDPBCGR states, header
    /// included. A set that is the wrong length by four is the failure that
    /// comes back as `ERRINFO_CAPABILITYSETTOOLARGE` twenty PDUs later.
    #[test]
    fn every_set_is_the_length_the_specification_states() {
        let cases: &[(&str, usize, usize)] = &[
            ("general", GeneralCapabilitySet::client().size(), 24),
            ("bitmap", BitmapCapabilitySet::client(1920, 1080).size(), 28),
            ("order", OrderCapabilitySet::client().size(), 88),
            (
                "bitmap cache",
                BitmapCacheCapabilitySet::default().size(),
                40,
            ),
            (
                "bitmap cache rev2",
                BitmapCacheRev2CapabilitySet::default().size(),
                40,
            ),
            (
                "bitmap cache host support",
                BitmapCacheHostSupportCapabilitySet::default().size(),
                8,
            ),
            ("pointer", PointerCapabilitySet::client().size(), 10),
            ("input", InputCapabilitySet::client(0, 0, 0, 0).size(), 88),
            ("brush", BrushCapabilitySet::default().size(), 8),
            ("glyph cache", GlyphCacheCapabilitySet::default().size(), 52),
            (
                "offscreen cache",
                OffscreenCacheCapabilitySet::default().size(),
                12,
            ),
            (
                "virtual channel",
                VirtualChannelCapabilitySet::client().size(),
                12,
            ),
            ("sound", SoundCapabilitySet::default().size(), 8),
            ("control", ControlCapabilitySet::client().size(), 12),
            (
                "window activation",
                WindowActivationCapabilitySet::default().size(),
                12,
            ),
            ("share", ShareCapabilitySet::default().size(), 8),
            ("font", FontCapabilitySet::client().size(), 8),
            ("colour cache", ColorCacheCapabilitySet::client().size(), 8),
            ("window list", WindowListCapabilitySet::default().size(), 11),
            (
                "desktop composition",
                DesktopCompositionCapabilitySet::client(true).size(),
                6,
            ),
            (
                "multifragment",
                MultifragmentUpdateCapabilitySet::client().size(),
                8,
            ),
            (
                "large pointer",
                LargePointerCapabilitySet::client().size(),
                6,
            ),
            (
                "surface commands",
                SurfaceCommandsCapabilitySet::client().size(),
                12,
            ),
            (
                "frame acknowledge",
                FrameAcknowledgeCapabilitySet::client().size(),
                8,
            ),
        ];
        for (name, actual, expected) in cases {
            assert_eq!(actual, expected, "{name}");
        }
    }

    /// Every set this client sends survives a round trip, and its
    /// `lengthCapability` matches the bytes that follow it.
    #[test]
    fn every_client_set_round_trips() {
        let sets = client_sets();
        let bytes = {
            let mut buf = Vec::new();
            sets.encode(&mut Writer::new(&mut buf)).unwrap();
            buf
        };
        assert_eq!(bytes.len(), sets.size());
        let back = CapabilitySets::read(&mut Reader::new(&bytes), sets.sets.len()).unwrap();
        assert_eq!(back, sets);

        // And each set's declared length is exactly what it wrote.
        let mut r = Reader::new(&bytes);
        for set in &sets.sets {
            let mut probe = r;
            let set_type = probe.u16("t").unwrap();
            let length = probe.u16("t").unwrap();
            assert_eq!(set_type, set.capability_set_type());
            assert_eq!(usize::from(length), set.size(), "{set_type:#06x}");
            r.skip(set.size(), "t").unwrap();
        }
    }

    /// The decision PRDRDP/04 §8.2 made, checked at the byte level: no order
    /// index is set, and the flag that makes a server read the array is.
    #[test]
    fn the_order_set_advertises_no_order_at_all() {
        let set = OrderCapabilitySet::client();
        assert!(set.supports_no_orders());
        assert_eq!(
            set.order_flags,
            order_flags::NEGOTIATE_ORDER_SUPPORT | order_flags::ZERO_BOUNDS_DELTAS_SUPPORT
        );
        assert_eq!(set.order_flags, 0x000a);
        let bytes = encode(&set);
        // `orderSupport` sits at offset 4 + 16 + 4 + 2 + 2 + 2 + 2 + 2 + 2.
        let start = 4 + 16 + 4 + 2 + 2 + 2 + 2 + 2 + 2;
        assert_eq!(
            &bytes[start..start + ORDER_SUPPORT_LEN],
            &[0u8; ORDER_SUPPORT_LEN]
        );
        for index in [
            order_index::DSTBLT,
            order_index::MEMBLT,
            order_index::GLYPH,
            order_index::POLYLINE,
        ] {
            assert_eq!(set.order_support[index], 0);
        }
        assert_eq!(set.order_support_ex_flags, 0);
        assert_eq!(set.desktop_save_size, 0);
        assert_eq!(set.text_ansi_code_page, 0);
    }

    /// The extensible tail of §2.5, on the set that has it: an RDP 4.0
    /// server's eight byte Virtual Channel set decodes, and a missing
    /// `VCChunkSize` means 1600.
    #[test]
    fn a_virtual_channel_set_without_its_chunk_size_decodes() {
        let short = [0x14, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let set = VirtualChannelCapabilitySet::decode(&mut Reader::new(&short)).unwrap();
        assert_eq!(set.chunk_size, None);
        assert_eq!(set.effective_chunk_size(), CHANNEL_CHUNK_LENGTH);
        assert_eq!(encode(&set), short);

        let long = VirtualChannelCapabilitySet::client();
        assert_eq!(long.effective_chunk_size(), 1600);
        assert_eq!(encode(&long).len(), 12);
    }

    /// A set we do not implement is kept whole rather than dropped, so a
    /// round trip proves nothing was lost.
    #[test]
    fn an_unknown_set_is_preserved_byte_for_byte() {
        let bytes = [0x99, 0x99, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let set = CapabilitySet::decode(&mut Reader::new(&bytes)).unwrap();
        let CapabilitySet::Unknown {
            capability_set_type,
            body,
        } = &set
        else {
            panic!("not preserved");
        };
        assert_eq!(*capability_set_type, 0x9999);
        assert_eq!(body.as_slice(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(encode(&set), bytes);
    }

    /// A Demand Active mixes sets we know with sets we do not, and both come
    /// back in order.
    #[test]
    fn a_mixed_list_keeps_its_order() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            GeneralCapabilitySet::client().encode(&mut w).unwrap();
            w.u16(0x0015);
            w.u16(0x0006);
            w.u16(0xbeef);
            BitmapCapabilitySet::client(800, 600)
                .encode(&mut w)
                .unwrap();
        }
        let sets = CapabilitySets::read(&mut Reader::new(&buf), 3).unwrap();
        assert_eq!(sets.sets.len(), 3);
        assert_eq!(
            sets.sets[1].capability_set_type(),
            capability_set_type::DRAW_NINE_GRID_CACHE
        );
        assert_eq!(sets.bitmap().unwrap().desktop_width, 800);
        assert!(sets.general().unwrap().fastpath_output());
        let mut again = Vec::new();
        sets.encode(&mut Writer::new(&mut again)).unwrap();
        assert_eq!(again, buf);
    }

    #[test]
    fn a_wrong_protocol_version_is_refused() {
        let mut bytes = encode(&GeneralCapabilitySet::client());
        bytes[8] = 0x00;
        bytes[9] = 0x03;
        let err = GeneralCapabilitySet::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "protocolVersion",
                ..
            }
        ));
    }

    #[test]
    fn a_length_below_the_header_is_refused() {
        let bytes = [0x01, 0x00, 0x02, 0x00];
        let err = CapabilitySet::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "lengthCapability",
                ..
            }
        ));
    }

    #[test]
    fn more_sets_than_the_cap_allows_names_the_cap() {
        let err = CapabilitySets::read(&mut Reader::new(&[]), MAX_CAPABILITY_SETS + 1).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_CAPABILITY_SETS",
                ..
            }
        ));
    }

    /// The RemoteFX property blob, which is three nested length prefixed
    /// structures and the easiest place in the crate to be off by four.
    #[test]
    fn the_remotefx_caps_container_round_trips() {
        let container = RfxClientCapsContainer::client();
        let bytes = encode(&container);
        // 12 byte container header, 8 byte TS_RFX_CAPS, 13 byte capset, two
        // icaps of eight.
        assert_eq!(bytes.len(), 12 + 8 + 13 + 16);
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        assert_eq!(
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize,
            bytes.len() - 12
        );
        assert_eq!(
            RfxClientCapsContainer::read(&mut Reader::new(&bytes)).unwrap(),
            container
        );
        assert_eq!(container.icaps[0].entropy_bits, rfx_entropy::RLGR1);
        assert_eq!(container.icaps[1].entropy_bits, rfx_entropy::RLGR3);
        // Video mode is off.
        assert_eq!(container.icaps[0].flags & RfxICap::CODEC_MODE, 0);
    }

    #[test]
    fn a_bitmap_codecs_set_round_trips_with_its_property_blobs() {
        let mut rfx = Vec::new();
        RfxClientCapsContainer::client()
            .encode(&mut Writer::new(&mut rfx))
            .unwrap();
        let mut ns = Vec::new();
        NsCodecCapabilitySet::client()
            .encode(&mut Writer::new(&mut ns))
            .unwrap();

        let set = BitmapCodecsCapabilitySet {
            codecs: vec![
                BitmapCodec {
                    codec_guid: codec_guid::REMOTEFX,
                    codec_id: 3,
                    properties: Payload::new(&rfx),
                },
                BitmapCodec {
                    codec_guid: codec_guid::NSCODEC,
                    codec_id: 1,
                    properties: Payload::new(&ns),
                },
            ],
        };
        let bytes = encode(&set);
        let back = BitmapCodecsCapabilitySet::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back, set);
        assert_eq!(back.codecs[0].codec_guid, codec_guid::REMOTEFX);
        assert_eq!(
            NsCodecCapabilitySet::decode(&mut Reader::new(back.codecs[1].properties.as_slice()))
                .unwrap(),
            NsCodecCapabilitySet::client()
        );
    }

    /// Two codecs sharing an id makes every `TS_BITMAP_DATA_EX.codecID`
    /// ambiguous, so it is refused rather than resolved.
    #[test]
    fn a_duplicate_codec_id_is_refused() {
        let set = BitmapCodecsCapabilitySet {
            codecs: vec![
                BitmapCodec {
                    codec_guid: codec_guid::REMOTEFX,
                    codec_id: 3,
                    properties: Payload::new(&[]),
                },
                BitmapCodec {
                    codec_guid: codec_guid::NSCODEC,
                    codec_id: 3,
                    properties: Payload::new(&[]),
                },
            ],
        };
        let bytes = encode(&set);
        let err = BitmapCodecsCapabilitySet::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "codecID",
                ..
            }
        ));
    }

    /// The GUID trap, checked against the braced form: the first three groups
    /// are little endian and the last two are not.
    #[test]
    fn the_codec_guids_are_in_wire_order() {
        // {76772F12-BD72-4463-AFB3-B73C9C6F7886}
        assert_eq!(&codec_guid::REMOTEFX[..4], &[0x12, 0x2f, 0x77, 0x76]);
        assert_eq!(&codec_guid::REMOTEFX[4..6], &[0x72, 0xbd]);
        assert_eq!(&codec_guid::REMOTEFX[6..8], &[0x63, 0x44]);
        assert_eq!(
            &codec_guid::REMOTEFX[8..],
            &[0xaf, 0xb3, 0xb7, 0x3c, 0x9c, 0x6f, 0x78, 0x86]
        );
    }

    /// The dependency MS-RDPBCGR 2.2.7.2.7 states: advertising the 384 by 384
    /// pointer needs a multifragment budget of at least 38055.
    #[test]
    fn the_large_pointer_flag_is_backed_by_the_multifragment_budget() {
        let large = LargePointerCapabilitySet::client();
        assert_eq!(
            large.large_pointer_support_flags & large_pointer_flags::SUPPORT_384X384,
            2
        );
        assert!(
            MultifragmentUpdateCapabilitySet::client().max_request_size
                >= LARGE_POINTER_384_MIN_REQUEST_SIZE
        );
    }

    /// PRDRDP/13 §9.3: every prefix of the whole capability list errors
    /// rather than panicking, and never decodes the full count.
    #[test]
    fn every_prefix_of_the_capability_list_errors() {
        let sets = client_sets();
        let mut bytes = Vec::new();
        sets.encode(&mut Writer::new(&mut bytes)).unwrap();
        let count = sets.sets.len();
        for cut in 0..bytes.len() {
            assert!(
                CapabilitySets::read(&mut Reader::new(&bytes[..cut]), count).is_err(),
                "a {cut} byte prefix decoded {count} sets"
            );
        }
    }
}
