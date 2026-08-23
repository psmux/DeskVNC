//! The client GCC user data blocks, `TS_UD_CS_*` (PRDRDP/13 §4.3,
//! MS-RDPBCGR 2.2.1.3.2 to 2.2.1.3.9).
//!
//! Eight blocks, each with a four byte `TS_UD_HEADER`, concatenated into the
//! `userData` of a Conference Create Request. The encoder emits them in the
//! order MS-RDPBCGR 2.2.1.3 lists; the decoder accepts any order, because the
//! only thing that ever decodes a client block is our own mock server and a
//! test fixture.

use super::{
    block_type, peek_block_type, read_block, skip_unknown_block, write_block_header,
    BLOCK_HEADER_LEN,
};
use crate::io::limits::{MAX_CHANNELS, MAX_MONITORS};
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `TS_UD_CS_CORE.version` (MS-RDPBCGR 2.2.1.3.2).
pub const RDP_VERSION_5_PLUS: u32 = 0x0008_0004;

/// The build number this client claims, in `TS_UD_CS_CORE.clientBuild` and,
/// per PRDRDP/14 §5.6, in the NTLM `Version` structure as well.
///
/// 19041 with `RDP_VERSION_5_PLUS` is Windows 10 version 2004. The two
/// agreeing is the point: a server that sees build 2600 in `TS_UD_CS_CORE`
/// and build 19041 in the NTLM AUTHENTICATE message is looking at something
/// that does not exist, and a middlebox keying a policy off either one gets a
/// coherent answer. 19041 rather than something newer because it is old
/// enough to be universally recognised, and rather than 2600 because a
/// Windows XP era build that negotiates CredSSP version 6 and EGFX is the
/// combination most likely to trip a rule (PRDRDP/13 §4.3.1).
pub const CLIENT_BUILD: u32 = 19041;

/// `RNS_UD_COLOR_8BPP`, the legacy `colorDepth` field superseded by
/// `highColorDepth` (MS-RDPBCGR 2.2.1.3.2).
pub const RNS_UD_COLOR_8BPP: u16 = 0xca01;

/// `RNS_UD_SAS_DEL`, the only value `SASSequence` takes.
pub const RNS_UD_SAS_DEL: u16 = 0xaa03;

/// `TS_UD_CS_CORE.supportedColorDepths` (MS-RDPBCGR 2.2.1.3.2).
pub mod color_depth_support {
    /// `RNS_UD_24BPP_SUPPORT`.
    pub const BPP24: u16 = 0x0001;
    /// `RNS_UD_16BPP_SUPPORT`.
    pub const BPP16: u16 = 0x0002;
    /// `RNS_UD_15BPP_SUPPORT`.
    pub const BPP15: u16 = 0x0004;
    /// `RNS_UD_32BPP_SUPPORT`.
    pub const BPP32: u16 = 0x0008;
}

/// `TS_UD_CS_CORE.earlyCapabilityFlags` (MS-RDPBCGR 2.2.1.3.2). Setting a bit
/// commits the client to handling what it advertises.
pub mod early_capability_flags {
    /// We parse Set Error Info (2.2.5.1), so this is always set. R15 asked
    /// whether a dependency set it for us; the code is ours and the answer is
    /// that we set it unconditionally (PRDRDP/03 §2.4).
    pub const SUPPORT_ERRINFO_PDU: u16 = 0x0001;
    /// `RNS_UD_CS_WANT_32BPP_SESSION`.
    pub const WANT_32BPP_SESSION: u16 = 0x0002;
    /// We parse `PDUTYPE2_STATUS_INFO_PDU`.
    pub const SUPPORT_STATUSINFO_PDU: u16 = 0x0004;
    /// Standard RDP security only, so clear.
    pub const STRONG_ASYMMETRIC_KEYS: u16 = 0x0008;
    /// `RNS_UD_CS_UNUSED`.
    pub const UNUSED: u16 = 0x0010;
    /// Set when `connectionType` carries a real value.
    pub const VALID_CONNECTION_TYPE: u16 = 0x0020;
    /// We parse Monitor Layout (2.2.12.1).
    pub const SUPPORT_MONITOR_LAYOUT_PDU: u16 = 0x0040;
    /// We answer network characteristics detection (2.2.14).
    pub const SUPPORT_NETCHAR_AUTODETECT: u16 = 0x0080;
    /// EGFX, phase 2.
    pub const SUPPORT_DYNVC_GFX_PROTOCOL: u16 = 0x0100;
    /// We fill the dynamic daylight saving time key name.
    pub const SUPPORT_DYNAMIC_TIME_ZONE: u16 = 0x0200;
    /// We answer the heartbeat PDU (2.2.16).
    pub const SUPPORT_HEARTBEAT_PDU: u16 = 0x0400;
    /// Lets the server skip the Channel Join round trips (PRDRDP/03 §2.5).
    pub const SUPPORT_SKIP_CHANNELJOIN: u16 = 0x0800;
}

/// `TS_UD_CS_CORE.connectionType` (MS-RDPBCGR 2.2.1.3.2).
pub mod connection_type {
    /// Modem, 56 Kbps.
    pub const MODEM: u8 = 0x01;
    /// Low speed broadband.
    pub const BROADBAND_LOW: u8 = 0x02;
    /// Satellite.
    pub const SATELLITE: u8 = 0x03;
    /// High speed broadband.
    pub const BROADBAND_HIGH: u8 = 0x04;
    /// WAN.
    pub const WAN: u8 = 0x05;
    /// LAN, which is what a quality preset of "best" selects.
    pub const LAN: u8 = 0x06;
    /// The client intends to run network auto detection.
    pub const AUTODETECT: u8 = 0x07;
}

/// The mandatory part of `TS_UD_CS_CORE`, before the extensible tail.
const CORE_MANDATORY_LEN: usize = 128;

/// Read a field only if the whole of it is there, which is PRDRDP/13 §2.5's
/// extensible tail rule.
fn opt_u8(r: &mut Reader<'_>, context: &'static str) -> PduResult<Option<u8>> {
    if r.remaining() < 1 {
        return Ok(None);
    }
    Ok(Some(r.u8(context)?))
}

fn opt_u16(r: &mut Reader<'_>, context: &'static str) -> PduResult<Option<u16>> {
    if r.remaining() < 2 {
        return Ok(None);
    }
    Ok(Some(r.u16(context)?))
}

fn opt_u32(r: &mut Reader<'_>, context: &'static str) -> PduResult<Option<u32>> {
    if r.remaining() < 4 {
        return Ok(None);
    }
    Ok(Some(r.u32(context)?))
}

fn opt_utf16(r: &mut Reader<'_>, bytes: usize, context: &'static str) -> PduResult<Option<String>> {
    if r.remaining() < bytes {
        return Ok(None);
    }
    Ok(Some(r.utf16_fixed(bytes, context)?))
}

/// `TS_UD_CS_CORE` (MS-RDPBCGR 2.2.1.3.2).
///
/// The fields from `postBeta2ColorDepth` onwards are the extensible tail: a
/// server that understands only RDP 5 never reads them, and each is
/// `Option` so a short block from a mock server or an old capture round trips
/// byte for byte. Presence is cumulative on the wire, and the decoder
/// preserves that by reading each field only while the whole of it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCoreData {
    /// `version`, [`RDP_VERSION_5_PLUS`].
    pub version: u32,
    /// `desktopWidth`, 1 to 4096.
    pub desktop_width: u16,
    /// `desktopHeight`, 1 to 2048.
    pub desktop_height: u16,
    /// `colorDepth`, the legacy field, [`RNS_UD_COLOR_8BPP`].
    pub color_depth: u16,
    /// `SASSequence`, [`RNS_UD_SAS_DEL`].
    pub sas_sequence: u16,
    /// `keyboardLayout`, the Windows KLID.
    pub keyboard_layout: u32,
    /// `clientBuild`, [`CLIENT_BUILD`].
    pub client_build: u32,
    /// `clientName`, at most fifteen characters in a 32 byte field.
    pub client_name: String,
    /// `keyboardType`, 4 for IBM enhanced 101/102.
    pub keyboard_type: u32,
    /// `keyboardSubType`.
    pub keyboard_sub_type: u32,
    /// `keyboardFunctionKey`, 12.
    pub keyboard_function_key: u32,
    /// `imeFileName`, a 64 byte field we leave empty.
    pub ime_file_name: String,
    /// `postBeta2ColorDepth`.
    pub post_beta2_color_depth: Option<u16>,
    /// `clientProductId`, 1.
    pub client_product_id: Option<u16>,
    /// `serialNumber`, 0.
    pub serial_number: Option<u32>,
    /// `highColorDepth`, 32.
    pub high_color_depth: Option<u16>,
    /// `supportedColorDepths`, a mask of [`color_depth_support`].
    pub supported_color_depths: Option<u16>,
    /// `earlyCapabilityFlags`, a mask of [`early_capability_flags`].
    pub early_capability_flags: Option<u16>,
    /// `clientDigProductId`, a 64 byte field we leave empty.
    pub client_dig_product_id: Option<String>,
    /// `connectionType`, one of [`connection_type`].
    pub connection_type: Option<u8>,
    /// `pad1octet`.
    pub pad1octet: Option<u8>,
    /// `serverSelectedProtocol`, echoed from `RDP_NEG_RSP.selectedProtocol`.
    /// MS-RDPBCGR 2.2.1.3.2 makes this the client's assertion of what it
    /// thinks was negotiated, and a server that sees a mismatch aborts.
    pub server_selected_protocol: Option<u32>,
    /// `desktopPhysicalWidth`, millimetres, 10 to 10000 or zero.
    pub desktop_physical_width: Option<u32>,
    /// `desktopPhysicalHeight`, millimetres.
    pub desktop_physical_height: Option<u32>,
    /// `desktopOrientation`, 0, 90, 180 or 270.
    pub desktop_orientation: Option<u16>,
    /// `desktopScaleFactor`, 100 to 500.
    pub desktop_scale_factor: Option<u32>,
    /// `deviceScaleFactor`, 100, 140 or 180 only.
    pub device_scale_factor: Option<u32>,
}

impl Default for ClientCoreData {
    /// The block PRDRDP/13 §4.3.1 says we send, at 1024 by 768 with a US
    /// keyboard, which the caller then adjusts.
    fn default() -> Self {
        Self {
            version: RDP_VERSION_5_PLUS,
            desktop_width: 1024,
            desktop_height: 768,
            color_depth: RNS_UD_COLOR_8BPP,
            sas_sequence: RNS_UD_SAS_DEL,
            keyboard_layout: 0x0000_0409,
            client_build: CLIENT_BUILD,
            client_name: String::new(),
            keyboard_type: 4,
            keyboard_sub_type: 0,
            keyboard_function_key: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: Some(RNS_UD_COLOR_8BPP),
            client_product_id: Some(1),
            serial_number: Some(0),
            high_color_depth: Some(32),
            supported_color_depths: Some(
                color_depth_support::BPP24
                    | color_depth_support::BPP16
                    | color_depth_support::BPP15
                    | color_depth_support::BPP32,
            ),
            early_capability_flags: Some(
                early_capability_flags::SUPPORT_ERRINFO_PDU
                    | early_capability_flags::WANT_32BPP_SESSION
                    | early_capability_flags::SUPPORT_STATUSINFO_PDU
                    | early_capability_flags::VALID_CONNECTION_TYPE
                    | early_capability_flags::SUPPORT_MONITOR_LAYOUT_PDU
                    | early_capability_flags::SUPPORT_NETCHAR_AUTODETECT
                    | early_capability_flags::SUPPORT_DYNAMIC_TIME_ZONE
                    | early_capability_flags::SUPPORT_HEARTBEAT_PDU,
            ),
            client_dig_product_id: Some(String::new()),
            connection_type: Some(connection_type::LAN),
            pad1octet: Some(0),
            server_selected_protocol: Some(0),
            desktop_physical_width: None,
            desktop_physical_height: None,
            desktop_orientation: None,
            desktop_scale_factor: None,
            device_scale_factor: None,
        }
    }
}

impl ClientCoreData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_CORE";

    /// The length of the tail fields that are present.
    fn tail_len(&self) -> usize {
        self.post_beta2_color_depth.map_or(0, |_| 2)
            + self.client_product_id.map_or(0, |_| 2)
            + self.serial_number.map_or(0, |_| 4)
            + self.high_color_depth.map_or(0, |_| 2)
            + self.supported_color_depths.map_or(0, |_| 2)
            + self.early_capability_flags.map_or(0, |_| 2)
            + self.client_dig_product_id.as_ref().map_or(0, |_| 64)
            + self.connection_type.map_or(0, |_| 1)
            + self.pad1octet.map_or(0, |_| 1)
            + self.server_selected_protocol.map_or(0, |_| 4)
            + self.desktop_physical_width.map_or(0, |_| 4)
            + self.desktop_physical_height.map_or(0, |_| 4)
            + self.desktop_orientation.map_or(0, |_| 2)
            + self.desktop_scale_factor.map_or(0, |_| 4)
            + self.device_scale_factor.map_or(0, |_| 4)
    }
}

impl Encode for ClientCoreData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + CORE_MANDATORY_LEN + self.tail_len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::CS_CORE, self.size(), Self::NAME)?;
        w.u32(self.version);
        w.u16(self.desktop_width);
        w.u16(self.desktop_height);
        w.u16(self.color_depth);
        w.u16(self.sas_sequence);
        w.u32(self.keyboard_layout);
        w.u32(self.client_build);
        w.utf16_fixed(&self.client_name, 32, Self::NAME)?;
        w.u32(self.keyboard_type);
        w.u32(self.keyboard_sub_type);
        w.u32(self.keyboard_function_key);
        w.utf16_fixed(&self.ime_file_name, 64, Self::NAME)?;
        // The extensible tail. Each field is written only if it is present,
        // and presence is cumulative, so the first `None` ends the block.
        let Some(v) = self.post_beta2_color_depth else {
            return Ok(());
        };
        w.u16(v);
        let Some(v) = self.client_product_id else {
            return Ok(());
        };
        w.u16(v);
        let Some(v) = self.serial_number else {
            return Ok(());
        };
        w.u32(v);
        let Some(v) = self.high_color_depth else {
            return Ok(());
        };
        w.u16(v);
        let Some(v) = self.supported_color_depths else {
            return Ok(());
        };
        w.u16(v);
        let Some(v) = self.early_capability_flags else {
            return Ok(());
        };
        w.u16(v);
        let Some(v) = &self.client_dig_product_id else {
            return Ok(());
        };
        w.utf16_fixed(v, 64, Self::NAME)?;
        let Some(v) = self.connection_type else {
            return Ok(());
        };
        w.u8(v);
        let Some(v) = self.pad1octet else {
            return Ok(());
        };
        w.u8(v);
        let Some(v) = self.server_selected_protocol else {
            return Ok(());
        };
        w.u32(v);
        let Some(v) = self.desktop_physical_width else {
            return Ok(());
        };
        w.u32(v);
        let Some(v) = self.desktop_physical_height else {
            return Ok(());
        };
        w.u32(v);
        let Some(v) = self.desktop_orientation else {
            return Ok(());
        };
        w.u16(v);
        let Some(v) = self.desktop_scale_factor else {
            return Ok(());
        };
        w.u32(v);
        let Some(v) = self.device_scale_factor else {
            return Ok(());
        };
        w.u32(v);
        Ok(())
    }
}

impl Decode<'_> for ClientCoreData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_CORE, Self::NAME)?;
        Ok(Self {
            version: b.u32(Self::NAME)?,
            desktop_width: b.u16(Self::NAME)?,
            desktop_height: b.u16(Self::NAME)?,
            color_depth: b.u16(Self::NAME)?,
            sas_sequence: b.u16(Self::NAME)?,
            keyboard_layout: b.u32(Self::NAME)?,
            client_build: b.u32(Self::NAME)?,
            client_name: b.utf16_fixed(32, Self::NAME)?,
            keyboard_type: b.u32(Self::NAME)?,
            keyboard_sub_type: b.u32(Self::NAME)?,
            keyboard_function_key: b.u32(Self::NAME)?,
            ime_file_name: b.utf16_fixed(64, Self::NAME)?,
            post_beta2_color_depth: opt_u16(&mut b, Self::NAME)?,
            client_product_id: opt_u16(&mut b, Self::NAME)?,
            serial_number: opt_u32(&mut b, Self::NAME)?,
            high_color_depth: opt_u16(&mut b, Self::NAME)?,
            supported_color_depths: opt_u16(&mut b, Self::NAME)?,
            early_capability_flags: opt_u16(&mut b, Self::NAME)?,
            client_dig_product_id: opt_utf16(&mut b, 64, Self::NAME)?,
            connection_type: opt_u8(&mut b, Self::NAME)?,
            pad1octet: opt_u8(&mut b, Self::NAME)?,
            server_selected_protocol: opt_u32(&mut b, Self::NAME)?,
            desktop_physical_width: opt_u32(&mut b, Self::NAME)?,
            desktop_physical_height: opt_u32(&mut b, Self::NAME)?,
            desktop_orientation: opt_u16(&mut b, Self::NAME)?,
            desktop_scale_factor: opt_u32(&mut b, Self::NAME)?,
            device_scale_factor: opt_u32(&mut b, Self::NAME)?,
        })
    }
}

/// `TS_UD_CS_SEC` (MS-RDPBCGR 2.2.1.3.3).
///
/// Both words are zero under an external security protocol, which is the
/// correct "I am using TLS or CredSSP" signal and the only value this client
/// ever sends (PRDRDP/03 §2.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientSecurityData {
    /// `encryptionMethods`: `40BIT` 0x01, `128BIT` 0x02, `56BIT` 0x08,
    /// `FIPS` 0x10.
    pub encryption_methods: u32,
    /// `extEncryptionMethods`, the French locale field, always zero.
    pub ext_encryption_methods: u32,
}

impl ClientSecurityData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_SEC";
}

impl Encode for ClientSecurityData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::CS_SECURITY, self.size(), Self::NAME)?;
        w.u32(self.encryption_methods);
        w.u32(self.ext_encryption_methods);
        Ok(())
    }
}

impl Decode<'_> for ClientSecurityData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_SECURITY, Self::NAME)?;
        Ok(Self {
            encryption_methods: b.u32(Self::NAME)?,
            ext_encryption_methods: b.u32(Self::NAME)?,
        })
    }
}

/// `CHANNEL_DEF.options` (MS-RDPBCGR 2.2.1.3.4.1).
pub mod channel_option {
    /// `CHANNEL_OPTION_INITIALIZED`.
    ///
    /// PRDRDP/11 §5.3 item 6: the erratum of 2020-08-17 says this flag is
    /// unused and that its value must be ignored. We set it anyway, because
    /// every client does and a server that reads it expects it, and we ignore
    /// it on receive.
    pub const INITIALIZED: u32 = 0x8000_0000;
    /// `CHANNEL_OPTION_ENCRYPT_RDP`.
    pub const ENCRYPT_RDP: u32 = 0x4000_0000;
    /// `CHANNEL_OPTION_ENCRYPT_SC`.
    pub const ENCRYPT_SC: u32 = 0x2000_0000;
    /// `CHANNEL_OPTION_ENCRYPT_CS`.
    pub const ENCRYPT_CS: u32 = 0x1000_0000;
    /// `CHANNEL_OPTION_PRI_HIGH`.
    pub const PRI_HIGH: u32 = 0x0800_0000;
    /// `CHANNEL_OPTION_PRI_MED`.
    pub const PRI_MED: u32 = 0x0400_0000;
    /// `CHANNEL_OPTION_PRI_LOW`.
    pub const PRI_LOW: u32 = 0x0200_0000;
    /// `CHANNEL_OPTION_COMPRESS_RDP`.
    pub const COMPRESS_RDP: u32 = 0x0080_0000;
    /// `CHANNEL_OPTION_COMPRESS`.
    pub const COMPRESS: u32 = 0x0040_0000;
    /// `CHANNEL_OPTION_SHOW_PROTOCOL`.
    pub const SHOW_PROTOCOL: u32 = 0x0020_0000;
    /// `REMOTE_CONTROL_PERSISTENT`.
    pub const REMOTE_CONTROL_PERSISTENT: u32 = 0x0010_0000;
}

/// `CHANNEL_DEF` (MS-RDPBCGR 2.2.1.3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDef {
    /// `name`, at most seven significant characters in an eight byte ANSI
    /// field. The encoder refuses a longer or non ASCII name rather than
    /// truncating: a silently cut channel name produces a channel that never
    /// opens and a debugging session.
    pub name: String,
    /// `options`, a mask of [`channel_option`].
    pub options: u32,
}

impl ChannelDef {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CHANNEL_DEF";

    /// Twelve bytes: eight of name and a `u32` of options.
    pub const SIZE: usize = 12;
}

/// `TS_UD_CS_NET` (MS-RDPBCGR 2.2.1.3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientNetworkData {
    /// One entry per static virtual channel, at most
    /// [`MAX_CHANNELS`](crate::io::limits::MAX_CHANNELS).
    pub channels: Vec<ChannelDef>,
}

impl ClientNetworkData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_NET";
}

impl Encode for ClientNetworkData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 4 + self.channels.len() * ChannelDef::SIZE
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.channels.len() > MAX_CHANNELS {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "more channels than MCS allows",
            });
        }
        write_block_header(w, block_type::CS_NET, self.size(), Self::NAME)?;
        w.u32(self.channels.len() as u32);
        for channel in &self.channels {
            w.ansi_fixed(&channel.name, 8, ChannelDef::NAME)?;
            w.u32(channel.options);
        }
        Ok(())
    }
}

impl Decode<'_> for ClientNetworkData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_NET, Self::NAME)?;
        let count = b.u32(Self::NAME)? as usize;
        b.ensure_cap(count, MAX_CHANNELS, "MAX_CHANNELS", Self::NAME)?;
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            channels.push(ChannelDef {
                name: b.ansi_fixed(8, ChannelDef::NAME)?,
                options: b.u32(ChannelDef::NAME)?,
            });
        }
        Ok(Self { channels })
    }
}

/// `TS_UD_CS_CLUSTER.Flags` (MS-RDPBCGR 2.2.1.3.5).
pub mod cluster_flags {
    /// `REDIRECTION_SUPPORTED`.
    pub const REDIRECTION_SUPPORTED: u32 = 0x0000_0001;
    /// `REDIRECTED_SESSIONID_FIELD_VALID`.
    pub const REDIRECTED_SESSIONID_FIELD_VALID: u32 = 0x0000_0002;
    /// `REDIRECTED_SMARTCARD`.
    pub const REDIRECTED_SMARTCARD: u32 = 0x0000_0040;
    /// `ServerSessionRedirectionVersionMask`, bits 2 to 5.
    pub const VERSION_MASK: u32 = 0x0000_003c;
    /// The shift that puts a redirection version into
    /// [`VERSION_MASK`].
    pub const VERSION_SHIFT: u32 = 2;
    /// `REDIRECTION_VERSION6`, the version a session broker expects from a
    /// modern client.
    pub const VERSION6: u32 = 0x05;
}

/// `TS_UD_CS_CLUSTER` (MS-RDPBCGR 2.2.1.3.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientClusterData {
    /// `Flags`, a mask of [`cluster_flags`] with the redirection version in
    /// bits 2 to 5.
    pub flags: u32,
    /// `RedirectedSessionID`, meaningful only with
    /// `REDIRECTED_SESSIONID_FIELD_VALID`.
    pub redirected_session_id: u32,
}

impl ClientClusterData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_CLUSTER";
}

impl Encode for ClientClusterData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::CS_CLUSTER, self.size(), Self::NAME)?;
        w.u32(self.flags);
        w.u32(self.redirected_session_id);
        Ok(())
    }
}

impl Decode<'_> for ClientClusterData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_CLUSTER, Self::NAME)?;
        Ok(Self {
            flags: b.u32(Self::NAME)?,
            redirected_session_id: b.u32(Self::NAME)?,
        })
    }
}

/// `TS_MONITOR_DEF` (MS-RDPBCGR 2.2.1.3.6.1).
///
/// The coordinates are signed and inclusive, in a virtual desktop space whose
/// primary monitor sits at (0, 0), so a monitor to the left of the primary
/// has negative `left`. This crate keeps them exactly as they arrive and
/// translates nowhere: R20 records that our `Rect` is unsigned, and PRDRDP/04
/// does the translation. A wire layer that quietly moves coordinates is a
/// wire layer nobody can debug from a packet capture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MonitorDef {
    /// `left`.
    pub left: i32,
    /// `top`.
    pub top: i32,
    /// `right`, inclusive.
    pub right: i32,
    /// `bottom`, inclusive.
    pub bottom: i32,
    /// `flags`, with `TS_MONITOR_PRIMARY` 0x01 on exactly one monitor.
    pub flags: u32,
}

impl MonitorDef {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_MONITOR_DEF";
    /// `TS_MONITOR_PRIMARY`.
    pub const PRIMARY: u32 = 0x0000_0001;
    /// Five four byte fields.
    pub const SIZE: usize = 20;
}

/// `TS_UD_CS_MONITOR` (MS-RDPBCGR 2.2.1.3.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientMonitorData {
    /// `flags`, zero.
    pub flags: u32,
    /// One entry per monitor, at most
    /// [`MAX_MONITORS`](crate::io::limits::MAX_MONITORS).
    pub monitors: Vec<MonitorDef>,
}

impl ClientMonitorData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_MONITOR";
}

impl Encode for ClientMonitorData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 8 + self.monitors.len() * MonitorDef::SIZE
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.monitors.len() > MAX_MONITORS {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "more monitors than the block allows",
            });
        }
        write_block_header(w, block_type::CS_MONITOR, self.size(), Self::NAME)?;
        w.u32(self.flags);
        w.u32(self.monitors.len() as u32);
        for m in &self.monitors {
            w.i32(m.left);
            w.i32(m.top);
            w.i32(m.right);
            w.i32(m.bottom);
            w.u32(m.flags);
        }
        Ok(())
    }
}

impl Decode<'_> for ClientMonitorData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_MONITOR, Self::NAME)?;
        let flags = b.u32(Self::NAME)?;
        let count = b.u32(Self::NAME)? as usize;
        b.ensure_cap(count, MAX_MONITORS, "MAX_MONITORS", Self::NAME)?;
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            monitors.push(MonitorDef {
                left: b.i32(MonitorDef::NAME)?,
                top: b.i32(MonitorDef::NAME)?,
                right: b.i32(MonitorDef::NAME)?,
                bottom: b.i32(MonitorDef::NAME)?,
                flags: b.u32(MonitorDef::NAME)?,
            });
        }
        Ok(Self { flags, monitors })
    }
}

/// `TS_MONITOR_ATTRIBUTES` (MS-RDPBCGR 2.2.1.3.9.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MonitorAttributes {
    /// `physicalWidth`, millimetres, 10 to 10000 or zero.
    pub physical_width: u32,
    /// `physicalHeight`, millimetres.
    pub physical_height: u32,
    /// `orientation`, 0, 90, 180 or 270.
    pub orientation: u32,
    /// `desktopScaleFactor`, 100 to 500.
    pub desktop_scale_factor: u32,
    /// `deviceScaleFactor`, 100, 140 or 180.
    pub device_scale_factor: u32,
}

impl MonitorAttributes {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_MONITOR_ATTRIBUTES";
    /// The only `monitorAttributeSize` the block allows.
    pub const SIZE: usize = 20;
}

/// `TS_UD_CS_MONITOR_EX` (MS-RDPBCGR 2.2.1.3.9).
///
/// PRDRDP/11 §5.3 item 8: this block and the `CS_UNUSED1` type code were
/// added to the document by the erratum of 2023-08-16, after Windows clients
/// had been sending them for years.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientMonitorExtendedData {
    /// `flags`, zero.
    pub flags: u32,
    /// One entry per monitor, matching `TS_UD_CS_MONITOR`'s count.
    pub monitors: Vec<MonitorAttributes>,
}

impl ClientMonitorExtendedData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_MONITOR_EX";
}

impl Encode for ClientMonitorExtendedData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 12 + self.monitors.len() * MonitorAttributes::SIZE
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.monitors.len() > MAX_MONITORS {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "more monitors than the block allows",
            });
        }
        write_block_header(w, block_type::CS_MONITOR_EX, self.size(), Self::NAME)?;
        w.u32(self.flags);
        w.u32(MonitorAttributes::SIZE as u32);
        w.u32(self.monitors.len() as u32);
        for m in &self.monitors {
            w.u32(m.physical_width);
            w.u32(m.physical_height);
            w.u32(m.orientation);
            w.u32(m.desktop_scale_factor);
            w.u32(m.device_scale_factor);
        }
        Ok(())
    }
}

impl Decode<'_> for ClientMonitorExtendedData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_MONITOR_EX, Self::NAME)?;
        let flags = b.u32(Self::NAME)?;
        let at = b.offset();
        let stride = b.u32(Self::NAME)? as usize;
        if stride != MonitorAttributes::SIZE {
            // The array stride depends on it, so a different value is a
            // structure we cannot walk rather than one we can skip.
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "monitorAttributeSize",
                value: stride as u64,
                offset: at,
            });
        }
        let count = b.u32(Self::NAME)? as usize;
        b.ensure_cap(count, MAX_MONITORS, "MAX_MONITORS", Self::NAME)?;
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            monitors.push(MonitorAttributes {
                physical_width: b.u32(MonitorAttributes::NAME)?,
                physical_height: b.u32(MonitorAttributes::NAME)?,
                orientation: b.u32(MonitorAttributes::NAME)?,
                desktop_scale_factor: b.u32(MonitorAttributes::NAME)?,
                device_scale_factor: b.u32(MonitorAttributes::NAME)?,
            });
        }
        Ok(Self { flags, monitors })
    }
}

/// `TS_UD_CS_MCS_MSGCHANNEL` (MS-RDPBCGR 2.2.1.3.7).
///
/// One always zero field. Sending the block is what asks for a message
/// channel, and the message channel is where connect time network auto
/// detection and the heartbeat arrive, so we always send it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientMessageChannelData {
    /// `flags`, zero.
    pub flags: u32,
}

impl ClientMessageChannelData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_MCS_MSGCHANNEL";
}

impl Encode for ClientMessageChannelData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::CS_MCS_MSGCHANNEL, self.size(), Self::NAME)?;
        w.u32(self.flags);
        Ok(())
    }
}

impl Decode<'_> for ClientMessageChannelData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_MCS_MSGCHANNEL, Self::NAME)?;
        Ok(Self {
            flags: b.u32(Self::NAME)?,
        })
    }
}

/// `TS_UD_CS_MULTITRANSPORT.flags` and `TS_UD_SC_MULTITRANSPORT.flags`
/// (MS-RDPBCGR 2.2.1.3.8, 2.2.1.4.6).
pub mod multitransport_flags {
    /// `TRANSPORTTYPE_UDPFECR`, reliable UDP.
    pub const UDPFECR: u32 = 0x0000_0001;
    /// `TRANSPORTTYPE_UDPFECL`, lossy UDP.
    pub const UDPFECL: u32 = 0x0000_0004;
    /// `TRANSPORTTYPE_UDP_PREFERRED`.
    pub const UDP_PREFERRED: u32 = 0x0000_0100;
    /// `SOFTSYNC_TCP_TO_UDP`.
    pub const SOFTSYNC_TCP_TO_UDP: u32 = 0x0000_0200;
}

/// `TS_UD_CS_MULTITRANSPORT` (MS-RDPBCGR 2.2.1.3.8).
///
/// We send it with `flags = 0`, which says the client understands
/// multitransport bootstrapping and wants no UDP transport. That stops the
/// server bootstrapping one and keeps the block present so the server's own
/// block round trips in tests. A UDP transport is a separate project.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientMultitransportData {
    /// `flags`, a mask of [`multitransport_flags`].
    pub flags: u32,
}

impl ClientMultitransportData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS_MULTITRANSPORT";
}

impl Encode for ClientMultitransportData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::CS_MULTITRANSPORT, self.size(), Self::NAME)?;
        w.u32(self.flags);
        Ok(())
    }
}

impl Decode<'_> for ClientMultitransportData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::CS_MULTITRANSPORT, Self::NAME)?;
        Ok(Self {
            flags: b.u32(Self::NAME)?,
        })
    }
}

/// Every client block, in one structure.
///
/// The encoder writes the blocks in MS-RDPBCGR 2.2.1.3's order: CORE,
/// SECURITY, NET, CLUSTER, MONITOR, MCS_MSGCHANNEL, MULTITRANSPORT,
/// MONITOR_EX.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientGccBlocks {
    /// `TS_UD_CS_CORE`.
    pub core: Option<ClientCoreData>,
    /// `TS_UD_CS_SEC`.
    pub security: Option<ClientSecurityData>,
    /// `TS_UD_CS_NET`.
    pub network: Option<ClientNetworkData>,
    /// `TS_UD_CS_CLUSTER`.
    pub cluster: Option<ClientClusterData>,
    /// `TS_UD_CS_MONITOR`.
    pub monitor: Option<ClientMonitorData>,
    /// `TS_UD_CS_MCS_MSGCHANNEL`.
    pub message_channel: Option<ClientMessageChannelData>,
    /// `TS_UD_CS_MULTITRANSPORT`.
    pub multitransport: Option<ClientMultitransportData>,
    /// `TS_UD_CS_MONITOR_EX`.
    pub monitor_ex: Option<ClientMonitorExtendedData>,
}

impl ClientGccBlocks {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_CS";
}

impl Encode for ClientGccBlocks {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        self.core.as_ref().map_or(0, Encode::size)
            + self.security.as_ref().map_or(0, Encode::size)
            + self.network.as_ref().map_or(0, Encode::size)
            + self.cluster.as_ref().map_or(0, Encode::size)
            + self.monitor.as_ref().map_or(0, Encode::size)
            + self.message_channel.as_ref().map_or(0, Encode::size)
            + self.multitransport.as_ref().map_or(0, Encode::size)
            + self.monitor_ex.as_ref().map_or(0, Encode::size)
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if let Some(b) = &self.core {
            b.encode(w)?;
        }
        if let Some(b) = &self.security {
            b.encode(w)?;
        }
        if let Some(b) = &self.network {
            b.encode(w)?;
        }
        if let Some(b) = &self.cluster {
            b.encode(w)?;
        }
        if let Some(b) = &self.monitor {
            b.encode(w)?;
        }
        if let Some(b) = &self.message_channel {
            b.encode(w)?;
        }
        if let Some(b) = &self.multitransport {
            b.encode(w)?;
        }
        if let Some(b) = &self.monitor_ex {
            b.encode(w)?;
        }
        Ok(())
    }
}

impl Decode<'_> for ClientGccBlocks {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut out = Self::default();
        while !r.is_empty() {
            match peek_block_type(r, Self::NAME)? {
                block_type::CS_CORE => out.core = Some(ClientCoreData::decode(r)?),
                block_type::CS_SECURITY => out.security = Some(ClientSecurityData::decode(r)?),
                block_type::CS_NET => out.network = Some(ClientNetworkData::decode(r)?),
                block_type::CS_CLUSTER => out.cluster = Some(ClientClusterData::decode(r)?),
                block_type::CS_MONITOR => out.monitor = Some(ClientMonitorData::decode(r)?),
                block_type::CS_MCS_MSGCHANNEL => {
                    out.message_channel = Some(ClientMessageChannelData::decode(r)?);
                }
                block_type::CS_MULTITRANSPORT => {
                    out.multitransport = Some(ClientMultitransportData::decode(r)?);
                }
                block_type::CS_MONITOR_EX => {
                    out.monitor_ex = Some(ClientMonitorExtendedData::decode(r)?);
                }
                _ => {
                    skip_unknown_block(r, Self::NAME)?;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn sample() -> ClientGccBlocks {
        ClientGccBlocks {
            core: Some(ClientCoreData {
                client_name: "TESTCLIENT".to_owned(),
                server_selected_protocol: Some(2),
                ..ClientCoreData::default()
            }),
            security: Some(ClientSecurityData::default()),
            network: Some(ClientNetworkData {
                channels: vec![
                    ChannelDef {
                        name: "cliprdr".to_owned(),
                        options: channel_option::INITIALIZED
                            | channel_option::ENCRYPT_RDP
                            | channel_option::COMPRESS_RDP
                            | channel_option::SHOW_PROTOCOL,
                    },
                    ChannelDef {
                        name: "drdynvc".to_owned(),
                        options: channel_option::INITIALIZED | channel_option::COMPRESS_RDP,
                    },
                ],
            }),
            cluster: Some(ClientClusterData {
                flags: cluster_flags::REDIRECTION_SUPPORTED
                    | (cluster_flags::VERSION6 << cluster_flags::VERSION_SHIFT),
                redirected_session_id: 0,
            }),
            monitor: Some(ClientMonitorData {
                flags: 0,
                monitors: vec![
                    MonitorDef {
                        left: 0,
                        top: 0,
                        right: 1023,
                        bottom: 767,
                        flags: MonitorDef::PRIMARY,
                    },
                    MonitorDef {
                        left: -1920,
                        top: -200,
                        right: -1,
                        bottom: 879,
                        flags: 0,
                    },
                ],
            }),
            message_channel: Some(ClientMessageChannelData::default()),
            multitransport: Some(ClientMultitransportData::default()),
            monitor_ex: Some(ClientMonitorExtendedData {
                flags: 0,
                monitors: vec![MonitorAttributes {
                    physical_width: 340,
                    physical_height: 190,
                    orientation: 0,
                    desktop_scale_factor: 100,
                    device_scale_factor: 100,
                }],
            }),
        }
    }

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    #[test]
    fn every_client_block_round_trips() {
        let blocks = sample();
        let bytes = encode(&blocks);
        assert_eq!(
            ClientGccBlocks::decode(&mut Reader::new(&bytes)).unwrap(),
            blocks
        );
    }

    /// The default core data is the block PRDRDP/13 §4.3.1 specifies, and
    /// two of its values are asserted here because other documents depend on
    /// them: the ERRINFO bit closes R15, and the build number has to agree
    /// with the one PRDRDP/14 §5.6 sends in the NTLM `Version` structure.
    #[test]
    fn the_default_core_data_advertises_errinfo_and_the_agreed_build() {
        let core = ClientCoreData::default();
        assert_eq!(core.client_build, 19041);
        assert_eq!(
            core.early_capability_flags.unwrap() & early_capability_flags::SUPPORT_ERRINFO_PDU,
            early_capability_flags::SUPPORT_ERRINFO_PDU
        );
        let bytes = encode(&core);
        // TS_UD_HEADER, then the version, in little endian.
        assert_eq!(
            &bytes[..8],
            &[0x01, 0xc0, 0xd8, 0x00, 0x04, 0x00, 0x08, 0x00]
        );
        // 4 header bytes, 128 mandatory, and every tail field but the five
        // DPI ones: 2+2+4+2+2+2+64+1+1+4 = 84.
        assert_eq!(bytes.len(), 4 + 128 + 84);
    }

    /// The block order the encoder emits, which MS-RDPBCGR 2.2.1.3 fixes.
    #[test]
    fn the_blocks_go_out_in_the_order_the_specification_lists() {
        let bytes = encode(&sample());
        let mut r = Reader::new(&bytes);
        let mut seen = Vec::new();
        while !r.is_empty() {
            let block_type = peek_block_type(&r, "t").unwrap();
            seen.push(block_type);
            skip_unknown_block(&mut r, "t").unwrap();
        }
        assert_eq!(
            seen,
            [
                block_type::CS_CORE,
                block_type::CS_SECURITY,
                block_type::CS_NET,
                block_type::CS_CLUSTER,
                block_type::CS_MONITOR,
                block_type::CS_MCS_MSGCHANNEL,
                block_type::CS_MULTITRANSPORT,
                block_type::CS_MONITOR_EX,
            ]
        );
    }

    /// A newer server sends blocks we do not know, and MS-RDPBCGR gained one
    /// as recently as 2023 (PRDRDP/11 §5.3 item 8). The length is known, so
    /// an unknown block is skipped rather than rejected.
    #[test]
    fn an_unknown_block_is_skipped_and_the_rest_still_decodes() {
        let mut bytes = Vec::new();
        // CS_UNUSED1, the block the 2023 erratum documented.
        bytes.extend_from_slice(&[0x0c, 0xc0, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]);
        bytes.extend_from_slice(&encode(&ClientSecurityData::default()));
        let blocks = ClientGccBlocks::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(blocks.security, Some(ClientSecurityData::default()));
        assert_eq!(blocks.core, None);
    }

    /// The decoder accepts any order, because only our own mock server ever
    /// sends a client block.
    #[test]
    fn the_decoder_accepts_the_blocks_in_any_order() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode(&ClientMessageChannelData { flags: 0 }));
        bytes.extend_from_slice(&encode(&ClientSecurityData::default()));
        let blocks = ClientGccBlocks::decode(&mut Reader::new(&bytes)).unwrap();
        assert!(blocks.security.is_some() && blocks.message_channel.is_some());
    }

    /// A short core data block is what an RDP 5 era client sends, and it must
    /// round trip byte for byte rather than gaining fields on re-encode.
    #[test]
    fn a_core_block_with_a_short_tail_round_trips() {
        let core = ClientCoreData {
            post_beta2_color_depth: None,
            client_product_id: None,
            serial_number: None,
            high_color_depth: None,
            supported_color_depths: None,
            early_capability_flags: None,
            client_dig_product_id: None,
            connection_type: None,
            pad1octet: None,
            server_selected_protocol: None,
            ..ClientCoreData::default()
        };
        let bytes = encode(&core);
        assert_eq!(bytes.len(), 4 + 128);
        assert_eq!(
            ClientCoreData::decode(&mut Reader::new(&bytes)).unwrap(),
            core
        );
    }

    /// The DPI fields are the last five, so a block that carries them is the
    /// longest form.
    #[test]
    fn a_core_block_with_the_dpi_fields_round_trips() {
        let core = ClientCoreData {
            desktop_physical_width: Some(340),
            desktop_physical_height: Some(190),
            desktop_orientation: Some(90),
            desktop_scale_factor: Some(140),
            device_scale_factor: Some(140),
            ..ClientCoreData::default()
        };
        let bytes = encode(&core);
        assert_eq!(bytes.len(), 4 + 128 + 84 + 18);
        assert_eq!(
            ClientCoreData::decode(&mut Reader::new(&bytes)).unwrap(),
            core
        );
    }

    /// PRDRDP/13 §9.3's second generated test, stated for this module: a
    /// user data block with one byte appended and its length bumped must
    /// still decode, because every one of these blocks is extensible.
    #[test]
    fn a_block_with_one_byte_appended_still_decodes() {
        let mut bytes = encode(&ClientSecurityData::default());
        bytes.push(0xff);
        bytes[2] += 1;
        assert_eq!(
            ClientSecurityData::decode(&mut Reader::new(&bytes)).unwrap(),
            ClientSecurityData::default()
        );

        let core = ClientCoreData::default();
        let mut bytes = encode(&core);
        bytes.push(0xff);
        let len = (bytes.len() as u16).to_le_bytes();
        bytes[2] = len[0];
        bytes[3] = len[1];
        assert_eq!(
            ClientCoreData::decode(&mut Reader::new(&bytes)).unwrap(),
            core
        );
    }

    #[test]
    fn a_channel_name_that_cannot_be_represented_is_an_encode_error() {
        for name in ["toolongname", "caf\u{e9}"] {
            let net = ClientNetworkData {
                channels: vec![ChannelDef {
                    name: name.to_owned(),
                    options: 0,
                }],
            };
            let mut buf = Vec::new();
            assert!(net.encode(&mut Writer::new(&mut buf)).is_err());
        }
    }

    #[test]
    fn more_channels_or_monitors_than_the_caps_allow_are_refused_by_name() {
        let net = ClientNetworkData {
            channels: (0..MAX_CHANNELS + 1)
                .map(|i| ChannelDef {
                    name: format!("ch{i}"),
                    options: 0,
                })
                .collect(),
        };
        let mut buf = Vec::new();
        assert!(net.encode(&mut Writer::new(&mut buf)).is_err());

        // A hostile channelCount with no channels behind it.
        let bytes = [0x03, 0xc0, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff];
        let err = ClientNetworkData::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_CHANNELS",
                ..
            }
        ));
    }

    #[test]
    fn a_monitor_attribute_size_other_than_twenty_is_rejected() {
        let mut bytes = encode(&ClientMonitorExtendedData {
            flags: 0,
            monitors: vec![MonitorAttributes::default()],
        });
        bytes[8] = 24;
        let err = ClientMonitorExtendedData::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "monitorAttributeSize",
                ..
            }
        ));
    }

    #[test]
    fn negative_monitor_coordinates_survive_unchanged() {
        let block = ClientMonitorData {
            flags: 0,
            monitors: vec![MonitorDef {
                left: -1920,
                top: -1080,
                right: -1,
                bottom: -1,
                flags: 0,
            }],
        };
        let bytes = encode(&block);
        assert_eq!(
            ClientMonitorData::decode(&mut Reader::new(&bytes)).unwrap(),
            block
        );
    }

    #[test]
    fn every_prefix_of_the_block_list_errors_without_panicking() {
        let bytes = encode(&sample());
        for cut in 0..bytes.len() {
            let _ = ClientGccBlocks::decode(&mut Reader::new(&bytes[..cut]));
        }
        // The individual blocks are the ones with a mandatory part, so their
        // truncation must be an error rather than a short decode.
        let core = encode(&ClientCoreData::default());
        for cut in 0..core.len() {
            assert!(
                ClientCoreData::decode(&mut Reader::new(&core[..cut])).is_err(),
                "TS_UD_CS_CORE truncated to {cut} bytes decoded"
            );
        }
    }
}
