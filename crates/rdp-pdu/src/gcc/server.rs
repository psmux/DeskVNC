//! The server GCC user data blocks, `TS_UD_SC_*` (PRDRDP/13 §4.4,
//! MS-RDPBCGR 2.2.1.4.2 to 2.2.1.4.6).
//!
//! Five blocks inside the `userData` of a Conference Create Response. Three
//! of them are the ones the connection sequence turns on: `TS_UD_SC_NET`
//! carries the I/O channel id and the joined channel ids, `TS_UD_SC_CORE`
//! carries the flag that lets the Channel Join loop be skipped, and
//! `TS_UD_SC_SEC1` says whether the server wants standard RDP security, which
//! is the one answer we cannot proceed from.

use super::{
    block_type, peek_block_type, read_block, skip_unknown_block, write_block_header,
    BLOCK_HEADER_LEN,
};
use crate::io::limits::{MAX_CHANNELS, MAX_GCC_USER_DATA};
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `TS_UD_SC_CORE.earlyCapabilityFlags` (MS-RDPBCGR 2.2.1.4.2).
pub mod server_early_capability_flags {
    /// `RNS_UD_SC_EDGE_ACTIONS_SUPPORTED_V1`.
    pub const EDGE_ACTIONS_SUPPORTED_V1: u32 = 0x0000_0001;
    /// `RNS_UD_SC_DYNAMIC_DST_SUPPORTED`.
    pub const DYNAMIC_DST_SUPPORTED: u32 = 0x0000_0002;
    /// `RNS_UD_SC_EDGE_ACTIONS_SUPPORTED_V2`.
    pub const EDGE_ACTIONS_SUPPORTED_V2: u32 = 0x0000_0004;
    /// `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED`. The one that changes control
    /// flow: with our own `RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN`, the whole
    /// Channel Join loop is skipped and the client goes straight from Attach
    /// User Confirm to the Client Info PDU. PRDRDP/03 owns that branch; this
    /// crate decodes the bit.
    pub const SKIP_CHANNELJOIN_SUPPORTED: u32 = 0x0000_0008;
}

/// `ENCRYPTION_METHOD_NONE` (MS-RDPBCGR 2.2.1.4.3).
pub const ENCRYPTION_METHOD_NONE: u32 = 0x0000_0000;

/// `ENCRYPTION_LEVEL_NONE` (MS-RDPBCGR 2.2.1.4.3).
pub const ENCRYPTION_LEVEL_NONE: u32 = 0x0000_0000;

/// `TS_UD_SC_CORE` (MS-RDPBCGR 2.2.1.4.2).
///
/// Two of the three fields are an extensible tail, so a server that answers
/// with four bytes is legal and common.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerCoreData {
    /// `version`.
    pub version: u32,
    /// `clientRequestedProtocols`, echoed from our `RDP_NEG_REQ`.
    pub client_requested_protocols: Option<u32>,
    /// `earlyCapabilityFlags`, a mask of [`server_early_capability_flags`].
    pub early_capability_flags: Option<u32>,
}

impl ServerCoreData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_SC_CORE";

    /// True when the server will accept a connection that skips the Channel
    /// Join round trips.
    #[must_use]
    pub fn skip_channel_join(&self) -> bool {
        self.early_capability_flags.unwrap_or(0)
            & server_early_capability_flags::SKIP_CHANNELJOIN_SUPPORTED
            != 0
    }
}

impl Encode for ServerCoreData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN
            + 4
            + self.client_requested_protocols.map_or(0, |_| 4)
            + self.early_capability_flags.map_or(0, |_| 4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::SC_CORE, self.size(), Self::NAME)?;
        w.u32(self.version);
        let Some(v) = self.client_requested_protocols else {
            return Ok(());
        };
        w.u32(v);
        let Some(v) = self.early_capability_flags else {
            return Ok(());
        };
        w.u32(v);
        Ok(())
    }
}

impl Decode<'_> for ServerCoreData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::SC_CORE, Self::NAME)?;
        let version = b.u32(Self::NAME)?;
        let client_requested_protocols = if b.remaining() >= 4 {
            Some(b.u32(Self::NAME)?)
        } else {
            None
        };
        let early_capability_flags = if b.remaining() >= 4 {
            Some(b.u32(Self::NAME)?)
        } else {
            None
        };
        Ok(Self {
            version,
            client_requested_protocols,
            early_capability_flags,
        })
    }
}

/// `TS_UD_SC_SEC1` (MS-RDPBCGR 2.2.1.4.3).
///
/// Under TLS or CredSSP the server sends `ENCRYPTION_METHOD_NONE` and
/// `ENCRYPTION_LEVEL_NONE` and the block is eight bytes. That is the only
/// case a connection proceeds from (PRDRDP/03 §2.6). The long form is parsed
/// anyway, for the three reasons PRDRDP/13 §4.5 gives: the whole block gets
/// consumed so a length mismatch is reported as one rather than corrupting
/// the next block, the error message can name the key size, and the mock
/// server can exercise the path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerSecurityData<'a> {
    /// `encryptionMethod`.
    pub encryption_method: u32,
    /// `encryptionLevel`.
    pub encryption_level: u32,
    /// `serverRandom`, 32 bytes when present.
    pub server_random: Option<&'a [u8]>,
    /// `serverCertificate`, which [`super::parse_server_certificate`] parses
    /// and nothing verifies.
    pub server_certificate: Option<&'a [u8]>,
}

impl ServerSecurityData<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_SC_SEC1";

    /// True when the server is asking for Standard RDP Security, which
    /// PRDRDP/03 §13.1 refuses.
    #[must_use]
    pub const fn wants_standard_security(&self) -> bool {
        self.encryption_method != ENCRYPTION_METHOD_NONE
            || self.encryption_level != ENCRYPTION_LEVEL_NONE
    }
}

impl Encode for ServerSecurityData<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let long_form = if self.wants_standard_security() {
            8 + self.server_random.map_or(0, <[u8]>::len)
                + self.server_certificate.map_or(0, <[u8]>::len)
        } else {
            0
        };
        BLOCK_HEADER_LEN + 8 + long_form
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::SC_SECURITY, self.size(), Self::NAME)?;
        w.u32(self.encryption_method);
        w.u32(self.encryption_level);
        if !self.wants_standard_security() {
            return Ok(());
        }
        let random = self.server_random.unwrap_or(&[]);
        let cert = self.server_certificate.unwrap_or(&[]);
        w.u32(random.len() as u32);
        w.u32(cert.len() as u32);
        w.bytes(random);
        w.bytes(cert);
        Ok(())
    }
}

impl<'a> Decode<'a> for ServerSecurityData<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::SC_SECURITY, Self::NAME)?;
        let encryption_method = b.u32(Self::NAME)?;
        let encryption_level = b.u32(Self::NAME)?;
        if encryption_method == ENCRYPTION_METHOD_NONE && encryption_level == ENCRYPTION_LEVEL_NONE
        {
            return Ok(Self {
                encryption_method,
                encryption_level,
                server_random: None,
                server_certificate: None,
            });
        }
        // MS-RDPBCGR 2.2.1.4.3 says `serverRandomLen` is 32. It is not
        // checked, because nothing in the walk depends on it: both lengths
        // are explicit and the reads below are bounded by the block. The
        // fields whose value the walk does depend on, such as
        // `monitorAttributeSize`, are checked.
        let random_len = b.u32(Self::NAME)? as usize;
        let cert_len = b.u32(Self::NAME)? as usize;
        b.ensure_cap(
            random_len,
            MAX_GCC_USER_DATA,
            "MAX_GCC_USER_DATA",
            Self::NAME,
        )?;
        b.ensure_cap(cert_len, MAX_GCC_USER_DATA, "MAX_GCC_USER_DATA", Self::NAME)?;
        Ok(Self {
            encryption_method,
            encryption_level,
            server_random: Some(b.slice(random_len, Self::NAME)?),
            server_certificate: Some(b.slice(cert_len, Self::NAME)?),
        })
    }
}

/// `TS_UD_SC_NET` (MS-RDPBCGR 2.2.1.4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerNetworkData {
    /// `MCSChannelId`, the I/O channel every share PDU travels on.
    pub io_channel_id: u16,
    /// `channelIdArray`, in the same order as our `TS_UD_CS_NET` requests.
    pub channel_ids: Vec<u16>,
}

impl ServerNetworkData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_SC_NET";

    /// The two byte alignment pad, which MS-RDPBCGR 2.2.1.4.4 calls optional
    /// and every server sends when `channelCount` is odd.
    fn pad_len(&self) -> usize {
        if self.channel_ids.len() % 2 == 1 {
            2
        } else {
            0
        }
    }
}

impl Encode for ServerNetworkData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 4 + self.channel_ids.len() * 2 + self.pad_len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.channel_ids.len() > MAX_CHANNELS {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "more channels than MCS allows",
            });
        }
        write_block_header(w, block_type::SC_NET, self.size(), Self::NAME)?;
        w.u16(self.io_channel_id);
        w.u16(self.channel_ids.len() as u16);
        for id in &self.channel_ids {
            w.u16(*id);
        }
        w.zeros(self.pad_len());
        Ok(())
    }
}

impl Decode<'_> for ServerNetworkData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::SC_NET, Self::NAME)?;
        let io_channel_id = b.u16(Self::NAME)?;
        let count = usize::from(b.u16(Self::NAME)?);
        b.ensure_cap(count, MAX_CHANNELS, "MAX_CHANNELS", Self::NAME)?;
        let mut channel_ids = Vec::with_capacity(count);
        for _ in 0..count {
            channel_ids.push(b.u16(Self::NAME)?);
        }
        // The pad is read if it is there and not required if it is not.
        if b.remaining() >= 2 {
            b.skip(2, Self::NAME)?;
        }
        Ok(Self {
            io_channel_id,
            channel_ids,
        })
    }
}

/// `TS_UD_SC_MCS_MSGCHANNEL` (MS-RDPBCGR 2.2.1.4.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerMessageChannelData {
    /// `MCSChannelId`, the message channel auto detect and the heartbeat
    /// arrive on.
    pub channel_id: u16,
}

impl ServerMessageChannelData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_SC_MCS_MSGCHANNEL";
}

impl Encode for ServerMessageChannelData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 2
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::SC_MCS_MSGCHANNEL, self.size(), Self::NAME)?;
        w.u16(self.channel_id);
        Ok(())
    }
}

impl Decode<'_> for ServerMessageChannelData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::SC_MCS_MSGCHANNEL, Self::NAME)?;
        Ok(Self {
            channel_id: b.u16(Self::NAME)?,
        })
    }
}

/// `TS_UD_SC_MULTITRANSPORT` (MS-RDPBCGR 2.2.1.4.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerMultitransportData {
    /// `flags`, the same bits as
    /// [`multitransport_flags`](super::client::multitransport_flags).
    pub flags: u32,
}

impl ServerMultitransportData {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_SC_MULTITRANSPORT";
}

impl Encode for ServerMultitransportData {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BLOCK_HEADER_LEN + 4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_block_header(w, block_type::SC_MULTITRANSPORT, self.size(), Self::NAME)?;
        w.u32(self.flags);
        Ok(())
    }
}

impl Decode<'_> for ServerMultitransportData {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut b = read_block(r, block_type::SC_MULTITRANSPORT, Self::NAME)?;
        Ok(Self {
            flags: b.u32(Self::NAME)?,
        })
    }
}

/// Every server block, in one structure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerGccBlocks<'a> {
    /// `TS_UD_SC_CORE`.
    pub core: Option<ServerCoreData>,
    /// `TS_UD_SC_SEC1`.
    pub security: Option<ServerSecurityData<'a>>,
    /// `TS_UD_SC_NET`.
    pub network: Option<ServerNetworkData>,
    /// `TS_UD_SC_MCS_MSGCHANNEL`.
    pub message_channel: Option<ServerMessageChannelData>,
    /// `TS_UD_SC_MULTITRANSPORT`.
    pub multitransport: Option<ServerMultitransportData>,
}

impl ServerGccBlocks<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UD_SC";
}

impl Encode for ServerGccBlocks<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        self.core.as_ref().map_or(0, Encode::size)
            + self.security.as_ref().map_or(0, Encode::size)
            + self.network.as_ref().map_or(0, Encode::size)
            + self.message_channel.as_ref().map_or(0, Encode::size)
            + self.multitransport.as_ref().map_or(0, Encode::size)
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
        if let Some(b) = &self.message_channel {
            b.encode(w)?;
        }
        if let Some(b) = &self.multitransport {
            b.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ServerGccBlocks<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut out = Self::default();
        while !r.is_empty() {
            match peek_block_type(r, Self::NAME)? {
                block_type::SC_CORE => out.core = Some(ServerCoreData::decode(r)?),
                block_type::SC_SECURITY => out.security = Some(ServerSecurityData::decode(r)?),
                block_type::SC_NET => out.network = Some(ServerNetworkData::decode(r)?),
                block_type::SC_MCS_MSGCHANNEL => {
                    out.message_channel = Some(ServerMessageChannelData::decode(r)?);
                }
                block_type::SC_MULTITRANSPORT => {
                    out.multitransport = Some(ServerMultitransportData::decode(r)?);
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

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    fn sample() -> ServerGccBlocks<'static> {
        ServerGccBlocks {
            core: Some(ServerCoreData {
                version: 0x0008_0004,
                client_requested_protocols: Some(3),
                early_capability_flags: Some(
                    server_early_capability_flags::SKIP_CHANNELJOIN_SUPPORTED,
                ),
            }),
            security: Some(ServerSecurityData {
                encryption_method: ENCRYPTION_METHOD_NONE,
                encryption_level: ENCRYPTION_LEVEL_NONE,
                server_random: None,
                server_certificate: None,
            }),
            network: Some(ServerNetworkData {
                io_channel_id: 1003,
                channel_ids: vec![1004, 1005, 1006],
            }),
            message_channel: Some(ServerMessageChannelData { channel_id: 1007 }),
            multitransport: Some(ServerMultitransportData { flags: 0 }),
        }
    }

    #[test]
    fn every_server_block_round_trips() {
        let blocks = sample();
        let bytes = encode(&blocks);
        assert_eq!(
            ServerGccBlocks::decode(&mut Reader::new(&bytes)).unwrap(),
            blocks
        );
    }

    /// The eight byte security block is the only one a connection proceeds
    /// from, and it is what a server under TLS or CredSSP sends.
    #[test]
    fn the_external_security_protocol_block_is_eight_bytes() {
        let block = ServerSecurityData::default();
        let bytes = encode(&block);
        assert_eq!(bytes, [0x02, 0x0c, 0x0c, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!block.wants_standard_security());
        assert_eq!(
            ServerSecurityData::decode(&mut Reader::new(&bytes)).unwrap(),
            block
        );
    }

    /// A server asking for 128 bit RC4 sends the long form, and we parse the
    /// whole of it so the block boundary stays right and the message can name
    /// what it found.
    #[test]
    fn the_standard_security_long_form_round_trips() {
        let random = [0x11u8; 32];
        let cert = [0x22u8; 16];
        let block = ServerSecurityData {
            encryption_method: 0x0000_0002,
            encryption_level: 0x0000_0002,
            server_random: Some(&random),
            server_certificate: Some(&cert),
        };
        let bytes = encode(&block);
        assert_eq!(bytes.len(), 4 + 8 + 8 + 32 + 16);
        let back = ServerSecurityData::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back, block);
        assert!(back.wants_standard_security());
    }

    /// The `channelCount` pad is present when the count is odd and absent
    /// when it is even, which is what every server does.
    #[test]
    fn the_channel_id_array_is_padded_only_when_the_count_is_odd() {
        for count in 0..5usize {
            let block = ServerNetworkData {
                io_channel_id: 1003,
                channel_ids: (0..count).map(|i| 1004 + i as u16).collect(),
            };
            let bytes = encode(&block);
            let expected_pad = if count % 2 == 1 { 2 } else { 0 };
            assert_eq!(
                bytes.len(),
                4 + 4 + count * 2 + expected_pad,
                "count {count}"
            );
            assert_eq!(
                ServerNetworkData::decode(&mut Reader::new(&bytes)).unwrap(),
                block
            );
        }
    }

    /// A four byte core block is a legal older server, and the two tail
    /// fields must round trip as absent rather than as zero.
    #[test]
    fn a_short_core_block_round_trips_without_gaining_fields() {
        let block = ServerCoreData {
            version: 0x0008_0004,
            client_requested_protocols: None,
            early_capability_flags: None,
        };
        let bytes = encode(&block);
        assert_eq!(bytes.len(), 8);
        assert_eq!(
            ServerCoreData::decode(&mut Reader::new(&bytes)).unwrap(),
            block
        );
        assert!(!block.skip_channel_join());
    }

    #[test]
    fn skip_channel_join_reads_the_bit_that_changes_control_flow() {
        let block = ServerCoreData {
            version: 0,
            client_requested_protocols: Some(0),
            early_capability_flags: Some(
                server_early_capability_flags::SKIP_CHANNELJOIN_SUPPORTED
                    | server_early_capability_flags::DYNAMIC_DST_SUPPORTED,
            ),
        };
        assert!(block.skip_channel_join());
    }

    #[test]
    fn an_unknown_server_block_is_skipped() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x99, 0x0c, 0x06, 0x00, 0xaa, 0xbb]);
        bytes.extend_from_slice(&encode(&ServerMessageChannelData { channel_id: 1009 }));
        let blocks = ServerGccBlocks::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            blocks.message_channel,
            Some(ServerMessageChannelData { channel_id: 1009 })
        );
    }

    #[test]
    fn a_hostile_channel_count_is_refused_by_name() {
        let bytes = [0x03, 0x0c, 0x08, 0x00, 0xeb, 0x03, 0xff, 0xff];
        let err = ServerNetworkData::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_CHANNELS",
                ..
            }
        ));
    }

    #[test]
    fn a_hostile_certificate_length_is_refused_by_name() {
        let bytes = [
            0x02, 0x0c, 0x18, 0x00, // SC_SECURITY, length 24
            0x02, 0x00, 0x00, 0x00, // encryptionMethod
            0x02, 0x00, 0x00, 0x00, // encryptionLevel
            0x20, 0x00, 0x00, 0x00, // serverRandomLen
            0xff, 0xff, 0xff, 0x7f, // serverCertLen
            0x00, 0x00, 0x00, 0x00,
        ];
        let err = ServerSecurityData::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_GCC_USER_DATA",
                ..
            }
        ));
    }

    #[test]
    fn every_prefix_of_every_server_block_errors_without_panicking() {
        for bytes in [
            encode(&sample().core.unwrap()),
            encode(&sample().security.unwrap()),
            encode(&sample().network.unwrap()),
            encode(&sample().message_channel.unwrap()),
            encode(&sample().multitransport.unwrap()),
        ] {
            // A cut of zero is an empty block list, which is legal. Every
            // other prefix must fail, because `TS_UD_HEADER.length` declares
            // the whole block and the sub reader cannot be built from less.
            for cut in 1..bytes.len() {
                let mut r = Reader::new(&bytes[..cut]);
                assert!(ServerGccBlocks::decode(&mut r).is_err(), "cut {cut}");
            }
        }
    }
}
