//! Connection finalisation: synchronise, control, font list and font map
//! (MS-RDPBCGR 2.2.1.14 to 2.2.1.22, PRDRDP/13 §4.9).
//!
//! Nine PDUs with tiny bodies, all of them Share Data PDUs on the I/O
//! channel. The client sends its four (or five, with a Persistent Key List we
//! never send) as one write without waiting, which MS-RDPBCGR 1.3.1.1 allows
//! and every real client does because it saves four round trips. The server's
//! four come back in any order, and the Font Map is the one that ends the
//! connection sequence: when it arrives the session is up (PRDRDP/03 §2.11).
//!
//! Every type here is the **body** of a Share Data PDU. The eighteen header
//! bytes are [`share`](super::share)'s, and
//! [`write_share_data_pdu`](super::share::write_share_data_pdu) puts the two
//! together with both lengths computed in one place.

use super::share::pdu_type2;
use crate::io::limits::MAX_PERSISTENT_KEYS;
use crate::io::{Decode, Encode, PduResult, Reader, Writer};

/// `TS_SYNCHRONIZE_PDU.messageType`, `SYNCMSGTYPE_SYNC` (MS-RDPBCGR
/// 2.2.1.14.1).
pub const SYNCMSGTYPE_SYNC: u16 = 0x0001;

/// `TS_CONTROL_PDU.action` (MS-RDPBCGR 2.2.1.15.1).
pub mod control_action {
    /// `CTRLACTION_REQUEST_CONTROL`.
    pub const REQUEST_CONTROL: u16 = 0x0001;
    /// `CTRLACTION_GRANTED_CONTROL`, server to client.
    pub const GRANTED_CONTROL: u16 = 0x0002;
    /// `CTRLACTION_DETACH`.
    pub const DETACH: u16 = 0x0003;
    /// `CTRLACTION_COOPERATE`.
    pub const COOPERATE: u16 = 0x0004;
}

/// `TS_FONT_LIST_PDU.listFlags` (MS-RDPBCGR 2.2.1.18.1).
pub mod font_list_flags {
    /// `FONTLIST_FIRST`.
    pub const FIRST: u16 = 0x0001;
    /// `FONTLIST_LAST`.
    pub const LAST: u16 = 0x0002;
}

/// `TS_FONT_MAP_PDU.mapFlags` (MS-RDPBCGR 2.2.1.22.1).
pub mod font_map_flags {
    /// `FONTMAP_FIRST`.
    pub const FIRST: u16 = 0x0001;
    /// `FONTMAP_LAST`.
    pub const LAST: u16 = 0x0002;
}

/// `TS_BITMAPCACHE_PERSISTENT_LIST_PDU.bBitMask` (MS-RDPBCGR 2.2.1.17.1).
pub mod persistent_list_flags {
    /// `PERSIST_FIRST_PDU`.
    pub const FIRST: u8 = 0x01;
    /// `PERSIST_LAST_PDU`.
    pub const LAST: u8 = 0x02;
}

/// `TS_SYNCHRONIZE_PDU` (MS-RDPBCGR 2.2.1.14.1, 2.2.1.19.1), four bytes.
///
/// Sent by both sides. `targetUser` is the other end's MCS channel id, and no
/// server has ever been observed to check it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SynchronizePdu {
    /// `messageType`, [`SYNCMSGTYPE_SYNC`].
    pub message_type: u16,
    /// `targetUser`.
    pub target_user: u16,
}

impl SynchronizePdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SYNCHRONIZE_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::SYNCHRONIZE;

    /// The client's synchronise, addressed to the server's channel.
    #[must_use]
    pub const fn client(target_user: u16) -> Self {
        Self {
            message_type: SYNCMSGTYPE_SYNC,
            target_user,
        }
    }
}

impl Encode for SynchronizePdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.message_type);
        w.u16(self.target_user);
        Ok(())
    }
}

impl Decode<'_> for SynchronizePdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            message_type: r.u16(Self::NAME)?,
            target_user: r.u16(Self::NAME)?,
        })
    }
}

/// `TS_CONTROL_PDU` (MS-RDPBCGR 2.2.1.15.1, 2.2.1.16.1, 2.2.1.20.1,
/// 2.2.1.21.1), eight bytes.
///
/// One structure for four PDUs; `action` is what tells them apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlPdu {
    /// `action`, from [`control_action`].
    pub action: u16,
    /// `grantId`, zero from the client and our user id in a Granted Control.
    pub grant_id: u16,
    /// `controlId`, zero from the client and `0x03EA` in a Granted Control.
    pub control_id: u32,
}

impl ControlPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_CONTROL_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::CONTROL;

    /// Client Control (Cooperate) (MS-RDPBCGR 2.2.1.15).
    #[must_use]
    pub const fn cooperate() -> Self {
        Self {
            action: control_action::COOPERATE,
            grant_id: 0,
            control_id: 0,
        }
    }

    /// Client Control (Request Control) (MS-RDPBCGR 2.2.1.16).
    #[must_use]
    pub const fn request_control() -> Self {
        Self {
            action: control_action::REQUEST_CONTROL,
            grant_id: 0,
            control_id: 0,
        }
    }

    /// True for the Granted Control that ends the control exchange.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        self.action == control_action::GRANTED_CONTROL
    }
}

impl Encode for ControlPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.action);
        w.u16(self.grant_id);
        w.u32(self.control_id);
        Ok(())
    }
}

impl Decode<'_> for ControlPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            action: r.u16(Self::NAME)?,
            grant_id: r.u16(Self::NAME)?,
            control_id: r.u32(Self::NAME)?,
        })
    }
}

/// `TS_FONT_LIST_PDU` (MS-RDPBCGR 2.2.1.18.1), eight bytes.
///
/// The client sends no fonts. The PDU exists because sending it is what makes
/// the server answer with the Font Map that ends the sequence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FontListPdu {
    /// `numberFonts`, zero.
    pub number_fonts: u16,
    /// `totalNumFonts`, zero.
    pub total_num_fonts: u16,
    /// `listFlags`, `FONTLIST_FIRST | FONTLIST_LAST`.
    pub list_flags: u16,
    /// `entrySize`, `0x0032`, which is the size of the font entry this PDU
    /// does not contain.
    pub entry_size: u16,
}

impl FontListPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FONT_LIST_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::FONT_LIST;

    /// `entrySize` as every client sends it.
    pub const ENTRY_SIZE: u16 = 0x0032;

    /// The PDU this client sends.
    #[must_use]
    pub const fn client() -> Self {
        Self {
            number_fonts: 0,
            total_num_fonts: 0,
            list_flags: font_list_flags::FIRST | font_list_flags::LAST,
            entry_size: Self::ENTRY_SIZE,
        }
    }
}

impl Encode for FontListPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.number_fonts);
        w.u16(self.total_num_fonts);
        w.u16(self.list_flags);
        w.u16(self.entry_size);
        Ok(())
    }
}

impl Decode<'_> for FontListPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            number_fonts: r.u16(Self::NAME)?,
            total_num_fonts: r.u16(Self::NAME)?,
            list_flags: r.u16(Self::NAME)?,
            entry_size: r.u16(Self::NAME)?,
        })
    }
}

/// `TS_FONT_MAP_PDU` (MS-RDPBCGR 2.2.1.22.1), eight bytes.
///
/// The PDU that ends the connection sequence. Nothing in it matters; its
/// arrival is the event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FontMapPdu {
    /// `numberEntries`, zero.
    pub number_entries: u16,
    /// `totalNumEntries`, zero.
    pub total_num_entries: u16,
    /// `mapFlags`, `FONTMAP_FIRST | FONTMAP_LAST`.
    pub map_flags: u16,
    /// `entrySize`, `0x0004`.
    pub entry_size: u16,
}

impl FontMapPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FONT_MAP_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::FONT_MAP;

    /// The PDU a server sends, for the mock server.
    #[must_use]
    pub const fn server() -> Self {
        Self {
            number_entries: 0,
            total_num_entries: 0,
            map_flags: font_map_flags::FIRST | font_map_flags::LAST,
            entry_size: 0x0004,
        }
    }
}

impl Encode for FontMapPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        8
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.number_entries);
        w.u16(self.total_num_entries);
        w.u16(self.map_flags);
        w.u16(self.entry_size);
        Ok(())
    }
}

impl Decode<'_> for FontMapPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            number_entries: r.u16(Self::NAME)?,
            total_num_entries: r.u16(Self::NAME)?,
            map_flags: r.u16(Self::NAME)?,
            entry_size: r.u16(Self::NAME)?,
        })
    }
}

/// One `TS_BITMAPCACHE_PERSISTENT_LIST_ENTRY` (MS-RDPBCGR 2.2.1.17.1.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistentCacheEntry {
    /// `Key1`, the low half of the bitmap's cache key.
    pub key1: u32,
    /// `Key2`, the high half.
    pub key2: u32,
}

impl PersistentCacheEntry {
    /// Eight bytes.
    pub const SIZE: usize = 8;
}

/// `TS_BITMAPCACHE_PERSISTENT_LIST_PDU` (MS-RDPBCGR 2.2.1.17.1).
///
/// Decode only. We advertise no persistent cache, so we never send one; the
/// decoder exists for the mock server and so that a capture can be read
/// (PRDRDP/13 §4.9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistentKeyListPdu {
    /// `numEntriesCache0` to `numEntriesCache4`.
    pub num_entries_cache: [u16; 5],
    /// `totalEntriesCache0` to `totalEntriesCache4`.
    pub total_entries_cache: [u16; 5],
    /// `bBitMask`, from [`persistent_list_flags`].
    pub bit_mask: u8,
    /// The entries, `numEntriesCache0` through 4 of them in total.
    pub entries: Vec<PersistentCacheEntry>,
}

impl PersistentKeyListPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAPCACHE_PERSISTENT_LIST_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::BITMAPCACHE_PERSISTENT_LIST;

    /// The entries this PDU declares across its five caches.
    fn declared_entries(&self) -> usize {
        self.num_entries_cache
            .iter()
            .map(|n| usize::from(*n))
            .sum::<usize>()
    }
}

impl Encode for PersistentKeyListPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        20 + 1 + 3 + self.entries.len() * PersistentCacheEntry::SIZE
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        for count in &self.num_entries_cache {
            w.u16(*count);
        }
        for count in &self.total_entries_cache {
            w.u16(*count);
        }
        w.u8(self.bit_mask);
        // `Pad2` and `Pad3`.
        w.zeros(3);
        for entry in &self.entries {
            w.u32(entry.key1);
            w.u32(entry.key2);
        }
        Ok(())
    }
}

impl Decode<'_> for PersistentKeyListPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut num_entries_cache = [0u16; 5];
        for count in &mut num_entries_cache {
            *count = r.u16(Self::NAME)?;
        }
        let mut total_entries_cache = [0u16; 5];
        for count in &mut total_entries_cache {
            *count = r.u16(Self::NAME)?;
        }
        let bit_mask = r.u8(Self::NAME)?;
        r.skip(3, Self::NAME)?;
        let mut out = Self {
            num_entries_cache,
            total_entries_cache,
            bit_mask,
            entries: Vec::new(),
        };
        let count = out.declared_entries();
        r.ensure_cap(
            count,
            MAX_PERSISTENT_KEYS,
            "MAX_PERSISTENT_KEYS",
            Self::NAME,
        )?;
        out.entries.reserve(count);
        for _ in 0..count {
            out.entries.push(PersistentCacheEntry {
                key1: r.u32(Self::NAME)?,
                key2: r.u32(Self::NAME)?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::super::share::{
        read_share_control, write_share_data_pdu, ShareControl, ShareDataHeader,
    };
    use super::*;
    use crate::io::PduError;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    #[test]
    fn the_client_synchronize_is_four_bytes_of_the_values_the_spec_names() {
        let pdu = SynchronizePdu::client(0x03ea);
        assert_eq!(encode(&pdu), [0x01, 0x00, 0xea, 0x03]);
        assert_eq!(
            SynchronizePdu::decode(&mut Reader::new(&encode(&pdu))).unwrap(),
            pdu
        );
    }

    #[test]
    fn the_two_client_control_pdus_differ_only_in_their_action() {
        let cooperate = ControlPdu::cooperate();
        let request = ControlPdu::request_control();
        assert_eq!(
            encode(&cooperate),
            [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode(&request),
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert!(!cooperate.is_granted());

        // The server's Granted Control, which carries our user id.
        let granted = ControlPdu {
            action: control_action::GRANTED_CONTROL,
            grant_id: 0x03ea,
            control_id: 0x0000_03ea,
        };
        let bytes = encode(&granted);
        assert_eq!(
            ControlPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            granted
        );
        assert!(granted.is_granted());
    }

    #[test]
    fn the_font_list_and_font_map_round_trip() {
        let list = FontListPdu::client();
        assert_eq!(
            encode(&list),
            [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00]
        );
        assert_eq!(
            FontListPdu::decode(&mut Reader::new(&encode(&list))).unwrap(),
            list
        );

        let map = FontMapPdu::server();
        assert_eq!(
            encode(&map),
            [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00]
        );
        assert_eq!(
            FontMapPdu::decode(&mut Reader::new(&encode(&map))).unwrap(),
            map
        );
    }

    #[test]
    fn a_persistent_key_list_round_trips() {
        let pdu = PersistentKeyListPdu {
            num_entries_cache: [2, 0, 0, 0, 0],
            total_entries_cache: [2, 0, 0, 0, 0],
            bit_mask: persistent_list_flags::FIRST | persistent_list_flags::LAST,
            entries: vec![
                PersistentCacheEntry {
                    key1: 0x1111_1111,
                    key2: 0x2222_2222,
                },
                PersistentCacheEntry {
                    key1: 0x3333_3333,
                    key2: 0x4444_4444,
                },
            ],
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 24 + 16);
        assert_eq!(
            PersistentKeyListPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// A declared entry count larger than the cap is refused before the `Vec`
    /// is reserved.
    #[test]
    fn an_oversized_persistent_key_list_names_the_cap() {
        let mut bytes = vec![0u8; 24];
        for (index, chunk) in bytes.chunks_mut(2).take(5).enumerate() {
            let _ = index;
            chunk.copy_from_slice(&0xffff_u16.to_le_bytes());
        }
        let err = PersistentKeyListPdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_PERSISTENT_KEYS",
                ..
            }
        ));
    }

    /// The four client PDUs as the session sends them: one write, each inside
    /// its own Share Data PDU, and every length computed once.
    #[test]
    fn the_client_sends_its_four_as_one_write() {
        let share_id = 0x0010_3ea9;
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_share_data_pdu(
                &mut w,
                0x03ea,
                share_id,
                SynchronizePdu::PDU_TYPE2,
                &SynchronizePdu::client(0x03ea),
            )
            .unwrap();
            write_share_data_pdu(
                &mut w,
                0x03ea,
                share_id,
                ControlPdu::PDU_TYPE2,
                &ControlPdu::cooperate(),
            )
            .unwrap();
            write_share_data_pdu(
                &mut w,
                0x03ea,
                share_id,
                ControlPdu::PDU_TYPE2,
                &ControlPdu::request_control(),
            )
            .unwrap();
            write_share_data_pdu(
                &mut w,
                0x03ea,
                share_id,
                FontListPdu::PDU_TYPE2,
                &FontListPdu::client(),
            )
            .unwrap();
        }
        assert_eq!(buf.len(), 22 + 26 + 26 + 26);

        let mut r = Reader::new(&buf);
        let expected = [
            (SynchronizePdu::PDU_TYPE2, 4usize),
            (ControlPdu::PDU_TYPE2, 8),
            (ControlPdu::PDU_TYPE2, 8),
            (FontListPdu::PDU_TYPE2, 8),
        ];
        for (pdu_type2, body_len) in expected {
            let ShareControl::Pdu { mut body, .. } = read_share_control(&mut r).unwrap() else {
                panic!("flow control");
            };
            let header = ShareDataHeader::decode(&mut body).unwrap();
            assert_eq!(header.pdu_type2, pdu_type2);
            assert_eq!(header.share_id, share_id);
            assert_eq!(header.expected_uncompressed_len(), Some(body_len));
            assert_eq!(body.remaining(), body_len);
        }
        assert!(r.is_empty());
    }

    #[test]
    fn every_prefix_of_every_body_errors_rather_than_panicking() {
        let cases: [Vec<u8>; 5] = [
            encode(&SynchronizePdu::client(1)),
            encode(&ControlPdu::cooperate()),
            encode(&FontListPdu::client()),
            encode(&FontMapPdu::server()),
            encode(&PersistentKeyListPdu::default()),
        ];
        for bytes in &cases {
            for cut in 0..bytes.len() {
                let prefix = &bytes[..cut];
                assert!(SynchronizePdu::decode(&mut Reader::new(prefix)).is_err() || cut >= 4);
                assert!(ControlPdu::decode(&mut Reader::new(prefix)).is_err() || cut >= 8);
                assert!(FontListPdu::decode(&mut Reader::new(prefix)).is_err() || cut >= 8);
                assert!(FontMapPdu::decode(&mut Reader::new(prefix)).is_err() || cut >= 8);
                assert!(
                    PersistentKeyListPdu::decode(&mut Reader::new(prefix)).is_err() || cut >= 24
                );
            }
        }
    }
}
