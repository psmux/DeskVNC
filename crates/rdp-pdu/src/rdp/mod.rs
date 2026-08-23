//! Share headers, the connection PDUs and the capability sets (PRDRDP/13
//! §4.6 to §4.10, §5.1, §5.2).
//!
//! Everything from the Client Info PDU to the Font Map that ends the
//! connection sequence, plus the two headers every later PDU sits inside.
//!
//! # The layering, from the outside in
//!
//! ```text
//! TPKT | X.224 Data | MCS Send Data | [security header] | share headers | body
//!  x224.rs            mcs/            security.rs         share.rs        here
//! ```
//!
//! The security header is in brackets because it is usually not there.
//! [`security`] owns the rule that decides, and it is the one place in this
//! crate where a wrong answer produces a session that dies two seconds in
//! with an unintelligible error.
//!
//! # What the session calls
//!
//! * [`ClientInfoPdu`] to log on, [`LicensePdu`] to get past licensing.
//! * [`SharePdu::decode`] for everything on the I/O channel afterwards, which
//!   dispatches Demand Active, Confirm Active, Deactivate All and every Share
//!   Data PDU.
//! * [`CapabilitySets::client_defaults`] to build the Confirm Active.
//! * [`decode_io_pdu`] when the PDU class is not a share PDU: licensing,
//!   network detection, heartbeat.
//!
//! Nothing here is a state machine. Which PDU may arrive when is PRDRDP/03
//! §3's table and lives in `rdp-core`.

pub mod activation;
pub mod capabilities;
pub mod client_info;
pub mod control;
pub mod finalize;
pub mod license;
pub mod security;
pub mod share;

pub use activation::{ConfirmActivePdu, DemandActivePdu, ORIGINATOR_ID};
pub use capabilities::{CapabilitySet, CapabilitySets};
pub use client_info::{
    ArcClientPrivatePacket, ArcServerPrivatePacket, ClientInfoPdu, ExtendedInfoPacket, InfoPacket,
    SecretString, SystemTime, TimeZoneInfo,
};
pub use control::{
    AutoDetectBody, AutoDetectKind, AutoDetectPdu, AutoDetectPhase, DeactivateAllPdu, HeartbeatPdu,
    LogonInfo, LogonInfoExtended, LogonInfoVersion2, MonitorLayoutPdu, Rectangle16, RefreshRectPdu,
    SaveSessionInfoPdu, SetErrorInfoPdu, SuppressOutputPdu,
};
pub use finalize::{ControlPdu, FontListPdu, FontMapPdu, PersistentKeyListPdu, SynchronizePdu};
pub use license::{LicenseErrorMessage, LicenseMessage, LicensePdu, LicensePreamble};
pub use security::{
    BasicSecurityHeader, IoPduContext, SecurityHeader, SecurityHeaderKind, SlowPathClass,
};
pub use share::{
    read_share_control, write_share_control_with, write_share_data_pdu, ShareControl,
    ShareControlHeader, ShareDataHeader,
};

use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// The body of a Share Data PDU, dispatched on `pduType2` (MS-RDPBCGR
/// 2.2.8.1.1.1.2).
///
/// The variants this lane owns are decoded; the rest are carried as a
/// [`Payload`] for the module that does own them, which keeps `input` and
/// `update` free to land beside this one without either lane reaching into
/// the other. An unrecognised `pduType2` is preserved for the same reason
/// every unknown length prefixed thing in this crate is: the length was
/// explicit, so skipping cannot desync (PRDRDP/13 §2.7 rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareDataPdu<'a> {
    /// `PDUTYPE2_SYNCHRONIZE`.
    Synchronize(SynchronizePdu),
    /// `PDUTYPE2_CONTROL`.
    Control(ControlPdu),
    /// `PDUTYPE2_FONTLIST`.
    FontList(FontListPdu),
    /// `PDUTYPE2_FONTMAP`, whose arrival ends the connection sequence.
    FontMap(FontMapPdu),
    /// `PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST`.
    PersistentKeyList(Box<PersistentKeyListPdu>),
    /// `PDUTYPE2_SHUTDOWN_REQUEST`, an empty body.
    ShutdownRequest,
    /// `PDUTYPE2_SHUTDOWN_DENIED`, an empty body.
    ShutdownDenied,
    /// `PDUTYPE2_SET_ERROR_INFO_PDU`.
    SetErrorInfo(SetErrorInfoPdu),
    /// `PDUTYPE2_SAVE_SESSION_INFO`.
    SaveSessionInfo(Box<SaveSessionInfoPdu>),
    /// `PDUTYPE2_REFRESH_RECT`.
    RefreshRect(RefreshRectPdu),
    /// `PDUTYPE2_SUPPRESS_OUTPUT`.
    SuppressOutput(SuppressOutputPdu),
    /// `PDUTYPE2_MONITOR_LAYOUT_PDU`.
    MonitorLayout(MonitorLayoutPdu),
    /// A body whose `compressedType` said it is compressed. This crate reads
    /// the header and hands the bytes on; `rdp-codecs` decompresses them
    /// (PRDRDP/13 §7).
    Compressed(Payload<'a>),
    /// A body another module owns, or one nothing owns yet: the update,
    /// pointer and input PDUs among them.
    Other {
        /// `pduType2`.
        pdu_type2: u8,
        /// The body.
        body: Payload<'a>,
    },
}

impl<'a> ShareDataPdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SHAREDATAHEADER body";

    /// This body's `pduType2`.
    #[must_use]
    pub const fn pdu_type2(&self) -> u8 {
        use share::pdu_type2 as t;
        match self {
            Self::Synchronize(_) => t::SYNCHRONIZE,
            Self::Control(_) => t::CONTROL,
            Self::FontList(_) => t::FONT_LIST,
            Self::FontMap(_) => t::FONT_MAP,
            Self::PersistentKeyList(_) => t::BITMAPCACHE_PERSISTENT_LIST,
            Self::ShutdownRequest => t::SHUTDOWN_REQUEST,
            Self::ShutdownDenied => t::SHUTDOWN_DENIED,
            Self::SetErrorInfo(_) => t::SET_ERROR_INFO,
            Self::SaveSessionInfo(_) => t::SAVE_SESSION_INFO,
            Self::RefreshRect(_) => t::REFRESH_RECT,
            Self::SuppressOutput(_) => t::SUPPRESS_OUTPUT,
            Self::MonitorLayout(_) => t::MONITOR_LAYOUT,
            // A compressed body keeps the type its header carried, which the
            // enclosing `SharePdu::Data` still holds.
            Self::Compressed(_) => 0,
            Self::Other { pdu_type2, .. } => *pdu_type2,
        }
    }

    /// The encoded size of the body alone.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::Synchronize(pdu) => pdu.size(),
            Self::Control(pdu) => pdu.size(),
            Self::FontList(pdu) => pdu.size(),
            Self::FontMap(pdu) => pdu.size(),
            Self::PersistentKeyList(pdu) => pdu.size(),
            Self::ShutdownRequest | Self::ShutdownDenied => 0,
            Self::SetErrorInfo(pdu) => pdu.size(),
            Self::SaveSessionInfo(pdu) => pdu.size(),
            Self::RefreshRect(pdu) => pdu.size(),
            Self::SuppressOutput(pdu) => pdu.size(),
            Self::MonitorLayout(pdu) => pdu.size(),
            Self::Compressed(body) | Self::Other { body, .. } => body.len(),
        }
    }

    /// Write the body alone, without either header.
    pub fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::Synchronize(pdu) => pdu.encode(w),
            Self::Control(pdu) => pdu.encode(w),
            Self::FontList(pdu) => pdu.encode(w),
            Self::FontMap(pdu) => pdu.encode(w),
            Self::PersistentKeyList(pdu) => pdu.encode(w),
            Self::ShutdownRequest | Self::ShutdownDenied => Ok(()),
            Self::SetErrorInfo(pdu) => pdu.encode(w),
            Self::SaveSessionInfo(pdu) => pdu.encode(w),
            Self::RefreshRect(pdu) => pdu.encode(w),
            Self::SuppressOutput(pdu) => pdu.encode(w),
            Self::MonitorLayout(pdu) => pdu.encode(w),
            Self::Compressed(body) | Self::Other { body, .. } => {
                w.bytes(body.as_slice());
                Ok(())
            }
        }
    }

    /// Read a body of the type the Share Data header declared.
    pub fn read(r: &mut Reader<'a>, header: &ShareDataHeader) -> PduResult<Self> {
        use share::pdu_type2 as t;
        if header.is_compressed() {
            return Ok(ShareDataPdu::Compressed(Payload::new(r.rest())));
        }
        Ok(match header.pdu_type2 {
            t::SYNCHRONIZE => ShareDataPdu::Synchronize(SynchronizePdu::decode(r)?),
            t::CONTROL => ShareDataPdu::Control(ControlPdu::decode(r)?),
            t::FONT_LIST => ShareDataPdu::FontList(FontListPdu::decode(r)?),
            t::FONT_MAP => ShareDataPdu::FontMap(FontMapPdu::decode(r)?),
            t::BITMAPCACHE_PERSISTENT_LIST => {
                ShareDataPdu::PersistentKeyList(Box::new(PersistentKeyListPdu::decode(r)?))
            }
            t::SHUTDOWN_REQUEST => ShareDataPdu::ShutdownRequest,
            t::SHUTDOWN_DENIED => ShareDataPdu::ShutdownDenied,
            t::SET_ERROR_INFO => ShareDataPdu::SetErrorInfo(SetErrorInfoPdu::decode(r)?),
            t::SAVE_SESSION_INFO => {
                ShareDataPdu::SaveSessionInfo(Box::new(SaveSessionInfoPdu::decode(r)?))
            }
            t::REFRESH_RECT => ShareDataPdu::RefreshRect(RefreshRectPdu::decode(r)?),
            t::SUPPRESS_OUTPUT => ShareDataPdu::SuppressOutput(SuppressOutputPdu::decode(r)?),
            t::MONITOR_LAYOUT => ShareDataPdu::MonitorLayout(MonitorLayoutPdu::decode(r)?),
            other => ShareDataPdu::Other {
                pdu_type2: other,
                body: Payload::new(r.rest()),
            },
        })
    }
}

/// Any PDU that arrives inside a Share Control header (MS-RDPBCGR
/// 2.2.8.1.1.1).
///
/// This is the entry point PRDRDP/13 §9.4 names as the `fuzz_share_pdu`
/// target: every slow path PDU after the capability exchange goes through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharePdu<'a> {
    /// A flow control PDU, to be ignored (MS-RDPBCGR 2.2.8.1.1.1.1).
    FlowControl,
    /// `PDUTYPE_DEMANDACTIVEPDU`.
    DemandActive {
        /// `PDUSource`.
        pdu_source: u16,
        /// The PDU.
        pdu: Box<DemandActivePdu<'a>>,
    },
    /// `PDUTYPE_CONFIRMACTIVEPDU`.
    ConfirmActive {
        /// `PDUSource`.
        pdu_source: u16,
        /// The PDU.
        pdu: Box<ConfirmActivePdu<'a>>,
    },
    /// `PDUTYPE_DEACTIVATEALLPDU`.
    DeactivateAll {
        /// `PDUSource`.
        pdu_source: u16,
        /// The PDU.
        pdu: DeactivateAllPdu,
    },
    /// `PDUTYPE_DATAPDU`.
    Data {
        /// `PDUSource`.
        pdu_source: u16,
        /// The twelve bytes after the control header, kept as they arrived.
        header: ShareDataHeader,
        /// The body.
        pdu: ShareDataPdu<'a>,
    },
    /// `PDUTYPE_SERVER_REDIR_PKT`, the standard Server Redirection PDU
    /// (MS-RDPBCGR 2.2.13.2), carried whole. Decoding
    /// `RDP_SERVER_REDIRECTION_PACKET` is phase 2 and is not written yet.
    ServerRedirection {
        /// `PDUSource`.
        pdu_source: u16,
        /// The packet.
        body: Payload<'a>,
    },
}

impl<'a> SharePdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "SHARE_PDU";

    /// A Share Data PDU ready to send, with both lengths computed here.
    #[must_use]
    pub fn data(pdu_source: u16, share_id: u32, pdu: ShareDataPdu<'a>) -> Self {
        let uncompressed_length =
            u16::try_from(pdu.size() + share::SHARE_DATA_HEADER_LEN).unwrap_or(u16::MAX);
        Self::Data {
            pdu_source,
            header: ShareDataHeader {
                share_id,
                stream_id: share::stream_id::MED,
                uncompressed_length,
                pdu_type2: pdu.pdu_type2(),
                compressed_type: 0,
                compressed_length: 0,
            },
            pdu,
        }
    }

    /// The `PDUSource` this PDU carried, or [`None`] for a flow control PDU.
    #[must_use]
    pub const fn pdu_source(&self) -> Option<u16> {
        match self {
            Self::FlowControl => None,
            Self::DemandActive { pdu_source, .. }
            | Self::ConfirmActive { pdu_source, .. }
            | Self::DeactivateAll { pdu_source, .. }
            | Self::Data { pdu_source, .. }
            | Self::ServerRedirection { pdu_source, .. } => Some(*pdu_source),
        }
    }
}

impl Encode for SharePdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        match self {
            // A flow control PDU is eight bytes on the wire, and this crate
            // never sends one.
            Self::FlowControl => 0,
            Self::DemandActive { pdu, .. } => share::SHARE_CONTROL_HEADER_LEN + pdu.size(),
            Self::ConfirmActive { pdu, .. } => share::SHARE_CONTROL_HEADER_LEN + pdu.size(),
            Self::DeactivateAll { pdu, .. } => share::SHARE_CONTROL_HEADER_LEN + pdu.size(),
            Self::Data { pdu, .. } => share::SHARE_DATA_HEADER_LEN + pdu.size(),
            Self::ServerRedirection { body, .. } => share::SHARE_CONTROL_HEADER_LEN + body.len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        use share::pdu_type;
        match self {
            Self::FlowControl => Err(PduError::Encode {
                context: Self::NAME,
                reason: "this client never sends a flow control PDU",
            }),
            Self::DemandActive { pdu_source, pdu } => {
                write_share_control_with(w, pdu_type::DEMAND_ACTIVE, *pdu_source, |w| pdu.encode(w))
            }
            Self::ConfirmActive { pdu_source, pdu } => {
                write_share_control_with(w, pdu_type::CONFIRM_ACTIVE, *pdu_source, |w| {
                    pdu.encode(w)
                })
            }
            Self::DeactivateAll { pdu_source, pdu } => {
                write_share_control_with(w, pdu_type::DEACTIVATE_ALL, *pdu_source, |w| {
                    pdu.encode(w)
                })
            }
            Self::Data {
                pdu_source,
                header,
                pdu,
            } => write_share_control_with(w, pdu_type::DATA, *pdu_source, |w| {
                header.encode(w)?;
                pdu.encode(w)
            }),
            Self::ServerRedirection { pdu_source, body } => {
                write_share_control_with(w, pdu_type::SERVER_REDIR_PKT, *pdu_source, |w| {
                    w.bytes(body.as_slice());
                    Ok(())
                })
            }
        }
    }
}

impl<'a> Decode<'a> for SharePdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        use share::pdu_type;
        let ShareControl::Pdu { header, mut body } = read_share_control(r)? else {
            return Ok(Self::FlowControl);
        };
        let pdu_source = header.pdu_source;
        Ok(match header.kind() {
            pdu_type::DEMAND_ACTIVE => Self::DemandActive {
                pdu_source,
                pdu: Box::new(DemandActivePdu::decode(&mut body)?),
            },
            pdu_type::CONFIRM_ACTIVE => Self::ConfirmActive {
                pdu_source,
                pdu: Box::new(ConfirmActivePdu::decode(&mut body)?),
            },
            pdu_type::DEACTIVATE_ALL => Self::DeactivateAll {
                pdu_source,
                pdu: DeactivateAllPdu::decode(&mut body)?,
            },
            pdu_type::DATA => {
                let data_header = ShareDataHeader::decode(&mut body)?;
                let pdu = ShareDataPdu::read(&mut body, &data_header)?;
                Self::Data {
                    pdu_source,
                    header: data_header,
                    pdu,
                }
            }
            pdu_type::SERVER_REDIR_PKT => Self::ServerRedirection {
                pdu_source,
                body: Payload::new(body.rest()),
            },
            other => {
                // The type is unknown but the length was not, so this cannot
                // desync. Naming it is still better than pretending we parsed
                // it, and `ERRINFO_UNKNOWNPDUTYPE` is what a server says when
                // the mistake runs the other way.
                return Err(PduError::Unsupported {
                    context: Self::NAME,
                    kind: "pduType",
                    value: u64::from(other),
                    offset: r.offset(),
                });
            }
        })
    }
}

/// A PDU on the I/O or message channel, whatever class it turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoPdu<'a> {
    /// A licensing PDU (MS-RDPBCGR 2.2.1.12).
    License(Box<LicensePdu<'a>>),
    /// A network characteristics detection PDU (MS-RDPBCGR 2.2.14).
    AutoDetect(AutoDetectPdu<'a>),
    /// The heartbeat PDU (MS-RDPBCGR 2.2.16.1).
    Heartbeat(HeartbeatPdu),
    /// Anything inside a Share Control header.
    Share(Box<SharePdu<'a>>),
    /// A class this function does not decode, with its security header read
    /// and its body untouched: the Enhanced Server Redirection PDU and the
    /// two multitransport PDUs.
    Other {
        /// The header that was there.
        header: SecurityHeader,
        /// The body.
        body: Payload<'a>,
    },
}

/// Decode one slow path PDU, reading the security header the class and the
/// context say is there (PRDRDP/13 §5.2).
///
/// `class` is a parameter rather than something this function works out,
/// which is the whole point. The first two bytes of a Share Control PDU are a
/// length and the first two bytes of a Client Info PDU are a flag word, and
/// there is no way to tell them apart by looking: a Demand Active of 64 bytes
/// begins with the same two bytes as `SEC_INFO_PKT`. The session knows which
/// class it is expecting from the state machine (PRDRDP/03 §3.3) and from
/// which MCS channel the PDU arrived on, so it says.
pub fn decode_io_pdu<'a>(
    r: &mut Reader<'a>,
    context: IoPduContext,
    class: SlowPathClass,
) -> PduResult<IoPdu<'a>> {
    let header = security::read_expected_header(r, context, class)?;
    Ok(match class {
        SlowPathClass::Licensing => {
            let preamble = LicensePreamble::decode(r)?;
            let mut body = r.take(
                usize::from(preamble.msg_size) - license::LICENSE_PREAMBLE_LEN,
                LicensePdu::NAME,
            )?;
            IoPdu::License(Box::new(LicensePdu {
                message: license::read_message(&mut body, preamble.msg_type)?,
                preamble,
            }))
        }
        SlowPathClass::AutoDetectRequest | SlowPathClass::AutoDetectResponse => {
            IoPdu::AutoDetect(AutoDetectPdu::read(r)?)
        }
        SlowPathClass::Heartbeat => IoPdu::Heartbeat(HeartbeatPdu::decode(r)?),
        SlowPathClass::Other => IoPdu::Share(Box::new(SharePdu::decode(r)?)),
        _ => IoPdu::Other {
            header: header.ok_or(PduError::InvalidField {
                context: "decode_io_pdu",
                field: "security header",
                value: 0,
                offset: r.offset(),
            })?,
            body: Payload::new(r.rest()),
        },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::codes::ErrInfo;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    fn round_trip(pdu: &SharePdu<'_>) {
        let bytes = encode(pdu);
        assert_eq!(&SharePdu::decode(&mut Reader::new(&bytes)).unwrap(), pdu);
    }

    #[test]
    fn every_share_data_pdu_this_lane_owns_round_trips() {
        let cases = [
            ShareDataPdu::Synchronize(SynchronizePdu::client(0x03ea)),
            ShareDataPdu::Control(ControlPdu::cooperate()),
            ShareDataPdu::FontList(FontListPdu::client()),
            ShareDataPdu::FontMap(FontMapPdu::server()),
            ShareDataPdu::ShutdownRequest,
            ShareDataPdu::ShutdownDenied,
            ShareDataPdu::SetErrorInfo(SetErrorInfoPdu {
                error_info: ErrInfo::LogoffByUser,
            }),
            ShareDataPdu::SaveSessionInfo(Box::new(SaveSessionInfoPdu::PlainNotify)),
            ShareDataPdu::RefreshRect(RefreshRectPdu {
                areas: vec![Rectangle16::default()],
            }),
            ShareDataPdu::SuppressOutput(SuppressOutputPdu::suppress()),
            ShareDataPdu::MonitorLayout(MonitorLayoutPdu::default()),
        ];
        for case in cases {
            let pdu = SharePdu::data(0x03ea, 0x0010_3ea9, case);
            round_trip(&pdu);
        }
    }

    #[test]
    fn a_demand_active_and_its_confirm_round_trip_through_the_dispatcher() {
        let sets = CapabilitySets::client_defaults(
            1024,
            768,
            0x03ea,
            capabilities::InputCapabilitySet::client(0x0409, 4, 0, 12),
            false,
        );
        let demand = SharePdu::DemandActive {
            pdu_source: 0x03ea,
            pdu: Box::new(DemandActivePdu {
                share_id: 0x0010_3ea9,
                source_descriptor: b"RDP\0".to_vec(),
                capabilities: sets.clone(),
                session_id: Some(1),
            }),
        };
        round_trip(&demand);

        let confirm = SharePdu::ConfirmActive {
            pdu_source: 0x03ea,
            pdu: Box::new(ConfirmActivePdu::new(0x0010_3ea9, sets)),
        };
        round_trip(&confirm);
    }

    #[test]
    fn a_deactivate_all_and_a_redirection_round_trip() {
        round_trip(&SharePdu::DeactivateAll {
            pdu_source: 0x03ea,
            pdu: DeactivateAllPdu {
                share_id: 0x0010_3ea9,
                source_descriptor: vec![0],
            },
        });
        round_trip(&SharePdu::ServerRedirection {
            pdu_source: 0x03ea,
            body: Payload::new(&[0x00, 0x04, 0x10, 0x00]),
        });
    }

    /// A body another lane owns arrives as bytes rather than as an error, so
    /// `input` and `update` can decode it without this module knowing how.
    #[test]
    fn a_body_another_module_owns_is_carried_rather_than_rejected() {
        let pdu = SharePdu::data(
            0x03ea,
            1,
            ShareDataPdu::Other {
                pdu_type2: share::pdu_type2::UPDATE,
                body: Payload::new(&[0x01, 0x00, 0x02, 0x00]),
            },
        );
        let bytes = encode(&pdu);
        let back = SharePdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back, pdu);
        let SharePdu::Data { header, pdu, .. } = &back else {
            panic!("not a data PDU");
        };
        assert_eq!(header.pdu_type2, share::pdu_type2::UPDATE);
        assert_eq!(pdu.size(), 4);
    }

    /// A compressed body is handed on whole, because decompressing is
    /// `rdp-codecs`' job and mis-parsing it here would be silent.
    #[test]
    fn a_compressed_body_is_handed_on_with_its_expected_size() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_share_control_with(&mut w, share::pdu_type::DATA, 0x03ea, |w| {
                ShareDataHeader {
                    share_id: 1,
                    stream_id: share::stream_id::MED,
                    uncompressed_length: 18 + 64,
                    pdu_type2: share::pdu_type2::UPDATE,
                    compressed_type: share::compression_flags::COMPRESSED | 0x01,
                    compressed_length: 8,
                }
                .encode(w)?;
                w.bytes(&[0xaa; 8]);
                Ok(())
            })
            .unwrap();
        }
        let pdu = SharePdu::decode(&mut Reader::new(&buf)).unwrap();
        let SharePdu::Data { header, pdu, .. } = &pdu else {
            panic!("not a data PDU");
        };
        assert!(header.is_compressed());
        assert_eq!(header.expected_uncompressed_len(), Some(64));
        assert_eq!(
            header.compression_type(),
            crate::codes::CompressionType::Mppc64K
        );
        assert_eq!(*pdu, ShareDataPdu::Compressed(Payload::new(&[0xaa; 8])));
    }

    #[test]
    fn a_flow_control_pdu_dispatches_to_its_own_variant() {
        let bytes = [0x00, 0x80, 0x00, 0x00, 0x00, 0xea, 0x03, 0x00];
        assert_eq!(
            SharePdu::decode(&mut Reader::new(&bytes)).unwrap(),
            SharePdu::FlowControl
        );
        assert_eq!(SharePdu::FlowControl.pdu_source(), None);
    }

    #[test]
    fn an_unknown_share_control_type_is_reported_rather_than_guessed() {
        let bytes = [0x08, 0x00, 0x1f, 0x00, 0xea, 0x03, 0x00, 0x00];
        let err = SharePdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::Unsupported {
                kind: "pduType",
                ..
            }
        ));
    }

    /// The whole point of [`decode_io_pdu`]: the class decides, and a share
    /// PDU never loses four bytes to a header that is not there.
    #[test]
    fn decode_io_pdu_reads_a_header_only_where_the_class_says_there_is_one() {
        let context = IoPduContext::external_security();

        let share = encode(&SharePdu::data(
            0x03ea,
            1,
            ShareDataPdu::SetErrorInfo(SetErrorInfoPdu {
                error_info: ErrInfo::ServerShutdown,
            }),
        ));
        let IoPdu::Share(pdu) =
            decode_io_pdu(&mut Reader::new(&share), context, SlowPathClass::Other).unwrap()
        else {
            panic!("not a share PDU");
        };
        let SharePdu::Data { pdu, .. } = pdu.as_ref() else {
            panic!("not a data PDU");
        };
        assert_eq!(
            *pdu,
            ShareDataPdu::SetErrorInfo(SetErrorInfoPdu {
                error_info: ErrInfo::ServerShutdown
            })
        );

        let license = encode(&LicensePdu::client_error_alert());
        let IoPdu::License(pdu) = decode_io_pdu(
            &mut Reader::new(&license),
            context,
            SlowPathClass::Licensing,
        )
        .unwrap() else {
            panic!("not a licensing PDU");
        };
        assert_eq!(pdu.preamble.msg_type, license::message_type::ERROR_ALERT);

        // `SEC_HEARTBEAT` is 0x4000, so its two little endian bytes are 00 40.
        let heartbeat = [0x00, 0x40, 0x00, 0x00, 0x00, 30, 3, 5];
        let IoPdu::Heartbeat(pdu) = decode_io_pdu(
            &mut Reader::new(&heartbeat),
            context,
            SlowPathClass::Heartbeat,
        )
        .unwrap() else {
            panic!("not a heartbeat");
        };
        assert_eq!(pdu.period, 30);

        // `SEC_AUTODETECT_REQ` is 0x1000, so its bytes are 00 10.
        let detect = [0x00, 0x10, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00];
        let IoPdu::AutoDetect(pdu) = decode_io_pdu(
            &mut Reader::new(&detect),
            context,
            SlowPathClass::AutoDetectRequest,
        )
        .unwrap() else {
            panic!("not a detection PDU");
        };
        assert_eq!(pdu.classify().0, AutoDetectKind::RttMeasure);
    }

    #[test]
    fn every_prefix_of_a_share_pdu_errors_rather_than_panicking() {
        let bytes = encode(&SharePdu::data(
            0x03ea,
            1,
            ShareDataPdu::Control(ControlPdu::request_control()),
        ));
        for cut in 0..bytes.len() {
            let mut r = Reader::new(&bytes[..cut]);
            match SharePdu::decode(&mut r) {
                Err(_) | Ok(SharePdu::FlowControl) => {}
                Ok(other) => panic!("a {cut} byte prefix decoded as {other:?}"),
            }
        }
    }
}

pub mod redirection;
