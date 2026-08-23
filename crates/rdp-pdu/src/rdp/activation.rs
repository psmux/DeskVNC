//! Demand Active and Confirm Active (MS-RDPBCGR 2.2.1.13, PRDRDP/13 §4.8.1).
//!
//! The pair that decides what the session can do. The server demands, the
//! client confirms, and the `shareId` from the demand is echoed in the
//! confirm and used by every Share Data PDU afterwards. The pair can recur:
//! MS-RDPBCGR 1.3.1.3 lets a server send a Deactivate All at any time and
//! restart the exchange, which is why the connect state machine and the
//! running session share one implementation of it (PRDRDP/03 §2.10).
//!
//! Both PDUs here are the **body** of a Share Control PDU. The six byte
//! header is [`share`](super::share)'s and the dispatcher in
//! [`rdp`](super) puts the two together, so neither type has to carry a
//! `PDUSource` it does not own.
//!
//! # The off by four
//!
//! `lengthCombinedCapabilities` counts `numberCapabilities`, `pad2Octets` and
//! every capability set byte, which is four more than the sum of the sets.
//! Getting it wrong by four is a classic, so the decoder bounds the sets by
//! that field and the test below asserts the field against a hand computed
//! number rather than against the encoder's own arithmetic.

use super::capabilities::CapabilitySets;
use crate::io::limits::MAX_SOURCE_DESCRIPTOR;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `TS_CONFIRM_ACTIVE_PDU.originatorId`, which MS-RDPBCGR 2.2.1.13.2.1 fixes
/// at `0x03EA`. A server that receives anything else drops the connection.
pub const ORIGINATOR_ID: u16 = 0x03ea;

/// The `sourceDescriptor` mstsc sends, and what we send (PRDRDP/13 §4.8.1).
pub const CLIENT_SOURCE_DESCRIPTOR: &[u8] = b"MSTSC\0";

/// `numberCapabilities` and `pad2Octets`, the four bytes
/// `lengthCombinedCapabilities` counts beyond the sets themselves.
const COMBINED_CAPABILITIES_OVERHEAD: usize = 4;

/// Read a `sourceDescriptor` of the declared length, capped.
fn read_source_descriptor(
    r: &mut Reader<'_>,
    len: usize,
    context: &'static str,
) -> PduResult<Vec<u8>> {
    r.ensure_cap(len, MAX_SOURCE_DESCRIPTOR, "MAX_SOURCE_DESCRIPTOR", context)?;
    Ok(r.slice(len, context)?.to_vec())
}

/// `lengthSourceDescriptor` as a `u16`, or an encode error.
fn source_descriptor_len(descriptor: &[u8], context: &'static str) -> PduResult<u16> {
    u16::try_from(descriptor.len()).map_err(|_| PduError::Encode {
        context,
        reason: "sourceDescriptor longer than its length field",
    })
}

/// `lengthCombinedCapabilities` as a `u16`, or an encode error.
fn combined_capabilities_len(sets: &CapabilitySets<'_>, context: &'static str) -> PduResult<u16> {
    u16::try_from(sets.size() + COMBINED_CAPABILITIES_OVERHEAD).map_err(|_| PduError::Encode {
        context,
        reason: "capability sets longer than lengthCombinedCapabilities",
    })
}

/// `numberCapabilities` as a `u16`, or an encode error.
fn number_capabilities(sets: &CapabilitySets<'_>, context: &'static str) -> PduResult<u16> {
    u16::try_from(sets.sets.len()).map_err(|_| PduError::Encode {
        context,
        reason: "more capability sets than numberCapabilities can count",
    })
}

/// Read `numberCapabilities`, `pad2Octets` and the sets, bounded by
/// `lengthCombinedCapabilities`.
fn read_combined_capabilities<'a>(
    r: &mut Reader<'a>,
    combined_len: usize,
    context: &'static str,
) -> PduResult<CapabilitySets<'a>> {
    let at = r.offset();
    let body_len = combined_len
        .checked_sub(COMBINED_CAPABILITIES_OVERHEAD)
        .ok_or(PduError::InvalidField {
            context,
            field: "lengthCombinedCapabilities",
            value: combined_len as u64,
            offset: at,
        })?;
    let count = usize::from(r.u16(context)?);
    // `pad2Octets`.
    r.skip(2, context)?;
    let mut body = r.take(body_len, context)?;
    CapabilitySets::read(&mut body, count)
}

/// `TS_DEMAND_ACTIVE_PDU` (MS-RDPBCGR 2.2.1.13.1.1), the body of a Share
/// Control PDU with `PDUTYPE_DEMANDACTIVEPDU`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemandActivePdu<'a> {
    /// `shareId`, which every Share Data PDU afterwards echoes.
    pub share_id: u32,
    /// `sourceDescriptor`, an opaque name the server chose. Kept as bytes
    /// because a server may put anything here and a round trip has to be
    /// exact.
    pub source_descriptor: Vec<u8>,
    /// `capabilitySets`.
    pub capabilities: CapabilitySets<'a>,
    /// `sessionId`, documented as present and omitted by some servers, so it
    /// is the extensible tail of PRDRDP/13 §2.5.
    pub session_id: Option<u32>,
}

impl DemandActivePdu<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_DEMAND_ACTIVE_PDU";

    /// `sourceDescriptor` as text, for a log line. Lossy, because it is a
    /// server controlled field.
    #[must_use]
    pub fn source_descriptor_lossy(&self) -> String {
        String::from_utf8_lossy(&self.source_descriptor)
            .trim_end_matches('\0')
            .to_owned()
    }
}

impl Encode for DemandActivePdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 2
            + 2
            + self.source_descriptor.len()
            + COMBINED_CAPABILITIES_OVERHEAD
            + self.capabilities.size()
            + if self.session_id.is_some() { 4 } else { 0 }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.share_id);
        w.u16(source_descriptor_len(&self.source_descriptor, Self::NAME)?);
        w.u16(combined_capabilities_len(&self.capabilities, Self::NAME)?);
        w.bytes(&self.source_descriptor);
        w.u16(number_capabilities(&self.capabilities, Self::NAME)?);
        // `pad2Octets`.
        w.u16(0);
        self.capabilities.encode(w)?;
        if let Some(session_id) = self.session_id {
            w.u32(session_id);
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for DemandActivePdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let share_id = r.u32(Self::NAME)?;
        let descriptor_len = usize::from(r.u16(Self::NAME)?);
        let combined_len = usize::from(r.u16(Self::NAME)?);
        let source_descriptor = read_source_descriptor(r, descriptor_len, Self::NAME)?;
        let capabilities = read_combined_capabilities(r, combined_len, Self::NAME)?;
        let session_id = if r.remaining() >= 4 {
            Some(r.u32(Self::NAME)?)
        } else {
            None
        };
        Ok(Self {
            share_id,
            source_descriptor,
            capabilities,
            session_id,
        })
    }
}

/// `TS_CONFIRM_ACTIVE_PDU` (MS-RDPBCGR 2.2.1.13.2.1), the body of a Share
/// Control PDU with `PDUTYPE_CONFIRMACTIVEPDU`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfirmActivePdu<'a> {
    /// `shareId`, echoed from the Demand Active. A server that sees a
    /// different value answers `ERRINFO_CONFIRMACTIVEWRONGSHAREID`.
    pub share_id: u32,
    /// `originatorId`, always [`ORIGINATOR_ID`].
    pub originator_id: u16,
    /// `sourceDescriptor`, [`CLIENT_SOURCE_DESCRIPTOR`] for us.
    pub source_descriptor: Vec<u8>,
    /// `capabilitySets`.
    pub capabilities: CapabilitySets<'a>,
}

impl<'a> ConfirmActivePdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_CONFIRM_ACTIVE_PDU";

    /// The PDU this client answers a Demand Active with.
    #[must_use]
    pub fn new(share_id: u32, capabilities: CapabilitySets<'a>) -> Self {
        Self {
            share_id,
            originator_id: ORIGINATOR_ID,
            source_descriptor: CLIENT_SOURCE_DESCRIPTOR.to_vec(),
            capabilities,
        }
    }
}

impl Encode for ConfirmActivePdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 2
            + 2
            + 2
            + self.source_descriptor.len()
            + COMBINED_CAPABILITIES_OVERHEAD
            + self.capabilities.size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.share_id);
        w.u16(self.originator_id);
        w.u16(source_descriptor_len(&self.source_descriptor, Self::NAME)?);
        w.u16(combined_capabilities_len(&self.capabilities, Self::NAME)?);
        w.bytes(&self.source_descriptor);
        w.u16(number_capabilities(&self.capabilities, Self::NAME)?);
        // `pad2Octets`.
        w.u16(0);
        self.capabilities.encode(w)
    }
}

impl<'a> Decode<'a> for ConfirmActivePdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let share_id = r.u32(Self::NAME)?;
        let originator_id = r.u16(Self::NAME)?;
        let descriptor_len = usize::from(r.u16(Self::NAME)?);
        let combined_len = usize::from(r.u16(Self::NAME)?);
        let source_descriptor = read_source_descriptor(r, descriptor_len, Self::NAME)?;
        let capabilities = read_combined_capabilities(r, combined_len, Self::NAME)?;
        Ok(Self {
            share_id,
            originator_id,
            source_descriptor,
            capabilities,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::super::capabilities::{
        capability_set_type, BitmapCapabilitySet, CapabilitySet, GeneralCapabilitySet,
        ShareCapabilitySet,
    };
    use super::*;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    fn sets() -> CapabilitySets<'static> {
        CapabilitySets {
            sets: vec![
                CapabilitySet::General(GeneralCapabilitySet::client()),
                CapabilitySet::Bitmap(BitmapCapabilitySet::client(1024, 768)),
                CapabilitySet::Share(ShareCapabilitySet { node_id: 0x03ea }),
            ],
        }
    }

    #[test]
    fn a_confirm_active_round_trips() {
        let pdu = ConfirmActivePdu::new(0x0010_3ea9, sets());
        let bytes = encode(&pdu);
        assert_eq!(
            ConfirmActivePdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
        assert_eq!(pdu.originator_id, ORIGINATOR_ID);
    }

    /// The off by four, against a hand computed number: three sets of 24, 28
    /// and 8 bytes are 60, and `lengthCombinedCapabilities` is 64.
    #[test]
    fn length_combined_capabilities_counts_four_more_than_the_sets() {
        let pdu = ConfirmActivePdu::new(1, sets());
        assert_eq!(pdu.capabilities.size(), 24 + 28 + 8);
        let bytes = encode(&pdu);
        let combined = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(combined, 64);
        assert_eq!(usize::from(combined), pdu.capabilities.size() + 4);
        // `numberCapabilities` sits after the source descriptor.
        let at = 10 + pdu.source_descriptor.len();
        assert_eq!(u16::from_le_bytes([bytes[at], bytes[at + 1]]), 3);
    }

    /// The whole PDU inside its Share Control header, which is how it goes on
    /// the wire.
    #[test]
    fn a_confirm_active_inside_its_share_control_header() {
        use super::super::share::{
            pdu_type, read_share_control, write_share_control_with, ShareControl,
        };

        let pdu = ConfirmActivePdu::new(0x0010_3ea9, sets());
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_share_control_with(&mut w, pdu_type::CONFIRM_ACTIVE, 0x03ea, |w| pdu.encode(w))
                .unwrap();
        }
        assert_eq!(buf.len(), pdu.size() + 6);

        let ShareControl::Pdu { header, mut body } =
            read_share_control(&mut Reader::new(&buf)).unwrap()
        else {
            panic!("flow control");
        };
        assert_eq!(header.kind(), pdu_type::CONFIRM_ACTIVE);
        assert_eq!(ConfirmActivePdu::decode(&mut body).unwrap(), pdu);
    }

    #[test]
    fn a_demand_active_round_trips_with_and_without_its_session_id() {
        let mut pdu = DemandActivePdu {
            share_id: 0x0010_3ea9,
            source_descriptor: b"RDP\0".to_vec(),
            capabilities: sets(),
            session_id: Some(1),
        };
        let bytes = encode(&pdu);
        assert_eq!(
            DemandActivePdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
        assert_eq!(pdu.source_descriptor_lossy(), "RDP");

        // The servers that omit `sessionId` (PRDRDP/13 §4.8.1).
        pdu.session_id = None;
        let bytes = encode(&pdu);
        assert_eq!(
            DemandActivePdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// The capability sets are bounded by `lengthCombinedCapabilities`, so a
    /// server that lies about it cannot make the parser read into the
    /// `sessionId` that follows.
    #[test]
    fn the_sets_are_bounded_by_their_declared_length() {
        let pdu = DemandActivePdu {
            share_id: 1,
            source_descriptor: b"RDP\0".to_vec(),
            capabilities: sets(),
            session_id: Some(0xdead_beef),
        };
        let mut bytes = encode(&pdu);
        // A Demand Active has no `originatorId`, so its
        // `lengthCombinedCapabilities` sits at offset 6 and its descriptor at
        // 8. Claim one set fewer than there is, and the trailing set becomes
        // part of what follows rather than being read as a set.
        bytes[6] = 64 - 8;
        let at = 8 + pdu.source_descriptor.len();
        bytes[at] = 2;
        let back = DemandActivePdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.capabilities.sets.len(), 2);
        assert_eq!(back.capabilities.find(capability_set_type::SHARE), None);
    }

    #[test]
    fn a_combined_length_below_its_own_overhead_is_refused() {
        let pdu = ConfirmActivePdu::new(1, sets());
        let mut bytes = encode(&pdu);
        bytes[8] = 2;
        bytes[9] = 0;
        let err = ConfirmActivePdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "lengthCombinedCapabilities",
                ..
            }
        ));
    }

    #[test]
    fn an_oversized_source_descriptor_names_the_cap() {
        let pdu = ConfirmActivePdu::new(1, sets());
        let mut bytes = encode(&pdu);
        bytes[6] = 0xff;
        bytes[7] = 0xff;
        let err = ConfirmActivePdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_SOURCE_DESCRIPTOR",
                ..
            }
        ));
    }

    #[test]
    fn every_prefix_errors_rather_than_panicking() {
        let confirm = encode(&ConfirmActivePdu::new(1, sets()));
        for cut in 0..confirm.len() {
            assert!(
                ConfirmActivePdu::decode(&mut Reader::new(&confirm[..cut])).is_err(),
                "a {cut} byte prefix of a Confirm Active decoded"
            );
        }
        let demand = encode(&DemandActivePdu {
            share_id: 1,
            source_descriptor: b"RDP\0".to_vec(),
            capabilities: sets(),
            session_id: None,
        });
        for cut in 0..demand.len() {
            assert!(
                DemandActivePdu::decode(&mut Reader::new(&demand[..cut])).is_err(),
                "a {cut} byte prefix of a Demand Active decoded"
            );
        }
    }
}
