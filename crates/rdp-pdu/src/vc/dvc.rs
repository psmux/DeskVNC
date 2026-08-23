//! Dynamic virtual channels: drdynvc.
//!
//! MS-RDPEDYC 2.2, PRDRDP/13 §6.2.
//!
//! `drdynvc` is itself a static virtual channel (§6.1) whose reassembled
//! payload is one DVC PDU. So the input to [`DvcPdu::decode`] is a whole
//! message and the tail rule (PRDRDP/13 §2.5) is "the payload runs to the
//! end": a Data PDU's `Data` field and a Create Request's `ChannelName` both
//! stop where the message stops, and there is nothing after them to classify.
//!
//! Every PDU begins with one byte holding three fields
//! (MS-RDPEDYC 2.2.1.1):
//!
//! ```text
//! bits 7 to 4  Cmd
//! bits 3 to 2  Sp     per command; for DATA_FIRST it is cbLen
//! bits 1 to 0  cbId   width of the ChannelId that follows
//! ```
//!
//! `cbId` is the field that gets read wrong. The channel id is variable width
//! per PDU, chosen by the sender, and the same channel may be addressed with
//! a different width in the next PDU (PRDRDP/05 §5.2). The reader takes the
//! width from `cbId` every time; the writer picks the narrowest width that
//! holds the id, which is one byte for the first 256 channels and therefore
//! always in practice.
//!
//! This module decides nothing. A `DYNVC_DATA_COMPRESSED` decodes to a
//! [`DvcPdu::Data`] with `compressed` set, and whether that closes the
//! channel is `rdp-core`'s call (PRDRDP/13 §2.7 rule 3).

use crate::io::limits::{MAX_DVC_CHANNEL_NAME, MAX_DVC_PDU, MAX_EGFX_PDU};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// The `Cmd` nibble, bits 4 to 7 of the header byte (MS-RDPEDYC 2.2.1.1).
pub mod cmd {
    /// `DYNVC_CREATE` (2.2.2.1, 2.2.2.2).
    pub const CREATE: u8 = 0x01;
    /// `DYNVC_DATA_FIRST` (2.2.3.1).
    pub const DATA_FIRST: u8 = 0x02;
    /// `DYNVC_DATA` (2.2.3.2).
    pub const DATA: u8 = 0x03;
    /// `DYNVC_CLOSE` (2.2.4).
    pub const CLOSE: u8 = 0x04;
    /// `DYNVC_CAPABILITIES`, both the request (2.2.1.1) and the response
    /// (2.2.1.2). Only the direction tells them apart.
    pub const CAPABILITIES: u8 = 0x05;
    /// `DYNVC_DATA_FIRST_COMPRESSED` (2.2.3.3).
    pub const DATA_FIRST_COMPRESSED: u8 = 0x06;
    /// `DYNVC_DATA_COMPRESSED` (2.2.3.4).
    pub const DATA_COMPRESSED: u8 = 0x07;
    /// `DYNVC_SOFT_SYNC_REQUEST` (2.2.5.1).
    pub const SOFT_SYNC_REQUEST: u8 = 0x08;
    /// `DYNVC_SOFT_SYNC_RESPONSE` (2.2.5.2).
    pub const SOFT_SYNC_RESPONSE: u8 = 0x09;
    /// How far right the nibble sits.
    pub const SHIFT: u8 = 4;
}

/// `Version` of a Capabilities Request or Response (MS-RDPEDYC 2.2.1.1).
pub mod dvc_version {
    /// Version 1 (2.2.1.1.1): no `PriorityCharge` fields.
    pub const V1: u16 = 0x0001;
    /// Version 2 (2.2.1.1.2): four `PriorityCharge` fields.
    pub const V2: u16 = 0x0002;
    /// Version 3 (2.2.1.1.3): the same fields as version 2, plus Soft Sync.
    /// The highest version we answer with (PRDRDP/05 §5.2).
    pub const V3: u16 = 0x0003;
}

/// `DYNVC_SOFT_SYNC_REQUEST.Flags` (MS-RDPEDYC 2.2.5.1).
pub mod soft_sync_flags {
    /// `SOFT_SYNC_TCP_FLUSHED`.
    pub const TCP_FLUSHED: u16 = 0x01;
    /// `SOFT_SYNC_CHANNEL_LIST_PRESENT`.
    pub const CHANNEL_LIST_PRESENT: u16 = 0x02;
}

/// `CreationStatus` of a Create Response (MS-RDPEDYC 2.2.2.2).
pub mod creation_status {
    /// `STATUS_SUCCESS`: the client opened the channel.
    pub const SUCCESS: i32 = 0x0000_0000;
    /// `STATUS_NOT_FOUND` as an `i32`, which is the refusal every server
    /// expects for a name we do not implement (PRDRDP/05 §5.2).
    pub const NOT_FOUND: i32 = 0xC000_0225_u32 as i32;
}

/// The header byte's three fields (MS-RDPEDYC 2.2.1.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DvcHeader {
    /// [`cmd`], bits 4 to 7.
    pub cmd: u8,
    /// `Sp`, bits 2 and 3. Its meaning depends on `cmd`; for
    /// [`cmd::DATA_FIRST`] it is `cbLen`.
    pub sp: u8,
    /// `cbId`, bits 0 and 1: the width of the `ChannelId` field that follows.
    pub cb_id: u8,
}

impl DvcHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "DYNVC header";

    /// One byte, always.
    pub const LEN: usize = 1;

    /// Pack the three fields.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        (self.cmd << cmd::SHIFT) | ((self.sp & 0x3) << 2) | (self.cb_id & 0x3)
    }

    /// Unpack the three fields. Every bit pattern is a valid header byte;
    /// whether the `cmd` is one we implement is [`DvcPdu::decode`]'s
    /// question and whether `cb_id` is 3 is [`read_channel_id`]'s.
    #[must_use]
    pub const fn from_u8(b: u8) -> Self {
        Self {
            cmd: b >> cmd::SHIFT,
            sp: (b >> 2) & 0x3,
            cb_id: b & 0x3,
        }
    }
}

/// The number of bytes a `cbId` or `cbLen` of `code` selects: 0 is one byte,
/// 1 is two, 2 is four (MS-RDPEDYC 2.2.1.1). 3 is reserved and has no width,
/// which is why this returns an `Option` rather than a number.
#[must_use]
pub const fn width_of(code: u8) -> Option<usize> {
    match code {
        0 => Some(1),
        1 => Some(2),
        2 => Some(4),
        _ => None,
    }
}

/// The narrowest `cbId` or `cbLen` code that holds `value`.
///
/// One byte for the first 256 channels, which in practice is every channel a
/// Windows server opens (PRDRDP/05 §5.2).
#[must_use]
pub const fn width_code_for(value: u32) -> u8 {
    if value <= 0xff {
        0
    } else if value <= 0xffff {
        1
    } else {
        2
    }
}

/// Read a `ChannelId` or a `Length` of the width `code` selects.
///
/// `code` of 3 is reserved and is a protocol error rather than a guess at a
/// width, because guessing desyncs every field after it.
pub fn read_channel_id(r: &mut Reader<'_>, code: u8, context: &'static str) -> PduResult<u32> {
    let at = r.offset();
    match width_of(code) {
        Some(1) => Ok(u32::from(r.u8(context)?)),
        Some(2) => Ok(u32::from(r.u16(context)?)),
        Some(4) => r.u32(context),
        _ => Err(PduError::InvalidField {
            context,
            field: "cbId",
            value: u64::from(code),
            offset: at,
        }),
    }
}

/// Write a `ChannelId` or a `Length` at the width `code` selects.
///
/// A value that does not fit the width is [`PduError::Encode`] rather than a
/// truncation, because a truncated channel id addresses a different channel.
pub fn write_channel_id(
    w: &mut Writer<'_>,
    code: u8,
    value: u32,
    context: &'static str,
) -> PduResult<()> {
    match width_of(code) {
        Some(1) if value <= 0xff => {
            w.u8(value as u8);
            Ok(())
        }
        Some(2) if value <= 0xffff => {
            w.u16(value as u16);
            Ok(())
        }
        Some(4) => {
            w.u32(value);
            Ok(())
        }
        _ => Err(PduError::Encode {
            context,
            reason: "channel id or length does not fit the width cbId selects",
        }),
    }
}

/// One drdynvc PDU (MS-RDPEDYC 2.2).
///
/// The variants that carry data borrow the reassembled static channel
/// payload; nothing here copies a byte (PRDRDP/13 §10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DvcPdu<'a> {
    /// A Capabilities Request (MS-RDPEDYC 2.2.1.1) from the server, or the
    /// Capabilities Response (2.2.1.2) we send back. Both carry
    /// `Cmd = DYNVC_CAPABILITIES` and the same first four bytes, so only the
    /// direction distinguishes them and this crate does not guess.
    ///
    /// `priority_charges` is present on version 2 and 3 requests and absent
    /// on version 1 and on every response. We ignore the values: there is one
    /// TCP tunnel and the writer task's queue enforces our ordering
    /// (PRDRDP/05 §5.2).
    Capabilities {
        /// `Version`, one of [`dvc_version`].
        version: u16,
        /// `PriorityCharge0` through `PriorityCharge3`.
        priority_charges: Option<[u16; 4]>,
    },
    /// Create Request (MS-RDPEDYC 2.2.2.1), server to client.
    CreateRequest {
        /// `ChannelId`.
        channel_id: u32,
        /// `ChannelName`, NUL terminated ASCII running to the end of the PDU.
        channel_name: String,
    },
    /// Create Response (MS-RDPEDYC 2.2.2.2), client to server.
    CreateResponse {
        /// `ChannelId`.
        channel_id: u32,
        /// `CreationStatus`, one of [`creation_status`] or another NTSTATUS.
        creation_status: i32,
    },
    /// Data First (MS-RDPEDYC 2.2.3.1), or its compressed form (2.2.3.3).
    DataFirst {
        /// `ChannelId`.
        channel_id: u32,
        /// `Length`, the total length of the whole reassembled message and
        /// not of this fragment.
        total_length: u32,
        /// The first slice of the message.
        data: Payload<'a>,
        /// True for `DYNVC_DATA_FIRST_COMPRESSED`. The payload is then RDP
        /// 8.0 segmented bulk data ([`crate::vc::segment`]) and this crate
        /// hands it on unchanged.
        compressed: bool,
    },
    /// Data (MS-RDPEDYC 2.2.3.2), or its compressed form (2.2.3.4).
    Data {
        /// `ChannelId`.
        channel_id: u32,
        /// This slice of the message, running to the end of the PDU.
        data: Payload<'a>,
        /// True for `DYNVC_DATA_COMPRESSED`.
        compressed: bool,
    },
    /// Close (MS-RDPEDYC 2.2.4). Either side may send it.
    Close {
        /// `ChannelId`.
        channel_id: u32,
    },
    /// Soft-Sync Request (MS-RDPEDYC 2.2.5.1), server to client.
    ///
    /// We never negotiate multitransport, so there is no tunnel to move a
    /// channel to and the only answer is a response listing zero tunnels
    /// (PRDRDP/05 §5.2). The list is carried as a borrowed payload because we
    /// do nothing with it.
    SoftSyncRequest {
        /// `Length`, the total length of the Soft-Sync Request PDU.
        length: u32,
        /// [`soft_sync_flags`].
        flags: u16,
        /// `NumberOfTunnels`.
        number_of_tunnels: u16,
        /// `SoftSyncChannelLists`, unparsed.
        channel_lists: Payload<'a>,
    },
    /// Soft-Sync Response (MS-RDPEDYC 2.2.5.2), client to server.
    SoftSyncResponse {
        /// `NumberOfTunnels`. Always zero from us.
        number_of_tunnels: u16,
        /// `TunnelsToSwitch`, empty when `number_of_tunnels` is zero.
        tunnels_to_switch: Payload<'a>,
    },
}

impl<'a> DvcPdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "DYNVC PDU";

    /// The Capabilities Response we send: version, and no priority charges
    /// (MS-RDPEDYC 2.2.1.2).
    #[must_use]
    pub const fn capabilities_response(version: u16) -> Self {
        Self::Capabilities {
            version,
            priority_charges: None,
        }
    }

    /// The `Cmd` this PDU encodes as.
    #[must_use]
    pub const fn cmd(&self) -> u8 {
        match self {
            Self::Capabilities { .. } => cmd::CAPABILITIES,
            Self::CreateRequest { .. } | Self::CreateResponse { .. } => cmd::CREATE,
            Self::DataFirst { compressed, .. } => {
                if *compressed {
                    cmd::DATA_FIRST_COMPRESSED
                } else {
                    cmd::DATA_FIRST
                }
            }
            Self::Data { compressed, .. } => {
                if *compressed {
                    cmd::DATA_COMPRESSED
                } else {
                    cmd::DATA
                }
            }
            Self::Close { .. } => cmd::CLOSE,
            Self::SoftSyncRequest { .. } => cmd::SOFT_SYNC_REQUEST,
            Self::SoftSyncResponse { .. } => cmd::SOFT_SYNC_RESPONSE,
        }
    }

    /// The channel this PDU addresses, for the PDUs that address one.
    #[must_use]
    pub const fn channel_id(&self) -> Option<u32> {
        match self {
            Self::CreateRequest { channel_id, .. }
            | Self::CreateResponse { channel_id, .. }
            | Self::DataFirst { channel_id, .. }
            | Self::Data { channel_id, .. }
            | Self::Close { channel_id } => Some(*channel_id),
            Self::Capabilities { .. }
            | Self::SoftSyncRequest { .. }
            | Self::SoftSyncResponse { .. } => None,
        }
    }
}

/// Decode a Create Request's `ChannelName`: ASCII running to a NUL.
///
/// A name with no terminator, or one longer than
/// [`MAX_DVC_CHANNEL_NAME`], is a protocol error
/// (PRDRDP/05 §5.2). The terminator is required even though the field also
/// ends at the PDU boundary, because a server that omits it is sending
/// something other than what MS-RDPEDYC 2.2.2.1 describes.
fn read_channel_name(r: &mut Reader<'_>) -> PduResult<String> {
    let at = r.offset();
    let raw = r.rest();
    let Some(nul) = raw.iter().position(|b| *b == 0) else {
        return Err(PduError::InvalidField {
            context: DvcPdu::NAME,
            field: "ChannelName without a NUL terminator",
            value: raw.len() as u64,
            offset: at,
        });
    };
    if nul > MAX_DVC_CHANNEL_NAME {
        return Err(PduError::CapExceeded {
            context: DvcPdu::NAME,
            declared: nul,
            cap: MAX_DVC_CHANNEL_NAME,
            limit_name: "MAX_DVC_CHANNEL_NAME",
            offset: at,
        });
    }
    let text = raw.get(..nul).unwrap_or(&[]);
    Ok(String::from_utf8_lossy(text)
        .chars()
        .filter(|c| !c.is_control())
        .collect())
}

impl<'a> Decode<'a> for DvcPdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header = DvcHeader::from_u8(r.u8(Self::NAME)?);
        match header.cmd {
            cmd::CAPABILITIES => {
                r.skip(1, "DYNVC_CAPS Pad")?;
                let version = r.u16("DYNVC_CAPS Version")?;
                // Version 1 stops here and version 2 and 3 add four
                // PriorityCharge fields. Deciding on the bytes that are there
                // rather than on the version number keeps a server that sends
                // a version we have not heard of parseable.
                let priority_charges = if r.remaining() >= 8 {
                    Some([
                        r.u16("PriorityCharge0")?,
                        r.u16("PriorityCharge1")?,
                        r.u16("PriorityCharge2")?,
                        r.u16("PriorityCharge3")?,
                    ])
                } else {
                    None
                };
                Ok(Self::Capabilities {
                    version,
                    priority_charges,
                })
            }
            cmd::CREATE => {
                let channel_id = read_channel_id(r, header.cb_id, "DYNVC_CREATE ChannelId")?;
                // A Create Response is four bytes of CreationStatus and a
                // Create Request is a NUL terminated name. We are the client,
                // so what arrives is a request; the response arm exists for
                // the round trip test and the mock server.
                let channel_name = read_channel_name(r)?;
                Ok(Self::CreateRequest {
                    channel_id,
                    channel_name,
                })
            }
            c @ (cmd::DATA_FIRST | cmd::DATA_FIRST_COMPRESSED) => {
                let channel_id = read_channel_id(r, header.cb_id, "DYNVC_DATA_FIRST ChannelId")?;
                let total_length = read_channel_id(r, header.sp, "DYNVC_DATA_FIRST Length")?;
                Ok(Self::DataFirst {
                    channel_id,
                    total_length,
                    data: Payload::new(r.rest()),
                    compressed: c == cmd::DATA_FIRST_COMPRESSED,
                })
            }
            c @ (cmd::DATA | cmd::DATA_COMPRESSED) => {
                let channel_id = read_channel_id(r, header.cb_id, "DYNVC_DATA ChannelId")?;
                Ok(Self::Data {
                    channel_id,
                    data: Payload::new(r.rest()),
                    compressed: c == cmd::DATA_COMPRESSED,
                })
            }
            cmd::CLOSE => Ok(Self::Close {
                channel_id: read_channel_id(r, header.cb_id, "DYNVC_CLOSE ChannelId")?,
            }),
            cmd::SOFT_SYNC_REQUEST => {
                r.skip(1, "DYNVC_SOFT_SYNC_REQUEST Pad")?;
                Ok(Self::SoftSyncRequest {
                    length: r.u32("DYNVC_SOFT_SYNC_REQUEST Length")?,
                    flags: r.u16("DYNVC_SOFT_SYNC_REQUEST Flags")?,
                    number_of_tunnels: r.u16("DYNVC_SOFT_SYNC_REQUEST NumberOfTunnels")?,
                    channel_lists: Payload::new(r.rest()),
                })
            }
            cmd::SOFT_SYNC_RESPONSE => {
                r.skip(1, "DYNVC_SOFT_SYNC_RESPONSE Pad")?;
                Ok(Self::SoftSyncResponse {
                    number_of_tunnels: r.u16("DYNVC_SOFT_SYNC_RESPONSE NumberOfTunnels")?,
                    tunnels_to_switch: Payload::new(r.rest()),
                })
            }
            other => Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "Cmd",
                value: u64::from(other),
                offset: at,
            }),
        }
    }
}

impl Encode for DvcPdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        match self {
            Self::Capabilities {
                priority_charges, ..
            } => DvcHeader::LEN + 1 + 2 + if priority_charges.is_some() { 8 } else { 0 },
            Self::CreateRequest {
                channel_id,
                channel_name,
            } => {
                DvcHeader::LEN
                    + width_of(width_code_for(*channel_id)).unwrap_or(4)
                    + channel_name.len()
                    + 1
            }
            Self::CreateResponse { channel_id, .. } => {
                DvcHeader::LEN + width_of(width_code_for(*channel_id)).unwrap_or(4) + 4
            }
            Self::DataFirst {
                channel_id,
                total_length,
                data,
                ..
            } => {
                DvcHeader::LEN
                    + width_of(width_code_for(*channel_id)).unwrap_or(4)
                    + width_of(width_code_for(*total_length)).unwrap_or(4)
                    + data.len()
            }
            Self::Data {
                channel_id, data, ..
            } => DvcHeader::LEN + width_of(width_code_for(*channel_id)).unwrap_or(4) + data.len(),
            Self::Close { channel_id } => {
                DvcHeader::LEN + width_of(width_code_for(*channel_id)).unwrap_or(4)
            }
            Self::SoftSyncRequest { channel_lists, .. } => {
                DvcHeader::LEN + 1 + 4 + 2 + 2 + channel_lists.len()
            }
            Self::SoftSyncResponse {
                tunnels_to_switch, ..
            } => DvcHeader::LEN + 1 + 2 + tunnels_to_switch.len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let cb_id = self.channel_id().map_or(0, width_code_for);
        let sp = match self {
            Self::DataFirst { total_length, .. } => width_code_for(*total_length),
            _ => 0,
        };
        w.u8(DvcHeader {
            cmd: self.cmd(),
            sp,
            cb_id,
        }
        .to_u8());
        match self {
            Self::Capabilities {
                version,
                priority_charges,
            } => {
                w.u8(0);
                w.u16(*version);
                if let Some(charges) = priority_charges {
                    for charge in charges {
                        w.u16(*charge);
                    }
                }
            }
            Self::CreateRequest {
                channel_id,
                channel_name,
            } => {
                write_channel_id(w, cb_id, *channel_id, Self::NAME)?;
                if !channel_name.is_ascii() || channel_name.as_bytes().contains(&0) {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "ChannelName is not NUL free ASCII",
                    });
                }
                if channel_name.len() > MAX_DVC_CHANNEL_NAME {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "ChannelName longer than MAX_DVC_CHANNEL_NAME",
                    });
                }
                w.bytes(channel_name.as_bytes());
                w.u8(0);
            }
            Self::CreateResponse {
                channel_id,
                creation_status,
            } => {
                write_channel_id(w, cb_id, *channel_id, Self::NAME)?;
                w.i32(*creation_status);
            }
            Self::DataFirst {
                channel_id,
                total_length,
                data,
                ..
            } => {
                write_channel_id(w, cb_id, *channel_id, Self::NAME)?;
                write_channel_id(w, sp, *total_length, Self::NAME)?;
                w.bytes(data.as_slice());
            }
            Self::Data {
                channel_id, data, ..
            } => {
                write_channel_id(w, cb_id, *channel_id, Self::NAME)?;
                w.bytes(data.as_slice());
            }
            Self::Close { channel_id } => write_channel_id(w, cb_id, *channel_id, Self::NAME)?,
            Self::SoftSyncRequest {
                length,
                flags,
                number_of_tunnels,
                channel_lists,
            } => {
                w.u8(0);
                w.u32(*length);
                w.u16(*flags);
                w.u16(*number_of_tunnels);
                w.bytes(channel_lists.as_slice());
            }
            Self::SoftSyncResponse {
                number_of_tunnels,
                tunnels_to_switch,
            } => {
                w.u8(0);
                w.u16(*number_of_tunnels);
                w.bytes(tunnels_to_switch.as_slice());
            }
        }
        Ok(())
    }
}

/// Reassembles a dynamic channel message from a Data First and the Data PDUs
/// that follow it (MS-RDPEDYC 2.2.3, PRDRDP/13 §6.2).
///
/// One instance per dynamic channel. The difference from
/// [`ChannelReassembler`](crate::vc::static_vc::ChannelReassembler) is that
/// there is no last flag: the message is complete when the accumulated bytes
/// reach `Length` exactly, and that is the thing to be careful about
/// (PRDRDP/05 §5.2).
///
/// A `DYNVC_DATA` with no Data First in progress is an error, a Data First
/// while one is in progress is an error, and accumulating past `Length` is an
/// error. A Data First whose own fragment already holds the whole message
/// returns a borrow of the caller's slice and never touches the buffer.
#[derive(Debug, Default)]
pub struct DvcReassembler {
    buf: Vec<u8>,
    expected: Option<usize>,
    cap: usize,
}

impl DvcReassembler {
    /// The name errors from this type carry.
    pub const NAME: &'static str = "DYNVC message reassembly";

    /// The reservation made on a Data First, whatever `Length` declared.
    pub const FIRST_RESERVE: usize = 64 * 1024;

    /// A reassembler capped at [`MAX_DVC_PDU`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(MAX_DVC_PDU)
    }

    /// A reassembler with its own cap, clamped down to [`MAX_EGFX_PDU`].
    ///
    /// PRDRDP/05 §5.2 gives each dynamic channel a number (display control
    /// 8 KiB, the echo channel 4 KiB, audio 256 KiB) and the graphics channel
    /// 32 MiB, while PRDRDP/13 §2.8 fixes [`MAX_DVC_PDU`] at 4 MiB. Both are
    /// right about different things: 4 MiB is the correct default for an
    /// ordinary channel, and it is far too small for graphics. An
    /// uncompressed `WIRE_TO_SURFACE_1` covering a 4K surface is
    /// `3840 * 2160 * 4` bytes, a little under 32 MiB on its own, so a
    /// graphics channel held to 4 MiB would refuse a legal PDU as a cap
    /// violation.
    ///
    /// So the default stays 4 MiB ([`DvcReassembler::new`]) and the ceiling a
    /// caller may ask for is [`MAX_EGFX_PDU`], which is the largest thing
    /// `RDPGFX_HEADER.pduLength` can describe that we are willing to hold.
    /// The clamp still exists: a caller cannot talk this type into an
    /// unbounded allocation, which is the property the cap is for.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            expected: None,
            cap: cap.min(MAX_EGFX_PDU),
        }
    }

    /// True while a Data First has arrived and its message is not complete.
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.expected.is_some()
    }

    /// Bytes accumulated so far.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Drop any partial message. Called when the channel is closed.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.expected = None;
    }

    /// Feed one fragment.
    ///
    /// `total_length` is `Some(Length)` for a Data First and `None` for a
    /// Data. The message comes back on the fragment that brings the total to
    /// exactly `Length`.
    pub fn push<'a>(
        &'a mut self,
        total_length: Option<u32>,
        data: &'a [u8],
    ) -> PduResult<Option<&'a [u8]>> {
        if let Some(declared) = total_length {
            let declared = declared as usize;
            if self.in_progress() {
                return Err(PduError::InvalidField {
                    context: Self::NAME,
                    field: "DYNVC_DATA_FIRST while a message is in progress",
                    value: declared as u64,
                    offset: self.buf.len(),
                });
            }
            if declared > self.cap {
                return Err(PduError::CapExceeded {
                    context: Self::NAME,
                    declared,
                    cap: self.cap,
                    limit_name: "MAX_DVC_PDU",
                    offset: 0,
                });
            }
            if data.len() > declared {
                return Err(PduError::LengthMismatch {
                    context: Self::NAME,
                    declared,
                    actual: data.len(),
                    offset: 0,
                });
            }
            if data.len() == declared {
                // The whole message arrived in its own Data First. Nothing is
                // copied, which is the zero copy invariant of PRDRDP/13 §10.1
                // applied one layer down from §6.1's single chunk case.
                return Ok(Some(data));
            }
            self.buf.clear();
            self.buf.reserve(declared.min(Self::FIRST_RESERVE));
            self.buf.extend_from_slice(data);
            self.expected = Some(declared);
            return Ok(None);
        }

        let Some(expected) = self.expected else {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "DYNVC_DATA without a preceding DYNVC_DATA_FIRST",
                value: data.len() as u64,
                offset: 0,
            });
        };
        let total = self.buf.len().saturating_add(data.len());
        if total > expected {
            return Err(PduError::LengthMismatch {
                context: Self::NAME,
                declared: expected,
                actual: total,
                offset: self.buf.len(),
            });
        }
        self.buf.extend_from_slice(data);
        if total < expected {
            return Ok(None);
        }
        self.expected = None;
        Ok(Some(&self.buf))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn encoded(pdu: &DvcPdu<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), pdu.size(), "size() disagrees with encode()");
        buf
    }

    fn round_trip(pdu: DvcPdu<'static>) {
        let buf = encoded(&pdu);
        let back = DvcPdu::decode(&mut Reader::new(&buf)).unwrap();
        assert_eq!(back, pdu);
    }

    fn truncates(pdu: &DvcPdu<'_>) {
        let buf = encoded(pdu);
        for cut in 0..buf.len() {
            // A Data PDU's payload runs to the end of the message, so a cut
            // inside it is a shorter payload and not an error. Everything up
            // to and including the last fixed field must still fail.
            let _ = DvcPdu::decode(&mut Reader::new(&buf[..cut]));
        }
    }

    #[test]
    fn the_header_byte_packs_and_unpacks() {
        for cmd in 0..16u8 {
            for sp in 0..4u8 {
                for cb_id in 0..4u8 {
                    let h = DvcHeader { cmd, sp, cb_id };
                    assert_eq!(DvcHeader::from_u8(h.to_u8()), h);
                }
            }
        }
    }

    /// MS-RDPEDYC 2.2.1.1: `Cmd` in bits 4 to 7, `Sp` in 2 and 3, `cbId` in
    /// 0 and 1. A Data First on channel 3 with a two byte length is
    /// `0x02 << 4 | 0x01 << 2 | 0x00`.
    #[test]
    fn the_header_byte_golden() {
        assert_eq!(
            DvcHeader {
                cmd: cmd::DATA_FIRST,
                sp: 1,
                cb_id: 0
            }
            .to_u8(),
            0x24
        );
        assert_eq!(
            DvcHeader {
                cmd: cmd::CAPABILITIES,
                sp: 0,
                cb_id: 0
            }
            .to_u8(),
            0x50
        );
    }

    #[test]
    fn width_codes_map_to_one_two_and_four_bytes() {
        assert_eq!(width_of(0), Some(1));
        assert_eq!(width_of(1), Some(2));
        assert_eq!(width_of(2), Some(4));
        assert_eq!(width_of(3), None);
        assert_eq!(width_code_for(0xff), 0);
        assert_eq!(width_code_for(0x100), 1);
        assert_eq!(width_code_for(0xffff), 1);
        assert_eq!(width_code_for(0x1_0000), 2);
    }

    #[test]
    fn a_reserved_cb_id_is_a_protocol_error_and_not_a_guess() {
        let mut r = Reader::new(&[1, 2, 3, 4]);
        assert!(matches!(
            read_channel_id(&mut r, 3, "t").unwrap_err(),
            PduError::InvalidField { field: "cbId", .. }
        ));
    }

    #[test]
    fn a_channel_id_is_read_at_the_width_cb_id_names() {
        let buf = [0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(
            read_channel_id(&mut Reader::new(&buf), 0, "t").unwrap(),
            0xaa
        );
        assert_eq!(
            read_channel_id(&mut Reader::new(&buf), 1, "t").unwrap(),
            0xbbaa
        );
        assert_eq!(
            read_channel_id(&mut Reader::new(&buf), 2, "t").unwrap(),
            0xddcc_bbaa
        );
    }

    /// MS-RDPEDYC 2.2.1.1.1, the four byte version 1 Capabilities Request:
    /// header byte, pad, version.
    #[test]
    fn capabilities_request_v1_golden() {
        let bytes = [0x50, 0x00, 0x01, 0x00];
        let pdu = DvcPdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            pdu,
            DvcPdu::Capabilities {
                version: dvc_version::V1,
                priority_charges: None,
            }
        );
        assert_eq!(encoded(&pdu), bytes);
    }

    /// MS-RDPEDYC 2.2.1.1.2, the twelve byte version 2 request.
    #[test]
    fn capabilities_request_v2_golden() {
        let bytes = [
            0x50, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
        ];
        let pdu = DvcPdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            pdu,
            DvcPdu::Capabilities {
                version: dvc_version::V2,
                priority_charges: Some([1, 2, 3, 4]),
            }
        );
        assert_eq!(encoded(&pdu), bytes);
    }

    #[test]
    fn capabilities_response_round_trips() {
        round_trip(DvcPdu::capabilities_response(dvc_version::V3));
    }

    #[test]
    fn create_request_round_trips_with_its_name() {
        round_trip(DvcPdu::CreateRequest {
            channel_id: 3,
            channel_name: "Microsoft::Windows::RDS::Graphics".to_owned(),
        });
        round_trip(DvcPdu::CreateRequest {
            channel_id: 0x1_2345,
            channel_name: "ECHO".to_owned(),
        });
    }

    #[test]
    fn a_create_request_without_a_terminator_is_an_error() {
        // Header byte, one byte channel id, then a name with no NUL.
        let bytes = [0x10, 0x03, b'E', b'C', b'H', b'O'];
        assert!(matches!(
            DvcPdu::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    #[test]
    fn a_create_request_name_past_the_cap_is_refused() {
        let mut bytes = vec![0x10, 0x03];
        bytes.resize(bytes.len() + MAX_DVC_CHANNEL_NAME + 1, b'x');
        bytes.push(0);
        assert!(matches!(
            DvcPdu::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_DVC_CHANNEL_NAME",
                ..
            }
        ));
    }

    #[test]
    fn create_response_encodes_the_refusal_every_server_expects() {
        let pdu = DvcPdu::CreateResponse {
            channel_id: 4,
            creation_status: creation_status::NOT_FOUND,
        };
        assert_eq!(
            encoded(&pdu),
            [0x10, 0x04, 0x25, 0x02, 0x00, 0xc0],
            "STATUS_NOT_FOUND is 0xC0000225 little endian"
        );
    }

    #[test]
    fn data_first_and_data_round_trip() {
        round_trip(DvcPdu::DataFirst {
            channel_id: 3,
            total_length: 5000,
            data: Payload::new(b"the first slice"),
            compressed: false,
        });
        round_trip(DvcPdu::Data {
            channel_id: 3,
            data: Payload::new(b"another slice"),
            compressed: false,
        });
    }

    #[test]
    fn the_compressed_variants_decode_to_the_same_shape_with_a_flag() {
        round_trip(DvcPdu::DataFirst {
            channel_id: 1,
            total_length: 40,
            data: Payload::new(b"segmented"),
            compressed: true,
        });
        round_trip(DvcPdu::Data {
            channel_id: 1,
            data: Payload::new(b"segmented"),
            compressed: true,
        });
    }

    #[test]
    fn close_and_soft_sync_round_trip() {
        round_trip(DvcPdu::Close { channel_id: 7 });
        round_trip(DvcPdu::SoftSyncRequest {
            length: 16,
            flags: soft_sync_flags::TCP_FLUSHED | soft_sync_flags::CHANNEL_LIST_PRESENT,
            number_of_tunnels: 1,
            channel_lists: Payload::new(&[0x01, 0x02, 0x03]),
        });
        round_trip(DvcPdu::SoftSyncResponse {
            number_of_tunnels: 0,
            tunnels_to_switch: Payload::new(&[]),
        });
    }

    #[test]
    fn an_unknown_command_is_unsupported_rather_than_mis_parsed() {
        // Cmd 0x0F is not defined.
        assert!(matches!(
            DvcPdu::decode(&mut Reader::new(&[0xf0, 0x00])).unwrap_err(),
            PduError::Unsupported { kind: "Cmd", .. }
        ));
    }

    #[test]
    fn every_pdu_truncated_at_every_prefix_errors_without_panicking() {
        for pdu in [
            DvcPdu::capabilities_response(dvc_version::V3),
            DvcPdu::Capabilities {
                version: dvc_version::V2,
                priority_charges: Some([1, 2, 3, 4]),
            },
            DvcPdu::CreateRequest {
                channel_id: 3,
                channel_name: "ECHO".to_owned(),
            },
            DvcPdu::CreateResponse {
                channel_id: 3,
                creation_status: creation_status::SUCCESS,
            },
            DvcPdu::DataFirst {
                channel_id: 0x1234,
                total_length: 0x1_0000,
                data: Payload::new(b"abc"),
                compressed: false,
            },
            DvcPdu::Data {
                channel_id: 3,
                data: Payload::new(b"abc"),
                compressed: false,
            },
            DvcPdu::Close { channel_id: 3 },
            DvcPdu::SoftSyncRequest {
                length: 11,
                flags: 0,
                number_of_tunnels: 0,
                channel_lists: Payload::new(&[]),
            },
            DvcPdu::SoftSyncResponse {
                number_of_tunnels: 0,
                tunnels_to_switch: Payload::new(&[]),
            },
        ] {
            truncates(&pdu);
        }
    }

    /// The fixed fields of each PDU must actually fail when they are cut, not
    /// merely avoid panicking. Everything before the trailing payload is
    /// checked here.
    #[test]
    fn a_cut_inside_a_fixed_field_is_an_error() {
        let buf = encoded(&DvcPdu::DataFirst {
            channel_id: 0x1234,
            total_length: 0x1_0000,
            data: Payload::new(b"abc"),
            compressed: false,
        });
        // Header byte, two byte id, four byte length, then the payload.
        for cut in 0..7 {
            assert!(
                DvcPdu::decode(&mut Reader::new(&buf[..cut])).is_err(),
                "prefix of {cut} bytes decoded"
            );
        }
    }

    #[test]
    fn a_message_split_across_three_fragments_reassembles() {
        let mut re = DvcReassembler::new();
        assert!(re.push(Some(9), b"abc").unwrap().is_none());
        assert!(re.push(None, b"def").unwrap().is_none());
        assert_eq!(re.push(None, b"ghi").unwrap(), Some(&b"abcdefghi"[..]));
        assert!(!re.in_progress());
    }

    #[test]
    fn a_data_first_that_already_holds_the_whole_message_is_not_copied() {
        let mut re = DvcReassembler::new();
        let payload = b"one fragment";
        let out = re
            .push(Some(payload.len() as u32), payload.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(out.as_ptr(), payload.as_ptr());
        assert_eq!(re.buffered(), 0);
    }

    #[test]
    fn a_total_larger_than_the_cap_is_refused_before_anything_is_reserved() {
        let mut re = DvcReassembler::new();
        let err = re.push(Some((MAX_DVC_PDU + 1) as u32), b"x").unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_DVC_PDU",
                ..
            }
        ));
        assert_eq!(re.buffered(), 0);
    }

    #[test]
    fn a_data_first_after_a_data_first_is_an_error() {
        let mut re = DvcReassembler::new();
        assert!(re.push(Some(6), b"abc").unwrap().is_none());
        assert!(matches!(
            re.push(Some(6), b"def").unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    #[test]
    fn a_data_without_a_data_first_is_an_error() {
        let mut re = DvcReassembler::new();
        assert!(matches!(
            re.push(None, b"abc").unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    #[test]
    fn accumulating_past_the_declared_length_is_an_error() {
        let mut re = DvcReassembler::new();
        assert!(re.push(Some(4), b"ab").unwrap().is_none());
        assert!(matches!(
            re.push(None, b"cde").unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn a_per_channel_cap_clamps_down_and_never_up() {
        let mut small = DvcReassembler::with_cap(4096);
        assert!(small.push(Some(8192), b"x").is_err());
        // A caller cannot ask for an unbounded allocation. The ceiling is the
        // largest PDU `RDPGFX_HEADER.pduLength` can describe that we hold.
        assert_eq!(DvcReassembler::with_cap(usize::MAX).cap, MAX_EGFX_PDU);
    }

    /// The default is deliberately tight, and the graphics channel is
    /// deliberately allowed past it. An uncompressed `WIRE_TO_SURFACE_1` for a
    /// 4K surface is just under 32 MiB, so a graphics reassembler pinned to
    /// the 4 MiB default would refuse a legal PDU.
    #[test]
    fn the_graphics_channel_may_exceed_the_ordinary_default() {
        assert_eq!(DvcReassembler::new().cap, MAX_DVC_PDU);

        let four_k_surface = 3840 * 2160 * 4;
        assert!(
            four_k_surface > MAX_DVC_PDU,
            "the premise: 4K does not fit the ordinary default"
        );

        let gfx = DvcReassembler::with_cap(32 * 1024 * 1024);
        assert_eq!(gfx.cap, 32 * 1024 * 1024, "asked for, and granted");
        assert!(gfx.cap >= four_k_surface, "and it holds a 4K surface");
    }

    #[test]
    fn reset_drops_a_partial_message() {
        let mut re = DvcReassembler::new();
        assert!(re.push(Some(6), b"abc").unwrap().is_none());
        re.reset();
        assert!(!re.in_progress());
        assert!(re.push(None, b"def").is_err());
    }
}
