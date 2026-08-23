//! Lifecycle and control PDUs (MS-RDPBCGR 2.2.2, 2.2.3, 2.2.5, 2.2.10,
//! 2.2.11, 2.2.12, 2.2.14, 2.2.16, PRDRDP/13 §4.10).
//!
//! Everything a running session says to itself: why the server is about to
//! disconnect, who logged on, which rectangles to repaint, whether to stop
//! sending output at all, and the two measurement PDUs that ride on the
//! message channel rather than inside a share header.
//!
//! Most of these are Share Data PDU bodies and the eighteen header bytes are
//! [`share`](super::share)'s. The two exceptions are
//! [`AutoDetectPdu`] and [`HeartbeatPdu`], which sit directly behind a basic
//! security header with their own flag (PRDRDP/13 §5.2) and never inside a
//! share header at all.

use super::security::{security_flags, BasicSecurityHeader, BASIC_SECURITY_HEADER_LEN};
use super::share::pdu_type2;
use crate::codes::{ErrInfo, LogonErrorData, LogonErrorType};
use crate::gcc::client::MonitorDef;
use crate::io::limits::{MAX_MONITORS, MAX_SOURCE_DESCRIPTOR, MAX_STRING_UTF16};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `TS_RECTANGLE16` (MS-RDPBCGR 2.2.11.2.1), eight bytes, every edge
/// inclusive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rectangle16 {
    /// `left`.
    pub left: u16,
    /// `top`.
    pub top: u16,
    /// `right`, inclusive.
    pub right: u16,
    /// `bottom`, inclusive.
    pub bottom: u16,
}

impl Rectangle16 {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_RECTANGLE16";
    /// Four `u16`.
    pub const SIZE: usize = 8;

    /// Read one.
    pub fn read(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            left: r.u16(Self::NAME)?,
            top: r.u16(Self::NAME)?,
            right: r.u16(Self::NAME)?,
            bottom: r.u16(Self::NAME)?,
        })
    }

    /// Write one.
    pub fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.left);
        w.u16(self.top);
        w.u16(self.right);
        w.u16(self.bottom);
    }
}

/// `TS_DEACTIVATE_ALL_PDU` (MS-RDPBCGR 2.2.3.1), the body of a Share Control
/// PDU with `PDUTYPE_DEACTIVATEALLPDU`.
///
/// Extensible per PRDRDP/13 §2.5, and for once the extension is at both ends:
/// some servers send `lengthSourceDescriptor = 0` with no descriptor and some
/// send a one byte descriptor, and older ones send the whole PDU with no
/// `shareId` at all. All three decode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeactivateAllPdu {
    /// `shareId`.
    pub share_id: u32,
    /// `sourceDescriptor`, often a single NUL.
    pub source_descriptor: Vec<u8>,
}

impl DeactivateAllPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_DEACTIVATE_ALL_PDU";
}

impl Encode for DeactivateAllPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 2 + self.source_descriptor.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.share_id);
        w.u16(
            u16::try_from(self.source_descriptor.len()).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "sourceDescriptor longer than its length field",
            })?,
        );
        w.bytes(&self.source_descriptor);
        Ok(())
    }
}

impl Decode<'_> for DeactivateAllPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        if r.remaining() < 6 {
            // The short form some servers send. There is nothing to read and
            // nothing that needs reading: the PDU's arrival is the event.
            let _ = r.rest();
            return Ok(Self::default());
        }
        let share_id = r.u32(Self::NAME)?;
        let len = usize::from(r.u16(Self::NAME)?);
        r.ensure_cap(
            len,
            MAX_SOURCE_DESCRIPTOR,
            "MAX_SOURCE_DESCRIPTOR",
            Self::NAME,
        )?;
        Ok(Self {
            share_id,
            source_descriptor: r.slice(len, Self::NAME)?.to_vec(),
        })
    }
}

/// Shutdown Request (MS-RDPBCGR 2.2.2.1) and Shutdown Request Denied
/// (2.2.2.2), which are two empty Share Data bodies.
///
/// PRDRDP/06 owns what the pair means for teardown. On the wire it is two
/// PDUs with nothing in them, and the type exists so the dispatcher can name
/// what it saw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmptyPdu;

impl EmptyPdu {
    /// The structure's name, such as it is.
    pub const NAME: &'static str = "TS_SHUTDOWN_REQ_PDU";
}

impl Encode for EmptyPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        0
    }

    fn encode(&self, _w: &mut Writer<'_>) -> PduResult<()> {
        Ok(())
    }
}

impl Decode<'_> for EmptyPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(_r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self)
    }
}

/// `TS_SET_ERROR_INFO_PDU` (MS-RDPBCGR 2.2.5.1), four bytes.
///
/// The most useful four bytes in the protocol. What the session does about
/// the code is PRDRDP/06 §4.3's classification and not ours; what is here is
/// the code, its symbol and a line of English ([`ErrInfo`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetErrorInfoPdu {
    /// `errorInfo`.
    pub error_info: ErrInfo,
}

impl SetErrorInfoPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SET_ERROR_INFO_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::SET_ERROR_INFO;
}

impl Encode for SetErrorInfoPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.error_info.to_u32());
        Ok(())
    }
}

impl Decode<'_> for SetErrorInfoPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            error_info: ErrInfo::from_u32(r.u32(Self::NAME)?),
        })
    }
}

/// `TS_REFRESH_RECT_PDU` (MS-RDPBCGR 2.2.11.2), client to server.
///
/// Requires `refreshRectSupport` in the General capability set.
/// `numberOfAreas` is a `u8`, so the count needs no cap of ours.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshRectPdu {
    /// `areasToRefresh`, at most 255 of them.
    pub areas: Vec<Rectangle16>,
}

impl RefreshRectPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_REFRESH_RECT_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::REFRESH_RECT;
}

impl Encode for RefreshRectPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + self.areas.len() * Rectangle16::SIZE
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let count = u8::try_from(self.areas.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "more areas than numberOfAreas can count",
        })?;
        w.u8(count);
        // `pad3Octets`.
        w.zeros(3);
        for area in &self.areas {
            area.write(w);
        }
        Ok(())
    }
}

impl Decode<'_> for RefreshRectPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let count = usize::from(r.u8(Self::NAME)?);
        r.skip(3, Self::NAME)?;
        let mut areas = Vec::with_capacity(count);
        for _ in 0..count {
            areas.push(Rectangle16::read(r)?);
        }
        Ok(Self { areas })
    }
}

/// `TS_SUPPRESS_OUTPUT_PDU` (MS-RDPBCGR 2.2.11.3), client to server.
///
/// The rectangle is present **only** when updates are allowed. Encoding it in
/// the suppress direction makes some servers stop sending anything until the
/// connection is remade (PRDRDP/13 §4.10.7), so the two are one field here
/// and cannot be set inconsistently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SuppressOutputPdu {
    /// `desktopRect` when updates are allowed, [`None`] to suppress them.
    pub allow: Option<Rectangle16>,
}

impl SuppressOutputPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SUPPRESS_OUTPUT_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::SUPPRESS_OUTPUT;

    /// `SUPPRESS_DISPLAY_UPDATES`.
    pub const SUPPRESS_DISPLAY_UPDATES: u8 = 0x00;
    /// `ALLOW_DISPLAY_UPDATES`.
    pub const ALLOW_DISPLAY_UPDATES: u8 = 0x01;

    /// Stop the server sending output, which is what a hidden window does.
    #[must_use]
    pub const fn suppress() -> Self {
        Self { allow: None }
    }

    /// Resume output over the given rectangle.
    #[must_use]
    pub const fn allow(desktop: Rectangle16) -> Self {
        Self {
            allow: Some(desktop),
        }
    }
}

impl Encode for SuppressOutputPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + if self.allow.is_some() {
            Rectangle16::SIZE
        } else {
            0
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self.allow {
            Some(rect) => {
                w.u8(Self::ALLOW_DISPLAY_UPDATES);
                w.zeros(3);
                rect.write(w);
            }
            None => {
                w.u8(Self::SUPPRESS_DISPLAY_UPDATES);
                w.zeros(3);
            }
        }
        Ok(())
    }
}

impl Decode<'_> for SuppressOutputPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let allow_display_updates = r.u8(Self::NAME)?;
        r.skip(3, Self::NAME)?;
        if allow_display_updates == Self::SUPPRESS_DISPLAY_UPDATES {
            return Ok(Self { allow: None });
        }
        Ok(Self {
            allow: Some(Rectangle16::read(r)?),
        })
    }
}

/// `TS_MONITOR_LAYOUT_PDU` (MS-RDPBCGR 2.2.12.1), server to client.
///
/// How the server actually laid the monitors out, which may differ from what
/// we asked for. It only arrives when `RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU`
/// was set in `TS_UD_CS_CORE`. The monitor structure is the same
/// `TS_MONITOR_DEF` the GCC block uses, so it is
/// [`gcc::client::MonitorDef`](crate::gcc::client::MonitorDef) and not a
/// second copy of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorLayoutPdu {
    /// `monitorDefArray`.
    pub monitors: Vec<MonitorDef>,
}

impl MonitorLayoutPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_MONITOR_LAYOUT_PDU";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::MONITOR_LAYOUT;
}

impl Encode for MonitorLayoutPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + self.monitors.len() * MonitorDef::SIZE
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.monitors.len() > MAX_MONITORS {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "more monitors than the PDU allows",
            });
        }
        w.u32(self.monitors.len() as u32);
        for monitor in &self.monitors {
            w.i32(monitor.left);
            w.i32(monitor.top);
            w.i32(monitor.right);
            w.i32(monitor.bottom);
            w.u32(monitor.flags);
        }
        Ok(())
    }
}

impl Decode<'_> for MonitorLayoutPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let count = r.u32(Self::NAME)? as usize;
        r.ensure_cap(count, MAX_MONITORS, "MAX_MONITORS", Self::NAME)?;
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            monitors.push(MonitorDef {
                left: r.i32(MonitorDef::NAME)?,
                top: r.i32(MonitorDef::NAME)?,
                right: r.i32(MonitorDef::NAME)?,
                bottom: r.i32(MonitorDef::NAME)?,
                flags: r.u32(MonitorDef::NAME)?,
            });
        }
        Ok(Self { monitors })
    }
}

/// `TS_SAVE_SESSION_INFO_PDU_DATA.infoType` (MS-RDPBCGR 2.2.10.1.1).
pub mod info_type {
    /// `INFOTYPE_LOGON`, `TS_LOGON_INFO`.
    pub const LOGON: u32 = 0x0000_0000;
    /// `INFOTYPE_LOGON_LONG`, `TS_LOGON_INFO_VERSION_2`.
    pub const LOGON_LONG: u32 = 0x0000_0001;
    /// `INFOTYPE_LOGON_PLAINNOTIFY`, `TS_PLAIN_NOTIFY`.
    pub const LOGON_PLAIN_NOTIFY: u32 = 0x0000_0002;
    /// `INFOTYPE_LOGON_EXTENDED_INFO`, `TS_LOGON_INFO_EXTENDED`.
    pub const LOGON_EXTENDED_INFO: u32 = 0x0000_0003;
}

/// `TS_LOGON_INFO_EXTENDED.FieldsPresent` (MS-RDPBCGR 2.2.10.1.1.4).
pub mod logon_ex_flags {
    /// `LOGON_EX_AUTORECONNECTCOOKIE`.
    pub const AUTORECONNECT_COOKIE: u32 = 0x0000_0001;
    /// `LOGON_EX_LOGONERRORS`.
    pub const LOGON_ERRORS: u32 = 0x0000_0002;
}

/// The fixed width of `TS_LOGON_INFO.Domain`, in bytes.
const LOGON_INFO_DOMAIN_LEN: usize = 52;

/// The fixed width of `TS_LOGON_INFO.UserName`, in bytes.
const LOGON_INFO_USER_NAME_LEN: usize = 512;

/// `TS_PLAIN_NOTIFY` is this many bytes of padding and nothing else.
const PLAIN_NOTIFY_LEN: usize = 576;

/// The `Pad` of `TS_LOGON_INFO_VERSION_2`.
const LOGON_INFO_V2_PAD_LEN: usize = 558;

/// `TS_LOGON_INFO_VERSION_2.Size`, the fixed part before the pad.
const LOGON_INFO_V2_SIZE: u32 = 18;

/// The `Pad` of `TS_LOGON_INFO_EXTENDED`.
const LOGON_INFO_EX_PAD_LEN: usize = 570;

/// `TS_LOGON_INFO` (MS-RDPBCGR 2.2.10.1.1.1), 576 bytes.
///
/// The two strings are fixed width and the counts say how much of each is
/// real. A `cbDomain` above 52 or a `cbUserName` above 512 is an
/// `InvalidField` rather than a read past the field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogonInfo {
    /// `Domain`.
    pub domain: String,
    /// `UserName`.
    pub user_name: String,
    /// `SessionId`.
    pub session_id: u32,
}

impl LogonInfo {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_LOGON_INFO";

    /// Read one.
    pub fn read(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let cb_domain = r.u32(Self::NAME)? as usize;
        if cb_domain > LOGON_INFO_DOMAIN_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "cbDomain",
                value: cb_domain as u64,
                offset: at,
            });
        }
        let mut domain_field = r.take(LOGON_INFO_DOMAIN_LEN, Self::NAME)?;
        let domain = domain_field.utf16_len(cb_domain, Self::NAME)?;
        let at = r.offset();
        let cb_user_name = r.u32(Self::NAME)? as usize;
        if cb_user_name > LOGON_INFO_USER_NAME_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "cbUserName",
                value: cb_user_name as u64,
                offset: at,
            });
        }
        let mut user_field = r.take(LOGON_INFO_USER_NAME_LEN, Self::NAME)?;
        let user_name = user_field.utf16_len(cb_user_name, Self::NAME)?;
        Ok(Self {
            domain,
            user_name,
            session_id: r.u32(Self::NAME)?,
        })
    }

    /// Write one, for the mock server.
    pub fn write(&self, w: &mut Writer<'_>) -> PduResult<()> {
        // The count includes the terminator the fixed field always carries.
        w.u32((self.domain.encode_utf16().count() * 2 + 2) as u32);
        w.utf16_fixed(&self.domain, LOGON_INFO_DOMAIN_LEN, Self::NAME)?;
        w.u32((self.user_name.encode_utf16().count() * 2 + 2) as u32);
        w.utf16_fixed(&self.user_name, LOGON_INFO_USER_NAME_LEN, Self::NAME)?;
        w.u32(self.session_id);
        Ok(())
    }

    /// The encoded size, which is fixed.
    #[must_use]
    pub const fn size() -> usize {
        4 + LOGON_INFO_DOMAIN_LEN + 4 + LOGON_INFO_USER_NAME_LEN + 4
    }
}

/// `TS_LOGON_INFO_VERSION_2` (MS-RDPBCGR 2.2.10.1.1.2).
///
/// The strings are **after** the 558 byte pad and are variable length here,
/// the opposite layout from version 1. Getting that backwards yields a user
/// name made of padding (PRDRDP/13 §4.10.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogonInfoVersion2 {
    /// `SessionId`.
    pub session_id: u32,
    /// `Domain`.
    pub domain: String,
    /// `UserName`.
    pub user_name: String,
}

impl LogonInfoVersion2 {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_LOGON_INFO_VERSION_2";

    /// `SAVE_SESSION_PDU_VERSION_ONE`.
    pub const VERSION_ONE: u16 = 0x0001;

    /// Read one.
    pub fn read(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let version = r.u16(Self::NAME)?;
        if version != Self::VERSION_ONE {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "Version",
                value: u64::from(version),
                offset: at,
            });
        }
        // `Size`, which is the fixed part and not the whole structure.
        r.skip(4, Self::NAME)?;
        let session_id = r.u32(Self::NAME)?;
        let cb_domain = r.u32(Self::NAME)? as usize;
        let cb_user_name = r.u32(Self::NAME)? as usize;
        r.ensure_cap(cb_domain, MAX_STRING_UTF16, "MAX_STRING_UTF16", Self::NAME)?;
        r.ensure_cap(
            cb_user_name,
            MAX_STRING_UTF16,
            "MAX_STRING_UTF16",
            Self::NAME,
        )?;
        r.skip(LOGON_INFO_V2_PAD_LEN, Self::NAME)?;
        Ok(Self {
            session_id,
            domain: r.utf16_len(cb_domain, Self::NAME)?,
            user_name: r.utf16_len(cb_user_name, Self::NAME)?,
        })
    }

    /// Write one, for the mock server.
    pub fn write(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let cb_domain = self.domain.encode_utf16().count() * 2 + 2;
        let cb_user_name = self.user_name.encode_utf16().count() * 2 + 2;
        w.u16(Self::VERSION_ONE);
        w.u32(LOGON_INFO_V2_SIZE);
        w.u32(self.session_id);
        w.u32(cb_domain as u32);
        w.u32(cb_user_name as u32);
        w.zeros(LOGON_INFO_V2_PAD_LEN);
        w.utf16(&self.domain);
        w.utf16(&self.user_name);
        Ok(())
    }

    /// The encoded size.
    #[must_use]
    pub fn size(&self) -> usize {
        18 + LOGON_INFO_V2_PAD_LEN
            + self.domain.encode_utf16().count() * 2
            + 2
            + self.user_name.encode_utf16().count() * 2
            + 2
    }
}

/// `TS_LOGON_ERRORS_INFO` (MS-RDPBCGR 2.2.10.1.1.4.1), eight bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonErrorsInfo {
    /// `ErrorNotificationType`.
    pub notification_type: LogonErrorType,
    /// `ErrorNotificationData`, which falls through to a Windows status code
    /// and is not an error when it does.
    pub notification_data: LogonErrorData,
}

impl LogonErrorsInfo {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_LOGON_ERRORS_INFO";
    /// Two `u32`.
    pub const SIZE: usize = 8;
}

/// `TS_LOGON_INFO_EXTENDED` (MS-RDPBCGR 2.2.10.1.1.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogonInfoExtended {
    /// `autoReconnectCookie`, present when `LOGON_EX_AUTORECONNECTCOOKIE` is
    /// set. Phase 2 stores it (D7).
    pub auto_reconnect_cookie: Option<super::client_info::ArcServerPrivatePacket>,
    /// `logonErrors`, present when `LOGON_EX_LOGONERRORS` is set.
    pub logon_errors: Option<LogonErrorsInfo>,
}

impl LogonInfoExtended {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_LOGON_INFO_EXTENDED";

    /// `FieldsPresent` for what this value holds.
    #[must_use]
    pub const fn fields_present(&self) -> u32 {
        let mut flags = 0;
        if self.auto_reconnect_cookie.is_some() {
            flags |= logon_ex_flags::AUTORECONNECT_COOKIE;
        }
        if self.logon_errors.is_some() {
            flags |= logon_ex_flags::LOGON_ERRORS;
        }
        flags
    }

    /// Read one.
    pub fn read(r: &mut Reader<'_>) -> PduResult<Self> {
        // `Length`, which covers the fields and not the trailing pad, and
        // which nothing here needs: every field carries its own length.
        r.skip(2, Self::NAME)?;
        let fields_present = r.u32(Self::NAME)?;
        let mut out = Self::default();
        if fields_present & logon_ex_flags::AUTORECONNECT_COOKIE != 0 {
            let len = r.u32(Self::NAME)? as usize;
            let mut field = r.take(len, Self::NAME)?;
            out.auto_reconnect_cookie = Some(super::client_info::ArcServerPrivatePacket::decode(
                &mut field,
            )?);
        }
        if fields_present & logon_ex_flags::LOGON_ERRORS != 0 {
            let len = r.u32(Self::NAME)? as usize;
            let mut field = r.take(len, Self::NAME)?;
            out.logon_errors = Some(LogonErrorsInfo {
                notification_type: LogonErrorType::from_u32(field.u32(LogonErrorsInfo::NAME)?),
                notification_data: LogonErrorData::from_u32(field.u32(LogonErrorsInfo::NAME)?),
            });
        }
        // The trailing `Pad`, which is only there on a real PDU.
        let _ = r.rest();
        Ok(out)
    }

    /// Write one, for the mock server.
    pub fn write(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let mut length = 6;
        if self.auto_reconnect_cookie.is_some() {
            length += 4 + super::client_info::ARC_PACKET_LEN;
        }
        if self.logon_errors.is_some() {
            length += 4 + LogonErrorsInfo::SIZE;
        }
        w.u16(u16::try_from(length).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "extended logon info longer than its Length field",
        })?);
        w.u32(self.fields_present());
        if let Some(cookie) = self.auto_reconnect_cookie {
            w.u32(super::client_info::ARC_PACKET_LEN as u32);
            cookie.encode(w)?;
        }
        if let Some(errors) = self.logon_errors {
            w.u32(LogonErrorsInfo::SIZE as u32);
            w.u32(errors.notification_type.to_u32());
            w.u32(errors.notification_data.to_u32());
        }
        w.zeros(LOGON_INFO_EX_PAD_LEN);
        Ok(())
    }

    /// The encoded size.
    #[must_use]
    pub const fn size(&self) -> usize {
        let mut size = 6 + LOGON_INFO_EX_PAD_LEN;
        if self.auto_reconnect_cookie.is_some() {
            size += 4 + super::client_info::ARC_PACKET_LEN;
        }
        if self.logon_errors.is_some() {
            size += 4 + LogonErrorsInfo::SIZE;
        }
        size
    }
}

/// `TS_SAVE_SESSION_INFO_PDU_DATA` (MS-RDPBCGR 2.2.10.1), server to client.
///
/// Carries three things the rest of the design depends on: the user and
/// domain for `RdpEvent::LogonInfo` (R35), the session id, and the auto
/// reconnect cookie phase 2 stores (R4, D7). PRDRDP/06 owns all three
/// behaviours; the decode is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveSessionInfoPdu {
    /// `INFOTYPE_LOGON`.
    Logon(LogonInfo),
    /// `INFOTYPE_LOGON_LONG`.
    LogonLong(LogonInfoVersion2),
    /// `INFOTYPE_LOGON_PLAINNOTIFY`: "a logon happened and I am not telling
    /// you who", which is what a server sends when the session is an existing
    /// one being reconnected.
    PlainNotify,
    /// `INFOTYPE_LOGON_EXTENDED_INFO`.
    Extended(LogonInfoExtended),
    /// An `infoType` this build does not know. Preserved rather than
    /// rejected: the Share Data header gave us its length (PRDRDP/13 §2.7
    /// rule 3).
    Unknown {
        /// `infoType`.
        info_type: u32,
        /// The body.
        body: Vec<u8>,
    },
}

impl SaveSessionInfoPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SAVE_SESSION_INFO_PDU_DATA";

    /// The `pduType2` this body belongs to.
    pub const PDU_TYPE2: u8 = pdu_type2::SAVE_SESSION_INFO;

    /// `infoType` for this value.
    #[must_use]
    pub const fn info_type(&self) -> u32 {
        match self {
            Self::Logon(_) => info_type::LOGON,
            Self::LogonLong(_) => info_type::LOGON_LONG,
            Self::PlainNotify => info_type::LOGON_PLAIN_NOTIFY,
            Self::Extended(_) => info_type::LOGON_EXTENDED_INFO,
            Self::Unknown { info_type, .. } => *info_type,
        }
    }

    /// The user and domain this PDU reported, if it reported any.
    #[must_use]
    pub fn logon_identity(&self) -> Option<(&str, &str)> {
        match self {
            Self::Logon(info) => Some((info.domain.as_str(), info.user_name.as_str())),
            Self::LogonLong(info) => Some((info.domain.as_str(), info.user_name.as_str())),
            _ => None,
        }
    }
}

impl Encode for SaveSessionInfoPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + match self {
            Self::Logon(_) => LogonInfo::size(),
            Self::LogonLong(info) => info.size(),
            Self::PlainNotify => PLAIN_NOTIFY_LEN,
            Self::Extended(info) => info.size(),
            Self::Unknown { body, .. } => body.len(),
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.info_type());
        match self {
            Self::Logon(info) => info.write(w),
            Self::LogonLong(info) => info.write(w),
            Self::PlainNotify => {
                w.zeros(PLAIN_NOTIFY_LEN);
                Ok(())
            }
            Self::Extended(info) => info.write(w),
            Self::Unknown { body, .. } => {
                w.bytes(body);
                Ok(())
            }
        }
    }
}

impl Decode<'_> for SaveSessionInfoPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let info_type = r.u32(Self::NAME)?;
        Ok(match info_type {
            info_type::LOGON => Self::Logon(LogonInfo::read(r)?),
            info_type::LOGON_LONG => Self::LogonLong(LogonInfoVersion2::read(r)?),
            info_type::LOGON_PLAIN_NOTIFY => {
                r.skip(PLAIN_NOTIFY_LEN, Self::NAME)?;
                Self::PlainNotify
            }
            info_type::LOGON_EXTENDED_INFO => Self::Extended(LogonInfoExtended::read(r)?),
            other => {
                tracing::trace!(info_type = other, "an unrecognised Save Session Info type");
                Self::Unknown {
                    info_type: other,
                    body: r.rest().to_vec(),
                }
            }
        })
    }
}

/// `RDP_NETCHAR_SYNC` and its siblings: the header every network
/// characteristics detection PDU starts with (MS-RDPBCGR 2.2.14).
pub mod autodetect {
    /// `TYPE_ID_AUTODETECT_REQUEST`.
    pub const TYPE_ID_REQUEST: u8 = 0x00;
    /// `TYPE_ID_AUTODETECT_RESPONSE`.
    pub const TYPE_ID_RESPONSE: u8 = 0x01;

    /// RTT Measure Request, connect time (2.2.14.1.1).
    pub const RTT_REQUEST_CONNECT: u16 = 0x0001;
    /// RTT Measure Request, continuous.
    pub const RTT_REQUEST_CONTINUOUS: u16 = 0x1001;
    /// RTT Measure Response (2.2.14.2.1).
    pub const RTT_RESPONSE: u16 = 0x0000;
    /// Bandwidth Measure Start, connect time over TCP (2.2.14.1.2).
    pub const BANDWIDTH_START_CONNECT: u16 = 0x0014;
    /// Bandwidth Measure Start, connect time over UDP.
    pub const BANDWIDTH_START_UDP: u16 = 0x0114;
    /// Bandwidth Measure Start, continuous.
    pub const BANDWIDTH_START_CONTINUOUS: u16 = 0x1014;
    /// Bandwidth Measure Payload (2.2.14.1.3).
    pub const BANDWIDTH_PAYLOAD: u16 = 0x0002;
    /// Bandwidth Measure Stop, connect time over TCP (2.2.14.1.4).
    pub const BANDWIDTH_STOP_CONNECT: u16 = 0x002b;
    /// Bandwidth Measure Stop, connect time over UDP.
    pub const BANDWIDTH_STOP_UDP: u16 = 0x0429;
    /// Bandwidth Measure Stop, continuous.
    pub const BANDWIDTH_STOP_CONTINUOUS: u16 = 0x0629;
    /// Bandwidth Measure Results (2.2.14.2.2).
    pub const BANDWIDTH_RESULTS: u16 = 0x0003;
    /// Network Characteristics Result, base and average RTT (2.2.14.1.5).
    pub const NETCHAR_RESULT_BASE_AVERAGE_RTT: u16 = 0x0840;
    /// Network Characteristics Result, bandwidth and average RTT.
    pub const NETCHAR_RESULT_BANDWIDTH_AVERAGE_RTT: u16 = 0x0880;
    /// Network Characteristics Result, all three.
    pub const NETCHAR_RESULT_ALL: u16 = 0x08c0;
    /// Network Characteristics Sync (2.2.14.2.3).
    pub const NETCHAR_SYNC: u16 = 0x0018;
}

/// What a network characteristics detection PDU is measuring (PRDRDP/13
/// §4.10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDetectKind {
    /// A round trip time measurement.
    RttMeasure,
    /// The start of a bandwidth measurement.
    BandwidthStart,
    /// The filler in the middle of one.
    BandwidthPayload,
    /// The end of one.
    BandwidthStop,
    /// The server reporting what it measured.
    BandwidthResults,
    /// The server's summary of the connection.
    NetworkCharacteristicsResult,
    /// The client's summary, sent once on a reconnect.
    NetworkCharacteristicsSync,
    /// A `requestType` this build does not know.
    Unknown,
}

/// Which phase of the connection a detection PDU belongs to.
///
/// The same measurement has three codes because the value encodes both the
/// measurement and the phase, which is why this is a pair and not one flat
/// enum: the session answers an RTT request identically whichever phase it is
/// in (PRDRDP/13 §4.10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDetectPhase {
    /// During the connection sequence, over the TCP connection.
    ConnectTime,
    /// During the connection sequence, over a UDP side channel.
    ConnectTimeUdp,
    /// While the session is running.
    Continuous,
}

/// The body of a network characteristics detection PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDetectBody<'a> {
    /// No body: RTT request and response, bandwidth start.
    Empty,
    /// `payloadLength` and the filler it counts.
    Payload(Payload<'a>),
    /// `timeDelta` and `byteCount`.
    Results {
        /// `timeDelta`, in milliseconds.
        time_delta: u32,
        /// `byteCount`.
        byte_count: u32,
    },
    /// One to three `u32`, chosen by `requestType`.
    NetworkCharacteristics {
        /// `baseRTT`, present for `0x0840` and `0x08C0`.
        base_rtt: Option<u32>,
        /// `bandwidth`, present for `0x0880` and `0x08C0`.
        bandwidth: Option<u32>,
        /// `averageRTT`, present in all three forms.
        average_rtt: Option<u32>,
    },
    /// `bandwidth` and `rtt`.
    Sync {
        /// `bandwidth`.
        bandwidth: u32,
        /// `rtt`.
        rtt: u32,
    },
    /// A body we could not interpret, kept because `headerLength` bounded it.
    Unknown(Payload<'a>),
}

/// A network characteristics detection PDU (MS-RDPBCGR 2.2.14).
///
/// Arrives on the message channel behind a basic security header with
/// `SEC_AUTODETECT_REQ`; the answer carries `SEC_AUTODETECT_RSP`. The header
/// is [`security`](super::security)'s, so this type starts at
/// `headerLength`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoDetectPdu<'a> {
    /// `headerTypeId`.
    pub header_type_id: u8,
    /// `sequenceNumber`, echoed in the response.
    pub sequence_number: u16,
    /// `requestType` or `responseType`, kept raw so a response reproduces the
    /// request's own code.
    pub request_type: u16,
    /// The body.
    pub body: AutoDetectBody<'a>,
}

impl<'a> AutoDetectPdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_NETWORK_DETECTION";

    /// The six byte header.
    pub const HEADER_LEN: usize = 6;

    /// What this PDU measures and which phase it belongs to.
    #[must_use]
    pub const fn classify(&self) -> (AutoDetectKind, AutoDetectPhase) {
        use autodetect as t;
        match self.request_type {
            t::RTT_REQUEST_CONNECT => (AutoDetectKind::RttMeasure, AutoDetectPhase::ConnectTime),
            t::RTT_REQUEST_CONTINUOUS => (AutoDetectKind::RttMeasure, AutoDetectPhase::Continuous),
            t::BANDWIDTH_START_CONNECT => {
                (AutoDetectKind::BandwidthStart, AutoDetectPhase::ConnectTime)
            }
            t::BANDWIDTH_START_UDP => (
                AutoDetectKind::BandwidthStart,
                AutoDetectPhase::ConnectTimeUdp,
            ),
            t::BANDWIDTH_START_CONTINUOUS => {
                (AutoDetectKind::BandwidthStart, AutoDetectPhase::Continuous)
            }
            t::BANDWIDTH_PAYLOAD => (
                AutoDetectKind::BandwidthPayload,
                AutoDetectPhase::ConnectTime,
            ),
            t::BANDWIDTH_STOP_CONNECT => {
                (AutoDetectKind::BandwidthStop, AutoDetectPhase::ConnectTime)
            }
            t::BANDWIDTH_STOP_UDP => (
                AutoDetectKind::BandwidthStop,
                AutoDetectPhase::ConnectTimeUdp,
            ),
            t::BANDWIDTH_STOP_CONTINUOUS => {
                (AutoDetectKind::BandwidthStop, AutoDetectPhase::Continuous)
            }
            t::BANDWIDTH_RESULTS => (
                AutoDetectKind::BandwidthResults,
                AutoDetectPhase::ConnectTime,
            ),
            t::NETCHAR_RESULT_BASE_AVERAGE_RTT
            | t::NETCHAR_RESULT_BANDWIDTH_AVERAGE_RTT
            | t::NETCHAR_RESULT_ALL => (
                AutoDetectKind::NetworkCharacteristicsResult,
                AutoDetectPhase::ConnectTime,
            ),
            t::NETCHAR_SYNC => (
                AutoDetectKind::NetworkCharacteristicsSync,
                AutoDetectPhase::ConnectTime,
            ),
            // `RTT_RESPONSE` is zero, which only means "response" when the
            // type id says so, so it is matched last.
            t::RTT_RESPONSE if self.header_type_id == autodetect::TYPE_ID_RESPONSE => {
                (AutoDetectKind::RttMeasure, AutoDetectPhase::ConnectTime)
            }
            _ => (AutoDetectKind::Unknown, AutoDetectPhase::ConnectTime),
        }
    }

    /// The RTT Measure Response to a request, which is the whole of our
    /// participation in connect time detection.
    #[must_use]
    pub const fn rtt_response(sequence_number: u16) -> Self {
        Self {
            header_type_id: autodetect::TYPE_ID_RESPONSE,
            sequence_number,
            request_type: autodetect::RTT_RESPONSE,
            body: AutoDetectBody::Empty,
        }
    }

    /// Read one, `headerLength` bounding the body.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header_length = usize::from(r.u8(Self::NAME)?);
        if header_length < Self::HEADER_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "headerLength",
                value: header_length as u64,
                offset: at,
            });
        }
        let header_type_id = r.u8(Self::NAME)?;
        let sequence_number = r.u16(Self::NAME)?;
        let request_type = r.u16(Self::NAME)?;
        let mut body_reader = r.take(header_length - Self::HEADER_LEN, Self::NAME)?;
        let mut probe = Self {
            header_type_id,
            sequence_number,
            request_type,
            body: AutoDetectBody::Empty,
        };
        let (kind, _) = probe.classify();
        probe.body = match kind {
            AutoDetectKind::RttMeasure | AutoDetectKind::BandwidthStart => AutoDetectBody::Empty,
            AutoDetectKind::BandwidthPayload | AutoDetectKind::BandwidthStop => {
                if body_reader.is_empty() {
                    // A continuous or UDP Bandwidth Measure Stop has no
                    // `payloadLength` (MS-RDPBCGR 2.2.14.1.4).
                    AutoDetectBody::Empty
                } else {
                    let declared = usize::from(body_reader.u16(Self::NAME)?);
                    let available = body_reader.remaining().min(declared);
                    AutoDetectBody::Payload(Payload::new(body_reader.slice(available, Self::NAME)?))
                }
            }
            AutoDetectKind::BandwidthResults => AutoDetectBody::Results {
                time_delta: body_reader.u32(Self::NAME)?,
                byte_count: body_reader.u32(Self::NAME)?,
            },
            AutoDetectKind::NetworkCharacteristicsResult => {
                let base_rtt = if request_type != autodetect::NETCHAR_RESULT_BANDWIDTH_AVERAGE_RTT {
                    Some(body_reader.u32(Self::NAME)?)
                } else {
                    None
                };
                let bandwidth = if request_type != autodetect::NETCHAR_RESULT_BASE_AVERAGE_RTT {
                    Some(body_reader.u32(Self::NAME)?)
                } else {
                    None
                };
                AutoDetectBody::NetworkCharacteristics {
                    base_rtt,
                    bandwidth,
                    average_rtt: Some(body_reader.u32(Self::NAME)?),
                }
            }
            AutoDetectKind::NetworkCharacteristicsSync => AutoDetectBody::Sync {
                bandwidth: body_reader.u32(Self::NAME)?,
                rtt: body_reader.u32(Self::NAME)?,
            },
            AutoDetectKind::Unknown => AutoDetectBody::Unknown(Payload::new(body_reader.rest())),
        };
        Ok(probe)
    }
}

impl Encode for AutoDetectPdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::HEADER_LEN
            + match &self.body {
                AutoDetectBody::Empty => 0,
                AutoDetectBody::Payload(filler) => 2 + filler.len(),
                AutoDetectBody::Results { .. } | AutoDetectBody::Sync { .. } => 8,
                AutoDetectBody::NetworkCharacteristics {
                    base_rtt,
                    bandwidth,
                    average_rtt,
                } => {
                    4 * (usize::from(base_rtt.is_some())
                        + usize::from(bandwidth.is_some())
                        + usize::from(average_rtt.is_some()))
                }
                AutoDetectBody::Unknown(body) => body.len(),
            }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let header_length = u8::try_from(self.size()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "detection PDU longer than its headerLength field",
        })?;
        w.u8(header_length);
        w.u8(self.header_type_id);
        w.u16(self.sequence_number);
        w.u16(self.request_type);
        match &self.body {
            AutoDetectBody::Empty => {}
            AutoDetectBody::Payload(filler) => {
                w.u16(u16::try_from(filler.len()).map_err(|_| PduError::Encode {
                    context: Self::NAME,
                    reason: "filler longer than payloadLength",
                })?);
                w.bytes(filler.as_slice());
            }
            AutoDetectBody::Results {
                time_delta,
                byte_count,
            } => {
                w.u32(*time_delta);
                w.u32(*byte_count);
            }
            AutoDetectBody::NetworkCharacteristics {
                base_rtt,
                bandwidth,
                average_rtt,
            } => {
                for value in [base_rtt, bandwidth, average_rtt].into_iter().flatten() {
                    w.u32(*value);
                }
            }
            AutoDetectBody::Sync { bandwidth, rtt } => {
                w.u32(*bandwidth);
                w.u32(*rtt);
            }
            AutoDetectBody::Unknown(body) => w.bytes(body.as_slice()),
        }
        Ok(())
    }
}

/// A Client-to-Server network characteristics detection response
/// (MS-RDPBCGR 2.2.14.2), complete with the basic security header it rides
/// behind.
///
/// # Why this is a second type
///
/// [`AutoDetectPdu`] deliberately starts at `headerLength`: by the time it
/// decodes, [`decode_io_pdu`](super::decode_io_pdu) has already read the
/// security header, and the same type serves both directions. Sending one
/// needs the header back. Every other client to server PDU in this crate
/// writes its own ([`LicensePdu`](super::LicensePdu) is the pattern), so the
/// response gets a type that does the same rather than a flag on the shared
/// one, and the session cannot forget the `SEC_AUTODETECT_RSP` that makes a
/// server recognise the answer at all (PRDRDP/13 §5.2).
///
/// # What the client actually sends
///
/// Three of them, all of 2.2.14.2. [`AutoDetectResponse::rtt`] answers an RTT
/// Measure Request and is the whole of connect time detection for a client
/// that measures nothing; [`AutoDetectResponse::bandwidth_results`] answers a
/// Bandwidth Measure Stop; [`AutoDetectResponse::network_characteristics_sync`]
/// is sent once on a reconnect. What to put in the two measured ones is
/// PRDRDP/05 §6.1's arithmetic and the session's to decide, which is why the
/// numbers are parameters and there is no constructor that measures anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoDetectResponse<'a> {
    /// The detection PDU, whose `headerTypeId` is
    /// [`autodetect::TYPE_ID_RESPONSE`].
    pub pdu: AutoDetectPdu<'a>,
}

impl<'a> AutoDetectResponse<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_NETWORK_DETECTION_RESPONSE";

    /// RTT Measure Response (MS-RDPBCGR 2.2.14.2.1), header only.
    ///
    /// `sequence_number` is echoed from the request; a server matches the
    /// answer to its request by that number and by nothing else.
    #[must_use]
    pub const fn rtt(sequence_number: u16) -> Self {
        Self {
            pdu: AutoDetectPdu::rtt_response(sequence_number),
        }
    }

    /// Bandwidth Measure Results (MS-RDPBCGR 2.2.14.2.2).
    ///
    /// `time_delta` is the milliseconds between the Bandwidth Measure Start
    /// and the Bandwidth Measure Stop, and `byte_count` is what arrived in
    /// between.
    #[must_use]
    pub const fn bandwidth_results(sequence_number: u16, time_delta: u32, byte_count: u32) -> Self {
        Self {
            pdu: AutoDetectPdu {
                header_type_id: autodetect::TYPE_ID_RESPONSE,
                sequence_number,
                request_type: autodetect::BANDWIDTH_RESULTS,
                body: AutoDetectBody::Results {
                    time_delta,
                    byte_count,
                },
            },
        }
    }

    /// Network Characteristics Sync (MS-RDPBCGR 2.2.14.2.3), the client
    /// telling a server what the previous connection measured.
    #[must_use]
    pub const fn network_characteristics_sync(
        sequence_number: u16,
        bandwidth: u32,
        rtt: u32,
    ) -> Self {
        Self {
            pdu: AutoDetectPdu {
                header_type_id: autodetect::TYPE_ID_RESPONSE,
                sequence_number,
                request_type: autodetect::NETCHAR_SYNC,
                body: AutoDetectBody::Sync { bandwidth, rtt },
            },
        }
    }
}

impl Encode for AutoDetectResponse<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BASIC_SECURITY_HEADER_LEN + self.pdu.size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.pdu.header_type_id != autodetect::TYPE_ID_RESPONSE {
            // A response with a request's type id is one a server ignores,
            // and it is a much better error here than a silent timeout.
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "headerTypeId is not TYPE_ID_AUTODETECT_RESPONSE",
            });
        }
        BasicSecurityHeader::new(security_flags::AUTODETECT_RSP).encode(w)?;
        self.pdu.encode(w)
    }
}

impl<'a> Decode<'a> for AutoDetectResponse<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header = BasicSecurityHeader::decode(r)?;
        if !header.has(security_flags::AUTODETECT_RSP) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_AUTODETECT_RSP)",
                value: u64::from(header.flags),
                offset: at,
            });
        }
        Ok(Self {
            pdu: AutoDetectPdu::read(r)?,
        })
    }
}

/// The Heartbeat PDU (MS-RDPBCGR 2.2.16.1), four bytes, server to client.
///
/// Behind a basic security header with `SEC_HEARTBEAT`, and only when
/// `RNS_UD_CS_SUPPORT_HEARTBEAT_PDU` was set in `TS_UD_CS_CORE`. R16 declines
/// to make this an RTT source; PRDRDP/06's liveness topic consumes it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeartbeatPdu {
    /// `period`, seconds between heartbeats.
    pub period: u8,
    /// `count1`, missed heartbeats before a warning.
    pub warning_count: u8,
    /// `count2`, missed heartbeats before a disconnect.
    pub reconnect_count: u8,
}

impl HeartbeatPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "HEARTBEAT_PDU";
}

impl Encode for HeartbeatPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        // `reserved`.
        w.u8(0);
        w.u8(self.period);
        w.u8(self.warning_count);
        w.u8(self.reconnect_count);
        Ok(())
    }
}

impl Decode<'_> for HeartbeatPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        r.skip(1, Self::NAME)?;
        Ok(Self {
            period: r.u8(Self::NAME)?,
            warning_count: r.u8(Self::NAME)?,
            reconnect_count: r.u8(Self::NAME)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::super::client_info::ArcServerPrivatePacket;
    use super::*;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    /// Four bytes, and the round trip that keeps a code we do not know.
    #[test]
    fn set_error_info_round_trips_known_and_unknown_codes() {
        let pdu = SetErrorInfoPdu {
            error_info: ErrInfo::LogoffByUser,
        };
        assert_eq!(encode(&pdu), [0x0c, 0x00, 0x00, 0x00]);
        assert_eq!(
            SetErrorInfoPdu::decode(&mut Reader::new(&encode(&pdu))).unwrap(),
            pdu
        );

        let unknown = SetErrorInfoPdu {
            error_info: ErrInfo::Unknown(0x0000_5555),
        };
        let bytes = encode(&unknown);
        assert_eq!(
            SetErrorInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            unknown
        );
        assert!(ErrInfo::UnknownPduType2.is_our_protocol_error());
    }

    /// All three shapes PRDRDP/13 §4.10.1 says a Deactivate All arrives in.
    #[test]
    fn a_deactivate_all_decodes_in_every_shape_servers_send() {
        let full = DeactivateAllPdu {
            share_id: 0x0010_3ea9,
            source_descriptor: b"RDP\0".to_vec(),
        };
        let bytes = encode(&full);
        assert_eq!(
            DeactivateAllPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            full
        );

        let one_byte = DeactivateAllPdu {
            share_id: 0x0010_3ea9,
            source_descriptor: vec![0],
        };
        let bytes = encode(&one_byte);
        assert_eq!(bytes.len(), 7);
        assert_eq!(
            DeactivateAllPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            one_byte
        );

        let empty = DeactivateAllPdu {
            share_id: 0x0010_3ea9,
            source_descriptor: Vec::new(),
        };
        let bytes = encode(&empty);
        assert_eq!(
            DeactivateAllPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            empty
        );

        // And the short form with nothing in it at all.
        assert_eq!(
            DeactivateAllPdu::decode(&mut Reader::new(&[])).unwrap(),
            DeactivateAllPdu::default()
        );
    }

    #[test]
    fn a_shutdown_pdu_has_no_body() {
        let pdu = EmptyPdu;
        assert_eq!(encode(&pdu), &[] as &[u8]);
        assert_eq!(EmptyPdu::decode(&mut Reader::new(&[])).unwrap(), pdu);
    }

    #[test]
    fn a_refresh_rect_round_trips() {
        let pdu = RefreshRectPdu {
            areas: vec![
                Rectangle16 {
                    left: 0,
                    top: 0,
                    right: 1023,
                    bottom: 767,
                },
                Rectangle16 {
                    left: 100,
                    top: 100,
                    right: 200,
                    bottom: 200,
                },
            ],
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 4 + 16);
        assert_eq!(bytes[0], 2);
        assert_eq!(
            RefreshRectPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// The asymmetry that stops a server sending anything until reconnect: no
    /// rectangle in the suppress direction.
    #[test]
    fn suppress_output_carries_a_rectangle_only_when_it_allows_updates() {
        let suppress = SuppressOutputPdu::suppress();
        assert_eq!(encode(&suppress), [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            SuppressOutputPdu::decode(&mut Reader::new(&encode(&suppress))).unwrap(),
            suppress
        );

        let allow = SuppressOutputPdu::allow(Rectangle16 {
            left: 0,
            top: 0,
            right: 1919,
            bottom: 1079,
        });
        let bytes = encode(&allow);
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[0], SuppressOutputPdu::ALLOW_DISPLAY_UPDATES);
        assert_eq!(
            SuppressOutputPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            allow
        );
    }

    #[test]
    fn a_monitor_layout_round_trips_and_keeps_negative_coordinates() {
        let pdu = MonitorLayoutPdu {
            monitors: vec![
                MonitorDef {
                    left: 0,
                    top: 0,
                    right: 1919,
                    bottom: 1079,
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
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 4 + 40);
        assert_eq!(
            MonitorLayoutPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    #[test]
    fn more_monitors_than_the_cap_allows_names_the_cap() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&99_u32.to_le_bytes());
        let err = MonitorLayoutPdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_MONITORS",
                ..
            }
        ));
    }

    #[test]
    fn a_logon_info_round_trips_and_bounds_its_fixed_fields() {
        let pdu = SaveSessionInfoPdu::Logon(LogonInfo {
            domain: "CONTOSO".to_owned(),
            user_name: "elton".to_owned(),
            session_id: 3,
        });
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 4 + LogonInfo::size());
        let back = SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back, pdu);
        assert_eq!(back.logon_identity(), Some(("CONTOSO", "elton")));

        // A `cbDomain` above the fixed field's width is refused rather than
        // read past.
        let mut broken = bytes.clone();
        broken[4] = 0xff;
        let err = SaveSessionInfoPdu::decode(&mut Reader::new(&broken)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "cbDomain",
                ..
            }
        ));
    }

    /// Version 2 puts its strings after the 558 byte pad, the opposite of
    /// version 1. Getting it backwards yields a user name made of padding, so
    /// the offsets are asserted rather than only the round trip.
    #[test]
    fn logon_info_version_2_puts_its_strings_after_the_pad() {
        let pdu = SaveSessionInfoPdu::LogonLong(LogonInfoVersion2 {
            session_id: 4,
            domain: "CONTOSO".to_owned(),
            user_name: "elton".to_owned(),
        });
        let bytes = encode(&pdu);
        // infoType, then Version, Size, SessionId, cbDomain, cbUserName.
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            LogonInfoVersion2::VERSION_ONE
        );
        assert_eq!(
            u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            18
        );
        let strings_at = 4 + 18 + 558;
        assert_eq!(&bytes[strings_at..strings_at + 2], b"C\0");
        assert_eq!(
            SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    #[test]
    fn a_plain_notify_is_five_hundred_and_seventy_six_bytes_of_nothing() {
        let pdu = SaveSessionInfoPdu::PlainNotify;
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 4 + 576);
        assert_eq!(
            SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
        assert_eq!(pdu.logon_identity(), None);
    }

    #[test]
    fn extended_logon_info_carries_the_cookie_and_the_errors() {
        let pdu = SaveSessionInfoPdu::Extended(LogonInfoExtended {
            auto_reconnect_cookie: Some(ArcServerPrivatePacket {
                logon_id: 3,
                arc_random_bits: [0x5a; 16],
            }),
            logon_errors: Some(LogonErrorsInfo {
                notification_type: LogonErrorType::FailedBadPassword,
                notification_data: LogonErrorData::SessionContinue,
            }),
        });
        let bytes = encode(&pdu);
        assert_eq!(
            SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );

        // Neither field present, which is what a plain successful logon on a
        // reconnect capable server sends.
        let bare = SaveSessionInfoPdu::Extended(LogonInfoExtended::default());
        let bytes = encode(&bare);
        assert_eq!(bytes.len(), 4 + 6 + 570);
        assert_eq!(
            SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            bare
        );
    }

    /// A status code outside the named table is the common case here and not
    /// an error (PRDRDP/13 §8).
    #[test]
    fn an_unnamed_logon_error_data_is_a_windows_status_code() {
        let pdu = SaveSessionInfoPdu::Extended(LogonInfoExtended {
            auto_reconnect_cookie: None,
            logon_errors: Some(LogonErrorsInfo {
                notification_type: LogonErrorType::FailedOther,
                notification_data: LogonErrorData::Unknown(0xc000_006d),
            }),
        });
        let bytes = encode(&pdu);
        assert_eq!(
            SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    #[test]
    fn an_unknown_save_session_info_type_is_preserved() {
        let bytes = [0x09, 0x00, 0x00, 0x00, 0xde, 0xad];
        let pdu = SaveSessionInfoPdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            pdu,
            SaveSessionInfoPdu::Unknown {
                info_type: 9,
                body: vec![0xde, 0xad],
            }
        );
        assert_eq!(encode(&pdu), bytes);
    }

    /// The pair PRDRDP/13 §4.10.5 asks for: the same measurement in two
    /// phases classifies the same way, so the session answers identically.
    #[test]
    fn an_rtt_request_classifies_the_same_in_both_phases() {
        let connect = [0x06, 0x00, 0x01, 0x00, 0x01, 0x00];
        let continuous = [0x06, 0x00, 0x01, 0x00, 0x01, 0x10];
        let a = AutoDetectPdu::read(&mut Reader::new(&connect)).unwrap();
        let b = AutoDetectPdu::read(&mut Reader::new(&continuous)).unwrap();
        assert_eq!(
            a.classify(),
            (AutoDetectKind::RttMeasure, AutoDetectPhase::ConnectTime)
        );
        assert_eq!(
            b.classify(),
            (AutoDetectKind::RttMeasure, AutoDetectPhase::Continuous)
        );
        assert_eq!(a.sequence_number, 1);
        assert_eq!(encode(&a), connect);

        let response = AutoDetectPdu::rtt_response(a.sequence_number);
        assert_eq!(encode(&response), [0x06, 0x01, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            AutoDetectPdu::read(&mut Reader::new(&encode(&response)))
                .unwrap()
                .classify(),
            (AutoDetectKind::RttMeasure, AutoDetectPhase::ConnectTime)
        );
    }

    /// The whole of the client's side of MS-RDPBCGR 2.2.14.2, header
    /// included.
    ///
    /// The RTT Measure Response is hand computed. `SEC_AUTODETECT_RSP` is
    /// 0x2000, so `flags` is `00 20` and `flagsHi` is `00 00`. Then
    /// `headerLength` 0x06, `headerTypeId` 0x01
    /// (`TYPE_ID_AUTODETECT_RESPONSE`), `sequenceNumber` 0x0001 as `01 00`,
    /// `responseType` 0x0000 as `00 00`. Four plus six is ten bytes.
    #[test]
    fn an_auto_detect_response_carries_its_own_security_header() {
        let response = AutoDetectResponse::rtt(1);
        let bytes = encode(&response);
        assert_eq!(
            bytes,
            [0x00, 0x20, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(bytes.len(), 4 + 6);
        assert_eq!(
            AutoDetectResponse::decode(&mut Reader::new(&bytes)).unwrap(),
            response
        );
        assert_eq!(
            response.pdu.classify(),
            (AutoDetectKind::RttMeasure, AutoDetectPhase::ConnectTime)
        );
    }

    #[test]
    fn every_measured_response_round_trips_through_its_header() {
        for response in [
            AutoDetectResponse::rtt(7),
            AutoDetectResponse::bandwidth_results(8, 40, 1_048_576),
            AutoDetectResponse::network_characteristics_sync(9, 100_000, 14),
        ] {
            let bytes = encode(&response);
            assert_eq!(
                AutoDetectResponse::decode(&mut Reader::new(&bytes)).unwrap(),
                response
            );
            for cut in 0..bytes.len() {
                assert!(
                    AutoDetectResponse::decode(&mut Reader::new(&bytes[..cut])).is_err(),
                    "a {cut} byte prefix decoded"
                );
            }
        }
    }

    /// A response the server would ignore is refused at the encoder, where
    /// the mistake is visible, rather than at the timeout twenty seconds
    /// later.
    #[test]
    fn a_response_with_a_requests_type_id_is_refused() {
        let mut wrong = AutoDetectResponse::rtt(1);
        wrong.pdu.header_type_id = autodetect::TYPE_ID_REQUEST;
        let mut buf = Vec::new();
        assert!(matches!(
            wrong.encode(&mut Writer::new(&mut buf)).unwrap_err(),
            PduError::Encode { .. }
        ));

        // And one without the flag is refused at the decoder.
        let mut bytes = encode(&AutoDetectResponse::rtt(1));
        bytes[1] = 0x10;
        assert!(matches!(
            AutoDetectResponse::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "flags (SEC_AUTODETECT_RSP)",
                ..
            }
        ));
    }

    #[test]
    fn the_measurement_bodies_round_trip() {
        let cases = [
            AutoDetectPdu {
                header_type_id: autodetect::TYPE_ID_RESPONSE,
                sequence_number: 2,
                request_type: autodetect::BANDWIDTH_RESULTS,
                body: AutoDetectBody::Results {
                    time_delta: 40,
                    byte_count: 1_048_576,
                },
            },
            AutoDetectPdu {
                header_type_id: autodetect::TYPE_ID_REQUEST,
                sequence_number: 3,
                request_type: autodetect::NETCHAR_RESULT_ALL,
                body: AutoDetectBody::NetworkCharacteristics {
                    base_rtt: Some(12),
                    bandwidth: Some(100_000),
                    average_rtt: Some(14),
                },
            },
            AutoDetectPdu {
                header_type_id: autodetect::TYPE_ID_RESPONSE,
                sequence_number: 4,
                request_type: autodetect::NETCHAR_SYNC,
                body: AutoDetectBody::Sync {
                    bandwidth: 100_000,
                    rtt: 14,
                },
            },
        ];
        for case in cases {
            let bytes = encode(&case);
            assert_eq!(usize::from(bytes[0]), bytes.len(), "headerLength");
            assert_eq!(AutoDetectPdu::read(&mut Reader::new(&bytes)).unwrap(), case);
        }
    }

    /// The three Network Characteristics Result forms carry one, two or three
    /// words, and which is which comes from `requestType` alone.
    #[test]
    fn the_network_characteristics_forms_carry_the_fields_their_code_names() {
        let base_average = [0x0e, 0x00, 0x01, 0x00, 0x40, 0x08, 12, 0, 0, 0, 14, 0, 0, 0];
        let pdu = AutoDetectPdu::read(&mut Reader::new(&base_average)).unwrap();
        assert_eq!(
            pdu.body,
            AutoDetectBody::NetworkCharacteristics {
                base_rtt: Some(12),
                bandwidth: None,
                average_rtt: Some(14),
            }
        );
        assert_eq!(encode(&pdu), base_average);

        let bandwidth_average = [
            0x0e, 0x00, 0x01, 0x00, 0x80, 0x08, 0x40, 0x0d, 3, 0, 14, 0, 0, 0,
        ];
        let pdu = AutoDetectPdu::read(&mut Reader::new(&bandwidth_average)).unwrap();
        assert_eq!(
            pdu.body,
            AutoDetectBody::NetworkCharacteristics {
                base_rtt: None,
                bandwidth: Some(0x0003_0d40),
                average_rtt: Some(14),
            }
        );
        assert_eq!(encode(&pdu), bandwidth_average);
    }

    #[test]
    fn a_bandwidth_payload_keeps_its_filler() {
        let mut bytes = vec![0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x04, 0x00];
        bytes.extend_from_slice(&[0xaa; 4]);
        bytes[0] = bytes.len() as u8;
        let pdu = AutoDetectPdu::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(pdu.body, AutoDetectBody::Payload(Payload::new(&[0xaa; 4])));
        assert_eq!(encode(&pdu), bytes);
    }

    #[test]
    fn a_header_length_below_the_header_is_refused() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0x01, 0x00];
        let err = AutoDetectPdu::read(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "headerLength",
                ..
            }
        ));
    }

    #[test]
    fn a_heartbeat_is_four_bytes() {
        let pdu = HeartbeatPdu {
            period: 30,
            warning_count: 3,
            reconnect_count: 5,
        };
        assert_eq!(encode(&pdu), [0x00, 30, 3, 5]);
        assert_eq!(
            HeartbeatPdu::decode(&mut Reader::new(&encode(&pdu))).unwrap(),
            pdu
        );
    }

    /// PRDRDP/13 §9.3 over every PDU in this module that has a fixed shape.
    #[test]
    fn every_prefix_errors_rather_than_panicking() {
        let logon = encode(&SaveSessionInfoPdu::Logon(LogonInfo {
            domain: "CONTOSO".to_owned(),
            user_name: "elton".to_owned(),
            session_id: 3,
        }));
        for cut in 0..logon.len() {
            assert!(
                SaveSessionInfoPdu::decode(&mut Reader::new(&logon[..cut])).is_err(),
                "a {cut} byte prefix of a Save Session Info decoded"
            );
        }

        let long = encode(&SaveSessionInfoPdu::LogonLong(LogonInfoVersion2 {
            session_id: 4,
            domain: "CONTOSO".to_owned(),
            user_name: "elton".to_owned(),
        }));
        for cut in 0..long.len() {
            assert!(SaveSessionInfoPdu::decode(&mut Reader::new(&long[..cut])).is_err());
        }

        let detect = encode(&AutoDetectPdu {
            header_type_id: autodetect::TYPE_ID_RESPONSE,
            sequence_number: 2,
            request_type: autodetect::BANDWIDTH_RESULTS,
            body: AutoDetectBody::Results {
                time_delta: 40,
                byte_count: 1024,
            },
        });
        for cut in 0..detect.len() {
            assert!(AutoDetectPdu::read(&mut Reader::new(&detect[..cut])).is_err());
        }

        let heartbeat = encode(&HeartbeatPdu::default());
        for cut in 0..heartbeat.len() {
            assert!(HeartbeatPdu::decode(&mut Reader::new(&heartbeat[..cut])).is_err());
        }

        let monitors = encode(&MonitorLayoutPdu {
            monitors: vec![MonitorDef::default()],
        });
        for cut in 0..monitors.len() {
            assert!(MonitorLayoutPdu::decode(&mut Reader::new(&monitors[..cut])).is_err());
        }
    }
}
