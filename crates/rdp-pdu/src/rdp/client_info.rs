//! The Client Info PDU and its extended info packet (MS-RDPBCGR 2.2.1.11,
//! PRDRDP/13 §4.6).
//!
//! One PDU, sent once, carrying the logon information: a basic security
//! header with `SEC_INFO_PKT`, then `TS_INFO_PACKET`, then
//! `TS_EXTENDED_INFO_PACKET`. Under NLA the credentials here are redundant
//! with the ones CredSSP already carried, and they are still sent, because
//! Windows uses them for single sign on into the session (PRDRDP/03 §2.7).
//!
//! # The length rule that breaks logons
//!
//! The five `cb*` fields of `TS_INFO_PACKET` count the string **without** its
//! terminator, and the terminator is on the wire anyway. The two `cb*` fields
//! of `TS_EXTENDED_INFO_PACKET` count the string **with** its terminator.
//! That is not a typo: it is the specification, and getting either backwards
//! produces a user name with a trailing NUL or a truncated password, which
//! the server reports as a logon failure that looks exactly like a wrong
//! password. Both rules have their own test below, including the zero length
//! domain, which is the case where "just use the string length" also happens
//! to work and hides the bug.
//!
//! # What this module will not do
//!
//! It will encode a Client Info PDU with an empty password. Deciding what to
//! send is the session's job (PRDRDP/13 §1.2). The password is held in
//! [`SecretString`], which zeroizes on drop and redacts itself in `Debug`, so
//! a `tracing` line that formats a PDU cannot print it.

use core::fmt;

use zeroize::Zeroize;

use super::security::{security_flags, BasicSecurityHeader};
use crate::io::limits::MAX_STRING_UTF16;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `TS_INFO_PACKET.flags` (MS-RDPBCGR 2.2.1.11.1.1).
pub mod info_flags {
    /// `INFO_MOUSE`.
    pub const MOUSE: u32 = 0x0000_0001;
    /// `INFO_DISABLECTRLALTDEL`.
    pub const DISABLECTRLALTDEL: u32 = 0x0000_0002;
    /// `INFO_AUTOLOGON`, set when a full credential is supplied. This is what
    /// makes the session land on the desktop rather than on a "press
    /// Ctrl+Alt+Del" screen (PRDRDP/03 §2.7).
    pub const AUTOLOGON: u32 = 0x0000_0008;
    /// `INFO_UNICODE`, always set, which makes the five strings UTF-16LE and
    /// `CodePage` zero.
    pub const UNICODE: u32 = 0x0000_0010;
    /// `INFO_MAXIMIZESHELL`.
    pub const MAXIMIZESHELL: u32 = 0x0000_0020;
    /// `INFO_LOGONNOTIFY`, which asks for the Save Session Info PDU.
    pub const LOGONNOTIFY: u32 = 0x0000_0040;
    /// `INFO_COMPRESSION`, phase 2, with a type in
    /// [`COMPRESSION_TYPE_MASK`](super::COMPRESSION_TYPE_MASK).
    pub const COMPRESSION: u32 = 0x0000_0080;
    /// `INFO_ENABLEWINDOWSKEY`.
    pub const ENABLEWINDOWSKEY: u32 = 0x0000_0100;
    /// `INFO_REMOTECONSOLEAUDIO`.
    pub const REMOTECONSOLEAUDIO: u32 = 0x0000_2000;
    /// `INFO_FORCE_ENCRYPTED_CS_PDU`, standard security only, so clear.
    pub const FORCE_ENCRYPTED_CS_PDU: u32 = 0x0000_4000;
    /// `INFO_RAIL`, RemoteApp, which is not planned.
    pub const RAIL: u32 = 0x0000_8000;
    /// `INFO_LOGONERRORS`, which asks for logon error notices.
    pub const LOGONERRORS: u32 = 0x0001_0000;
    /// `INFO_MOUSE_HAS_WHEEL`.
    pub const MOUSE_HAS_WHEEL: u32 = 0x0002_0000;
    /// `INFO_PASSWORD_IS_SC_PIN`.
    pub const PASSWORD_IS_SC_PIN: u32 = 0x0004_0000;
    /// `INFO_NOAUDIOPLAYBACK`, set in phase 1 and cleared in phase 2.
    pub const NOAUDIOPLAYBACK: u32 = 0x0008_0000;
    /// `INFO_USING_SAVED_CREDS`, set on a redirection reconnect.
    pub const USING_SAVED_CREDS: u32 = 0x0010_0000;
    /// `INFO_AUDIOCAPTURE`.
    pub const AUDIOCAPTURE: u32 = 0x0020_0000;
    /// `INFO_VIDEO_DISABLE`.
    pub const VIDEO_DISABLE: u32 = 0x0040_0000;
    /// `INFO_HIDEF_RAIL_SUPPORTED`.
    pub const HIDEF_RAIL_SUPPORTED: u32 = 0x0200_0000;
}

/// `CompressionTypeMask`, bits 9 to 12 of `TS_INFO_PACKET.flags`
/// (MS-RDPBCGR 2.2.1.11.1.1).
pub const COMPRESSION_TYPE_MASK: u32 = 0x0000_1e00;

/// How far left a [`CompressionType`](crate::codes::CompressionType) is
/// shifted to sit in [`COMPRESSION_TYPE_MASK`].
pub const COMPRESSION_TYPE_SHIFT: u32 = 9;

/// `TS_EXTENDED_INFO_PACKET.performanceFlags` (MS-RDPBCGR 2.2.1.11.1.1.1).
///
/// PRDRDP/04's quality preset mapping chooses the value, and R21 records that
/// these can change while a session is running, which is why the encoder
/// takes them as a field rather than baking a default.
pub mod performance_flags {
    /// `PERF_DISABLE_WALLPAPER`.
    pub const DISABLE_WALLPAPER: u32 = 0x0000_0001;
    /// `PERF_DISABLE_FULLWINDOWDRAG`.
    pub const DISABLE_FULLWINDOWDRAG: u32 = 0x0000_0002;
    /// `PERF_DISABLE_MENUANIMATIONS`.
    pub const DISABLE_MENUANIMATIONS: u32 = 0x0000_0004;
    /// `PERF_DISABLE_THEMING`.
    pub const DISABLE_THEMING: u32 = 0x0000_0008;
    /// `PERF_DISABLE_CURSOR_SHADOW`.
    pub const DISABLE_CURSOR_SHADOW: u32 = 0x0000_0020;
    /// `PERF_DISABLE_CURSORSETTINGS`.
    pub const DISABLE_CURSORSETTINGS: u32 = 0x0000_0040;
    /// `PERF_ENABLE_FONT_SMOOTHING`.
    pub const ENABLE_FONT_SMOOTHING: u32 = 0x0000_0080;
    /// `PERF_ENABLE_DESKTOP_COMPOSITION`. The Desktop Composition capability
    /// set must agree with this bit or the desktop can come back black
    /// (PRDRDP/13 §4.8.3).
    pub const ENABLE_DESKTOP_COMPOSITION: u32 = 0x0000_0100;
}

/// `TS_EXTENDED_INFO_PACKET.clientAddressFamily` (MS-RDPBCGR 2.2.1.11.1.1.1).
pub mod address_family {
    /// `AF_INET`.
    pub const INET: u16 = 0x0002;
    /// `AF_INET6`.
    pub const INET6: u16 = 0x0017;
}

/// `TS_TIME_ZONE_INFORMATION` is exactly this long (MS-RDPBCGR
/// 2.2.1.11.1.1.1.1).
pub const TIME_ZONE_INFORMATION_LEN: usize = 172;

/// `TS_SYSTEMTIME`, eight `u16` (MS-RDPBCGR 2.2.1.11.1.1.1.1.1).
pub const SYSTEMTIME_LEN: usize = 16;

/// The fixed width of `StandardName` and `DaylightName`, in bytes.
const TIME_ZONE_NAME_LEN: usize = 64;

/// `ARC_CS_PRIVATE_PACKET` and `ARC_SC_PRIVATE_PACKET` are both this long
/// (MS-RDPBCGR 2.2.4.2, 2.2.4.3).
pub const ARC_PACKET_LEN: usize = 28;

/// The only `Version` either auto reconnect packet carries
/// (MS-RDPBCGR 2.2.4.2).
pub const ARC_VERSION_1: u32 = 0x0000_0001;

/// A string that must not reach a log line and must not linger in memory.
///
/// The password field of `TS_INFO_PACKET` is the one place this crate holds a
/// credential. `Debug` prints a fixed string, and the buffer is zeroized on
/// drop, which is why `zeroize` is a dependency of a crate that does no
/// cryptography (PRDRDP/12 §6.4).
///
/// This is not a security boundary on its own: the string was built by the
/// session from a credential it already holds, and a `String` may have been
/// reallocated before it got here. What it does is stop the two mistakes that
/// actually happen, a `Debug` format of a PDU and a password sitting in freed
/// memory for the life of the process.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The string itself, for the encoder and for nothing else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// True for the empty password, which this crate encodes without
    /// complaint (PRDRDP/13 §1.2).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(redacted)")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// `TS_SYSTEMTIME` (MS-RDPBCGR 2.2.1.11.1.1.1.1.1).
///
/// A recurring rule rather than a date: `year` is zero, `day` is 1 to 5 where
/// 5 means "the last such weekday of the month".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemTime {
    /// `wYear`, zero for a recurring rule.
    pub year: u16,
    /// `wMonth`, 1 to 12, or 0 for "no transition".
    pub month: u16,
    /// `wDayOfWeek`, 0 for Sunday.
    pub day_of_week: u16,
    /// `wDay`, 1 to 5 where 5 means last.
    pub day: u16,
    /// `wHour`.
    pub hour: u16,
    /// `wMinute`.
    pub minute: u16,
    /// `wSecond`.
    pub second: u16,
    /// `wMilliseconds`.
    pub milliseconds: u16,
}

impl SystemTime {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SYSTEMTIME";
}

impl Encode for SystemTime {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        SYSTEMTIME_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.year);
        w.u16(self.month);
        w.u16(self.day_of_week);
        w.u16(self.day);
        w.u16(self.hour);
        w.u16(self.minute);
        w.u16(self.second);
        w.u16(self.milliseconds);
        Ok(())
    }
}

impl Decode<'_> for SystemTime {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            year: r.u16(Self::NAME)?,
            month: r.u16(Self::NAME)?,
            day_of_week: r.u16(Self::NAME)?,
            day: r.u16(Self::NAME)?,
            hour: r.u16(Self::NAME)?,
            minute: r.u16(Self::NAME)?,
            second: r.u16(Self::NAME)?,
            milliseconds: r.u16(Self::NAME)?,
        })
    }
}

/// `TS_TIME_ZONE_INFORMATION` (MS-RDPBCGR 2.2.1.11.1.1.1.1), 172 bytes.
///
/// The three bias fields are documented as unsigned and are signed: a zone
/// east of UTC has a negative `Bias`, and reading them unsigned puts a client
/// in Berlin eleven hundred minutes from where it is. PRDRDP/11 §5.3 carries
/// that erratum as an unnumbered note, and [`Reader::i32`] exists for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeZoneInfo {
    /// `Bias`, minutes to add to local time to get UTC.
    pub bias: i32,
    /// `StandardName`, at most 31 characters and a terminator.
    pub standard_name: String,
    /// `StandardDate`, when standard time resumes.
    pub standard_date: SystemTime,
    /// `StandardBias`, added to `Bias` during standard time.
    pub standard_bias: i32,
    /// `DaylightName`.
    pub daylight_name: String,
    /// `DaylightDate`, when daylight saving starts.
    pub daylight_date: SystemTime,
    /// `DaylightBias`, added to `Bias` during daylight saving, and usually
    /// minus sixty.
    pub daylight_bias: i32,
}

impl TimeZoneInfo {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_TIME_ZONE_INFORMATION";
}

impl Encode for TimeZoneInfo {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        TIME_ZONE_INFORMATION_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.i32(self.bias);
        w.utf16_fixed(&self.standard_name, TIME_ZONE_NAME_LEN, Self::NAME)?;
        self.standard_date.encode(w)?;
        w.i32(self.standard_bias);
        w.utf16_fixed(&self.daylight_name, TIME_ZONE_NAME_LEN, Self::NAME)?;
        self.daylight_date.encode(w)?;
        w.i32(self.daylight_bias);
        Ok(())
    }
}

impl Decode<'_> for TimeZoneInfo {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            bias: r.i32(Self::NAME)?,
            standard_name: r.utf16_fixed(TIME_ZONE_NAME_LEN, Self::NAME)?,
            standard_date: SystemTime::decode(r)?,
            standard_bias: r.i32(Self::NAME)?,
            daylight_name: r.utf16_fixed(TIME_ZONE_NAME_LEN, Self::NAME)?,
            daylight_date: SystemTime::decode(r)?,
            daylight_bias: r.i32(Self::NAME)?,
        })
    }
}

/// `ARC_CS_PRIVATE_PACKET` (MS-RDPBCGR 2.2.4.3), the client's half of the
/// auto reconnect cookie.
///
/// `security_verifier` is the HMAC-MD5 of the server's `ArcRandomBits` under a
/// key derived per MS-RDPBCGR 5.5. The HMAC is computed in `rdp-core`, which
/// has the stored cookie and a crypto primitive; this crate carries the
/// twenty eight bytes and derives nothing (PRDRDP/00 R54).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArcClientPrivatePacket {
    /// `LogonId`, the session the cookie belongs to.
    pub logon_id: u32,
    /// `SecurityVerifier`.
    pub security_verifier: [u8; 16],
}

impl ArcClientPrivatePacket {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "ARC_CS_PRIVATE_PACKET";
}

impl Encode for ArcClientPrivatePacket {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        ARC_PACKET_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(ARC_PACKET_LEN as u32);
        w.u32(ARC_VERSION_1);
        w.u32(self.logon_id);
        w.bytes(&self.security_verifier);
        Ok(())
    }
}

impl Decode<'_> for ArcClientPrivatePacket {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let cb_len = r.u32(Self::NAME)?;
        if cb_len as usize != ARC_PACKET_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "cbLen",
                value: u64::from(cb_len),
                offset: at,
            });
        }
        // `Version`, which is always 1 and which we do not reject: a newer
        // packet of the same length is still twenty eight bytes we can carry.
        r.skip(4, Self::NAME)?;
        Ok(Self {
            logon_id: r.u32(Self::NAME)?,
            security_verifier: r.array::<16>(Self::NAME)?,
        })
    }
}

/// `ARC_SC_PRIVATE_PACKET` (MS-RDPBCGR 2.2.4.2), the server's half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArcServerPrivatePacket {
    /// `LogonId`.
    pub logon_id: u32,
    /// `ArcRandomBits`, the sixteen bytes the client's verifier is computed
    /// over.
    pub arc_random_bits: [u8; 16],
}

impl ArcServerPrivatePacket {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "ARC_SC_PRIVATE_PACKET";
}

impl Encode for ArcServerPrivatePacket {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        ARC_PACKET_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(ARC_PACKET_LEN as u32);
        w.u32(ARC_VERSION_1);
        w.u32(self.logon_id);
        w.bytes(&self.arc_random_bits);
        Ok(())
    }
}

impl Decode<'_> for ArcServerPrivatePacket {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let cb_len = r.u32(Self::NAME)?;
        if cb_len as usize != ARC_PACKET_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "cbLen",
                value: u64::from(cb_len),
                offset: at,
            });
        }
        r.skip(4, Self::NAME)?;
        Ok(Self {
            logon_id: r.u32(Self::NAME)?,
            arc_random_bits: r.array::<16>(Self::NAME)?,
        })
    }
}

/// The bytes one string of `TS_INFO_PACKET` occupies, terminator excluded,
/// which is what its `cb*` field counts.
fn string_len(s: &str, unicode: bool) -> usize {
    if unicode {
        s.encode_utf16().count() * 2
    } else {
        s.len()
    }
}

/// The terminator's own width.
const fn terminator_len(unicode: bool) -> usize {
    if unicode {
        2
    } else {
        1
    }
}

/// Write one string and its terminator, returning what its `cb*` field must
/// hold.
fn write_string(
    w: &mut Writer<'_>,
    s: &str,
    unicode: bool,
    context: &'static str,
) -> PduResult<()> {
    if unicode {
        w.utf16(s);
        return Ok(());
    }
    if !s.is_ascii() {
        return Err(PduError::Encode {
            context,
            reason: "an ANSI info field is not ASCII; set INFO_UNICODE",
        });
    }
    w.bytes(s.as_bytes());
    w.u8(0);
    Ok(())
}

/// Read one string whose `cb*` field excluded its terminator.
fn read_string(
    r: &mut Reader<'_>,
    cb: usize,
    unicode: bool,
    context: &'static str,
) -> PduResult<String> {
    r.ensure_cap(cb, MAX_STRING_UTF16, "MAX_STRING_UTF16", context)?;
    let total = cb + terminator_len(unicode);
    if unicode {
        r.utf16_len(total, context)
    } else {
        r.ansi_fixed(total, context)
    }
}

/// `TS_EXTENDED_INFO_PACKET` (MS-RDPBCGR 2.2.1.11.1.1.1).
///
/// Extensible tail per PRDRDP/13 §2.5: every field from
/// `cbAutoReconnectCookie` onward arrived in a later revision, and a server
/// reading ours stops when it runs out. So the decoder reads an optional
/// field only when the whole of it is there, and never calls `expect_empty`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtendedInfoPacket {
    /// `clientAddressFamily`, one of [`address_family`].
    pub client_address_family: u16,
    /// `clientAddress`, our local address as text.
    pub client_address: String,
    /// `clientDir`, conventionally `C:\Windows\System32\mstscax.dll`.
    pub client_dir: String,
    /// `clientTimeZone`.
    pub client_time_zone: TimeZoneInfo,
    /// `clientSessionId`, zero.
    pub client_session_id: u32,
    /// `performanceFlags`, from [`performance_flags`].
    pub performance_flags: u32,
    /// `autoReconnectCookie`, present on a reconnect (phase 2, D7).
    pub auto_reconnect_cookie: Option<ArcClientPrivatePacket>,
    /// `dynamicDSTTimeZoneKeyName`, the Windows registry key name for the
    /// zone. Absent when we did not send the tail at all.
    pub dynamic_dst_time_zone_key_name: Option<String>,
    /// `dynamicDaylightTimeDisabled`.
    pub dynamic_daylight_time_disabled: Option<u16>,
}

impl ExtendedInfoPacket {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_EXTENDED_INFO_PACKET";

    /// The two `cb*` fields here **include** the terminator, unlike the five
    /// in `TS_INFO_PACKET`. Both strings are UTF-16LE whatever `INFO_UNICODE`
    /// says.
    fn address_len(s: &str) -> usize {
        s.encode_utf16().count() * 2 + 2
    }
}

impl Encode for ExtendedInfoPacket {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let mut size = 2
            + 2
            + Self::address_len(&self.client_address)
            + 2
            + Self::address_len(&self.client_dir)
            + TIME_ZONE_INFORMATION_LEN
            + 4
            + 4;
        if self.auto_reconnect_cookie.is_none()
            && self.dynamic_dst_time_zone_key_name.is_none()
            && self.dynamic_daylight_time_disabled.is_none()
        {
            return size;
        }
        // `cbAutoReconnectCookie` and the cookie itself.
        size += 2 + self.auto_reconnect_cookie.map_or(0, |_| ARC_PACKET_LEN);
        let Some(key_name) = self.dynamic_dst_time_zone_key_name.as_deref() else {
            return size;
        };
        // `reserved1`, `reserved2`, `cbDynamicDSTTimeZoneKeyName`, the name.
        size += 2 + 2 + 2 + key_name.encode_utf16().count() * 2;
        if self.dynamic_daylight_time_disabled.is_some() {
            size += 2;
        }
        size
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.client_address_family);
        w.u16(
            u16::try_from(Self::address_len(&self.client_address)).map_err(|_| {
                PduError::Encode {
                    context: Self::NAME,
                    reason: "clientAddress longer than its cbClientAddress field",
                }
            })?,
        );
        w.utf16(&self.client_address);
        w.u16(
            u16::try_from(Self::address_len(&self.client_dir)).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "clientDir longer than its cbClientDir field",
            })?,
        );
        w.utf16(&self.client_dir);
        self.client_time_zone.encode(w)?;
        w.u32(self.client_session_id);
        w.u32(self.performance_flags);

        if self.auto_reconnect_cookie.is_none()
            && self.dynamic_dst_time_zone_key_name.is_none()
            && self.dynamic_daylight_time_disabled.is_none()
        {
            return Ok(());
        }
        match self.auto_reconnect_cookie {
            Some(cookie) => {
                w.u16(ARC_PACKET_LEN as u16);
                cookie.encode(w)?;
            }
            None => w.u16(0),
        }
        let Some(key_name) = self.dynamic_dst_time_zone_key_name.as_deref() else {
            return Ok(());
        };
        // `reserved1` and `reserved2`.
        w.u16(0);
        w.u16(0);
        // This one counts the name without a terminator, and no terminator is
        // written: the field is the last variable one and its length is
        // exact (MS-RDPBCGR 2.2.1.11.1.1.1).
        let name_len = key_name.encode_utf16().count() * 2;
        w.u16(u16::try_from(name_len).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "dynamicDSTTimeZoneKeyName longer than its length field",
        })?);
        for unit in key_name.encode_utf16() {
            w.u16(unit);
        }
        if let Some(disabled) = self.dynamic_daylight_time_disabled {
            w.u16(disabled);
        }
        Ok(())
    }
}

impl Decode<'_> for ExtendedInfoPacket {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let client_address_family = r.u16(Self::NAME)?;
        let cb_client_address = usize::from(r.u16(Self::NAME)?);
        r.ensure_cap(
            cb_client_address,
            MAX_STRING_UTF16,
            "MAX_STRING_UTF16",
            Self::NAME,
        )?;
        let client_address = r.utf16_len(cb_client_address, Self::NAME)?;
        let cb_client_dir = usize::from(r.u16(Self::NAME)?);
        r.ensure_cap(
            cb_client_dir,
            MAX_STRING_UTF16,
            "MAX_STRING_UTF16",
            Self::NAME,
        )?;
        let client_dir = r.utf16_len(cb_client_dir, Self::NAME)?;
        let client_time_zone = TimeZoneInfo::decode(r)?;
        let client_session_id = r.u32(Self::NAME)?;
        let performance_flags = r.u32(Self::NAME)?;

        let mut out = Self {
            client_address_family,
            client_address,
            client_dir,
            client_time_zone,
            client_session_id,
            performance_flags,
            auto_reconnect_cookie: None,
            dynamic_dst_time_zone_key_name: None,
            dynamic_daylight_time_disabled: None,
        };

        if r.remaining() < 2 {
            return Ok(out);
        }
        let cb_cookie = usize::from(r.u16(Self::NAME)?);
        if cb_cookie != 0 {
            if cb_cookie != ARC_PACKET_LEN {
                return Err(PduError::InvalidField {
                    context: Self::NAME,
                    field: "cbAutoReconnectCookie",
                    value: cb_cookie as u64,
                    offset: r.offset(),
                });
            }
            out.auto_reconnect_cookie = Some(ArcClientPrivatePacket::decode(r)?);
        }
        // `reserved1`, `reserved2`, then the dynamic time zone key name.
        if r.remaining() < 6 {
            return Ok(out);
        }
        r.skip(4, Self::NAME)?;
        let cb_key_name = usize::from(r.u16(Self::NAME)?);
        r.ensure_cap(
            cb_key_name,
            MAX_STRING_UTF16,
            "MAX_STRING_UTF16",
            Self::NAME,
        )?;
        out.dynamic_dst_time_zone_key_name = Some(r.utf16_len(cb_key_name, Self::NAME)?);
        if r.remaining() >= 2 {
            out.dynamic_daylight_time_disabled = Some(r.u16(Self::NAME)?);
        }
        Ok(out)
    }
}

/// `TS_INFO_PACKET` (MS-RDPBCGR 2.2.1.11.1.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InfoPacket {
    /// `CodePage`, zero whenever `INFO_UNICODE` is set, which is always.
    pub code_page: u32,
    /// `flags`, from [`info_flags`].
    pub flags: u32,
    /// `Domain`.
    pub domain: String,
    /// `UserName`.
    pub user_name: String,
    /// `Password`, redacted in `Debug` and zeroized on drop.
    pub password: SecretString,
    /// `AlternateShell`, empty for a normal desktop session.
    pub alternate_shell: String,
    /// `WorkingDir`.
    pub working_dir: String,
    /// `extraInfo`, present whenever the client version is RDP 5 or later,
    /// which is always for us.
    pub extra_info: Option<ExtendedInfoPacket>,
}

impl InfoPacket {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_INFO_PACKET";

    /// True when the five strings are UTF-16LE rather than ANSI.
    #[must_use]
    pub const fn is_unicode(&self) -> bool {
        self.flags & info_flags::UNICODE != 0
    }

    /// The flags every connection sets, whatever the credentials are
    /// (PRDRDP/03 §2.7).
    ///
    /// `INFO_AUTOLOGON` is not here: it belongs on a PDU that carries a full
    /// credential, and that is the session's decision.
    pub const DEFAULT_FLAGS: u32 = info_flags::MOUSE
        | info_flags::DISABLECTRLALTDEL
        | info_flags::UNICODE
        | info_flags::MAXIMIZESHELL
        | info_flags::LOGONNOTIFY
        | info_flags::ENABLEWINDOWSKEY
        | info_flags::LOGONERRORS
        | info_flags::MOUSE_HAS_WHEEL
        | info_flags::NOAUDIOPLAYBACK;
}

impl Encode for InfoPacket {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let unicode = self.is_unicode();
        let t = terminator_len(unicode);
        4 + 4
            + 2 * 5
            + string_len(&self.domain, unicode)
            + t
            + string_len(&self.user_name, unicode)
            + t
            + string_len(self.password.expose(), unicode)
            + t
            + string_len(&self.alternate_shell, unicode)
            + t
            + string_len(&self.working_dir, unicode)
            + t
            + self.extra_info.as_ref().map_or(0, Encode::size)
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let unicode = self.is_unicode();
        let cb = |s: &str| -> PduResult<u16> {
            u16::try_from(string_len(s, unicode)).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "an info field is longer than its cb field",
            })
        };
        w.u32(self.code_page);
        w.u32(self.flags);
        w.u16(cb(&self.domain)?);
        w.u16(cb(&self.user_name)?);
        w.u16(cb(self.password.expose())?);
        w.u16(cb(&self.alternate_shell)?);
        w.u16(cb(&self.working_dir)?);
        write_string(w, &self.domain, unicode, Self::NAME)?;
        write_string(w, &self.user_name, unicode, Self::NAME)?;
        write_string(w, self.password.expose(), unicode, Self::NAME)?;
        write_string(w, &self.alternate_shell, unicode, Self::NAME)?;
        write_string(w, &self.working_dir, unicode, Self::NAME)?;
        if let Some(extra) = &self.extra_info {
            extra.encode(w)?;
        }
        Ok(())
    }
}

impl Decode<'_> for InfoPacket {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let code_page = r.u32(Self::NAME)?;
        let flags = r.u32(Self::NAME)?;
        let unicode = flags & info_flags::UNICODE != 0;
        let cb_domain = usize::from(r.u16(Self::NAME)?);
        let cb_user_name = usize::from(r.u16(Self::NAME)?);
        let cb_password = usize::from(r.u16(Self::NAME)?);
        let cb_alternate_shell = usize::from(r.u16(Self::NAME)?);
        let cb_working_dir = usize::from(r.u16(Self::NAME)?);
        let domain = read_string(r, cb_domain, unicode, Self::NAME)?;
        let user_name = read_string(r, cb_user_name, unicode, Self::NAME)?;
        let password = SecretString::new(read_string(r, cb_password, unicode, Self::NAME)?);
        let alternate_shell = read_string(r, cb_alternate_shell, unicode, Self::NAME)?;
        let working_dir = read_string(r, cb_working_dir, unicode, Self::NAME)?;
        // Extensible: an RDP 4 client sends nothing here, and we still parse
        // what it did send (PRDRDP/13 §2.5).
        let extra_info = if r.is_empty() {
            None
        } else {
            Some(ExtendedInfoPacket::decode(r)?)
        };
        Ok(Self {
            code_page,
            flags,
            domain,
            user_name,
            password,
            alternate_shell,
            working_dir,
            extra_info,
        })
    }
}

/// The Client Info PDU: a basic security header with `SEC_INFO_PKT`, then
/// `TS_INFO_PACKET` (MS-RDPBCGR 2.2.1.11).
///
/// The header is part of this type rather than of the caller, because §5.2's
/// table says this is one of the six PDU classes that always carries one and
/// a Client Info PDU without `SEC_INFO_PKT` is not a Client Info PDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfoPdu {
    /// `TS_INFO_PACKET`.
    pub info: InfoPacket,
}

impl ClientInfoPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CLIENT_INFO_PDU";
}

impl Encode for ClientInfoPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        super::security::BASIC_SECURITY_HEADER_LEN + self.info.size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        BasicSecurityHeader::new(security_flags::INFO_PKT).encode(w)?;
        self.info.encode(w)
    }
}

impl Decode<'_> for ClientInfoPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let header = BasicSecurityHeader::decode(r)?;
        if !header.has(security_flags::INFO_PKT) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_INFO_PKT)",
                value: u64::from(header.flags),
                offset: at,
            });
        }
        Ok(Self {
            info: InfoPacket::decode(r)?,
        })
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

    fn time_zone() -> TimeZoneInfo {
        TimeZoneInfo {
            bias: 0,
            standard_name: "GMT Standard Time".to_owned(),
            standard_date: SystemTime {
                month: 10,
                day_of_week: 0,
                day: 5,
                hour: 2,
                ..SystemTime::default()
            },
            standard_bias: 0,
            daylight_name: "GMT Daylight Time".to_owned(),
            daylight_date: SystemTime {
                month: 3,
                day_of_week: 0,
                day: 5,
                hour: 1,
                ..SystemTime::default()
            },
            daylight_bias: -60,
        }
    }

    fn sample() -> ClientInfoPdu {
        ClientInfoPdu {
            info: InfoPacket {
                code_page: 0,
                flags: InfoPacket::DEFAULT_FLAGS | info_flags::AUTOLOGON,
                domain: "CONTOSO".to_owned(),
                user_name: "elton".to_owned(),
                password: SecretString::new("hunter2"),
                alternate_shell: String::new(),
                working_dir: String::new(),
                extra_info: Some(ExtendedInfoPacket {
                    client_address_family: address_family::INET,
                    client_address: "192.168.1.50".to_owned(),
                    client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
                    client_time_zone: time_zone(),
                    client_session_id: 0,
                    performance_flags: performance_flags::DISABLE_WALLPAPER
                        | performance_flags::DISABLE_FULLWINDOWDRAG,
                    auto_reconnect_cookie: None,
                    dynamic_dst_time_zone_key_name: Some("GMT Standard Time".to_owned()),
                    dynamic_daylight_time_disabled: Some(0),
                }),
            },
        }
    }

    #[test]
    fn the_client_info_pdu_round_trips() {
        let pdu = sample();
        let bytes = encode(&pdu);
        assert_eq!(
            ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// The rule that breaks logons, in the direction that matters: the length
    /// excludes the terminator and the terminator is still on the wire.
    #[test]
    fn the_info_lengths_exclude_the_terminator_the_wire_still_carries() {
        let pdu = sample();
        let bytes = encode(&pdu);
        // Four bytes of security header, then CodePage and flags.
        let cb_domain = u16::from_le_bytes([bytes[12], bytes[13]]);
        let cb_user_name = u16::from_le_bytes([bytes[14], bytes[15]]);
        let cb_password = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert_eq!(cb_domain, 14, "CONTOSO is seven UTF-16 units");
        assert_eq!(cb_user_name, 10);
        assert_eq!(cb_password, 14);
        // The domain starts at offset 22, runs for its fourteen bytes, and
        // is followed by the terminator its length did not count.
        assert_eq!(&bytes[22..24], b"C\0");
        assert_eq!(&bytes[36..38], &[0x00, 0x00], "the terminator is missing");
    }

    /// The case where "just use the string length" also works and hides the
    /// bug: a zero length domain still puts two NUL bytes on the wire.
    #[test]
    fn a_zero_length_domain_still_carries_its_terminator() {
        let mut pdu = sample();
        pdu.info.domain = String::new();
        let bytes = encode(&pdu);
        assert_eq!(u16::from_le_bytes([bytes[12], bytes[13]]), 0);
        assert_eq!(&bytes[22..24], &[0x00, 0x00]);
        let back = ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.info.domain, "");
        assert_eq!(back.info.user_name, "elton");
    }

    /// The opposite rule, one structure later, and the reason it has its own
    /// test: `cbClientAddress` includes the terminator.
    #[test]
    fn the_extended_lengths_include_the_terminator() {
        let extra = sample().info.extra_info.unwrap();
        let bytes = encode(&extra);
        let cb_client_address = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_eq!(cb_client_address, 26, "twelve characters plus a terminator");
        let address_end = 4 + usize::from(cb_client_address);
        assert_eq!(&bytes[address_end - 2..address_end], &[0x00, 0x00]);
        let cb_client_dir = u16::from_le_bytes([bytes[address_end], bytes[address_end + 1]]);
        // Thirty one characters of `C:\Windows\System32\mstscax.dll` plus a
        // terminator, counted here where the info packet's rule would not
        // have counted it.
        assert_eq!(cb_client_dir, 64);
    }

    #[test]
    fn the_time_zone_is_exactly_one_hundred_and_seventy_two_bytes() {
        let tz = time_zone();
        let bytes = encode(&tz);
        assert_eq!(bytes.len(), TIME_ZONE_INFORMATION_LEN);
        assert_eq!(TimeZoneInfo::decode(&mut Reader::new(&bytes)).unwrap(), tz);
    }

    /// PRDRDP/11 §5.3, the unnumbered note: the bias fields are documented
    /// unsigned and are signed. A zone east of UTC round trips negative.
    #[test]
    fn a_negative_bias_survives_the_round_trip() {
        let tz = TimeZoneInfo {
            bias: -60,
            daylight_bias: -60,
            ..time_zone()
        };
        let bytes = encode(&tz);
        assert_eq!(&bytes[..4], &[0xc4, 0xff, 0xff, 0xff]);
        assert_eq!(
            TimeZoneInfo::decode(&mut Reader::new(&bytes)).unwrap().bias,
            -60
        );
    }

    #[test]
    fn the_auto_reconnect_cookies_round_trip_at_twenty_eight_bytes() {
        let client = ArcClientPrivatePacket {
            logon_id: 3,
            security_verifier: [0xab; 16],
        };
        let bytes = encode(&client);
        assert_eq!(bytes.len(), ARC_PACKET_LEN);
        assert_eq!(
            ArcClientPrivatePacket::decode(&mut Reader::new(&bytes)).unwrap(),
            client
        );

        let server = ArcServerPrivatePacket {
            logon_id: 3,
            arc_random_bits: [0xcd; 16],
        };
        let bytes = encode(&server);
        assert_eq!(bytes.len(), ARC_PACKET_LEN);
        assert_eq!(
            ArcServerPrivatePacket::decode(&mut Reader::new(&bytes)).unwrap(),
            server
        );
    }

    #[test]
    fn a_pdu_with_a_reconnect_cookie_round_trips() {
        let mut pdu = sample();
        if let Some(extra) = pdu.info.extra_info.as_mut() {
            extra.auto_reconnect_cookie = Some(ArcClientPrivatePacket {
                logon_id: 7,
                security_verifier: [0x11; 16],
            });
        }
        let bytes = encode(&pdu);
        assert_eq!(
            ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// The extensible tail: an old client's PDU stops after
    /// `performanceFlags` and still decodes.
    #[test]
    fn an_extended_packet_that_stops_early_still_decodes() {
        let mut pdu = sample();
        if let Some(extra) = pdu.info.extra_info.as_mut() {
            extra.auto_reconnect_cookie = None;
            extra.dynamic_dst_time_zone_key_name = None;
            extra.dynamic_daylight_time_disabled = None;
        }
        let bytes = encode(&pdu);
        assert_eq!(
            ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );

        // And a PDU with no extended packet at all, which is RDP 4.
        let bare = ClientInfoPdu {
            info: InfoPacket {
                flags: info_flags::UNICODE,
                user_name: "elton".to_owned(),
                ..InfoPacket::default()
            },
        };
        let bytes = encode(&bare);
        assert_eq!(
            ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            bare
        );
    }

    /// `INFO_UNICODE` clear puts ANSI strings and one byte terminators on the
    /// wire, which is the only thing `CodePage` is for.
    #[test]
    fn an_ansi_packet_round_trips_with_single_byte_terminators() {
        let pdu = ClientInfoPdu {
            info: InfoPacket {
                code_page: 1252,
                flags: info_flags::MOUSE,
                domain: "CONTOSO".to_owned(),
                user_name: "elton".to_owned(),
                password: SecretString::new("hunter2"),
                ..InfoPacket::default()
            },
        };
        let bytes = encode(&pdu);
        assert_eq!(u16::from_le_bytes([bytes[12], bytes[13]]), 7);
        assert_eq!(&bytes[22..30], b"CONTOSO\0");
        assert_eq!(
            ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// The password never reaches a log line.
    #[test]
    fn the_password_redacts_itself_in_debug() {
        let pdu = sample();
        let rendered = format!("{pdu:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("SecretString(redacted)"));
        assert_eq!(
            format!("{:?}", SecretString::new("s3cret")),
            "SecretString(redacted)"
        );
    }

    #[test]
    fn a_missing_sec_info_pkt_flag_is_an_invalid_field() {
        let mut bytes = encode(&sample());
        bytes[0] = 0x00;
        let err = ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "flags (SEC_INFO_PKT)",
                ..
            }
        ));
    }

    /// A `cb*` field larger than the cap is refused before anything is
    /// allocated for it.
    #[test]
    fn an_oversized_length_field_names_the_cap() {
        let mut bytes = encode(&sample());
        bytes[14] = 0xff;
        bytes[15] = 0xff;
        let err = ClientInfoPdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_STRING_UTF16",
                ..
            }
        ));
    }

    /// PRDRDP/13 §9.3's truncation loop, with the exception this PDU
    /// genuinely has. `extraInfo` is optional and its own tail is extensible
    /// (§2.5), so several prefixes of this PDU are valid shorter PDUs rather
    /// than truncations, and asserting an error on them would assert
    /// something false. What must hold for every prefix is §9.4's stability
    /// property: no panic, and a value that decodes must survive being
    /// encoded and decoded again.
    ///
    /// Byte level identity is deliberately not asserted. A prefix ending just
    /// after a zero `cbAutoReconnectCookie` decodes to a packet with no tail
    /// at all, and encoding that packet omits the field, which is the same
    /// PDU two bytes shorter.
    #[test]
    fn every_prefix_errors_or_decodes_to_a_stable_value() {
        let bytes = encode(&sample());
        for cut in 0..bytes.len() {
            let Ok(pdu) = ClientInfoPdu::decode(&mut Reader::new(&bytes[..cut])) else {
                continue;
            };
            let again = encode(&pdu);
            assert_eq!(
                ClientInfoPdu::decode(&mut Reader::new(&again)).unwrap(),
                pdu,
                "a {cut} byte prefix decoded to something that does not re-encode"
            );
        }
    }
}
