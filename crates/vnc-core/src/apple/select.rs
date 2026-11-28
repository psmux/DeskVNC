//! Choosing which session a macOS Screen Sharing login gets.
//!
//! A Mac that has someone else at its screen can offer the viewer a choice
//! right after ServerInit, before the encrypted session starts: share the
//! screen of the person at the Mac, which asks that person to accept, or log
//! in to a separate session of the viewer's own. The exchange is in
//! cleartext and carries no message type bytes, so it is only read in that
//! window between ServerInit and the prelude.
//!
//! ```text
//! C->S ClientInit 0xC1        (bit 0x40: the viewer can take part)
//! S->C ServerInit             (name field: marker, flags, capabilities, name)
//! S->C SessionInfo            (only when flag 0x04 is set)
//! C->S SessionCommand         (share the console, or a separate session)
//! S->C SessionResult ...      (pending while the person at the Mac decides)
//! ```
//!
//! Every message here starts with a u16 that counts the bytes after itself.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Result, VncError};
use crate::proto::messages::{map_eof, read_exact_vec};

/// Bits of the u32 flags word in the extended ServerInit name.
pub mod server_flag {
    /// The viewer may watch without control.
    pub const OBSERVE: u32 = 0x01;
    /// The viewer may take control.
    pub const CONTROL: u32 = 0x02;
    /// A SessionInfo follows this ServerInit.
    pub const SESSION_SELECT: u32 = 0x04;
    /// The Mac cannot give this login a separate session.
    pub const NO_VIRTUAL_DISPLAY: u32 = 0x08;
}

/// SessionCommand numbers.
pub mod command {
    /// Ask for the console when nobody owns it.
    pub const REQUEST_CONSOLE: u8 = 0;
    /// Share the Mac's real display. With someone logged in at the Mac, that
    /// person is asked to accept.
    pub const CONNECT_CONSOLE: u8 = 1;
    /// A separate session for the account that logged in.
    pub const VIRTUAL_DISPLAY: u8 = 2;
}

/// SessionResult status values.
pub mod status {
    pub const GRANTED: u32 = 0;
    pub const PENDING: u32 = 2;
    pub const PENDING_AGAIN: u32 = 3;
    pub const GRANTED_AFTER_WAIT: u32 = 4;
}

/// The extended name starts with two marker bytes, then the flags and a 16
/// byte capability bitmap.
const EXTENDED_HEADER: usize = 22;
/// Cap on a SessionInfo or SessionResult body.
const MAX_BODY: usize = 4096;
/// The SessionCommand body size and version.
const COMMAND_BODY: u16 = 72;
const COMMAND_VERSION: u16 = 1;
/// Room for the user name in a SessionCommand.
const COMMAND_NAME: usize = 64;

/// What the extended ServerInit name field carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedServerInit {
    pub flags: u32,
    pub capabilities: [u8; 16],
    /// The readable desktop name at the end of the field.
    pub name: String,
}

impl ExtendedServerInit {
    /// Whether a SessionInfo follows.
    pub fn offers_session_select(&self) -> bool {
        self.flags & server_flag::SESSION_SELECT != 0
    }

    /// Whether the Mac said it cannot give a separate session.
    pub fn no_virtual_display(&self) -> bool {
        self.flags & server_flag::NO_VIRTUAL_DISPLAY != 0
    }
}

/// Read the extended form out of a ServerInit name field, or `None` when the
/// field is an ordinary name.
///
/// The extended form is at least 22 bytes and starts with a zero byte, which
/// no readable name does. The desktop name is whatever follows the last zero
/// byte of the field.
pub fn parse_extended_name(raw: &[u8]) -> Option<ExtendedServerInit> {
    if raw.len() < EXTENDED_HEADER || raw[0] != 0 {
        return None;
    }
    let flags = u32::from_be_bytes(raw[2..6].try_into().ok()?);
    let capabilities: [u8; 16] = raw[6..22].try_into().ok()?;
    let tail = &raw[EXTENDED_HEADER..];
    let start = tail.iter().rposition(|&b| b == 0).map_or(0, |i| i + 1);
    let name = String::from_utf8_lossy(&tail[start..]).into_owned();
    Some(ExtendedServerInit {
        flags,
        capabilities,
        name,
    })
}

/// The Mac's description of its console, sent when it offers the choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub version: u16,
    /// One bit per allowed command number.
    pub allowed: u32,
    /// The short name of the user logged in at the Mac, empty when nobody is.
    pub console_user: String,
}

impl SessionInfo {
    pub fn allows(&self, command: u8) -> bool {
        command < 32 && self.allowed & (1 << command) != 0
    }

    /// Whether someone is logged in at the Mac.
    pub fn console_in_use(&self) -> bool {
        !self.console_user.is_empty()
    }
}

/// Read a u16 sized body, refusing one that is too short or absurdly long.
async fn read_body<R: AsyncRead + Unpin>(r: &mut R, min: usize, what: &str) -> Result<Vec<u8>> {
    let size = r.read_u16().await.map_err(map_eof)? as usize;
    if size < min || size > MAX_BODY {
        return Err(VncError::Protocol(format!(
            "the Mac sent a {what} of {size} bytes"
        )));
    }
    read_exact_vec(r, size).await
}

/// Read the SessionInfo that follows an extended ServerInit with flag 0x04.
pub async fn read_session_info<R: AsyncRead + Unpin>(r: &mut R) -> Result<SessionInfo> {
    // version, allowed commands, reserved word
    let body = read_body(r, 10, "session description").await?;
    let version = u16::from_be_bytes([body[0], body[1]]);
    let allowed = u32::from_be_bytes(body[2..6].try_into().expect("four"));
    let user = &body[10..];
    let end = user.iter().position(|&b| b == 0).unwrap_or(user.len());
    Ok(SessionInfo {
        version,
        allowed,
        console_user: String::from_utf8_lossy(&user[..end]).into_owned(),
    })
}

/// A SessionCommand: body size, version, a zero word, the command, a zero
/// byte, and the user name zero padded to 64 bytes.
pub fn session_command(command: u8, user: &str) -> [u8; 2 + COMMAND_BODY as usize] {
    let mut out = [0u8; 2 + COMMAND_BODY as usize];
    out[0..2].copy_from_slice(&COMMAND_BODY.to_be_bytes());
    out[2..4].copy_from_slice(&COMMAND_VERSION.to_be_bytes());
    out[8] = command;
    // At most 63 bytes of text, cut on a character boundary, so the field
    // always ends in a zero.
    let mut len = user.len().min(COMMAND_NAME - 1);
    while !user.is_char_boundary(len) {
        len -= 1;
    }
    out[10..10 + len].copy_from_slice(&user.as_bytes()[..len]);
    out
}

/// Read one SessionResult and return its status. Its tail is reserved and
/// its size is trusted rather than assumed.
pub async fn read_session_result<R: AsyncRead + Unpin>(r: &mut R) -> Result<u32> {
    let body = read_body(r, 6, "session result").await?;
    Ok(u32::from_be_bytes(body[2..6].try_into().expect("four")))
}

/// What a SessionResult status means for the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Granted,
    Pending,
    Refused(u32),
}

pub fn verdict(status: u32) -> Verdict {
    match status {
        status::GRANTED | status::GRANTED_AFTER_WAIT => Verdict::Granted,
        status::PENDING | status::PENDING_AGAIN => Verdict::Pending,
        other => Verdict::Refused(other),
    }
}

/// Which session the viewer wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wanted {
    /// The Mac's real display, asking the person at it when there is one.
    Console,
    /// A separate session for the account that logged in.
    Separate,
}

/// The command to send for what the viewer wants.
///
/// A separate session is command 2. The console is command 1, except that
/// when nobody is logged in and command 1 is not allowed, command 0 asks for
/// the empty console instead.
pub fn command_for(wanted: Wanted, info: &SessionInfo) -> u8 {
    match wanted {
        Wanted::Separate => command::VIRTUAL_DISPLAY,
        Wanted::Console if !info.console_in_use() && !info.allows(command::CONNECT_CONSOLE) => {
            command::REQUEST_CONSOLE
        }
        Wanted::Console => command::CONNECT_CONSOLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extended(flags: u32, name: &str) -> Vec<u8> {
        let mut v = vec![0, 0];
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&[0xAA; 16]);
        v.push(0);
        v.extend_from_slice(name.as_bytes());
        v
    }

    #[test]
    fn an_extended_name_gives_flags_and_the_readable_name() {
        let e = parse_extended_name(&extended(0x07, "Studio iMac")).unwrap();
        assert_eq!(e.flags, 7);
        assert!(e.offers_session_select());
        assert!(!e.no_virtual_display());
        assert_eq!(e.capabilities, [0xAA; 16]);
        assert_eq!(e.name, "Studio iMac");
    }

    #[test]
    fn an_ordinary_name_is_not_extended() {
        assert_eq!(parse_extended_name(b"pi"), None);
        assert_eq!(
            parse_extended_name(b"a name that is long enough to pass"),
            None
        );
        // Short, even with the marker.
        assert_eq!(parse_extended_name(&[0; 21]), None);
    }

    #[test]
    fn a_command_is_seventy_four_bytes_with_the_name_padded() {
        let c = session_command(command::CONNECT_CONSOLE, "anna");
        assert_eq!(c.len(), 74);
        assert_eq!(&c[0..2], &[0, 72]);
        assert_eq!(&c[2..4], &[0, 1]);
        assert_eq!(&c[4..8], &[0; 4]);
        assert_eq!(c[8], 1);
        assert_eq!(c[9], 0);
        assert_eq!(&c[10..14], b"anna");
        assert!(c[14..].iter().all(|&b| b == 0));
        // A long name is cut so the field still ends in a zero.
        let long = session_command(2, &"é".repeat(40));
        assert_eq!(long[10 + 63], 0);
        assert!(std::str::from_utf8(&long[10..10 + 62]).is_ok());
    }

    #[test]
    fn the_console_command_follows_who_is_at_the_mac() {
        let anna = SessionInfo {
            version: 1,
            allowed: 0b111,
            console_user: "anna".into(),
        };
        assert_eq!(command_for(Wanted::Console, &anna), 1);
        assert_eq!(command_for(Wanted::Separate, &anna), 2);
        let empty_without_1 = SessionInfo {
            version: 1,
            allowed: 0b101,
            console_user: String::new(),
        };
        assert_eq!(command_for(Wanted::Console, &empty_without_1), 0);
        let empty_with_1 = SessionInfo {
            allowed: 0b111,
            ..empty_without_1
        };
        assert_eq!(command_for(Wanted::Console, &empty_with_1), 1);
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(0), Verdict::Granted);
        assert_eq!(verdict(4), Verdict::Granted);
        assert_eq!(verdict(2), Verdict::Pending);
        assert_eq!(verdict(3), Verdict::Pending);
        assert_eq!(verdict(1), Verdict::Refused(1));
        assert_eq!(verdict(5), Verdict::Refused(5));
    }

    #[tokio::test]
    async fn session_info_and_result_read_by_their_size() {
        let mut info = Vec::new();
        let body_len = 10 + 5;
        info.extend_from_slice(&(body_len as u16).to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&0b110u32.to_be_bytes());
        info.extend_from_slice(&[0; 4]);
        info.extend_from_slice(b"anna\0");
        // A result with a long reserved tail, then a byte that must stay.
        info.extend_from_slice(&80u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&2u32.to_be_bytes());
        info.extend_from_slice(&[0; 74]);
        info.push(0x5A);
        let mut cur = std::io::Cursor::new(info);
        let si = read_session_info(&mut cur).await.unwrap();
        assert_eq!(si.console_user, "anna");
        assert!(si.allows(1) && si.allows(2) && !si.allows(0));
        assert_eq!(read_session_result(&mut cur).await.unwrap(), 2);
        assert_eq!(cur.read_u8().await.unwrap(), 0x5A);
    }

    #[tokio::test]
    async fn an_absurd_size_is_refused() {
        let mut cur = std::io::Cursor::new(vec![0xFF, 0xFF]);
        assert!(read_session_info(&mut cur).await.is_err());
        let mut cur = std::io::Cursor::new(vec![0, 2, 0, 1]);
        assert!(read_session_result(&mut cur).await.is_err());
    }
}
