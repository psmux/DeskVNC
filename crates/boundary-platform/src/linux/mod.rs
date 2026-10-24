//! Linux screens and input, on X11 and on Wayland.
//!
//! xcap asked the X server for a fresh picture over a new connection on every
//! capture and converted it a pixel at a time through a function pointer; on
//! Wayland it asked the screenshot portal for a PNG file each time, which on
//! GNOME and KDE either fails or asks the person every time. Here X11 is read
//! through shared memory and told what changed by the damage extension, and
//! Wayland goes through the ScreenCast portal once, with a PipeWire stream
//! handing over each new screen and the RemoteDesktop portal taking input.
use anyhow::{Result, bail};
use boundary_session::Rect;
use std::sync::Arc;

pub(crate) mod portal;
pub(crate) mod x11;

/// One screen as the system gave it: RGBA at its own size, with what changed
/// since the last one where that is known.
pub(crate) struct Raw {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    pub damage: Option<Vec<Rect>>,
}

/// Which kind of desktop this process runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    X11,
    Wayland,
}
pub(crate) fn kind() -> Kind {
    kind_from(
        std::env::var("XDG_SESSION_TYPE").ok().as_deref(),
        std::env::var_os("WAYLAND_DISPLAY").is_some(),
        std::env::var_os("DISPLAY").is_some(),
    )
}
/// A Wayland session still sets `DISPLAY` for Xwayland, and X11 there sees
/// only X programs, so Wayland wins whenever it is named.
fn kind_from(session: Option<&str>, wayland: bool, x11: bool) -> Kind {
    match session {
        Some("wayland") => Kind::Wayland,
        Some("x11") => Kind::X11,
        _ if wayland => Kind::Wayland,
        _ if x11 => Kind::X11,
        _ => Kind::X11,
    }
}

/// Where a screen is, in the X root window's pixels, for display lists and
/// pointer moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Area {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

pub(crate) enum Screen {
    X11(Box<x11::Screen>),
    Portal(portal::Screen),
}
impl Screen {
    /// The display `id` (a RandR output on X11; on Wayland the person or a
    /// saved permission picks the screen in the portal). Without
    /// `accelerated`, X11 is read whole over the socket every time, as xcap
    /// did, for timing the two against each other.
    pub fn open(id: u32, accelerated: bool) -> Result<Self> {
        match kind() {
            Kind::X11 => Ok(Self::X11(Box::new(x11::Screen::open(id, accelerated)?))),
            Kind::Wayland => match portal::Screen::open() {
                Ok(screen) => Ok(Self::Portal(screen)),
                Err(e) => bail!(
                    "This Wayland desktop did not share its screen ({e:#}). DeskVNC Support needs the xdg-desktop-portal ScreenCast service, which GNOME, KDE and wlroots desktops provide, or a session on Xorg"
                ),
            },
        }
    }
    /// The screen if it changed since the last call.
    pub fn next(&mut self) -> Result<Option<Raw>> {
        match self {
            Self::X11(s) => s.next(),
            Self::Portal(s) => s.next(),
        }
    }
    pub fn area(&self) -> Option<Area> {
        match self {
            Self::X11(s) => Some(s.area()),
            Self::Portal(_) => None,
        }
    }
    pub fn remote(&self) -> Option<Arc<portal::Remote>> {
        match self {
            Self::X11(_) => None,
            Self::Portal(s) => s.remote(),
        }
    }
    pub fn backend(&self) -> &'static str {
        match self {
            Self::X11(s) if s.damage() => "x11 shm with damage",
            Self::X11(s) if s.shm() => "x11 shm",
            Self::X11(_) => "x11",
            Self::Portal(s) if s.remote().is_some() => "wayland portal with remote desktop",
            Self::Portal(_) => "wayland portal",
        }
    }
}

/// Displays on this desktop. On Wayland the portal chooses, so there is one
/// entry for it unless Xwayland lists monitors.
pub(crate) fn displays() -> Result<Vec<(u32, String)>> {
    match kind() {
        Kind::X11 => x11::displays(),
        Kind::Wayland => {
            if let Ok(all) = x11::displays()
                && !all.is_empty()
            {
                return Ok(all);
            }
            Ok(vec![(0, "Screen (chosen in the sharing prompt)".into())])
        }
    }
}

/// BGRX rows, as both X11 and most PipeWire producers lay them out, into
/// RGBA.
pub(crate) fn bgrx_to_rgba(src: &[u8], dst: &mut [u8]) {
    for (s, d) in src
        .as_chunks::<4>()
        .0
        .iter()
        .zip(dst.as_chunks_mut::<4>().0)
    {
        *d = [s[2], s[1], s[0], 255];
    }
}

/// The keysym for one character, as X11 and the RemoteDesktop portal take
/// them: Latin-1 as itself, everything else in the Unicode range.
pub(crate) fn keysym(c: char) -> u32 {
    match c {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        '\u{8}' => 0xff08,
        ' '..='~' | '\u{a0}'..='\u{ff}' => c as u32,
        _ => 0x0100_0000 + c as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_kind() {
        assert_eq!(kind_from(Some("wayland"), true, true), Kind::Wayland);
        assert_eq!(kind_from(Some("x11"), true, true), Kind::X11);
        assert_eq!(kind_from(Some("tty"), true, true), Kind::Wayland);
        assert_eq!(kind_from(None, false, true), Kind::X11);
        assert_eq!(kind_from(None, true, false), Kind::Wayland);
    }

    #[test]
    fn keysyms() {
        assert_eq!(keysym('a'), 0x61);
        assert_eq!(keysym('é'), 0xe9);
        assert_eq!(keysym('€'), 0x0100_20ac);
        assert_eq!(keysym('\n'), 0xff0d);
    }

    #[test]
    fn swizzle() {
        let mut out = [0u8; 8];
        bgrx_to_rgba(&[1, 2, 3, 0, 4, 5, 6, 0], &mut out);
        assert_eq!(out, [3, 2, 1, 255, 6, 5, 4, 255]);
    }
}
