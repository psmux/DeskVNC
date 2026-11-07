//! The person's clipboard on Windows, macOS and Linux X11, through `arboard`.
//!
//! A helper may put text on it while they have control, and may see what the
//! person copies when the person allows it. Only text crosses, and only what
//! is copied while the session runs: the first look records where the
//! clipboard stands and reports nothing.
//!
//! A change is noticed cheaply, so polling twice a second costs next to
//! nothing: Windows keeps a sequence number that moves on every copy, macOS a
//! change count on the general pasteboard. X11 has neither without a window
//! of our own, so there the text itself is compared.

use anyhow::{Context, Result};

/// What says the clipboard changed since the last look.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stamp {
    /// Windows' sequence number or macOS's change count.
    #[cfg(any(windows, target_os = "macos"))]
    Count(i64),
    /// The text itself, on X11. `None` when the clipboard holds no text.
    #[cfg(not(any(windows, target_os = "macos")))]
    Text(Option<String>),
}

pub struct Clipboard {
    /// Made on first use: on X11 it connects to the display and starts the
    /// thread that keeps serving what we set, and nothing should do that
    /// unless a helper may use the clipboard.
    board: Option<arboard::Clipboard>,
    /// Where the clipboard stood at the last look. `None` before the first.
    seen: Option<Stamp>,
}

impl Clipboard {
    pub fn new() -> Self {
        Self {
            board: None,
            seen: None,
        }
    }

    /// Whether this computer has a clipboard this backend can use.
    pub fn available() -> bool {
        #[cfg(any(windows, target_os = "macos"))]
        {
            true
        }
        #[cfg(target_os = "linux")]
        {
            matches!(crate::linux::kind(), crate::linux::Kind::X11)
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    fn board(&mut self) -> Result<&mut arboard::Clipboard> {
        if self.board.is_none() {
            self.board = Some(
                arboard::Clipboard::new().context("Could not open this computer's clipboard")?,
            );
        }
        Ok(self.board.as_mut().expect("just made"))
    }

    /// The text on the clipboard, or `None` when it holds something else or
    /// nothing. `Err` only for a clipboard that could not be read right now.
    fn text(&mut self) -> Result<Option<String>> {
        match self.board()?.get_text() {
            Ok(text) if text.is_empty() => Ok(None),
            Ok(text) => Ok(Some(text)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(e).context("Could not read this computer's clipboard"),
        }
    }

    fn stamp(&mut self) -> Result<Stamp> {
        #[cfg(windows)]
        {
            // SAFETY: takes no arguments and only reads a counter.
            let n =
                unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() };
            Ok(Stamp::Count(n as i64))
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Stamp::Count(mac_change_count()?))
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Ok(Stamp::Text(self.text()?))
        }
    }

    /// Text the person copied since the last call, or `None` if nothing
    /// changed or what they copied is not text. The first call only records
    /// where the clipboard stands.
    pub fn changed(&mut self) -> Result<Option<String>> {
        let now = match self.stamp() {
            Ok(now) => now,
            // Another program has the clipboard open. Look again next time.
            Err(e) if busy(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        if self.seen.as_ref() == Some(&now) {
            return Ok(None);
        }
        let first = self.seen.is_none();
        let text = match &now {
            #[cfg(not(any(windows, target_os = "macos")))]
            Stamp::Text(text) => text.clone(),
            #[cfg(any(windows, target_os = "macos"))]
            Stamp::Count(_) if first => None,
            #[cfg(any(windows, target_os = "macos"))]
            Stamp::Count(_) => match self.text() {
                Ok(text) => text,
                // Not recorded as seen, so the next look tries again.
                Err(e) if busy(&e) => return Ok(None),
                Err(e) => return Err(e),
            },
        };
        self.seen = Some(now);
        Ok(if first { None } else { text })
    }

    /// Put text on the clipboard. On X11 the selection is served by
    /// arboard's own thread for as long as this lives, so it stays
    /// pasteable. What was set is recorded as seen, so it is not reported
    /// back as something the person copied.
    pub fn set(&mut self, text: &str) -> Result<()> {
        self.board()?
            .set_text(text)
            .context("Could not put text on this computer's clipboard")?;
        // A failed look leaves the old mark, and the session already skips a
        // change equal to what it set.
        if let Ok(now) = self.stamp() {
            self.seen = Some(now);
        }
        Ok(())
    }
}

impl Default for Clipboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether reading failed only because another program holds the clipboard.
fn busy(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<arboard::Error>(),
        Some(arboard::Error::ClipboardOccupied)
    )
}

/// The general pasteboard's change count, which moves on every copy.
#[cfg(target_os = "macos")]
fn mac_change_count() -> Result<i64> {
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};
    // SAFETY: `generalPasteboard` and `changeCount` take no arguments; the
    // pasteboard is a shared object that lives for the whole process, so
    // the unretained pointer stays valid while it is used here.
    let board: *mut AnyObject = unsafe { msg_send![class!(NSPasteboard), generalPasteboard] };
    anyhow::ensure!(!board.is_null(), "This Mac has no general pasteboard");
    let count: isize = unsafe { msg_send![board, changeCount] };
    Ok(count as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_is_only_an_occupied_clipboard() {
        assert!(busy(&anyhow::Error::new(arboard::Error::ClipboardOccupied)));
        assert!(!busy(&anyhow::Error::new(
            arboard::Error::ContentNotAvailable
        )));
        assert!(!busy(&anyhow::anyhow!("something else")));
    }
}
