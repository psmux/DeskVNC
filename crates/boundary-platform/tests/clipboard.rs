//! The clipboard backend against this computer's real clipboard, with
//! another process copying and pasting the way a person's programs would.
//!
//! These change what is on the clipboard, so they are ignored by default.
//! Run them on a machine nobody is using:
//!
//! ```text
//! cargo test -p boundary-platform --test clipboard -- --ignored --test-threads=1
//! ```
//!
//! Windows uses PowerShell's Set-Clipboard and Get-Clipboard; Linux needs an
//! X11 `DISPLAY` and `xclip`.

use boundary_platform::clipboard::Clipboard;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Copy `text` from another process.
fn copy_elsewhere(text: &str) {
    #[cfg(windows)]
    {
        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Set-Clipboard -Value $env:BCLIP_TEXT",
            ])
            .env("BCLIP_TEXT", text)
            .status()
            .expect("run powershell");
        assert!(status.success(), "Set-Clipboard failed");
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        // xclip forks and keeps serving the selection after the write.
        let mut child = Command::new("xclip")
            .args(["-selection", "clipboard", "-in"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("run xclip");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "xclip -in failed");
    }
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .expect("run pbcopy");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "pbcopy failed");
    }
}

/// Paste from another process.
fn paste_elsewhere() -> String {
    #[cfg(windows)]
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; [Console]::Write((Get-Clipboard -Raw))",
        ])
        .stderr(Stdio::inherit())
        .output()
        .expect("run powershell");
    #[cfg(target_os = "linux")]
    let out = Command::new("xclip")
        .args(["-selection", "clipboard", "-out"])
        .stderr(Stdio::inherit())
        .output()
        .expect("run xclip");
    #[cfg(target_os = "macos")]
    let out = Command::new("pbpaste").output().expect("run pbpaste");
    assert!(out.status.success(), "pasting from another process failed");
    String::from_utf8(out.stdout).expect("pasted text is UTF-8")
}

/// Poll the way the host session does, until something is reported or a few
/// seconds pass.
fn next_change(clipboard: &mut Clipboard) -> Option<String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if let Some(text) = clipboard.changed().expect("poll the clipboard") {
            return Some(text);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

#[test]
#[ignore = "changes this computer's clipboard"]
fn real_clipboard_both_ways() {
    assert!(Clipboard::available(), "no clipboard backend here");
    // Something copied before the session must never be sent.
    copy_elsewhere("copied before the session");
    let mut clipboard = Clipboard::new();
    assert_eq!(
        clipboard.changed().unwrap(),
        None,
        "first look reports nothing"
    );
    assert_eq!(
        clipboard.changed().unwrap(),
        None,
        "and nothing changed since"
    );

    // The person copies: seen once, then quiet.
    let copied = "the person copied this, ünïcödé ✓\nsecond line";
    copy_elsewhere(copied);
    assert_eq!(next_change(&mut clipboard).as_deref(), Some(copied));
    assert_eq!(clipboard.changed().unwrap(), None, "a change is seen once");

    // The helper sets text: it is not reported back as a copy, and another
    // program can paste it while this backend stays open.
    let set = "the helper sent this, 日本語 too";
    clipboard.set(set).unwrap();
    assert_eq!(clipboard.changed().unwrap(), None, "own text is not echoed");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(paste_elsewhere(), set);
    assert_eq!(paste_elsewhere(), set, "still pasteable on a second paste");
    assert_eq!(clipboard.changed().unwrap(), None, "pasting is not a copy");

    // The person copies again after that.
    copy_elsewhere("and copied once more");
    assert_eq!(
        next_change(&mut clipboard).as_deref(),
        Some("and copied once more")
    );
}

#[test]
#[ignore = "changes this computer's clipboard"]
fn first_look_on_a_fresh_backend_ignores_what_was_there() {
    copy_elsewhere("old text");
    let mut clipboard = Clipboard::new();
    assert_eq!(clipboard.changed().unwrap(), None);
    // A second backend that sets text, as a later session would.
    let mut other = Clipboard::new();
    other.set("from a later session").unwrap();
    assert_eq!(
        next_change(&mut clipboard).as_deref(),
        Some("from a later session"),
        "a change made by another clipboard user in this process is still a change"
    );
}

/// The desktop a host session gets carries the same clipboard, so a helper
/// can use it through the three Desktop calls.
#[test]
#[ignore = "changes this computer's clipboard"]
fn the_shared_desktop_carries_the_clipboard() {
    let mut desktop = boundary_platform::open_primary().expect("open the screen");
    assert!(desktop.has_clipboard(), "the desktop offers no clipboard");
    copy_elsewhere("copied before the helper came");
    assert_eq!(desktop.clipboard_changed().unwrap(), None, "first look");

    let set = "put there by the helper, ✓";
    desktop.set_clipboard(set).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(paste_elsewhere(), set);
    assert_eq!(
        desktop.clipboard_changed().unwrap(),
        None,
        "own text is not echoed"
    );

    copy_elsewhere("the person copied this");
    let start = Instant::now();
    let mut seen = None;
    while seen.is_none() && start.elapsed() < Duration::from_secs(3) {
        seen = desktop.clipboard_changed().unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(seen.as_deref(), Some("the person copied this"));
}
