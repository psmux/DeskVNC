//! The copy buttons: put text on the clipboard and say whether it got there.
//!
//! `egui::Context::copy_text` gives no answer, so a press that failed looked
//! exactly like one that worked. Here the text goes through this computer's
//! clipboard directly where that backend runs (Windows, macOS, X11), and the
//! button says "Copied" or "Could not copy" for a moment afterwards. On
//! Wayland the platform clipboard is not available, so the copy goes through
//! egui, whose backend serves Wayland, and is taken as done.

use eframe::egui;
use std::time::{Duration, Instant};

/// How long a button keeps saying what happened. Long enough to be seen.
pub const SHOWN_FOR: Duration = Duration::from_millis(1600);

/// What the last press did, and which button it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub key: &'static str,
    pub ok: bool,
    pub at: Instant,
}

pub struct Copier {
    board: boundary_platform::clipboard::Clipboard,
    last: Option<Outcome>,
}

impl Default for Copier {
    fn default() -> Self {
        Self {
            board: boundary_platform::clipboard::Clipboard::new(),
            last: None,
        }
    }
}

impl Copier {
    /// Put `text` on the clipboard for the button called `key`. Returns
    /// whether it got there, and keeps the answer for [`Copier::label`].
    pub fn copy(&mut self, ctx: &egui::Context, key: &'static str, text: &str) -> bool {
        let ok = if boundary_platform::clipboard::Clipboard::available() {
            self.board.set(text).is_ok()
        } else {
            ctx.copy_text(text.to_owned());
            true
        };
        self.last = Some(Outcome {
            key,
            ok,
            at: Instant::now(),
        });
        // Draw again when the note runs out, or the button keeps saying
        // "Copied" until the mouse next moves.
        ctx.request_repaint_after(SHOWN_FOR);
        ok
    }

    /// What the button called `key` should say now.
    pub fn label(&self, key: &'static str, idle: &'static str) -> &'static str {
        label(self.last, key, idle, Instant::now())
    }
}

pub const COPIED: &str = "Copied";
pub const FAILED: &str = "Could not copy";

/// What a copy button says at `now`, given the last press.
pub fn label(
    last: Option<Outcome>,
    key: &'static str,
    idle: &'static str,
    now: Instant,
) -> &'static str {
    match last {
        Some(o) if o.key == key && now.saturating_duration_since(o.at) < SHOWN_FOR => {
            if o.ok {
                COPIED
            } else {
                FAILED
            }
        }
        _ => idle,
    }
}

/// What to tell the person when a copy failed, so they still get the text.
pub fn failed_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "Could not put it on the clipboard. Select the text and press Command C instead"
    } else {
        "Could not put it on the clipboard. Select the text and press Ctrl C instead"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(key: &'static str, ok: bool, now: Instant) -> Option<Outcome> {
        Some(Outcome { key, ok, at: now })
    }

    #[test]
    fn a_button_says_what_its_own_press_did_for_a_moment() {
        let now = Instant::now();
        assert_eq!(label(at("code", true, now), "code", "Copy", now), COPIED);
        assert_eq!(label(at("code", false, now), "code", "Copy", now), FAILED);
        let later = now + SHOWN_FOR;
        assert_eq!(label(at("code", true, now), "code", "Copy", later), "Copy");
        assert_eq!(label(at("code", false, now), "code", "Copy", later), "Copy");
    }

    #[test]
    fn another_button_is_not_told_about_a_press_it_did_not_get() {
        let now = Instant::now();
        assert_eq!(
            label(at("code", true, now), "invitation", "Copy invitation", now),
            "Copy invitation"
        );
        assert_eq!(label(None, "invitation", "Copy invitation", now), "Copy invitation");
    }

    /// The bug behind "can't copy or paste the invitation": with eframe's
    /// default features off and `clipboard` not listed, egui kept copies in a
    /// string of its own. Cmd+C, Cmd+V and every copy button then only ever
    /// talked to themselves, never to the Mac's pasteboard.
    #[test]
    fn eframe_is_built_with_the_system_clipboard() {
        let manifest = include_str!("../Cargo.toml");
        let line = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("eframe"))
            .expect("boundary depends on eframe");
        assert!(
            line.contains("\"clipboard\""),
            "eframe needs its clipboard feature: {line}"
        );
    }
}
