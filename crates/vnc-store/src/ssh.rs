//! The typed form of the `hosts.ssh_settings` blob, and its version rule.
//!
//! The store holds that column as an opaque `Option<String>` and never parses
//! it, mirroring `rdp_settings` (PRDRDP/08 §2.4), so a profile whose blob is
//! malformed is still listable, editable and deletable. This module is the
//! separate, explicit reader: the shell calls it when it builds
//! `ConnectOptions`, where a failure is a refusal to connect rather than a
//! tile that vanished.
//!
//! ## Why the blob carries a version
//!
//! See [`crate::RdpSettings`] for the full argument; the short form is that
//! field level defaults handle a field being added or removed, but not a
//! field whose *meaning* changes, and an SSH blob is exactly as exposed to
//! that as an RDP one: a build that read `multiplexer: "tmux"` under a
//! different meaning of that value would attach to the wrong place on the far
//! side. So the blob carries `v`, and reading a blob whose `v` exceeds
//! [`SshSettings::MAX_V`] is an error rather than a downgrade.
//!
//! Bumping `v` is reserved for a change that would make an old build misread a
//! new blob. Adding an optional field never bumps it. Removing a field never
//! bumps it. Renaming a field with the same meaning uses a serde `alias` and
//! never bumps it, the same trick [`crate::StoredCredentials`] already uses for
//! its snake_case history.

use remote_core::SshOptions;

use crate::{Error, Result};

/// The blob version this build writes and the highest it understands.
const CURRENT_V: u32 = 1;

/// `serde` default for [`SshSettings::v`]: a blob written before the field
/// existed reads as version 1. There are none, and the rule has to be stated
/// once so it is not decided by accident later.
fn one() -> u32 {
    CURRENT_V
}

/// SSH-only options, stored as the `hosts.ssh_settings` JSON column.
///
/// camelCase on the wire, matching `HostProfile` and `RdpSettings`, so the
/// host editor round trips it without a translation layer. Unknown fields are
/// ignored (serde's default), so a blob written by a newer build still
/// parses; what a newer build cannot do is change what an existing field means
/// without bumping `v`.
///
/// The option fields themselves are [`remote_core::SshOptions`], flattened, so
/// the blob is one field list rather than two, the same way [`crate::RdpSettings`]
/// flattens `RdpOptions`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshSettings {
    /// Blob version. Absent means 1.
    #[serde(default = "one")]
    pub v: u32,

    /// Terminal font size, in points. A UI concern rather than a protocol one,
    /// so it sits beside [`SshSettings::scrollback`] rather than in
    /// [`SshOptions`], which nothing but the store's JSON column and the host
    /// editor form reads.
    #[serde(default = "default_font_size")]
    pub font_size: u8,

    /// How many lines of terminal output the client keeps for scrollback.
    /// Also a UI concern: `ssh-core` has no notion of a scrollback buffer,
    /// only the terminal widget that renders the PTY output does.
    #[serde(default = "default_scrollback")]
    pub scrollback: u32,

    /// Everything else: the connect options the driver reads.
    #[serde(flatten)]
    pub options: SshOptions,
}

/// `serde` default for [`SshSettings::font_size`].
fn default_font_size() -> u8 {
    13
}

/// `serde` default for [`SshSettings::scrollback`].
fn default_scrollback() -> u32 {
    10_000
}

impl Default for SshSettings {
    fn default() -> Self {
        Self {
            v: CURRENT_V,
            font_size: default_font_size(),
            scrollback: default_scrollback(),
            options: SshOptions::default(),
        }
    }
}

impl SshSettings {
    /// The highest blob version this build understands.
    pub const MAX_V: u32 = CURRENT_V;

    /// Parse a profile's `ssh_settings` column.
    ///
    /// `Ok(None)` when the column is empty, absent, or the literal string
    /// `null`, matching [`crate::RdpSettings::parse`] because the same column
    /// shape is used across every protocol's settings blob.
    ///
    /// An unparseable blob is an error, not a default. Defaulting would
    /// silently swap the multiplexer or the startup command the user chose
    /// for the built-in default, and the reverse is a behaviour change the
    /// user never asked for.
    pub fn parse(blob: Option<&str>) -> Result<Option<Self>> {
        let Some(text) = blob else {
            return Ok(None);
        };
        let text = text.trim();
        if text.is_empty() || text == "null" {
            return Ok(None);
        }
        let settings: Self = serde_json::from_str(text)?;
        if settings.v > Self::MAX_V {
            // Named as "the app is older than the profile" rather than "the
            // blob is corrupt": the other reading sends the user looking in
            // the wrong place.
            return Err(Error::SshSettingsTooNew {
                found: settings.v,
                max: Self::MAX_V,
            });
        }
        Ok(Some(settings))
    }

    /// Serialize for the `ssh_settings` column, always at the current version.
    pub fn to_json(&self) -> Result<String> {
        let mut current = self.clone();
        current.v = CURRENT_V;
        Ok(serde_json::to_string(&current)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::MultiplexerKind;

    #[test]
    fn an_empty_column_is_not_an_error() {
        assert!(SshSettings::parse(None).unwrap().is_none());
        assert!(SshSettings::parse(Some("")).unwrap().is_none());
        assert!(SshSettings::parse(Some("   ")).unwrap().is_none());
        assert!(SshSettings::parse(Some("null")).unwrap().is_none());
    }

    #[test]
    fn a_blob_round_trips_through_json() {
        let mut settings = SshSettings::default();
        settings.options.session_name = "work".into();
        settings.options.multiplexer = MultiplexerKind::Tmux;
        settings.options.term = "xterm-kitty".into();
        settings.font_size = 16;
        settings.scrollback = 50_000;

        let json = settings.to_json().unwrap();
        let back = SshSettings::parse(Some(&json)).unwrap().unwrap();
        assert_eq!(back, settings);

        // The option fields are flattened, so they sit beside `v` rather than
        // under an `options` key. The host editor reads them at one level.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("v").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            obj.get("sessionName").and_then(|v| v.as_str()),
            Some("work")
        );
        assert_eq!(
            obj.get("multiplexer").and_then(|v| v.as_str()),
            Some("tmux")
        );
        assert_eq!(obj.get("fontSize").and_then(|v| v.as_u64()), Some(16));
        assert!(obj.get("options").is_none(), "flattened, not nested");
    }

    /// The rule that stops a newer profile being misread. The failure names
    /// both versions so the message can say which side is old.
    #[test]
    fn a_blob_from_a_newer_build_is_refused_not_guessed() {
        let err = SshSettings::parse(Some(r#"{"v":2,"term":"xterm-256color"}"#)).unwrap_err();
        match err {
            Error::SshSettingsTooNew { found, max } => {
                assert_eq!(found, 2);
                assert_eq!(max, SshSettings::MAX_V);
            }
            other => panic!("expected SshSettingsTooNew, got {other:?}"),
        }
        let text = SshSettings::parse(Some(r#"{"v":9}"#))
            .unwrap_err()
            .to_string();
        assert!(text.contains('9'), "the message names the version: {text}");
    }

    #[test]
    fn an_unparseable_blob_is_an_error_not_a_default() {
        assert!(SshSettings::parse(Some("{not json")).is_err());
        assert!(SshSettings::parse(Some("[1,2,3]")).is_err());
    }

    /// A blob written before a field existed reads as that field's default,
    /// and unknown fields from a newer build are ignored rather than fatal.
    #[test]
    fn missing_fields_default_and_unknown_fields_are_ignored() {
        let settings = SshSettings::parse(Some(r#"{"sessionName":"work"}"#))
            .unwrap()
            .unwrap();
        assert_eq!(settings.v, 1, "a blob without `v` is version 1");
        assert_eq!(settings.options.session_name, "work");
        assert_eq!(settings.font_size, 13, "font size defaults to 13");
        assert_eq!(settings.scrollback, 10_000, "scrollback defaults to 10000");
        assert_eq!(settings.options.multiplexer, MultiplexerKind::Auto);

        let newer = SshSettings::parse(Some(r#"{"v":1,"somethingNew":{"a":1}}"#))
            .unwrap()
            .unwrap();
        assert_eq!(newer, SshSettings::default());
    }
}
