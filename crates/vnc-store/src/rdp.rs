//! The typed form of the `hosts.rdp_settings` blob, and its version rule.
//!
//! The store holds that column as an opaque `Option<String>` and never parses
//! it (PRDRDP/08 §2.4), so a profile whose blob is malformed is still
//! listable, editable and deletable. This module is the separate, explicit
//! reader: the shell calls it when it builds `ConnectOptions`, where a failure
//! is a refusal to connect rather than a tile that vanished.
//!
//! ## Why the blob carries a version and `ssh_tunnel` does not
//!
//! `SshTunnelSettings` (`src-tauri/src/tunnel.rs:33-52`) has no version of any
//! kind. It gets away with that because every field carries
//! `#[serde(default)]` and serde ignores unknown fields, so compatibility is
//! handled field by field in both directions.
//!
//! Field level defaults handle a field being added or removed. They do not
//! handle a field whose *meaning* changes, and at least one such change is
//! already on the roadmap: the codec set changes shape when EGFX arrives in
//! phase 2, and the gateway block changes shape when RD Gateway arrives in
//! phase 3. A build that read `codecs.remotefx: true` under a different
//! meaning of that flag would enable a codec path the user did not choose.
//! So the blob carries `v`, and reading a blob whose `v` exceeds
//! [`RdpSettings::MAX_V`] is an error rather than a downgrade.
//!
//! Bumping `v` is reserved for a change that would make an old build misread a
//! new blob. Adding an optional field never bumps it. Removing a field never
//! bumps it. Renaming a field with the same meaning uses a serde `alias` and
//! never bumps it, the same trick [`crate::StoredCredentials`] already uses for
//! its snake_case history.

use remote_core::RdpOptions;

use crate::{Error, Result};

/// The blob version this build writes and the highest it understands.
const CURRENT_V: u32 = 1;

/// `serde` default for [`RdpSettings::v`]: a blob written before the field
/// existed reads as version 1. There are none, and the rule has to be stated
/// once so it is not decided by accident later.
fn one() -> u32 {
    CURRENT_V
}

/// RDP-only options, stored as the `hosts.rdp_settings` JSON column.
///
/// camelCase on the wire, matching `HostProfile` and `SshTunnelSettings`, so
/// the host editor round trips it without a translation layer. Unknown fields
/// are ignored (serde's default), so a blob written by a newer build still
/// parses; what a newer build cannot do is change what an existing field means
/// without bumping `v`.
///
/// The option fields themselves are [`remote_core::RdpOptions`], flattened, so
/// the blob is one field list rather than two. PRDRDP/02 §5.4 already declares
/// `RdpOptions` to be what this column carries and `rdp-core` reads the same
/// struct to act on it; a second definition here would drift from it the first
/// time either side gained a field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdpSettings {
    /// Blob version. Absent means 1.
    #[serde(default = "one")]
    pub v: u32,

    /// Redirect the clipboard (MS-RDPECLIP).
    ///
    /// This field and the three below it are specified by PRDRDP/08 §2.5 and
    /// are absent from [`RdpOptions`], which PRDRDP/02 §5.4 specifies. They
    /// sit here until that is reconciled. Because [`RdpSettings::options`] is
    /// flattened, they occupy the same level of the JSON object either way, so
    /// moving one into `RdpOptions` later changes no stored blob and does not
    /// bump `v`.
    #[serde(default = "yes")]
    pub clipboard: bool,

    /// Audio input (MS-RDPEAI). Out of scope for phases 1 to 3; the field
    /// exists so an imported `.rdp` file does not lose the setting, and
    /// nothing reads it yet.
    #[serde(default)]
    pub microphone: bool,

    /// `/admin`, the console session.
    #[serde(default)]
    pub console_session: bool,

    /// Restricted Admin mode (RDP_NEG_REQ flag 0x01). Off by default; it
    /// changes what the server does with the credential, so it is never
    /// inferred.
    #[serde(default)]
    pub restricted_admin: bool,

    /// Everything else: the connect options the driver reads.
    #[serde(flatten)]
    pub options: RdpOptions,
}

/// `serde` default for the fields that are on unless a file says otherwise.
fn yes() -> bool {
    true
}

impl Default for RdpSettings {
    fn default() -> Self {
        Self {
            v: CURRENT_V,
            clipboard: true,
            microphone: false,
            console_session: false,
            restricted_admin: false,
            options: RdpOptions::default(),
        }
    }
}

impl RdpSettings {
    /// The highest blob version this build understands.
    pub const MAX_V: u32 = CURRENT_V;

    /// Parse a profile's `rdp_settings` column.
    ///
    /// `Ok(None)` when the column is empty, absent, or the literal string
    /// `null`, matching `SshTunnelSettings::parse` (tunnel.rs:65-69) because
    /// the same column can hold either through the same UI path.
    ///
    /// An unparseable blob is an error, not a default. Defaulting would
    /// connect with NLA on when the user had turned it off, or the reverse,
    /// and the reverse is a security downgrade the user never asked for.
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
            return Err(Error::RdpSettingsTooNew {
                found: settings.v,
                max: Self::MAX_V,
            });
        }
        Ok(Some(settings))
    }

    /// Serialize for the `rdp_settings` column, always at the current version.
    pub fn to_json(&self) -> Result<String> {
        let mut current = self.clone();
        current.v = CURRENT_V;
        Ok(serde_json::to_string(&current)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::{AudioMode, NlaPolicy, RdpColorDepth};

    #[test]
    fn an_empty_column_is_not_an_error() {
        assert!(RdpSettings::parse(None).unwrap().is_none());
        assert!(RdpSettings::parse(Some("")).unwrap().is_none());
        assert!(RdpSettings::parse(Some("   ")).unwrap().is_none());
        assert!(RdpSettings::parse(Some("null")).unwrap().is_none());
    }

    #[test]
    fn a_blob_round_trips_through_json() {
        let mut settings = RdpSettings::default();
        settings.options.domain = Some("CORP".into());
        settings.options.nla = NlaPolicy::AllowFallback;
        settings.options.color_depth = RdpColorDepth::Bpp24;
        settings.options.audio = AudioMode::Off;
        settings.console_session = true;

        let json = settings.to_json().unwrap();
        let back = RdpSettings::parse(Some(&json)).unwrap().unwrap();
        assert_eq!(back, settings);

        // The option fields are flattened, so they sit beside `v` rather than
        // under an `options` key. The host editor reads them at one level.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("v").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(obj.get("domain").and_then(|v| v.as_str()), Some("CORP"));
        assert_eq!(
            obj.get("nla").and_then(|v| v.as_str()),
            Some("allow-fallback")
        );
        assert!(obj.get("options").is_none(), "flattened, not nested");
    }

    /// The rule that stops a newer profile being misread. The failure names
    /// both versions so the message can say which side is old.
    #[test]
    fn a_blob_from_a_newer_build_is_refused_not_guessed() {
        let err = RdpSettings::parse(Some(r#"{"v":2,"nla":"allow-fallback"}"#)).unwrap_err();
        match err {
            Error::RdpSettingsTooNew { found, max } => {
                assert_eq!(found, 2);
                assert_eq!(max, RdpSettings::MAX_V);
            }
            other => panic!("expected RdpSettingsTooNew, got {other:?}"),
        }
        let text = RdpSettings::parse(Some(r#"{"v":9}"#))
            .unwrap_err()
            .to_string();
        assert!(text.contains('9'), "the message names the version: {text}");
    }

    #[test]
    fn an_unparseable_blob_is_an_error_not_a_default() {
        assert!(RdpSettings::parse(Some("{not json")).is_err());
        assert!(RdpSettings::parse(Some("[1,2,3]")).is_err());
    }

    /// A blob written before a field existed reads as that field's default,
    /// and unknown fields from a newer build are ignored rather than fatal.
    #[test]
    fn missing_fields_default_and_unknown_fields_are_ignored() {
        let settings = RdpSettings::parse(Some(r#"{"domain":"CORP"}"#))
            .unwrap()
            .unwrap();
        assert_eq!(settings.v, 1, "a blob without `v` is version 1");
        assert_eq!(settings.options.domain.as_deref(), Some("CORP"));
        assert_eq!(
            settings.options.nla,
            NlaPolicy::Required,
            "NLA on by default"
        );
        assert!(settings.clipboard, "clipboard defaults on");

        let newer = RdpSettings::parse(Some(r#"{"v":1,"somethingNew":{"a":1}}"#))
            .unwrap()
            .unwrap();
        assert_eq!(newer, RdpSettings::default());
    }

    /// V3-B: a blob written before `legacyTls` existed reads as off. A
    /// relaxation that switched itself on during an upgrade would be the worst
    /// bug this field can have.
    #[test]
    fn a_blob_without_legacy_tls_reads_as_off() {
        let old = RdpSettings::parse(Some(r#"{"v":1,"domain":"CORP"}"#))
            .unwrap()
            .unwrap();
        assert!(!old.options.legacy_tls);

        let on = RdpSettings::parse(Some(r#"{"v":1,"legacyTls":true}"#))
            .unwrap()
            .unwrap();
        assert!(on.options.legacy_tls);
        let back = RdpSettings::parse(Some(&on.to_json().unwrap()))
            .unwrap()
            .unwrap();
        assert!(back.options.legacy_tls, "it survives a round trip");
    }
}
