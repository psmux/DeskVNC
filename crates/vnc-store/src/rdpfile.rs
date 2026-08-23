//! Importing Microsoft `.rdp` connection files.
//!
//! A `.rdp` file is a flat list of `<key>:<type>:<value>` lines, where the
//! type is `s` for a string, `i` for an integer and `b` for a binary value
//! written as hex. Keys contain spaces (`screen mode id`) and values contain
//! colons (`full address:s:server.example:3389`), so a line splits on its
//! first two colons and the rest is taken verbatim.
//!
//! # This is hostile input
//!
//! The file arrives by email, from a hosting provider, or from a colleague.
//! We do not verify RDP file signatures (see [`parse_rdp_file`]), so nothing
//! distinguishes a file from a colleague from a file from an attacker. Two
//! consequences run through everything below:
//!
//! * The parser allocates nothing from a value it has not bounded. The file is
//!   read at most [`MAX_RDP_FILE_BYTES`], a line longer than [`MAX_LINE`] is
//!   counted and skipped rather than parsed, and the settings blob it produces
//!   is refused above [`MAX_RDP_SETTINGS_BYTES`]. Every limit is far above any
//!   real file, which `mstsc` writes at about two kilobytes.
//! * Import **writes nothing**. It produces a draft that pre-fills the host
//!   editor, and the user presses Save. A file can set `enablecredsspsupport:i:0`
//!   or point `gatewayhostname` at a host that will see the user's credentials,
//!   and those are exactly the settings a human should see before they take
//!   effect (PRDRDP/08 §5.4). It matches how a discovered host becomes a
//!   profile today: the dialog is pre-filled, not saved.
//!
//! `password 51:b:` is never read, never hex decoded and never logged. It is a
//! DPAPI blob decryptable only by the Windows account that wrote it, so there
//! is nothing here that could use it, and there is no code path from that key
//! to [`crate::StoredCredentials`].

use std::collections::BTreeMap;

use remote_core::{AudioMode, GatewayOptions, MonitorPolicy, NlaPolicy, RdpColorDepth};

use crate::rdp::RdpSettings;
use crate::{Error, HostProfile, ProtocolKind, Result};

/// Largest file the importer will read. `mstsc` writes about 2 KB.
pub const MAX_RDP_FILE_BYTES: usize = 1024 * 1024;

/// Largest settings blob an import may produce.
pub const MAX_RDP_SETTINGS_BYTES: usize = 8 * 1024;

/// Longest line the parser will look at. A real setting is tens of bytes; a
/// 100 kB line is not a setting, and bounding it here is what keeps the
/// parser linear in the file size.
const MAX_LINE: usize = 4096;

/// Widest and tallest initial size we will carry from a file.
const MIN_DESKTOP_DIM: u32 = 640;
const MAX_DESKTOP_DIM: u32 = 8192;

/// The result of reading a `.rdp` file: a draft, and an account of what
/// happened to every line.
///
/// The three lists are key names only. No value from the file is ever put in
/// them, which is what keeps a `password 51` line out of the summary, out of
/// `Debug` and out of the logs.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdpImport {
    /// The draft profile. A whole [`HostProfile`], because `save_host`
    /// deserializes a whole one: a draft missing a field would be rejected at
    /// save time, which is a confusing place to find out.
    pub profile: HostProfile,
    /// The username the file carried, for pre-filling the credential field.
    /// Never saved by the import itself; the credential is written by the
    /// normal post-connect path, so an imported profile's password is still
    /// only stored after a server accepted it.
    pub username: Option<String>,
    /// Keys that became something in the draft.
    pub mapped: Vec<String>,
    /// Keys recognised and deliberately not acted on, plus unknown keys.
    pub ignored: Vec<String>,
    /// Lines that were not `key:type:value` at all.
    pub unparseable: usize,
    /// Things the user should see: a setting that was dropped, a value out of
    /// range, a feature that is recorded but not yet supported.
    pub warnings: Vec<String>,
    /// The initial size the file asked for, if it asked for a sane one. No
    /// profile field holds it today; the shell can use it for the first
    /// window and the value is not lost in the meantime.
    pub desktop_size: Option<(u32, u32)>,
}

/// Parse a `.rdp` file.
///
/// `file_name` is the name the user has been calling this connection; its stem
/// becomes the friendly name. When it is empty the address is used, matching
/// `adopt_endpoint`'s rule.
///
/// Returns `Err` only for a file that must not become a profile at all: one
/// larger than [`MAX_RDP_FILE_BYTES`], and one that launches a RemoteApp,
/// which does something materially different from opening a desktop
/// (PRDRDP/08 §5.3). Everything else is a warning on an otherwise usable
/// draft, because a file the user chose to import should not be refused over a
/// setting this app does not have.
pub fn parse_rdp_file(bytes: &[u8], file_name: Option<&str>) -> Result<RdpImport> {
    if bytes.len() > MAX_RDP_FILE_BYTES {
        return Err(Error::RdpFileRefused(format!(
            "the file is {} bytes, over the {MAX_RDP_FILE_BYTES} byte limit",
            bytes.len()
        )));
    }

    let text = decode(bytes);
    let mut unparseable = 0usize;
    // Last occurrence wins, matching `mstsc`. Keys are matched case
    // insensitively, so the map is keyed on the lowercased key.
    let mut settings: BTreeMap<String, (char, String)> = BTreeMap::new();
    for line in text.split(['\n', '\r']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LINE {
            unparseable += 1;
            continue;
        }
        match split_line(line) {
            Some((key, kind, value)) => {
                settings.insert(key, (kind, value));
            }
            None => unparseable += 1,
        }
    }

    let mut out = RdpImport {
        profile: HostProfile::for_protocol(ProtocolKind::Rdp),
        username: None,
        mapped: Vec::new(),
        ignored: Vec::new(),
        unparseable,
        warnings: Vec::new(),
        desktop_size: None,
    };
    if text.is_empty() || settings.is_empty() {
        out.warnings
            .push("the file contained no settings this app could read".into());
    }
    refuse_remote_app(&settings)?;

    let mut rdp = RdpSettings::default();
    let mut gateway_host: Option<String> = None;
    let mut gateway_enabled = true;

    for (key, (kind, value)) in &settings {
        let key = key.as_str();
        let kind = *kind;
        let value = value.as_str();
        match key {
            "full address" => {
                let (address, port, warning) = split_address(value);
                out.profile.address = address;
                if let Some(port) = port {
                    out.profile.port = port;
                }
                if let Some(warning) = warning {
                    out.warnings.push(warning);
                }
                out.mapped.push(key.into());
            }
            "username" => {
                out.username = trimmed(value);
                out.mapped.push(key.into());
            }
            "domain" => {
                rdp.options.domain = trimmed(value);
                out.mapped.push(key.into());
            }
            "enablecredsspsupport" => match int(kind, value) {
                Some(0) => {
                    rdp.options.nla = NlaPolicy::AllowFallback;
                    out.warnings.push(
                        "this file turns Network Level Authentication off, so the password \
                         is checked by the Windows logon screen inside the session rather \
                         than before the connection starts"
                            .into(),
                    );
                    out.mapped.push(key.into());
                }
                Some(_) => {
                    rdp.options.nla = NlaPolicy::Required;
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "session bpp" => match int(kind, value) {
                Some(15) => set_depth(&mut rdp, RdpColorDepth::Bpp15, &mut out, key),
                Some(16) => set_depth(&mut rdp, RdpColorDepth::Bpp16, &mut out, key),
                Some(24) => set_depth(&mut rdp, RdpColorDepth::Bpp24, &mut out, key),
                Some(32) => set_depth(&mut rdp, RdpColorDepth::Bpp32, &mut out, key),
                Some(other) => {
                    // 8 bpp is a palette mode, which this client does not
                    // support. Refusing the value is honest; silently rounding
                    // it up would claim a colour depth the file did not ask for.
                    out.warnings.push(format!(
                        "colour depth {other} is not supported, the server's preference \
                         will be used instead"
                    ));
                    out.ignored.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "audiomode" => match int(kind, value) {
                Some(0) => set_audio(&mut rdp, AudioMode::PlayLocally, &mut out, key),
                Some(1) => set_audio(&mut rdp, AudioMode::LeaveAtServer, &mut out, key),
                Some(2) => set_audio(&mut rdp, AudioMode::Off, &mut out, key),
                _ => out.ignored.push(key.into()),
            },
            "audiocapturemode" => match flag(kind, value) {
                Some(on) => {
                    rdp.microphone = on;
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "redirectclipboard" => match flag(kind, value) {
                Some(on) => {
                    rdp.clipboard = on;
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "use multimon" => match flag(kind, value) {
                Some(on) => {
                    rdp.options.monitors = if on {
                        MonitorPolicy::All
                    } else {
                        MonitorPolicy::Primary
                    };
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "dynamic resolution" => match flag(kind, value) {
                Some(on) => {
                    rdp.options.dynamic_resolution = on;
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            // Two spellings of one setting across Windows versions. Both
            // mapping to the same field is agreement, not a conflict.
            "administrative session" | "connect to console" => match flag(kind, value) {
                Some(on) => {
                    rdp.console_session = rdp.console_session || on;
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "disable wallpaper" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.disable_wallpaper = on;
                },
                &mut rdp,
            ),
            "disable themes" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.disable_theming = on;
                },
                &mut rdp,
            ),
            "disable full window drag" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.disable_full_window_drag = on;
                },
                &mut rdp,
            ),
            "disable menu anims" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.disable_menu_animations = on;
                },
                &mut rdp,
            ),
            "disable cursor setting" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.disable_cursor_blinking = on;
                },
                &mut rdp,
            ),
            "allow font smoothing" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.enable_font_smoothing = on;
                },
                &mut rdp,
            ),
            "allow desktop composition" => perf(
                kind,
                value,
                &mut out,
                key,
                |p, on| {
                    p.enable_desktop_composition = on;
                },
                &mut rdp,
            ),
            "keyboardhook" => match int(kind, value) {
                // 1 is "on the remote computer", which is what passthrough
                // means here. 0 (local) and 2 (only in full screen) are not.
                Some(n) => {
                    out.profile.passthrough = n == 1;
                    out.mapped.push(key.into());
                }
                None => out.ignored.push(key.into()),
            },
            "smart sizing" => match flag(kind, value) {
                Some(true) => {
                    out.profile.scaling_mode = "aspect-fit".into();
                    out.mapped.push(key.into());
                }
                Some(false) => out.mapped.push(key.into()),
                None => out.ignored.push(key.into()),
            },
            "connection type" => match int(kind, value) {
                Some(n @ 1..=7) => {
                    out.profile.quality_pref = match n {
                        1 | 2 => "low",
                        3..=5 => "medium",
                        _ => "high",
                    }
                    .into();
                    out.warnings.push(format!(
                        "the file's connection type {n} was read as quality \
                         \"{}\"; check it in the editor",
                        out.profile.quality_pref
                    ));
                    out.mapped.push(key.into());
                }
                _ => out.ignored.push(key.into()),
            },
            "desktopwidth" | "desktopheight" => {
                // Collected below, once both are known.
                out.mapped.push(key.into());
            }
            "gatewayhostname" => {
                gateway_host = trimmed(value);
                out.mapped.push(key.into());
            }
            "gatewayusagemethod" => {
                // 0 never, 1 always, 2 detect, 4 default. "Never" is a file
                // saying not to use the gateway it also names, so honour it
                // rather than recording a gateway the file disabled.
                gateway_enabled = int(kind, value) != Some(0);
                out.mapped.push(key.into());
            }
            "gatewaycredentialssource" => {
                // MS-TSGU distinguishes several sources; `GatewayOptions` has
                // only "reuse the session credentials or prompt separately",
                // so anything other than 0 (ask for a password) is recorded as
                // a warning rather than guessed into that boolean.
                if int(kind, value) != Some(0) {
                    out.warnings.push(
                        "the file's gateway credential source is not a plain password \
                         prompt; the gateway will ask again when RD Gateway support lands"
                            .into(),
                    );
                }
                out.ignored.push(key.into());
            }
            "alternate full address" => {
                out.warnings.push(
                    "the file names a second address as a fallback, which a profile has \
                     nowhere to put; only the main address was imported"
                        .into(),
                );
                out.ignored.push(key.into());
            }
            "authentication level" => {
                // 0 connect anyway, 1 do not connect, 2 warn, 3 unspecified.
                // None of them is our model: we pin the certificate on first
                // use. So the value is recorded and nothing is weakened, which
                // is the one mapping where refusing to honour the file is the
                // safe answer.
                out.warnings.push(
                    "this app checks a server's certificate by pinning it the first time, \
                     so the file's authentication level was not applied"
                        .into(),
                );
                out.ignored.push(key.into());
            }
            "screen mode id" => {
                out.warnings.push(
                    "whether the session opens windowed or full screen is a window \
                     setting rather than part of the profile, so it was not imported"
                        .into(),
                );
                out.ignored.push(key.into());
            }
            "password 51" => {
                // Never read, never decoded, never logged. Only the key name
                // reaches this message.
                out.warnings.push(
                    "the file contains a saved password, which cannot be imported: it is \
                     encrypted for the Windows account that wrote it"
                        .into(),
                );
                out.ignored.push(key.into());
            }
            "signature" | "signscope" => {
                // We do not verify RDP file signatures, so we do not display
                // one as though it meant something.
                out.ignored.push(key.into());
            }
            _ => out.ignored.push(key.into()),
        }
    }

    // The size request needs both halves, so it is resolved after the loop.
    let width = settings.get("desktopwidth").and_then(|(k, v)| int(*k, v));
    let height = settings.get("desktopheight").and_then(|(k, v)| int(*k, v));
    if let (Some(w), Some(h)) = (width, height) {
        match (dimension(w), dimension(h)) {
            (Some(w), Some(h)) => out.desktop_size = Some((w, h)),
            // Dropped with a warning rather than clamped silently: a clamped
            // value looks deliberate and the user never learns their file said
            // something else.
            _ => out.warnings.push(format!(
                "the file asks for a {w} by {h} desktop, which is outside \
                 {MIN_DESKTOP_DIM} to {MAX_DESKTOP_DIM}, so the size was not imported"
            )),
        }
    }

    if let Some(host) = gateway_host {
        if gateway_enabled {
            // Microsoft writes the gateway's port into the host name rather
            // than into a key of its own, and 443 is the default.
            let (host, port, _) = split_address(&host);
            // `GatewayOptions` is `#[non_exhaustive]`, so it cannot be built
            // with a struct literal or with functional record update from
            // outside `remote-core`.
            #[allow(clippy::field_reassign_with_default)]
            let gateway = {
                let mut g = GatewayOptions::default();
                g.host = host;
                g.port = port.unwrap_or(443);
                g.separate_credentials = false;
                g
            };
            rdp.options.gateway = Some(gateway);
            out.warnings.push(
                "the file uses an RD Gateway. The setting is kept, and connecting through \
                 a gateway is not supported yet, so this profile will refuse to connect \
                 rather than reaching the server directly"
                    .into(),
            );
        } else {
            out.warnings.push(
                "the file names an RD Gateway and also turns it off, so it was not imported".into(),
            );
        }
    }

    // The friendly name is what the user has been calling the file.
    let stem = file_name
        .map(|n| n.trim_end_matches(".rdp").trim_end_matches(".RDP").trim())
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    out.profile.friendly_name = stem.unwrap_or_else(|| out.profile.address.clone());

    let blob = rdp.to_json()?;
    if blob.len() > MAX_RDP_SETTINGS_BYTES {
        return Err(Error::RdpFileRefused(format!(
            "the settings in this file come to {} bytes, over the \
             {MAX_RDP_SETTINGS_BYTES} byte limit",
            blob.len()
        )));
    }
    out.profile.rdp_settings = Some(blob);
    out.mapped.sort();
    out.mapped.dedup();
    out.ignored.sort();
    out.ignored.dedup();
    Ok(out)
}

/// A file that launches a RemoteApp does something materially different from
/// opening a desktop, and importing it as a plain desktop connection would
/// quietly give the user something else.
fn refuse_remote_app(settings: &BTreeMap<String, (char, String)>) -> Result<()> {
    let mode_on = settings
        .get("remoteapplicationmode")
        .and_then(|(k, v)| int(*k, v))
        == Some(1);
    let program = [
        "remoteapplicationprogram",
        "remoteapplicationcmdline",
        "alternate shell",
    ]
    .iter()
    .any(|key| {
        settings
            .get(*key)
            .is_some_and(|(_, v)| !v.trim().is_empty())
    });
    if mode_on || program {
        return Err(Error::RdpFileRefused(
            "it starts a single RemoteApp program rather than a desktop session, which \
             this app does not support"
                .into(),
        ));
    }
    Ok(())
}

/// Split one line into its key, type letter and value.
///
/// Splits on the first two colons only: keys contain spaces and values contain
/// colons, so anything cleverer would break `full address:s:host:3389`.
/// `None` for a line with fewer than two colons or an unknown type letter,
/// which the caller counts rather than guessing at.
fn split_line(line: &str) -> Option<(String, char, String)> {
    let mut parts = line.splitn(3, ':');
    let key = parts.next()?.trim();
    let kind = parts.next()?.trim();
    let value = parts.next()?;
    if key.is_empty() || kind.len() != 1 {
        return None;
    }
    let kind = kind.chars().next()?.to_ascii_lowercase();
    if !matches!(kind, 's' | 'i' | 'b') {
        return None;
    }
    Some((key.to_ascii_lowercase(), kind, value.trim().to_string()))
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`. A missing port means the
/// caller's default. A port that is not a port leaves the address and raises
/// a warning: the address is the useful half and it is still right.
fn split_address(value: &str) -> (String, Option<u16>, Option<String>) {
    let value = value.trim();
    let (host, port_text) = if let Some(rest) = value.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inside, after)) => (inside.trim(), after.trim().strip_prefix(':')),
            None => (rest.trim(), None),
        }
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) => (host.trim(), Some(port.trim())),
            None => (value, None),
        }
    };
    let host = host.to_string();
    match port_text {
        None => (host, None, None),
        Some(text) => match text.parse::<u16>() {
            Ok(0) | Err(_) => (
                host,
                None,
                Some(format!(
                    "the file's address carries {text:?} as a port, which is not one, \
                     so the default 3389 was kept"
                )),
            ),
            Ok(port) => (host, Some(port), None),
        },
    }
}

/// An `i` value. A non-numeric one is `None`, which every caller turns into
/// "ignored and counted" rather than a default that looks deliberate.
fn int(kind: char, value: &str) -> Option<i64> {
    if kind != 'i' {
        return None;
    }
    value.trim().parse::<i64>().ok()
}

/// An `i` value used as a boolean.
fn flag(kind: char, value: &str) -> Option<bool> {
    match int(kind, value) {
        Some(0) => Some(false),
        Some(1) => Some(true),
        _ => None,
    }
}

fn dimension(value: i64) -> Option<u32> {
    let value = u32::try_from(value).ok()?;
    (MIN_DESKTOP_DIM..=MAX_DESKTOP_DIM)
        .contains(&value)
        .then_some(value)
}

fn trimmed(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn set_depth(rdp: &mut RdpSettings, depth: RdpColorDepth, out: &mut RdpImport, key: &str) {
    rdp.options.color_depth = depth;
    out.mapped.push(key.to_string());
}

fn set_audio(rdp: &mut RdpSettings, mode: AudioMode, out: &mut RdpImport, key: &str) {
    rdp.options.audio = mode;
    out.mapped.push(key.to_string());
}

fn perf(
    kind: char,
    value: &str,
    out: &mut RdpImport,
    key: &str,
    set: impl FnOnce(&mut remote_core::PerformanceFlags, bool),
    rdp: &mut RdpSettings,
) {
    match flag(kind, value) {
        Some(on) => {
            set(&mut rdp.options.performance, on);
            out.mapped.push(key.to_string());
        }
        None => out.ignored.push(key.to_string()),
    }
}

/// Decode the file's bytes into text.
///
/// `mstsc` writes UTF-16LE with a BOM and CRLF endings. Files from other tools,
/// and files people paste together by hand, are commonly UTF-8 with or without
/// a BOM. Invalid sequences are replaced rather than rejected: a single bad
/// byte in one value should not lose the user the other forty settings, and
/// every value is bounds checked and range checked after decoding anyway.
fn decode(bytes: &[u8]) -> String {
    match bytes {
        [0xff, 0xfe, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xfe, 0xff, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xef, 0xbb, 0xbf, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        // No BOM. A UTF-16 file without one still has a NUL in its second or
        // first byte, because every `.rdp` file starts with an ASCII key.
        [a, b, ..] if *b == 0 && *a != 0 => utf16(bytes, u16::from_le_bytes),
        [a, b, ..] if *a == 0 && *b != 0 => utf16(bytes, u16::from_be_bytes),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Decode UTF-16 with the given byte order, replacing anything unpaired. A
/// trailing odd byte is dropped rather than being an error.
fn utf16(bytes: &[u8], order: fn([u8; 2]) -> u16) -> String {
    let units = bytes.chunks_exact(2).map(|pair| order([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `mstsc` writes: UTF-16LE with a BOM and CRLF endings.
    fn utf16le(text: &str) -> Vec<u8> {
        let mut out = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn utf16be(text: &str) -> Vec<u8> {
        let mut out = vec![0xfe, 0xff];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out
    }

    fn parse(text: &str) -> RdpImport {
        parse_rdp_file(text.as_bytes(), Some("Office PC.rdp")).unwrap()
    }

    fn settings_of(import: &RdpImport) -> RdpSettings {
        RdpSettings::parse(import.profile.rdp_settings.as_deref())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn a_file_from_mstsc_parses() {
        let text = "full address:s:server.example:3389\r\n\
                    username:s:CORP\\alice\r\n\
                    domain:s:CORP\r\n\
                    session bpp:i:32\r\n\
                    redirectclipboard:i:1\r\n";
        let import = parse_rdp_file(&utf16le(text), Some("Office PC.rdp")).unwrap();
        assert_eq!(import.profile.address, "server.example");
        assert_eq!(import.profile.port, 3389);
        assert_eq!(import.profile.protocol, "rdp");
        assert_eq!(import.profile.friendly_name, "Office PC");
        assert_eq!(import.username.as_deref(), Some("CORP\\alice"));
        let settings = settings_of(&import);
        assert_eq!(settings.options.domain.as_deref(), Some("CORP"));
        assert_eq!(settings.options.color_depth, RdpColorDepth::Bpp32);
        assert!(settings.clipboard);
    }

    #[test]
    fn every_encoding_we_promise_to_read() {
        let text = "full address:s:host.example\nsession bpp:i:24\n";
        for bytes in [
            utf16le(text),
            utf16be(text),
            text.as_bytes().to_vec(),
            {
                let mut b = vec![0xef, 0xbb, 0xbf];
                b.extend_from_slice(text.as_bytes());
                b
            },
            // UTF-16LE with no BOM at all.
            {
                let mut b = utf16le(text);
                b.drain(0..2);
                b
            },
        ] {
            let import = parse_rdp_file(&bytes, None).unwrap();
            assert_eq!(import.profile.address, "host.example");
            assert_eq!(
                settings_of(&import).options.color_depth,
                RdpColorDepth::Bpp24
            );
        }
    }

    #[test]
    fn lone_cr_line_endings_parse() {
        let import = parse("full address:s:host.example\rsession bpp:i:16\r");
        assert_eq!(import.profile.address, "host.example");
        assert_eq!(
            settings_of(&import).options.color_depth,
            RdpColorDepth::Bpp16
        );
    }

    #[test]
    fn an_empty_file_is_a_warning_not_an_error() {
        let import = parse_rdp_file(b"", Some("Empty.rdp")).unwrap();
        assert!(import.profile.address.is_empty());
        assert!(!import.warnings.is_empty());
    }

    #[test]
    fn an_oversize_file_is_refused_before_parsing() {
        let big = vec![b'x'; MAX_RDP_FILE_BYTES + 1];
        assert!(matches!(
            parse_rdp_file(&big, None),
            Err(Error::RdpFileRefused(_))
        ));
    }

    #[test]
    fn invalid_utf8_in_a_value_is_replaced_not_fatal() {
        let mut bytes = b"full address:s:host.example\nusername:s:".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, 0x41]);
        bytes.push(b'\n');
        // A leading `f` means no BOM sniffing kicks in, so this is UTF-8.
        let import = parse_rdp_file(&bytes, None).unwrap();
        assert_eq!(import.profile.address, "host.example");
        assert!(import.username.is_some());
    }

    #[test]
    fn addresses_of_every_shape() {
        for (value, address, port) in [
            ("server.example:3389", "server.example", 3389),
            ("server.example", "server.example", 3389),
            ("[2001:db8::1]:3390", "2001:db8::1", 3390),
            ("[2001:db8::1]", "2001:db8::1", 3389),
            ("10.0.0.5:13389", "10.0.0.5", 13389),
        ] {
            let import = parse(&format!("full address:s:{value}\n"));
            assert_eq!(import.profile.address, address, "{value}");
            assert_eq!(import.profile.port, port, "{value}");
        }
    }

    #[test]
    fn an_impossible_port_keeps_the_address_and_warns() {
        for value in ["host.example:0", "host.example:65536", "host.example:-1"] {
            let import = parse(&format!("full address:s:{value}\n"));
            assert_eq!(import.profile.address, "host.example", "{value}");
            assert_eq!(import.profile.port, 3389, "{value}");
            assert!(!import.warnings.is_empty(), "{value}");
        }
    }

    #[test]
    fn malformed_lines_are_counted_not_guessed() {
        let import = parse(
            "no colons here\n\
             one:colon\n\
             full address:x:host.example\n\
             session bpp:i:not-a-number\n",
        );
        assert_eq!(import.unparseable, 3, "{:?}", import.ignored);
        assert!(import.profile.address.is_empty());
        assert!(import.ignored.iter().any(|k| k == "session bpp"));
        // The default survives: a bad value must not look like a choice.
        assert_eq!(
            settings_of(&import).options.color_depth,
            RdpColorDepth::Auto
        );
    }

    #[test]
    fn the_last_occurrence_of_a_key_wins_and_case_does_not_matter() {
        let import = parse(
            "full address:s:first.example\n\
             FULL ADDRESS:s:second.example\n",
        );
        assert_eq!(import.profile.address, "second.example");
    }

    #[test]
    fn whitespace_around_keys_and_values_is_trimmed() {
        let import = parse("  full address  :  s  :  host.example  \n");
        assert_eq!(import.profile.address, "host.example");
    }

    /// A 100 kB line must be bounded rather than parsed. The parser stays
    /// linear in the file size and the line is counted, not acted on.
    #[test]
    fn an_enormous_line_is_bounded() {
        let line = format!("full address:s:{}\n", "a".repeat(100_000));
        let import = parse(&line);
        assert_eq!(import.unparseable, 1);
        assert!(import.profile.address.is_empty());
    }

    #[test]
    fn a_desktop_size_outside_the_range_is_dropped_with_a_warning() {
        let ok = parse("desktopwidth:i:1920\ndesktopheight:i:1080\n");
        assert_eq!(ok.desktop_size, Some((1920, 1080)));

        let bad = parse("desktopwidth:i:99999\ndesktopheight:i:1080\n");
        assert_eq!(bad.desktop_size, None);
        assert!(bad.warnings.iter().any(|w| w.contains("99999")));
    }

    #[test]
    fn nla_off_produces_the_setting_and_a_visible_warning() {
        let import = parse("enablecredsspsupport:i:0\n");
        assert_eq!(settings_of(&import).options.nla, NlaPolicy::AllowFallback);
        assert!(import
            .warnings
            .iter()
            .any(|w| w.contains("Network Level Authentication")));

        let on = parse("enablecredsspsupport:i:1\n");
        assert_eq!(settings_of(&on).options.nla, NlaPolicy::Required);
    }

    #[test]
    fn authentication_level_never_weakens_the_certificate_check() {
        let import = parse("authentication level:i:0\n");
        assert!(import.ignored.iter().any(|k| k == "authentication level"));
        assert!(!import.warnings.is_empty());
    }

    #[test]
    fn a_gateway_is_recorded_with_a_warning() {
        let import = parse("gatewayhostname:s:gw.example\ngatewayusagemethod:i:1\n");
        let gateway = settings_of(&import).options.gateway.expect("recorded");
        assert_eq!(gateway.host, "gw.example");
        assert!(import.warnings.iter().any(|w| w.contains("Gateway")));

        // A file that names a gateway and turns it off does not get one.
        let off = parse("gatewayhostname:s:gw.example\ngatewayusagemethod:i:0\n");
        assert!(settings_of(&off).options.gateway.is_none());
    }

    #[test]
    fn a_remote_app_file_is_refused_whole() {
        for text in [
            "full address:s:host.example\nremoteapplicationmode:i:1\n",
            "full address:s:host.example\nremoteapplicationprogram:s:||calc\n",
            "full address:s:host.example\nalternate shell:s:cmd.exe\n",
        ] {
            match parse_rdp_file(text.as_bytes(), None) {
                Err(Error::RdpFileRefused(msg)) => {
                    assert!(msg.contains("RemoteApp"), "{msg}")
                }
                other => panic!("expected a refusal for {text:?}, got {other:?}"),
            }
        }
        // `remoteapplicationmode:i:0` with no program is an ordinary desktop.
        assert!(parse_rdp_file(b"remoteapplicationmode:i:0\n", None).is_ok());
    }

    #[test]
    fn both_spellings_of_the_console_session_agree() {
        let import = parse("administrative session:i:1\nconnect to console:i:1\n");
        assert!(settings_of(&import).console_session);
        assert_eq!(
            import
                .mapped
                .iter()
                .filter(|k| k.contains("session"))
                .count(),
            1
        );
        assert!(import.mapped.iter().any(|k| k == "connect to console"));
    }

    #[test]
    fn unknown_keys_are_ignored_and_counted() {
        let import = parse(
            "full address:s:host.example\n\
             bitmapcachepersistenable:i:1\n\
             enableworkspacereconnect:i:0\n\
             somethingnobodyhaseverheardof:s:x\n",
        );
        assert_eq!(import.ignored.len(), 3, "{:?}", import.ignored);
        assert_eq!(import.unparseable, 0);
    }

    /// The one that must not be quietly deleted: the DPAPI blob is never read,
    /// never decoded and never repeated anywhere in the result.
    #[test]
    fn a_password_blob_is_never_read() {
        let hex = "01000000d08c9ddf0115d1118c7a00c04fc297eb".repeat(4);
        let import = parse(&format!(
            "full address:s:host.example\npassword 51:b:{hex}\n"
        ));
        let rendered = format!("{import:?}");
        let json = serde_json::to_string(&import).unwrap();
        assert!(!rendered.contains(&hex), "Debug leaked the blob");
        assert!(!json.contains(&hex), "the payload leaked the blob");
        assert!(!import
            .profile
            .rdp_settings
            .as_deref()
            .unwrap()
            .contains(&hex));
        assert!(import
            .warnings
            .iter()
            .any(|w| w.contains("saved password") && !w.contains(&hex)));
        // The key name is recorded; the value is not.
        assert!(import.ignored.iter().any(|k| k == "password 51"));
    }

    /// V3-B: no `.rdp` file, however constructed, produces a draft with legacy
    /// TLS on. The format has no key for it, and an invented one is counted as
    /// unknown rather than honoured.
    #[test]
    fn an_import_never_enables_legacy_tls() {
        let import = parse(
            "full address:s:host.example\n\
             authentication level:i:0\n\
             enablecredsspsupport:i:0\n\
             negotiate security layer:i:0\n\
             legacytls:i:1\n\
             tlsversion:s:1.0\n",
        );
        assert!(!settings_of(&import).options.legacy_tls);
        for invented in ["legacytls", "tlsversion", "negotiate security layer"] {
            assert!(
                import.ignored.iter().any(|k| k == invented),
                "{invented} must be counted as ignored"
            );
            assert!(
                !import.mapped.iter().any(|k| k == invented),
                "{invented} must not be mapped"
            );
        }
    }

    /// The draft is a whole `HostProfile` because `save_host` deserializes a
    /// whole one. A draft missing a field is rejected at save time, which is a
    /// confusing place to find out.
    #[test]
    fn the_draft_is_a_whole_profile_that_survives_a_round_trip() {
        let import = parse("full address:s:host.example\n");
        let json = serde_json::to_string(&import.profile).unwrap();
        let back: HostProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, "host.example");
        assert_eq!(back.protocol, "rdp");
        assert!(back.rdp_settings.is_some());
    }

    #[test]
    fn a_file_with_no_name_falls_back_to_the_address() {
        let import = parse_rdp_file(b"full address:s:host.example\n", None).unwrap();
        assert_eq!(import.profile.friendly_name, "host.example");
    }

    #[test]
    fn quality_and_scaling_reach_the_profile() {
        let import = parse("connection type:i:7\nsmart sizing:i:1\nkeyboardhook:i:1\n");
        assert_eq!(import.profile.quality_pref, "high");
        assert_eq!(import.profile.scaling_mode, "aspect-fit");
        assert!(import.profile.passthrough);

        let slow = parse("connection type:i:1\nkeyboardhook:i:2\n");
        assert_eq!(slow.profile.quality_pref, "low");
        assert!(!slow.profile.passthrough);
    }
}
