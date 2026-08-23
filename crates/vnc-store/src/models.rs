use crate::now_ts;
use remote_core::ProtocolKind;

/// `serde` default for [`HostProfile::protocol`].
///
/// A webview that predates the protocol column omits the field, and
/// `save_host` deserializes a whole [`HostProfile`], so without this every
/// save from such a webview would fail on a missing field. The value it omits
/// is the value it meant: a build that did not know about RDP only ever
/// created VNC profiles.
fn vnc_protocol() -> String {
    ProtocolKind::Vnc.as_str().to_string()
}

/// A saved host profile. Mirrors the `hosts` table (PRD 03 §5), plus the
/// joined tag ids from `host_tags`.
///
/// Never contains a secret: `has_password` is only a flag, the credential
/// lives in the keychain / encrypted file keyed by `id`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostProfile {
    /// UUID; also the keyring account key.
    pub id: String,
    pub friendly_name: String,
    pub address: String,
    pub port: u16,
    pub group_id: Option<String>,
    pub os_hint: Option<String>,
    pub server_hint: Option<String>,
    pub security_pref: Option<String>,
    /// "auto" | "high" | "medium" | "low" | "bw"
    pub quality_pref: String,
    pub color_depth: Option<i64>,
    /// "fit" | "aspect-fit" | "actual" | "remote-resize"
    pub scaling_mode: String,
    /// "auto" | "keysym" | "unicode" | "scancode"
    pub keyboard_mode: String,
    pub passthrough: bool,
    pub view_only: bool,
    /// JSON blob: `{enabled, host, user, port, auth, ...}`
    pub ssh_tunnel: Option<String>,
    pub wol_mac: Option<String>,
    pub wol_broadcast: Option<String>,
    pub network_id: Option<String>,
    pub cert_pin: Option<String>,
    pub has_password: bool,
    pub thumbnail_at: Option<i64>,
    pub last_connected: Option<i64>,
    pub connect_count: i64,
    /// Tag ids, joined from `host_tags`.
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,

    /// Which protocol this profile speaks: `"vnc"` or `"rdp"`.
    ///
    /// Stored as a string rather than an enum for the same reason
    /// [`CertPin::scheme`] is: a value written by a newer build must stay
    /// readable by an older one, and the store is not the layer that decides
    /// which protocols exist. The shell parses it with `ProtocolKind::parse`
    /// and refuses to connect a profile whose protocol it does not implement,
    /// which is a clear error rather than a silent fallback to VNC
    /// (PRDRDP/08 §2.3).
    #[serde(default = "vnc_protocol")]
    pub protocol: String,

    /// JSON blob of RDP-only options, `None` for a VNC profile.
    ///
    /// Opaque to the store, which never parses it, so a profile whose blob is
    /// malformed is still listable, editable and deletable rather than a tile
    /// that vanished (PRDRDP/08 §2.4). [`crate::RdpSettings::parse`] is the
    /// typed reader, and it is a separate call on purpose.
    ///
    /// `None` and `Some("{}")` are different things and must stay different:
    /// "not an RDP profile" is not "an RDP profile with nothing set".
    #[serde(default)]
    pub rdp_settings: Option<String>,
}

impl HostProfile {
    /// A blank profile for `protocol`, carrying that protocol's default port.
    ///
    /// The port lives on [`ProtocolKind`] rather than here (PRDRDP/00 R8):
    /// duplicating 3389 in the store would be a second place for it to drift.
    pub fn for_protocol(protocol: ProtocolKind) -> Self {
        Self {
            protocol: protocol.as_str().to_string(),
            port: protocol.default_port(),
            ..Default::default()
        }
    }

    /// The parsed protocol, or `None` for a value this build does not know.
    ///
    /// `None` is a refusal, never a fallback: connecting a `"spice"` profile
    /// as VNC would send an RFB handshake at something else and report a
    /// confusing error.
    pub fn protocol_kind(&self) -> Option<ProtocolKind> {
        ProtocolKind::parse(&self.protocol)
    }
}

impl Default for HostProfile {
    fn default() -> Self {
        let now = now_ts();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            friendly_name: String::new(),
            address: String::new(),
            port: 5900,
            group_id: None,
            os_hint: None,
            server_hint: None,
            security_pref: None,
            quality_pref: "auto".to_string(),
            color_depth: None,
            scaling_mode: "fit".to_string(),
            keyboard_mode: "auto".to_string(),
            passthrough: false,
            view_only: false,
            ssh_tunnel: None,
            wol_mac: None,
            wol_broadcast: None,
            network_id: None,
            cert_pin: None,
            has_password: false,
            thumbnail_at: None,
            last_connected: None,
            connect_count: 0,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            protocol: vnc_protocol(),
            rdp_settings: None,
        }
    }
}

/// A host group / folder (nestable via `parent_id`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub sort: i64,
}

/// A colored user tag.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
    pub id: String,
    pub name: String,
    pub color: String,
}

/// One connection-history record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: i64,
    pub host_id: String,
    pub connected_at: i64,
    pub duration_s: Option<i64>,
    pub security_type: Option<String>,
    pub disconnect_reason: Option<String>,
    /// Which protocol the recorded session spoke, `"vnc"` or `"rdp"`.
    ///
    /// Rows written before the column existed read as `"vnc"`, which is what
    /// they were. The `security_type` vocabulary for an RDP row is
    /// `nla-ntlm`, `tls` and, from phase 3, `nla-kerberos` (PRDRDP/00 R12);
    /// the protocol is a separate column so neither has to be parsed out of
    /// the other.
    #[serde(default = "vnc_protocol")]
    pub protocol: String,
}

/// A TOFU pin for one server key, keyed by `(host, port, scheme)`. Pins are
/// not secrets and live in SQLite.
///
/// `scheme` says *which* key the fingerprint describes, `"tls"` for a
/// VeNCrypt/X.509 SubjectPublicKeyInfo, `"ra2"` for a RealVNC RSA public key.
/// One endpoint can offer both, and the two fingerprints are unrelated: they
/// must never be compared against each other, or a server offering both would
/// look like it had changed identity. The store treats the scheme as an opaque
/// string, so a value it does not recognise matches nothing instead of
/// aliasing onto a known one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertPin {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub sha256_spki: String,
    pub subject: String,
    pub first_trusted_at: i64,
    pub last_seen_at: i64,
    pub security_type: Option<String>,
}

/// The per-host credential blob stored in one keyring entry (or one map slot
/// of the encrypted file), serialized as JSON.
///
/// The `Debug` impl redacts all values so secrets never reach logs or crash
/// reports.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredentials {
    // NOTE: this struct is BOTH the IPC shape (camelCase, like every other
    // model) and the at-rest keychain/vault JSON. The snake_case `alias`es
    // keep blobs written before the camelCase switch readable, so upgrading
    // never silently orphans a saved password.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "vnc_password"
    )]
    pub vnc_password: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "vencrypt_user"
    )]
    pub vencrypt_user: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "vencrypt_pass"
    )]
    pub vencrypt_pass: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "ssh_passphrase"
    )]
    pub ssh_passphrase: Option<String>,

    // The three RDP fields carry no snake_case `alias`. The aliases above
    // exist for one specific reason, blobs written before the camelCase
    // switch, and no such blob can contain a field that did not exist then.
    // An alias here would imply a history that is not there (PRDRDP/08 §3.2).
    /// RDP account name. Either a bare `sAMAccountName` (with the domain in
    /// [`StoredCredentials::rdp_domain`]) or a UPN like `alice@corp.example`,
    /// in which case `rdp_domain` stays `None`. Stored as the user typed it:
    /// rewriting a UPN into a down-level pair is a guess about the server's
    /// directory that we are not entitled to make.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_user: Option<String>,

    /// Windows domain or AD realm. `None` for a workgroup machine, a local
    /// account, or a UPN in `rdp_user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_domain: Option<String>,

    /// RDP password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_password: Option<String>,
}

impl StoredCredentials {
    /// Record an RDP identity that one successful exchange proved.
    ///
    /// Replaces the whole triple rather than merging it field by field: the
    /// three values were proven together, and keeping an old domain beside a
    /// new username would store a credential that has never worked anywhere
    /// (PRDRDP/08 §3.4). An empty username or domain clears the field, it does
    /// not store `""`.
    ///
    /// Never touches a VNC or SSH field. That is the invariant the two tests
    /// either side of it exist for: saving an RDP password on a profile that
    /// already holds a VNC one leaves the VNC one exactly where it was.
    ///
    /// This lives here rather than in the shell because both merges have to
    /// agree about which fields belong to which protocol, and the shell's
    /// `PendingCredentialSave::merge_into` is the only caller that can prove
    /// a password. It calls this after `SessionState::Connected`, and for a
    /// non-NLA session only once a logon notification has arrived
    /// (PRDRDP/00 R14); nothing here can enforce that, and nothing here
    /// should pretend to.
    pub fn set_rdp_identity(&mut self, user: Option<&str>, domain: Option<&str>, password: &str) {
        self.rdp_user = non_empty(user);
        self.rdp_domain = non_empty(domain);
        self.rdp_password = Some(password.to_string());
    }

    /// Record a VNC credential the server accepted.
    ///
    /// A username means an identity-carrying method (VeNCrypt `*Plain`, Apple
    /// DH, MSLogonII, RA2 subtype 1), so it goes in the `vencrypt_*` pair;
    /// password-only methods use `vnc_password`. Never touches an RDP field.
    pub fn set_vnc_credential(&mut self, username: Option<&str>, password: &str) {
        match non_empty(username) {
            Some(user) => {
                self.vencrypt_user = Some(user);
                self.vencrypt_pass = Some(password.to_string());
            }
            None => self.vnc_password = Some(password.to_string()),
        }
    }

    /// True when this blob holds something the given protocol could use.
    ///
    /// `hosts.has_password` stays a single boolean meaning "some credential
    /// exists for this host id"; the precision belongs at the call site, which
    /// knows which protocol it is about (PRDRDP/08 §3.5).
    pub fn has_for(&self, protocol: ProtocolKind) -> bool {
        match protocol {
            ProtocolKind::Rdp => self.rdp_password.is_some(),
            ProtocolKind::Vnc => self.vnc_password.is_some() || self.vencrypt_pass.is_some(),
            // `ProtocolKind` is `#[non_exhaustive]`. A protocol this build
            // does not know has no field here, so it has no credential here.
            _ => false,
        }
    }
}

/// `Some(trimmed)` for a value with content, `None` for empty or absent.
fn non_empty(v: Option<&str>) -> Option<String> {
    let v = v?;
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

#[cfg(test)]
thread_local! {
    /// Counts [`StoredCredentials::zeroize`] calls on this thread, so a test
    /// can assert that locking the vault wiped every entry rather than merely
    /// dropping the map.
    ///
    /// Safe Rust cannot read freed memory, so "the heap is clean" is not a
    /// testable claim. This makes the *structural* claim testable instead
    /// (PRDRDP/08 §3.6). Per thread rather than global because the test
    /// harness runs tests in parallel and a global counter would count
    /// somebody else's wipes.
    pub(crate) static ZEROIZE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The number of wipes this thread has performed.
#[cfg(test)]
pub(crate) fn zeroize_calls() -> usize {
    ZEROIZE_CALLS.with(std::cell::Cell::get)
}

/// Wipe every value in place.
///
/// Deliberately `Zeroize` by hand rather than `#[derive(ZeroizeOnDrop)]`: a
/// `Drop` impl makes it illegal to move fields out of the struct, and the
/// shell's `save_password` merge does exactly that. The derive would break
/// that build in a way that invites the wrong fix, cloning everything, which
/// multiplies the copies in memory rather than reducing them.
///
/// The honest limit: this wipes the buffer each `String` currently owns. A
/// `String` that was reallocated while it grew left its earlier, smaller
/// buffer freed and unwiped, and `serde_json` grows its buffer while it
/// serializes. This narrows the window; it does not close it. What carries the
/// weight is the OS keychain, where the secret is never in our address space
/// at rest.
impl zeroize::Zeroize for StoredCredentials {
    fn zeroize(&mut self) {
        #[cfg(test)]
        ZEROIZE_CALLS.with(|n| n.set(n.get() + 1));
        for field in [
            &mut self.vnc_password,
            &mut self.vencrypt_user,
            &mut self.vencrypt_pass,
            &mut self.ssh_passphrase,
            &mut self.rdp_user,
            &mut self.rdp_domain,
            &mut self.rdp_password,
        ] {
            if let Some(value) = field.as_mut() {
                value.zeroize();
            }
            *field = None;
        }
    }
}

impl std::fmt::Debug for StoredCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redact(v: &Option<String>) -> &'static str {
            if v.is_some() {
                "Some(***)"
            } else {
                "None"
            }
        }
        // Every field is named and every value is redacted. A field Debug
        // forgets is invisible in a bug report; a field Debug prints is a
        // leak. `debug_covers_every_credential_field_and_leaks_none` walks the
        // serialized shape to hold both halves as fields are added.
        f.debug_struct("StoredCredentials")
            .field("vnc_password", &redact(&self.vnc_password))
            .field("vencrypt_user", &redact(&self.vencrypt_user))
            .field("vencrypt_pass", &redact(&self.vencrypt_pass))
            .field("ssh_passphrase", &redact(&self.ssh_passphrase))
            .field("rdp_user", &redact(&self.rdp_user))
            .field("rdp_domain", &redact(&self.rdp_domain))
            .field("rdp_password", &redact(&self.rdp_password))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_sensible() {
        let p = HostProfile::default();
        assert_eq!(p.port, 5900);
        assert_eq!(p.quality_pref, "auto");
        assert_eq!(p.scaling_mode, "fit");
        assert_eq!(p.keyboard_mode, "auto");
        assert!(!p.has_password);
        assert!(uuid::Uuid::parse_str(&p.id).is_ok());
        let q = HostProfile::default();
        assert_ne!(p.id, q.id, "each default profile gets a fresh uuid");
    }

    /// The webview builds these payloads by hand (`save_group` / `save_tag`
    /// take a whole record), so the contract is asserted here rather than
    /// discovered at runtime.
    ///
    /// This is the regression test for "new groups and tags are never
    /// created": the Library used to send `{"name":"Office"}`, serde rejected
    /// the whole call for the missing fields, and the failure was swallowed on
    /// the way back, so nothing appeared and nothing was reported.
    #[test]
    fn group_and_tag_need_every_field_the_ui_now_sends() {
        let g: Group =
            serde_json::from_str(r#"{"id":"8f14e45f","name":"Office","parentId":null,"sort":2}"#)
                .expect("the payload the Library sends must deserialize");
        assert_eq!(g.name, "Office");
        assert_eq!(g.parent_id, None);
        assert_eq!(g.sort, 2);

        // r##"..."## throughout: the colours are `#rrggbb`, and `"#` would
        // close an ordinary raw string.
        let t: Tag = serde_json::from_str(r##"{"id":"c9f0f895","name":"prod","color":"#e5544b"}"##)
            .expect("the payload the Library sends must deserialize");
        assert_eq!(t.name, "prod");
        assert_eq!(t.color, "#e5544b");

        assert!(
            serde_json::from_str::<Group>(r#"{"name":"Office"}"#).is_err(),
            "a name-only group must still be rejected, that is what broke"
        );
        assert!(
            serde_json::from_str::<Tag>(r##"{"name":"prod","color":"#e5544b"}"##).is_err(),
            "a tag without an id must still be rejected"
        );
    }

    /// `camelCase` to `snake_case`, for comparing a serde key with the name
    /// the hand written `Debug` prints.
    fn camel_to_snake(key: &str) -> String {
        let mut out = String::with_capacity(key.len() + 4);
        for c in key.chars() {
            if c.is_ascii_uppercase() {
                out.push('_');
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Every field of `StoredCredentials` must be both redacted and
    /// *mentioned* by `Debug`. Redaction alone is not enough: a field `Debug`
    /// forgets is invisible in a bug report, and a field `Debug` prints is a
    /// leak. This walks the serialized shape rather than a hand written list,
    /// so adding a field without touching `Debug` fails here instead of in
    /// production.
    ///
    /// The struct literal has no `..Default::default()` on purpose: an eighth
    /// field breaks this test at compile time, which is the point.
    #[test]
    fn debug_covers_every_credential_field_and_leaks_none() {
        let creds = StoredCredentials {
            vnc_password: Some("leak-1".into()),
            vencrypt_user: Some("leak-2".into()),
            vencrypt_pass: Some("leak-3".into()),
            ssh_passphrase: Some("leak-4".into()),
            rdp_user: Some("leak-5".into()),
            rdp_domain: Some("leak-6".into()),
            rdp_password: Some("leak-7".into()),
        };
        let rendered = format!("{creds:?}");
        for i in 1..=7 {
            assert!(
                !rendered.contains(&format!("leak-{i}")),
                "Debug leaked: {rendered}"
            );
        }
        assert!(rendered.contains("***"));

        let json = serde_json::to_value(&creds).unwrap();
        let keys: Vec<String> = json.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 7, "every field must serialize: {keys:?}");
        for key in keys {
            let snake = camel_to_snake(&key);
            assert!(
                rendered.contains(&snake),
                "Debug does not mention `{snake}`; a field was added without redacting it"
            );
        }
    }

    #[test]
    fn an_rdp_save_never_touches_a_vnc_credential() {
        let mut creds = StoredCredentials {
            vnc_password: Some("vnc-pass".into()),
            vencrypt_user: Some("alice".into()),
            vencrypt_pass: Some("tls-pass".into()),
            ssh_passphrase: Some("ssh-pass".into()),
            ..Default::default()
        };
        creds.set_rdp_identity(Some("bob"), Some("CORP"), "rdp-pass");

        assert_eq!(creds.vnc_password.as_deref(), Some("vnc-pass"));
        assert_eq!(creds.vencrypt_user.as_deref(), Some("alice"));
        assert_eq!(creds.vencrypt_pass.as_deref(), Some("tls-pass"));
        assert_eq!(creds.ssh_passphrase.as_deref(), Some("ssh-pass"));
        assert_eq!(creds.rdp_user.as_deref(), Some("bob"));
        assert_eq!(creds.rdp_domain.as_deref(), Some("CORP"));
        assert_eq!(creds.rdp_password.as_deref(), Some("rdp-pass"));
    }

    #[test]
    fn a_vnc_save_never_touches_an_rdp_credential() {
        let mut creds = StoredCredentials::default();
        creds.set_rdp_identity(Some("bob"), Some("CORP"), "rdp-pass");
        creds.ssh_passphrase = Some("ssh-pass".into());

        creds.set_vnc_credential(Some("alice"), "tls-pass");
        assert_eq!(creds.vencrypt_user.as_deref(), Some("alice"));
        assert_eq!(creds.vencrypt_pass.as_deref(), Some("tls-pass"));
        assert_eq!(creds.rdp_user.as_deref(), Some("bob"));
        assert_eq!(creds.rdp_domain.as_deref(), Some("CORP"));
        assert_eq!(creds.rdp_password.as_deref(), Some("rdp-pass"));

        creds.set_vnc_credential(None, "plain-pass");
        assert_eq!(creds.vnc_password.as_deref(), Some("plain-pass"));
        assert_eq!(creds.rdp_password.as_deref(), Some("rdp-pass"));
        assert_eq!(creds.ssh_passphrase.as_deref(), Some("ssh-pass"));
    }

    /// The "replace, do not merge" half of §3.4: a save whose domain is gone
    /// must clear the stored one. Keeping it would leave a username and a
    /// domain that were never proven together.
    #[test]
    fn an_rdp_save_replaces_the_whole_triple() {
        let mut creds = StoredCredentials::default();
        creds.set_rdp_identity(Some("bob"), Some("OLD"), "old-pass");
        creds.set_rdp_identity(Some("bob@corp.example"), None, "new-pass");

        assert_eq!(creds.rdp_user.as_deref(), Some("bob@corp.example"));
        assert_eq!(creds.rdp_domain, None, "a stale domain must not survive");
        assert_eq!(creds.rdp_password.as_deref(), Some("new-pass"));

        // An empty string is absence, not a value.
        creds.set_rdp_identity(Some(""), Some(""), "pass");
        assert_eq!(creds.rdp_user, None);
        assert_eq!(creds.rdp_domain, None);
    }

    #[test]
    fn has_for_answers_per_protocol() {
        use remote_core::ProtocolKind;
        let mut creds = StoredCredentials::default();
        assert!(!creds.has_for(ProtocolKind::Vnc));
        assert!(!creds.has_for(ProtocolKind::Rdp));

        creds.set_rdp_identity(Some("bob"), None, "rdp-pass");
        assert!(creds.has_for(ProtocolKind::Rdp));
        assert!(
            !creds.has_for(ProtocolKind::Vnc),
            "an RDP password is not a VNC credential"
        );

        creds.set_vnc_credential(None, "vnc-pass");
        assert!(creds.has_for(ProtocolKind::Vnc));
    }

    #[test]
    fn zeroize_clears_every_field() {
        use zeroize::Zeroize as _;
        let mut creds = StoredCredentials {
            vnc_password: Some("leak-1".into()),
            vencrypt_user: Some("leak-2".into()),
            vencrypt_pass: Some("leak-3".into()),
            ssh_passphrase: Some("leak-4".into()),
            rdp_user: Some("leak-5".into()),
            rdp_domain: Some("leak-6".into()),
            rdp_password: Some("leak-7".into()),
        };
        creds.zeroize();
        assert_eq!(
            serde_json::to_string(&creds).unwrap(),
            "{}",
            "every field skips serialization once it is None"
        );
    }

    /// A blob at the realistic platform maxima still fits the Windows
    /// credential blob cap, which is the regression guard on §3.8's table.
    #[test]
    fn a_fully_populated_blob_fits_the_platform_cap() {
        let creds = StoredCredentials {
            // 8 to 256 for a VNC password (DES truncation at one end, a
            // sensible ceiling at the other).
            vnc_password: Some("v".repeat(256)),
            vencrypt_user: Some("u".repeat(64)),
            vencrypt_pass: Some("p".repeat(256)),
            ssh_passphrase: Some("s".repeat(256)),
            // A UPN is at most 104 characters.
            rdp_user: Some("r".repeat(104)),
            // A DNS domain name is at most 255.
            rdp_domain: Some("d".repeat(255)),
            // Windows caps an interactive logon password at 127.
            rdp_password: Some("w".repeat(127)),
        };
        let len = serde_json::to_string(&creds).unwrap().len();
        assert!(
            len < crate::MAX_CREDENTIAL_BLOB,
            "a full blob is {len} bytes, over the {} byte cap",
            crate::MAX_CREDENTIAL_BLOB
        );
    }

    #[test]
    fn a_default_profile_is_vnc_and_an_rdp_profile_knows_its_port() {
        use remote_core::ProtocolKind;
        let vnc = HostProfile::default();
        assert_eq!(vnc.protocol, "vnc");
        assert_eq!(vnc.port, 5900);
        assert!(vnc.rdp_settings.is_none());
        assert_eq!(vnc.protocol_kind(), Some(ProtocolKind::Vnc));

        let rdp = HostProfile::for_protocol(ProtocolKind::Rdp);
        assert_eq!(rdp.protocol, "rdp");
        assert_eq!(rdp.port, 3389);
        assert_eq!(rdp.protocol_kind(), Some(ProtocolKind::Rdp));
    }

    /// A profile whose protocol this build does not implement is readable and
    /// refuses to be connected, rather than aliasing onto VNC.
    #[test]
    fn an_unknown_protocol_is_readable_and_never_aliases() {
        let profile = HostProfile {
            protocol: "spice".into(),
            ..Default::default()
        };
        assert_eq!(profile.protocol, "spice");
        assert_eq!(profile.protocol_kind(), None);
    }

    /// A webview that predates the protocol column still saves a profile, and
    /// what it saves is VNC. Without the serde default every save from such a
    /// webview would fail on a missing field, which is the failure
    /// `group_and_tag_need_every_field_the_ui_now_sends` records for groups.
    #[test]
    fn a_profile_without_a_protocol_field_reads_as_vnc() {
        let json = r#"{
            "id":"abc","friendlyName":"Old","address":"10.0.0.1","port":5900,
            "groupId":null,"osHint":null,"serverHint":null,"securityPref":null,
            "qualityPref":"auto","colorDepth":null,"scalingMode":"fit",
            "keyboardMode":"auto","passthrough":false,"viewOnly":false,
            "sshTunnel":null,"wolMac":null,"wolBroadcast":null,"networkId":null,
            "certPin":null,"hasPassword":false,"thumbnailAt":null,
            "lastConnected":null,"connectCount":0,"tags":[],
            "createdAt":1,"updatedAt":2
        }"#;
        let p: HostProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p.protocol, "vnc");
        assert!(p.rdp_settings.is_none());
    }
}
