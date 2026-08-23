use crate::now_ts;

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
        f.debug_struct("StoredCredentials")
            .field("vnc_password", &redact(&self.vnc_password))
            .field("vencrypt_user", &redact(&self.vencrypt_user))
            .field("vencrypt_pass", &redact(&self.vencrypt_pass))
            .field("ssh_passphrase", &redact(&self.ssh_passphrase))
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

    #[test]
    fn credentials_debug_is_redacted() {
        let c = StoredCredentials {
            vnc_password: Some("hunter2-secret".into()),
            ..Default::default()
        };
        let dbg = format!("{c:?}");
        assert!(
            !dbg.contains("hunter2"),
            "Debug must not leak secrets: {dbg}"
        );
        assert!(dbg.contains("***"));
    }
}
