use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::{now_ts, CertPin, Error, Group, HistoryEntry, HostProfile, Result, Tag};

/// Numbered migrations, applied in order. `PRAGMA user_version` records how
/// many have run; future schema changes append a new entry here.
const MIGRATIONS: &[&str] = &[
    // v1, initial schema (PRD 03 §5) + settings + cert_pins.
    r#"
    CREATE TABLE hosts (
      id            TEXT PRIMARY KEY,        -- uuid; also the keyring account key
      friendly_name TEXT NOT NULL,
      address       TEXT NOT NULL,           -- host or IP
      port          INTEGER NOT NULL DEFAULT 5900,
      group_id      TEXT REFERENCES groups(id),
      os_hint       TEXT,                    -- macos|windows|linux|qemu|unknown
      server_hint   TEXT,                    -- e.g. "TigerVNC 3.8", "macOS Screen Sharing"
      security_pref TEXT,                    -- auto|vencrypt-x509|ra2|apple-dh|vncauth|none
      quality_pref  TEXT DEFAULT 'auto',     -- auto|high|medium|low|bw
      color_depth   INTEGER,                 -- override; null = auto
      scaling_mode  TEXT DEFAULT 'fit',      -- fit|aspect-fit|actual|remote-resize
      keyboard_mode TEXT DEFAULT 'auto',     -- keysym|unicode|scancode
      passthrough   INTEGER DEFAULT 0,
      view_only     INTEGER DEFAULT 0,
      ssh_tunnel    TEXT,                    -- json: {enabled,host,user,port,auth,...}
      wol_mac       TEXT,
      wol_broadcast TEXT,
      network_id    TEXT,
      cert_pin      TEXT,                    -- sha256 SPKI for TOFU
      has_password  INTEGER DEFAULT 0,       -- secret lives in keychain, not here
      thumbnail_at  INTEGER,
      last_connected INTEGER,
      connect_count INTEGER DEFAULT 0,
      created_at    INTEGER, updated_at INTEGER
    );
    CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT, parent_id TEXT, sort INTEGER);
    CREATE TABLE tags   (id TEXT PRIMARY KEY, name TEXT, color TEXT);
    CREATE TABLE host_tags (host_id TEXT, tag_id TEXT, PRIMARY KEY(host_id, tag_id));
    CREATE TABLE history (id INTEGER PRIMARY KEY, host_id TEXT, connected_at INTEGER,
                          duration_s INTEGER, security_type TEXT, disconnect_reason TEXT);
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE cert_pins (host TEXT, port INTEGER, sha256_spki TEXT, subject TEXT,
                            first_trusted_at INTEGER, last_seen_at INTEGER,
                            security_type TEXT, PRIMARY KEY(host, port));
    CREATE INDEX idx_hosts_address ON hosts(address, port);
    CREATE INDEX idx_history_host ON history(host_id, connected_at);
    "#,
    // v2, one endpoint can authenticate with more than one kind of server
    // key, so a pin is keyed by which key it describes.
    //
    // TLS/VeNCrypt pins the X.509 SubjectPublicKeyInfo; RA2 pins the server's
    // raw RSA key. They are unrelated values for the same (host, port), so a
    // single-pin table made a server offering both look like an identity
    // change on whichever path it did not pin first.
    //
    // Every row that exists at this point was written by the TLS path (it was
    // the only writer), so it backfills as 'tls'. Dropping or mislabelling
    // them would silently re-prompt for hosts the user already trusted, which
    // is indistinguishable from the bug this migration fixes.
    r#"
    ALTER TABLE cert_pins RENAME TO cert_pins_v1;
    CREATE TABLE cert_pins (host TEXT NOT NULL, port INTEGER NOT NULL,
                            scheme TEXT NOT NULL DEFAULT 'tls',
                            sha256_spki TEXT, subject TEXT,
                            first_trusted_at INTEGER, last_seen_at INTEGER,
                            security_type TEXT, PRIMARY KEY(host, port, scheme));
    INSERT INTO cert_pins (host, port, scheme, sha256_spki, subject,
                           first_trusted_at, last_seen_at, security_type)
      SELECT host, port, 'tls', sha256_spki, subject,
             first_trusted_at, last_seen_at, security_type
      FROM cert_pins_v1;
    DROP TABLE cert_pins_v1;
    "#,
];

/// SQLite-backed persistence. `Send + Sync`: the connection is wrapped in a
/// `parking_lot::Mutex`, so the Tauri shell can hold one `Store` in managed
/// state and call it from multiple tasks.
pub struct Store {
    dir: PathBuf,
    conn: Mutex<Connection>,
}

impl Store {
    /// Opens (and migrates) the database.
    ///
    /// `data_dir` overrides the location (used by tests); `None` resolves the
    /// platform app-data directory via `directories`.
    pub fn open(data_dir: Option<PathBuf>) -> Result<Self> {
        let dir = match data_dir {
            Some(d) => d,
            None => directories::ProjectDirs::from("com", "deskvncviewer", "DeskVNCViewer")
                .ok_or(Error::NoDataDir)?
                .data_dir()
                .to_path_buf(),
        };
        std::fs::create_dir_all(&dir)?;
        std::fs::create_dir_all(dir.join("thumbnails"))?;

        let mut conn = Connection::open(dir.join("deskvnc.db"))?;
        conn.busy_timeout(Duration::from_millis(5000))?;
        // journal_mode returns a row; query it instead of pragma_update.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        Self::migrate(&mut conn)?;
        Ok(Self {
            dir,
            conn: Mutex::new(conn),
        })
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let version = version.max(0) as usize;
        for (idx, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", (idx + 1) as i64)?;
            tx.commit()?;
            tracing::info!(version = idx + 1, "applied schema migration");
        }
        Ok(())
    }

    /// The resolved data directory (DB, thumbnails, credential file live here).
    pub fn data_dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn conn_lock(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    // ---- hosts ---------------------------------------------------------

    pub fn list_hosts(&self) -> Result<Vec<HostProfile>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT * FROM hosts ORDER BY friendly_name COLLATE NOCASE, address")?;
        let mut hosts = stmt
            .query_map([], host_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        // Join tag ids in one pass.
        let mut tag_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut stmt = conn.prepare("SELECT host_id, tag_id FROM host_tags ORDER BY tag_id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (host_id, tag_id) = row?;
            tag_map.entry(host_id).or_default().push(tag_id);
        }
        for host in &mut hosts {
            if let Some(tags) = tag_map.remove(&host.id) {
                host.tags = tags;
            }
        }
        Ok(hosts)
    }

    pub fn get_host(&self, id: &str) -> Result<Option<HostProfile>> {
        let conn = self.conn.lock();
        let host = conn
            .query_row("SELECT * FROM hosts WHERE id = ?1", [id], host_from_row)
            .optional()?;
        match host {
            Some(mut h) => {
                h.tags = host_tag_ids(&conn, id)?;
                Ok(Some(h))
            }
            None => Ok(None),
        }
    }

    /// Upserts the profile (including its tag assignments). `created_at` is
    /// preserved on update; `updated_at` is set to now.
    pub fn save_host(&self, profile: &HostProfile) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let now = now_ts();
        tx.execute(
            "INSERT INTO hosts (
                id, friendly_name, address, port, group_id, os_hint, server_hint,
                security_pref, quality_pref, color_depth, scaling_mode, keyboard_mode,
                passthrough, view_only, ssh_tunnel, wol_mac, wol_broadcast, network_id,
                cert_pin, has_password, thumbnail_at, last_connected, connect_count,
                created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                       ?19,?20,?21,?22,?23,?24,?25)
             ON CONFLICT(id) DO UPDATE SET
                friendly_name=excluded.friendly_name, address=excluded.address,
                port=excluded.port, group_id=excluded.group_id, os_hint=excluded.os_hint,
                server_hint=excluded.server_hint, security_pref=excluded.security_pref,
                quality_pref=excluded.quality_pref, color_depth=excluded.color_depth,
                scaling_mode=excluded.scaling_mode, keyboard_mode=excluded.keyboard_mode,
                passthrough=excluded.passthrough, view_only=excluded.view_only,
                ssh_tunnel=excluded.ssh_tunnel, wol_mac=excluded.wol_mac,
                wol_broadcast=excluded.wol_broadcast, network_id=excluded.network_id,
                cert_pin=excluded.cert_pin, has_password=excluded.has_password,
                thumbnail_at=excluded.thumbnail_at, last_connected=excluded.last_connected,
                connect_count=excluded.connect_count, updated_at=excluded.updated_at",
            params![
                profile.id,
                profile.friendly_name,
                profile.address,
                profile.port,
                profile.group_id,
                profile.os_hint,
                profile.server_hint,
                profile.security_pref,
                profile.quality_pref,
                profile.color_depth,
                profile.scaling_mode,
                profile.keyboard_mode,
                profile.passthrough as i64,
                profile.view_only as i64,
                profile.ssh_tunnel,
                profile.wol_mac,
                profile.wol_broadcast,
                profile.network_id,
                profile.cert_pin,
                profile.has_password as i64,
                profile.thumbnail_at,
                profile.last_connected,
                profile.connect_count,
                if profile.created_at > 0 {
                    profile.created_at
                } else {
                    now
                },
                now,
            ],
        )?;
        tx.execute("DELETE FROM host_tags WHERE host_id = ?1", [&profile.id])?;
        for tag_id in &profile.tags {
            tx.execute(
                "INSERT OR IGNORE INTO host_tags (host_id, tag_id) VALUES (?1, ?2)",
                params![profile.id, tag_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Deletes the profile, its tag assignments and history rows, its
    /// thumbnail file, and (best-effort) its keychain secret.
    pub fn delete_host(&self, id: &str) -> Result<()> {
        {
            let mut conn = self.conn.lock();
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM host_tags WHERE host_id = ?1", [id])?;
            tx.execute("DELETE FROM history WHERE host_id = ?1", [id])?;
            tx.execute("DELETE FROM hosts WHERE id = ?1", [id])?;
            tx.commit()?;
        }
        self.delete_thumbnail(id)?;
        // Best-effort keychain cleanup. The encrypted-file fallback (if in
        // use) is cleaned by CredentialStore::delete, which the app layer
        // calls alongside this.
        if let Ok(entry) = keyring::Entry::new(crate::KEYRING_SERVICE, id) {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => tracing::debug!(host_id = id, error = %e, "keychain cleanup failed"),
            }
        }
        Ok(())
    }

    pub fn find_host_by_address(&self, address: &str, port: u16) -> Result<Option<HostProfile>> {
        let id: Option<String> = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT id FROM hosts WHERE address = ?1 AND port = ?2 LIMIT 1",
                params![address, port],
                |r| r.get(0),
            )
            .optional()?
        };
        match id {
            Some(id) => self.get_host(&id),
            None => Ok(None),
        }
    }

    /// Records a successful connection: bumps `last_connected` and
    /// `connect_count`.
    pub fn touch_connected(&self, id: &str) -> Result<()> {
        let now = now_ts();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE hosts SET last_connected = ?1, connect_count = connect_count + 1,
                              updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    // ---- groups / tags -------------------------------------------------

    pub fn list_groups(&self) -> Result<Vec<Group>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, parent_id, sort FROM groups ORDER BY sort, name COLLATE NOCASE",
        )?;
        let groups = stmt
            .query_map([], |r| {
                Ok(Group {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    parent_id: r.get(2)?,
                    sort: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(groups)
    }

    pub fn save_group(&self, g: &Group) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO groups (id, name, parent_id, sort) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, parent_id=excluded.parent_id, sort=excluded.sort",
            params![g.id, g.name, g.parent_id, g.sort],
        )?;
        Ok(())
    }

    /// Deletes a group. Hosts in it become ungrouped; child groups are
    /// re-rooted (their `parent_id` is cleared).
    pub fn delete_group(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("UPDATE hosts SET group_id = NULL WHERE group_id = ?1", [id])?;
        tx.execute(
            "UPDATE groups SET parent_id = NULL WHERE parent_id = ?1",
            [id],
        )?;
        tx.execute("DELETE FROM groups WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_tags(&self) -> Result<Vec<Tag>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT id, name, color FROM tags ORDER BY name COLLATE NOCASE")?;
        let tags = stmt
            .query_map([], |r| {
                Ok(Tag {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    color: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(tags)
    }

    pub fn save_tag(&self, t: &Tag) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO tags (id, name, color) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, color=excluded.color",
            params![t.id, t.name, t.color],
        )?;
        Ok(())
    }

    pub fn delete_tag(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM host_tags WHERE tag_id = ?1", [id])?;
        tx.execute("DELETE FROM tags WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the host's tag set.
    pub fn set_host_tags(&self, host_id: &str, tag_ids: &[String]) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM host_tags WHERE host_id = ?1", [host_id])?;
        for tag_id in tag_ids {
            tx.execute(
                "INSERT OR IGNORE INTO host_tags (host_id, tag_id) VALUES (?1, ?2)",
                params![host_id, tag_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---- history -------------------------------------------------------

    /// Inserts a history record; the entry's `id` is ignored and the newly
    /// assigned row id is returned.
    pub fn add_history(&self, e: &HistoryEntry) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO history (host_id, connected_at, duration_s, security_type,
                                  disconnect_reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                e.host_id,
                e.connected_at,
                e.duration_s,
                e.security_type,
                e.disconnect_reason
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Most recent first; optionally filtered to one host.
    pub fn list_history(&self, host_id: Option<&str>, limit: u32) -> Result<Vec<HistoryEntry>> {
        let conn = self.conn.lock();
        let map = |r: &Row<'_>| -> rusqlite::Result<HistoryEntry> {
            Ok(HistoryEntry {
                id: r.get(0)?,
                host_id: r.get(1)?,
                connected_at: r.get(2)?,
                duration_s: r.get(3)?,
                security_type: r.get(4)?,
                disconnect_reason: r.get(5)?,
            })
        };
        let entries = match host_id {
            Some(hid) => {
                let mut stmt = conn.prepare(
                    "SELECT id, host_id, connected_at, duration_s, security_type,
                            disconnect_reason
                     FROM history WHERE host_id = ?1
                     ORDER BY connected_at DESC, id DESC LIMIT ?2",
                )?;
                let entries = stmt
                    .query_map(params![hid, limit], map)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                entries
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, host_id, connected_at, duration_s, security_type,
                            disconnect_reason
                     FROM history ORDER BY connected_at DESC, id DESC LIMIT ?1",
                )?;
                let entries = stmt
                    .query_map(params![limit], map)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                entries
            }
        };
        Ok(entries)
    }

    // ---- settings (simple KV) ------------------------------------------

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---- certificate pins (TOFU) ---------------------------------------

    /// The pin for one endpoint *and one key scheme* (`"tls"`, `"ra2"`).
    ///
    /// The scheme is part of the key: a TLS certificate and an RA2 RSA key for
    /// the same `(host, port)` are unrelated values, and matching one against
    /// the other would raise a false "identity changed" alarm. An unrecognised
    /// scheme string simply matches nothing.
    pub fn get_cert_pin(&self, host: &str, port: u16, scheme: &str) -> Result<Option<CertPin>> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT host, port, scheme, sha256_spki, subject, first_trusted_at,
                        last_seen_at, security_type
                 FROM cert_pins WHERE host = ?1 AND port = ?2 AND scheme = ?3",
                params![host, port, scheme],
                cert_pin_from_row,
            )
            .optional()?)
    }

    /// Every pin stored for an endpoint, whatever the scheme.
    ///
    /// Connecting reads all of them: which security type will be negotiated is
    /// not known until the handshake, so every pin that could apply has to be
    /// in hand before it starts.
    pub fn list_cert_pins(&self, host: &str, port: u16) -> Result<Vec<CertPin>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT host, port, scheme, sha256_spki, subject, first_trusted_at,
                    last_seen_at, security_type
             FROM cert_pins WHERE host = ?1 AND port = ?2 ORDER BY scheme",
        )?;
        let pins = stmt
            .query_map(params![host, port], cert_pin_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(pins)
    }

    pub fn save_cert_pin(&self, pin: &CertPin) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO cert_pins (host, port, scheme, sha256_spki, subject,
                                    first_trusted_at, last_seen_at, security_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(host, port, scheme) DO UPDATE SET
                sha256_spki=excluded.sha256_spki, subject=excluded.subject,
                first_trusted_at=excluded.first_trusted_at,
                last_seen_at=excluded.last_seen_at, security_type=excluded.security_type",
            params![
                pin.host,
                pin.port,
                pin.scheme,
                pin.sha256_spki,
                pin.subject,
                pin.first_trusted_at,
                pin.last_seen_at,
                pin.security_type,
            ],
        )?;
        Ok(())
    }

    pub fn delete_cert_pin(&self, host: &str, port: u16, scheme: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM cert_pins WHERE host = ?1 AND port = ?2 AND scheme = ?3",
            params![host, port, scheme],
        )?;
        Ok(())
    }

    /// Forget every pin for an endpoint, whatever the scheme.
    ///
    /// This is what "stop trusting this machine" means: the user is not
    /// distinguishing a TLS certificate from an RA2 key, and leaving one
    /// behind would keep the endpoint half-trusted.
    pub fn delete_cert_pins(&self, host: &str, port: u16) -> Result<usize> {
        let conn = self.conn.lock();
        Ok(conn.execute(
            "DELETE FROM cert_pins WHERE host = ?1 AND port = ?2",
            params![host, port],
        )?)
    }

    /// Flushes the WAL into the main database file (used by tests that
    /// inspect the raw DB bytes).
    #[cfg(test)]
    pub(crate) fn checkpoint(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }
}

fn host_tag_ids(conn: &Connection, host_id: &str) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT tag_id FROM host_tags WHERE host_id = ?1 ORDER BY tag_id")?;
    let tags = stmt
        .query_map([host_id], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(tags)
}

/// Column order: host, port, scheme, sha256_spki, subject, first_trusted_at,
/// last_seen_at, security_type.
fn cert_pin_from_row(row: &Row<'_>) -> rusqlite::Result<CertPin> {
    Ok(CertPin {
        host: row.get(0)?,
        port: row.get::<_, i64>(1)? as u16,
        // A row written by a future version with a scheme this build does not
        // know is readable, not fatal, it just never matches a lookup.
        scheme: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        sha256_spki: row.get(3)?,
        subject: row.get(4)?,
        first_trusted_at: row.get(5)?,
        last_seen_at: row.get(6)?,
        security_type: row.get(7)?,
    })
}

fn host_from_row(row: &Row<'_>) -> rusqlite::Result<HostProfile> {
    Ok(HostProfile {
        id: row.get("id")?,
        friendly_name: row.get("friendly_name")?,
        address: row.get("address")?,
        port: row.get::<_, i64>("port")? as u16,
        group_id: row.get("group_id")?,
        os_hint: row.get("os_hint")?,
        server_hint: row.get("server_hint")?,
        security_pref: row.get("security_pref")?,
        quality_pref: row
            .get::<_, Option<String>>("quality_pref")?
            .unwrap_or_else(|| "auto".to_string()),
        color_depth: row.get("color_depth")?,
        scaling_mode: row
            .get::<_, Option<String>>("scaling_mode")?
            .unwrap_or_else(|| "fit".to_string()),
        keyboard_mode: row
            .get::<_, Option<String>>("keyboard_mode")?
            .unwrap_or_else(|| "auto".to_string()),
        passthrough: row.get::<_, Option<i64>>("passthrough")?.unwrap_or(0) != 0,
        view_only: row.get::<_, Option<i64>>("view_only")?.unwrap_or(0) != 0,
        ssh_tunnel: row.get("ssh_tunnel")?,
        wol_mac: row.get("wol_mac")?,
        wol_broadcast: row.get("wol_broadcast")?,
        network_id: row.get("network_id")?,
        cert_pin: row.get("cert_pin")?,
        has_password: row.get::<_, Option<i64>>("has_password")?.unwrap_or(0) != 0,
        thumbnail_at: row.get("thumbnail_at")?,
        last_connected: row.get("last_connected")?,
        connect_count: row.get::<_, Option<i64>>("connect_count")?.unwrap_or(0),
        tags: Vec::new(),
        created_at: row.get::<_, Option<i64>>("created_at")?.unwrap_or(0),
        updated_at: row.get::<_, Option<i64>>("updated_at")?.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostProfile;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        (dir, store)
    }

    fn sample_host(name: &str, address: &str) -> HostProfile {
        HostProfile {
            friendly_name: name.to_string(),
            address: address.to_string(),
            port: 5901,
            os_hint: Some("macos".into()),
            server_hint: Some("macOS Screen Sharing".into()),
            security_pref: Some("apple-dh".into()),
            quality_pref: "high".into(),
            color_depth: Some(24),
            scaling_mode: "aspect-fit".into(),
            keyboard_mode: "unicode".into(),
            passthrough: true,
            view_only: false,
            ssh_tunnel: Some(r#"{"enabled":true,"host":"jump","port":22}"#.into()),
            wol_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            wol_broadcast: Some("192.168.1.255".into()),
            network_id: Some("home-wifi".into()),
            cert_pin: Some("ab".repeat(32)),
            has_password: true,
            ..Default::default()
        }
    }

    #[test]
    fn schema_creation_and_migration_idempotency() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
            let conn = store.conn.lock();
            let v: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v as usize, MIGRATIONS.len());
            for table in [
                "hosts",
                "groups",
                "tags",
                "host_tags",
                "history",
                "settings",
                "cert_pins",
            ] {
                let n: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(n, 1, "missing table {table}");
            }
        }
        // Re-opening must not fail or re-run migrations.
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        let v: i64 = store
            .conn
            .lock()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v as usize, MIGRATIONS.len());
    }

    #[test]
    fn host_crud_round_trip() {
        let (_dir, store) = temp_store();
        let host = sample_host("Living Room Mac", "192.168.1.42");
        store.save_host(&host).unwrap();

        let got = store
            .get_host(&host.id)
            .unwrap()
            .expect("host should exist");
        assert_eq!(got.friendly_name, "Living Room Mac");
        assert_eq!(got.address, "192.168.1.42");
        assert_eq!(got.port, 5901);
        assert_eq!(got.os_hint.as_deref(), Some("macos"));
        assert_eq!(got.quality_pref, "high");
        assert_eq!(got.scaling_mode, "aspect-fit");
        assert_eq!(got.keyboard_mode, "unicode");
        assert!(got.passthrough);
        assert!(!got.view_only);
        assert!(got.has_password);
        assert_eq!(got.ssh_tunnel, host.ssh_tunnel);
        assert_eq!(got.cert_pin, host.cert_pin);
        assert_eq!(got.created_at, host.created_at);

        // Update (upsert on same id) preserves created_at.
        let mut renamed = got.clone();
        renamed.friendly_name = "Bedroom Mac".into();
        store.save_host(&renamed).unwrap();
        let got2 = store.get_host(&host.id).unwrap().unwrap();
        assert_eq!(got2.friendly_name, "Bedroom Mac");
        assert_eq!(got2.created_at, host.created_at);
        assert_eq!(store.list_hosts().unwrap().len(), 1);

        // find_host_by_address
        let found = store
            .find_host_by_address("192.168.1.42", 5901)
            .unwrap()
            .unwrap();
        assert_eq!(found.id, host.id);
        assert!(store
            .find_host_by_address("192.168.1.42", 5900)
            .unwrap()
            .is_none());

        // touch_connected
        store.touch_connected(&host.id).unwrap();
        store.touch_connected(&host.id).unwrap();
        let touched = store.get_host(&host.id).unwrap().unwrap();
        assert_eq!(touched.connect_count, 2);
        assert!(touched.last_connected.is_some());

        // Delete
        store.delete_host(&host.id).unwrap();
        assert!(store.get_host(&host.id).unwrap().is_none());
        assert!(store.list_hosts().unwrap().is_empty());
    }

    #[test]
    fn groups_round_trip() {
        let (_dir, store) = temp_store();
        let g = Group {
            id: "g1".into(),
            name: "Home".into(),
            parent_id: None,
            sort: 0,
        };
        let child = Group {
            id: "g2".into(),
            name: "Office".into(),
            parent_id: Some("g1".into()),
            sort: 1,
        };
        store.save_group(&g).unwrap();
        store.save_group(&child).unwrap();
        assert_eq!(store.list_groups().unwrap().len(), 2);

        let mut host = sample_host("Grouped", "10.0.0.1");
        host.group_id = Some("g1".into());
        store.save_host(&host).unwrap();

        store.delete_group("g1").unwrap();
        let groups = store.list_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].parent_id, None, "child group re-rooted");
        let h = store.get_host(&host.id).unwrap().unwrap();
        assert_eq!(h.group_id, None, "host ungrouped when its group is deleted");
    }

    #[test]
    fn tag_assignment() {
        let (_dir, store) = temp_store();
        let t1 = Tag {
            id: "t1".into(),
            name: "prod".into(),
            color: "#ff0000".into(),
        };
        let t2 = Tag {
            id: "t2".into(),
            name: "lab".into(),
            color: "#00ff00".into(),
        };
        store.save_tag(&t1).unwrap();
        store.save_tag(&t2).unwrap();
        assert_eq!(store.list_tags().unwrap().len(), 2);

        let host = sample_host("Tagged", "10.0.0.2");
        store.save_host(&host).unwrap();
        store
            .set_host_tags(&host.id, &["t1".into(), "t2".into()])
            .unwrap();
        let got = store.get_host(&host.id).unwrap().unwrap();
        assert_eq!(got.tags, vec!["t1".to_string(), "t2".to_string()]);
        assert_eq!(store.list_hosts().unwrap()[0].tags.len(), 2);

        // Replacing the set works.
        store.set_host_tags(&host.id, &["t2".into()]).unwrap();
        assert_eq!(
            store.get_host(&host.id).unwrap().unwrap().tags,
            vec!["t2".to_string()]
        );

        // Deleting a tag removes assignments.
        store.delete_tag("t2").unwrap();
        assert!(store.get_host(&host.id).unwrap().unwrap().tags.is_empty());

        // save_host also syncs tags carried on the profile.
        store.save_tag(&t1).unwrap();
        let mut host2 = store.get_host(&host.id).unwrap().unwrap();
        host2.tags = vec!["t1".into()];
        store.save_host(&host2).unwrap();
        assert_eq!(
            store.get_host(&host.id).unwrap().unwrap().tags,
            vec!["t1".to_string()]
        );
    }

    #[test]
    fn history_round_trip() {
        let (_dir, store) = temp_store();
        let host = sample_host("Hist", "10.0.0.3");
        store.save_host(&host).unwrap();
        for i in 0..5 {
            let id = store
                .add_history(&HistoryEntry {
                    id: 0,
                    host_id: host.id.clone(),
                    connected_at: 1000 + i,
                    duration_s: Some(60 * i),
                    security_type: Some("VeNCrypt/X509Plain".into()),
                    disconnect_reason: if i == 4 { Some("user".into()) } else { None },
                })
                .unwrap();
            assert!(id > 0);
        }
        store
            .add_history(&HistoryEntry {
                id: 0,
                host_id: "other-host".into(),
                connected_at: 2000,
                duration_s: None,
                security_type: None,
                disconnect_reason: None,
            })
            .unwrap();

        let all = store.list_history(None, 100).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0].connected_at, 2000, "most recent first");

        let for_host = store.list_history(Some(&host.id), 3).unwrap();
        assert_eq!(for_host.len(), 3);
        assert_eq!(for_host[0].connected_at, 1004);
        assert!(for_host.iter().all(|e| e.host_id == host.id));
    }

    #[test]
    fn settings_kv() {
        let (_dir, store) = temp_store();
        assert!(store.get_setting("theme").unwrap().is_none());
        store.set_setting("theme", "dark").unwrap();
        assert_eq!(store.get_setting("theme").unwrap().as_deref(), Some("dark"));
        store.set_setting("theme", "light").unwrap();
        assert_eq!(
            store.get_setting("theme").unwrap().as_deref(),
            Some("light")
        );
    }

    fn sample_pin(host: &str, port: u16, scheme: &str, spki: &str) -> CertPin {
        CertPin {
            host: host.into(),
            port,
            scheme: scheme.into(),
            sha256_spki: spki.into(),
            subject: format!("CN={host}"),
            first_trusted_at: 111,
            last_seen_at: 111,
            security_type: None,
        }
    }

    #[test]
    fn cert_pin_round_trip() {
        let (_dir, store) = temp_store();
        assert!(store
            .get_cert_pin("mac.local", 5900, "tls")
            .unwrap()
            .is_none());
        let mut pin = sample_pin("mac.local", 5900, "tls", &"aa".repeat(32));
        pin.security_type = Some("VeNCrypt/X509Vnc".into());
        store.save_cert_pin(&pin).unwrap();
        let got = store
            .get_cert_pin("mac.local", 5900, "tls")
            .unwrap()
            .unwrap();
        assert_eq!(got.sha256_spki, pin.sha256_spki);
        assert_eq!(got.subject, "CN=mac.local");
        assert_eq!(got.port, 5900);
        assert_eq!(got.scheme, "tls");

        // Upsert updates last_seen_at.
        let mut updated = got.clone();
        updated.last_seen_at = 222;
        store.save_cert_pin(&updated).unwrap();
        assert_eq!(
            store
                .get_cert_pin("mac.local", 5900, "tls")
                .unwrap()
                .unwrap()
                .last_seen_at,
            222
        );

        store.delete_cert_pin("mac.local", 5900, "tls").unwrap();
        assert!(store
            .get_cert_pin("mac.local", 5900, "tls")
            .unwrap()
            .is_none());
    }

    /// A server can offer VeNCrypt *and* RA2 (wayvnc does). The two keys are
    /// unrelated, so both pins must live side by side for one endpoint and
    /// neither may be returned when the other is asked for, otherwise the
    /// path that was not pinned first sees a "changed" fingerprint and hard
    /// stops on a server that changed nothing.
    #[test]
    fn tls_and_ra2_pins_coexist_without_shadowing() {
        let (_dir, store) = temp_store();
        let tls = sample_pin("pi.local", 5900, "tls", &"aa".repeat(32));
        let ra2 = sample_pin("pi.local", 5900, "ra2", &"bb".repeat(32));
        store.save_cert_pin(&tls).unwrap();
        store.save_cert_pin(&ra2).unwrap();

        assert_eq!(
            store
                .get_cert_pin("pi.local", 5900, "tls")
                .unwrap()
                .unwrap()
                .sha256_spki,
            "aa".repeat(32)
        );
        assert_eq!(
            store
                .get_cert_pin("pi.local", 5900, "ra2")
                .unwrap()
                .unwrap()
                .sha256_spki,
            "bb".repeat(32),
            "saving the TLS pin must not have overwritten the RA2 one"
        );

        let all = store.list_cert_pins("pi.local", 5900).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.iter().map(|p| p.scheme.as_str()).collect::<Vec<_>>(),
            ["ra2", "tls"]
        );
    }

    /// Trusting a key under one scheme must not silently vouch for the other.
    #[test]
    fn a_pin_never_satisfies_a_different_scheme() {
        let (_dir, store) = temp_store();
        store
            .save_cert_pin(&sample_pin("pi.local", 5900, "tls", &"aa".repeat(32)))
            .unwrap();

        assert!(
            store
                .get_cert_pin("pi.local", 5900, "ra2")
                .unwrap()
                .is_none(),
            "a TLS pin must not answer an RA2 lookup"
        );
        // An unrecognised scheme string matches nothing rather than aliasing
        // onto a known one.
        assert!(store
            .get_cert_pin("pi.local", 5900, "quantum")
            .unwrap()
            .is_none());
        assert!(store.get_cert_pin("pi.local", 5900, "").unwrap().is_none());
    }

    /// "Forget saved key" means stop trusting the machine, not one of its
    /// keys, so every scheme goes.
    #[test]
    fn deleting_an_endpoint_clears_every_scheme() {
        let (_dir, store) = temp_store();
        store
            .save_cert_pin(&sample_pin("pi.local", 5900, "tls", &"aa".repeat(32)))
            .unwrap();
        store
            .save_cert_pin(&sample_pin("pi.local", 5900, "ra2", &"bb".repeat(32)))
            .unwrap();
        // A different endpoint must survive.
        store
            .save_cert_pin(&sample_pin("pi.local", 5901, "tls", &"cc".repeat(32)))
            .unwrap();

        assert_eq!(store.delete_cert_pins("pi.local", 5900).unwrap(), 2);
        assert!(store.list_cert_pins("pi.local", 5900).unwrap().is_empty());
        assert_eq!(store.list_cert_pins("pi.local", 5901).unwrap().len(), 1);
    }

    /// REGRESSION: a host trusted before the scheme column existed must still
    /// be trusted afterwards.
    ///
    /// Every v1 row was written by the TLS path, so v2 backfills `'tls'`.
    /// Getting this wrong re-prompts for every host the user already trusted,
    /// which looks exactly like the false-mismatch bug the column fixes.
    #[test]
    fn migrating_a_v1_database_preserves_its_pins() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("deskvnc.db");

        // Build a v1 database by hand: the v1 schema, one pin, user_version 1.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(MIGRATIONS[0]).unwrap();
            conn.execute(
                "INSERT INTO cert_pins (host, port, sha256_spki, subject, first_trusted_at,
                                        last_seen_at, security_type)
                 VALUES ('192.168.77.152', 5900, ?1, 'CN=raspberrypi', 7, 9, 'VeNCrypt/X509Plain')",
                params!["d2".repeat(32)],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 1i64).unwrap();
        }

        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(
            store
                .conn
                .lock()
                .query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap() as usize,
            MIGRATIONS.len(),
            "the database must be fully migrated"
        );

        let got = store
            .get_cert_pin("192.168.77.152", 5900, "tls")
            .unwrap()
            .expect("a pin trusted before the migration must survive it");
        assert_eq!(got.sha256_spki, "d2".repeat(32));
        assert_eq!(got.scheme, "tls", "v1 rows were all TLS pins");
        assert_eq!(got.subject, "CN=raspberrypi");
        assert_eq!(got.first_trusted_at, 7, "first-trusted date is not reset");
        assert_eq!(got.last_seen_at, 9);
        assert_eq!(got.security_type.as_deref(), Some("VeNCrypt/X509Plain"));

        // It is a TLS pin only, RA2 on the same endpoint is still first contact.
        assert!(store
            .get_cert_pin("192.168.77.152", 5900, "ra2")
            .unwrap()
            .is_none());

        // And the migrated table is the real one, still writable per scheme.
        store
            .save_cert_pin(&sample_pin("192.168.77.152", 5900, "ra2", &"11".repeat(32)))
            .unwrap();
        assert_eq!(
            store.list_cert_pins("192.168.77.152", 5900).unwrap().len(),
            2
        );
    }

    /// CRITICAL invariant: saving a profile must never write any secret to
    /// the DB file (or its WAL).
    #[test]
    fn no_secrets_in_db_file() {
        let secret = "sup3r-s3cret-hunter2-passw0rd";
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();

        let mut host = sample_host("Secret Host", "10.9.9.9");
        host.has_password = true;
        store.save_host(&host).unwrap();

        // Store a real credential through the encrypted-file fallback in the
        // same data dir, it must not leak into the DB either.
        let creds = crate::CredentialStore::new_with_file_backend(dir.path().to_path_buf());
        creds.set_kdf_params_for_tests(8, 1, 1);
        creds.unlock("master-pw").unwrap();
        creds
            .save(
                &host.id,
                &crate::StoredCredentials {
                    vnc_password: Some(secret.to_string()),
                    ..Default::default()
                },
            )
            .unwrap();

        store.checkpoint().unwrap();
        let mut blob = Vec::new();
        for name in [
            "deskvnc.db",
            "deskvnc.db-wal",
            "deskvnc.db-shm",
            "credentials.enc",
        ] {
            if let Ok(bytes) = std::fs::read(dir.path().join(name)) {
                blob.extend_from_slice(&bytes);
            }
        }
        assert!(!blob.is_empty());
        let needle = secret.as_bytes();
        let found = blob.windows(needle.len()).any(|w| w == needle);
        assert!(
            !found,
            "secret bytes must never appear in the DB or credential file"
        );
    }
}
