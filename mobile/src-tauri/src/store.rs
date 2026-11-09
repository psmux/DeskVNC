//! The saved computers, as one small JSON file in the app's data folder.
//!
//! A phone keeps a few dozen hosts at most, so the whole list is read and
//! written at once and every write goes to a temporary file that is renamed
//! over the old one, which leaves either the old list or the new one after a
//! crash and never half of each. Secrets never come here: the password lives
//! in the platform vault (`crate::secrets`) and this file only remembers that
//! there is one.

use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// `Protocol` in `contract.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vnc,
    Rdp,
    Boundary,
}

impl Protocol {
    pub fn kind(self) -> remote_core::ProtocolKind {
        match self {
            Protocol::Vnc => remote_core::ProtocolKind::Vnc,
            Protocol::Rdp => remote_core::ProtocolKind::Rdp,
            Protocol::Boundary => remote_core::ProtocolKind::Boundary,
        }
    }
}

/// `HostOs` in `contract.ts`. Unknown spellings from a newer UI read as
/// `unknown` rather than failing the whole list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostOs {
    Windows,
    Mac,
    Linux,
    Raspberry,
    #[default]
    #[serde(other)]
    Unknown,
}

/// `Host` in `contract.ts`, exactly as it crosses the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub has_password: bool,
    #[serde(default)]
    pub os: HostOs,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub last_connected_at: Option<i64>,
    #[serde(default)]
    pub has_thumbnail: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_invitation: Option<String>,
}

/// `HostDraft` in `contract.ts`: a host without the fields only Rust sets.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostDraft {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub os: HostOs,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub boundary_invitation: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("could not read or write the saved computers: {0}")]
    Io(#[from] std::io::Error),
    #[error("the saved computers file is damaged: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Default, Serialize, Deserialize)]
struct FileShape {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    hosts: Vec<Host>,
}

const FILE_VERSION: u32 = 1;

/// The longest name, address or user name this store accepts. Generous for
/// any real value and small enough that a buggy UI cannot grow the file
/// without bound.
const MAX_FIELD: usize = 512;

pub struct HostStore {
    path: PathBuf,
    hosts: Mutex<Vec<Host>>,
}

impl HostStore {
    /// Open the store at `dir/hosts.json`, creating `dir` if needed. A file
    /// that will not parse is moved aside rather than overwritten, so a bug
    /// in a newer build cannot silently wipe somebody's list.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("hosts.json");
        let hosts = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<FileShape>(&bytes) {
                Ok(file) => file.hosts,
                Err(error) => {
                    let aside = dir.join(format!(
                        "hosts.damaged-{}.json",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0)
                    ));
                    tracing::warn!(%error, "hosts.json did not parse, kept aside");
                    std::fs::rename(&path, aside)?;
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            hosts: Mutex::new(hosts),
        })
    }

    pub fn list(&self) -> Vec<Host> {
        let mut hosts = self.hosts.lock().clone();
        // Favourites first, then the most recently used, then by name, so
        // the UI gets a sensible order without sorting itself.
        hosts.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then(b.last_connected_at.cmp(&a.last_connected_at))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        hosts
    }

    pub fn get(&self, id: &str) -> Option<Host> {
        self.hosts.lock().iter().find(|h| h.id == id).cloned()
    }

    /// Insert a new host, or update the one with the draft's id. The fields
    /// only Rust owns (`hasPassword`, `lastConnectedAt`, `hasThumbnail`)
    /// survive an update untouched.
    pub fn save(&self, draft: HostDraft) -> Result<Host, StoreError> {
        validate(&draft)?;
        let mut hosts = self.hosts.lock();
        let existing = draft
            .id
            .as_deref()
            .and_then(|id| hosts.iter().position(|h| h.id == id));
        let id = match (&draft.id, existing) {
            (Some(id), _) => {
                validate_id(id)?;
                id.clone()
            }
            (None, _) => uuid::Uuid::new_v4().to_string(),
        };
        let previous = existing.map(|i| hosts[i].clone());
        let host = Host {
            id,
            name: draft.name.trim().to_string(),
            protocol: draft.protocol,
            address: draft.address.trim().to_string(),
            port: if draft.port == 0 && draft.protocol != Protocol::Boundary {
                draft.protocol.kind().default_port()
            } else {
                draft.port
            },
            username: draft.username.filter(|u| !u.is_empty()),
            has_password: previous.as_ref().is_some_and(|p| p.has_password),
            os: draft.os,
            color: draft.color,
            favorite: draft.favorite,
            last_connected_at: previous.as_ref().and_then(|p| p.last_connected_at),
            has_thumbnail: previous.as_ref().is_some_and(|p| p.has_thumbnail),
            domain: draft.domain.filter(|d| !d.is_empty()),
            boundary_invitation: draft.boundary_invitation.filter(|i| !i.is_empty()),
        };
        match existing {
            Some(i) => hosts[i] = host.clone(),
            None => hosts.push(host.clone()),
        }
        self.persist(&hosts)?;
        Ok(host)
    }

    /// Remove a host. Removing one that is not there is not an error: the UI
    /// may be catching up with a delete it already made.
    pub fn delete(&self, id: &str) -> Result<bool, StoreError> {
        let mut hosts = self.hosts.lock();
        let before = hosts.len();
        hosts.retain(|h| h.id != id);
        let removed = hosts.len() != before;
        if removed {
            self.persist(&hosts)?;
        }
        Ok(removed)
    }

    /// Change one host in place with `f`, then write. `Ok(None)` when there
    /// is no such host.
    pub fn update<F: FnOnce(&mut Host)>(&self, id: &str, f: F) -> Result<Option<Host>, StoreError> {
        let mut hosts = self.hosts.lock();
        let Some(host) = hosts.iter_mut().find(|h| h.id == id) else {
            return Ok(None);
        };
        f(host);
        let host = host.clone();
        self.persist(&hosts)?;
        Ok(Some(host))
    }

    fn persist(&self, hosts: &[Host]) -> Result<(), StoreError> {
        let file = FileShape {
            version: FILE_VERSION,
            hosts: hosts.to_vec(),
        };
        let bytes = serde_json::to_vec_pretty(&file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Host ids name files (thumbnails) and vault entries, so they are held to a
/// conservative alphabet: a uuid, or anything else made of letters, digits
/// and `-`.
pub fn validate_id(id: &str) -> Result<(), StoreError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(StoreError::Invalid("invalid host id".into()));
    }
    Ok(())
}

fn validate(draft: &HostDraft) -> Result<(), StoreError> {
    let too_long = |s: &str| s.len() > MAX_FIELD;
    if draft.name.trim().is_empty() {
        return Err(StoreError::Invalid("Give this computer a name".into()));
    }
    if too_long(&draft.name)
        || too_long(&draft.address)
        || draft.username.as_deref().is_some_and(too_long)
        || draft.domain.as_deref().is_some_and(too_long)
        || too_long(&draft.color)
    {
        return Err(StoreError::Invalid("A field is too long".into()));
    }
    if draft
        .boundary_invitation
        .as_deref()
        .is_some_and(|i| i.len() > 8192)
    {
        return Err(StoreError::Invalid("The invitation is too long".into()));
    }
    if draft.protocol != Protocol::Boundary && draft.address.trim().is_empty() {
        return Err(StoreError::Invalid("Enter the computer's address".into()));
    }
    if draft.protocol == Protocol::Boundary
        && draft.address.trim().is_empty()
        && draft
            .boundary_invitation
            .as_deref()
            .is_none_or(|i| i.trim().is_empty())
    {
        return Err(StoreError::Invalid(
            "A Boundary computer needs its ID or a saved invitation".into(),
        ));
    }
    Ok(())
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(name: &str) -> HostDraft {
        HostDraft {
            id: None,
            name: name.into(),
            protocol: Protocol::Vnc,
            address: "192.0.2.10".into(),
            port: 0,
            username: None,
            os: HostOs::Linux,
            color: "teal".into(),
            favorite: false,
            domain: None,
            boundary_invitation: None,
        }
    }

    #[test]
    fn save_assigns_an_id_and_the_default_port_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let store = HostStore::open(dir.path()).unwrap();
        let host = store.save(draft("Office")).unwrap();
        assert!(uuid::Uuid::parse_str(&host.id).is_ok());
        assert_eq!(host.port, 5900);
        assert!(!host.has_password && !host.has_thumbnail);

        let reopened = HostStore::open(dir.path()).unwrap();
        assert_eq!(reopened.list(), vec![host]);
    }

    #[test]
    fn update_keeps_the_fields_rust_owns() {
        let dir = tempfile::tempdir().unwrap();
        let store = HostStore::open(dir.path()).unwrap();
        let host = store.save(draft("Office")).unwrap();
        store
            .update(&host.id, |h| {
                h.has_password = true;
                h.has_thumbnail = true;
                h.last_connected_at = Some(42);
            })
            .unwrap();
        let mut edit = draft("Renamed");
        edit.id = Some(host.id.clone());
        edit.protocol = Protocol::Rdp;
        let saved = store.save(edit).unwrap();
        assert_eq!(saved.name, "Renamed");
        assert_eq!(saved.port, 3389);
        assert!(saved.has_password && saved.has_thumbnail);
        assert_eq!(saved.last_connected_at, Some(42));
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn wire_shape_is_camel_case_and_matches_the_contract() {
        let dir = tempfile::tempdir().unwrap();
        let store = HostStore::open(dir.path()).unwrap();
        let host = store.save(draft("Office")).unwrap();
        let json = serde_json::to_value(&host).unwrap();
        for key in [
            "id",
            "name",
            "protocol",
            "address",
            "port",
            "username",
            "hasPassword",
            "os",
            "color",
            "favorite",
            "lastConnectedAt",
            "hasThumbnail",
        ] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
        assert_eq!(json["protocol"], "vnc");
        assert_eq!(json["os"], "linux");
        // A draft straight from the UI, with fields Rust does not know.
        let draft: HostDraft = serde_json::from_value(serde_json::json!({
            "name": "Mac", "protocol": "boundary", "address": "", "port": 0,
            "username": null, "os": "mac", "color": "violet", "favorite": true,
            "boundaryInvitation": "boundary1:abc", "somethingNew": 1
        }))
        .unwrap();
        let saved = store.save(draft).unwrap();
        assert_eq!(saved.port, 0);
        assert_eq!(saved.os, HostOs::Mac);
    }

    #[test]
    fn unknown_os_reads_as_unknown() {
        let os: HostOs = serde_json::from_str("\"amiga\"").unwrap();
        assert_eq!(os, HostOs::Unknown);
    }

    #[test]
    fn rejects_bad_drafts_and_ids() {
        let dir = tempfile::tempdir().unwrap();
        let store = HostStore::open(dir.path()).unwrap();
        assert!(store.save(draft("  ")).is_err());
        let mut no_address = draft("x");
        no_address.address = String::new();
        assert!(store.save(no_address).is_err());
        let mut boundary = draft("x");
        boundary.protocol = Protocol::Boundary;
        boundary.address = String::new();
        assert!(store.save(boundary).is_err());
        let mut bad_id = draft("x");
        bad_id.id = Some("../etc".into());
        assert!(store.save(bad_id).is_err());
        assert!(store.list().is_empty());
    }

    #[test]
    fn delete_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = HostStore::open(dir.path()).unwrap();
        let a = store.save(draft("b host")).unwrap();
        let mut fav = draft("a host");
        fav.favorite = true;
        let b = store.save(fav).unwrap();
        let c = store.save(draft("c host")).unwrap();
        store
            .update(&c.id, |h| h.last_connected_at = Some(5))
            .unwrap();
        let order: Vec<_> = store.list().into_iter().map(|h| h.id).collect();
        assert_eq!(order, vec![b.id.clone(), c.id.clone(), a.id.clone()]);
        assert!(store.delete(&a.id).unwrap());
        assert!(!store.delete(&a.id).unwrap());
        assert_eq!(HostStore::open(dir.path()).unwrap().list().len(), 2);
    }

    #[test]
    fn a_damaged_file_is_kept_aside_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hosts.json"), b"{not json").unwrap();
        let store = HostStore::open(dir.path()).unwrap();
        assert!(store.list().is_empty());
        let kept = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("hosts.damaged-")
            });
        assert!(kept);
    }
}
