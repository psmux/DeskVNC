//! Trusted server keys, trust on first use, keyed by host, port and scheme.
//!
//! The same model as the desktop's `cert_pins` table: a fingerprint is only
//! ever looked up under the scheme it was stored under, because each security
//! path verifies against its own key and a TLS pin compared with an RA2 key
//! would read as a changed identity for a server that changed nothing.
//! A fingerprint is public, so this is an ordinary file.

use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use remote_core::PinScheme;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub sha256: String,
}

pub struct PinStore {
    path: PathBuf,
    pins: Mutex<Vec<Pin>>,
}

impl PinStore {
    pub fn open(dir: &Path) -> Self {
        let path = dir.join("pins.json");
        let pins = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self {
            path,
            pins: Mutex::new(pins),
        }
    }

    /// Every pin for an endpoint whose scheme this build knows. A row from a
    /// newer build is skipped, never guessed at.
    pub fn for_endpoint(&self, host: &str, port: u16) -> Vec<(PinScheme, String)> {
        let host = host.trim().to_ascii_lowercase();
        self.pins
            .lock()
            .iter()
            .filter(|p| p.host == host && p.port == port)
            .filter_map(|p| PinScheme::parse(&p.scheme).map(|s| (s, p.sha256.clone())))
            .collect()
    }

    pub fn trust(
        &self,
        host: &str,
        port: u16,
        scheme: PinScheme,
        sha256: &str,
    ) -> Result<(), String> {
        let host = host.trim().to_ascii_lowercase();
        let mut pins = self.pins.lock();
        pins.retain(|p| !(p.host == host && p.port == port && p.scheme == scheme.as_str()));
        pins.push(Pin {
            host,
            port,
            scheme: scheme.as_str().to_string(),
            sha256: sha256.to_string(),
        });
        let bytes = serde_json::to_vec_pretty(&*pins).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_are_per_scheme_and_replace_on_retrust() {
        let dir = tempfile::tempdir().unwrap();
        let store = PinStore::open(dir.path());
        store
            .trust("Box.example.com", 5900, PinScheme::Tls, "aa")
            .unwrap();
        store
            .trust("box.example.com", 5900, PinScheme::Ra2, "bb")
            .unwrap();
        store
            .trust("box.example.com", 5900, PinScheme::Tls, "cc")
            .unwrap();
        let reopened = PinStore::open(dir.path());
        let mut got = reopened.for_endpoint("box.example.com", 5900);
        got.sort();
        assert_eq!(
            got,
            vec![(PinScheme::Tls, "cc".into()), (PinScheme::Ra2, "bb".into())]
        );
        assert!(reopened.for_endpoint("box.example.com", 5901).is_empty());
    }
}
