//! SSH host-key trust-on-first-use, mirroring the TLS TOFU in `vnc-transport`.
//!
//! Same three-state shape as [`vnc_transport::TrustDecision`]:
//!
//! | outcome | meaning | UI |
//! |---|---|---|
//! | [`HostKeyDecision::Trusted`] | fingerprint matches the stored pin | connect |
//! | [`HostKeyDecision::Unknown`] | no pin yet | prompt, then persist + retry |
//! | [`HostKeyDecision::Changed`] | pin exists and differs | **HARD STOP** |
//!
//! The store shape ([`HostKeyPin`]) intentionally mirrors
//! `vnc_store::CertPin`: `(host, port)` key, the fingerprint, and first/last
//! seen timestamps. Pins are not secrets, the shell persists them as plain
//! JSON next to the rest of its app data.

use std::sync::Arc;

use parking_lot::Mutex;

/// A pinned SSH host key, keyed by `(host, port)` exactly like
/// `vnc_store::CertPin`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPin {
    pub host: String,
    pub port: u16,
    /// SSH key algorithm, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// OpenSSH-style `SHA256:…` fingerprint of the public key.
    pub fingerprint: String,
    pub first_trusted_at: i64,
    pub last_seen_at: i64,
}

/// Outcome of checking a presented host key against the pin store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum HostKeyDecision {
    /// Fingerprint matches the stored pin.
    Trusted,
    /// Nothing pinned for this endpoint yet, the UI must prompt.
    Unknown {
        key_type: String,
        fingerprint: String,
    },
    /// A pin exists and does **not** match. Never promptable, never retried.
    Changed {
        expected: String,
        actual: String,
        key_type: String,
    },
}

/// Verifies a presented SSH host key. Implemented by the shell over its
/// persisted pin store; a plain closure works too.
pub trait HostKeyVerifier: Send + Sync + 'static {
    fn verify(&self, host: &str, port: u16, key_type: &str, fingerprint: &str) -> HostKeyDecision;
}

impl<F> HostKeyVerifier for F
where
    F: Fn(&str, u16, &str, &str) -> HostKeyDecision + Send + Sync + 'static,
{
    fn verify(&self, host: &str, port: u16, key_type: &str, fingerprint: &str) -> HostKeyDecision {
        self(host, port, key_type, fingerprint)
    }
}

/// A serialisable collection of [`HostKeyPin`]s. The shell owns persistence;
/// this type owns the decision logic so it is unit-testable without IO.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyStore {
    #[serde(default)]
    pub pins: Vec<HostKeyPin>,
}

impl HostKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn index_of(&self, host: &str, port: u16) -> Option<usize> {
        self.pins
            .iter()
            .position(|p| p.host.eq_ignore_ascii_case(host) && p.port == port)
    }

    pub fn get(&self, host: &str, port: u16) -> Option<&HostKeyPin> {
        self.index_of(host, port).map(|i| &self.pins[i])
    }

    /// The TOFU decision for a presented key.
    pub fn decide(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> HostKeyDecision {
        match self.get(host, port) {
            None => HostKeyDecision::Unknown {
                key_type: key_type.to_string(),
                fingerprint: fingerprint.to_string(),
            },
            Some(pin) if pin.fingerprint == fingerprint => HostKeyDecision::Trusted,
            Some(pin) => HostKeyDecision::Changed {
                expected: pin.fingerprint.clone(),
                actual: fingerprint.to_string(),
                key_type: key_type.to_string(),
            },
        }
    }

    /// Pin a key (first trust, or an explicit user-approved replacement).
    pub fn trust(&mut self, host: &str, port: u16, key_type: &str, fingerprint: &str, now: i64) {
        match self.index_of(host, port) {
            Some(i) => {
                let pin = &mut self.pins[i];
                if pin.fingerprint != fingerprint {
                    pin.first_trusted_at = now;
                }
                pin.key_type = key_type.to_string();
                pin.fingerprint = fingerprint.to_string();
                pin.last_seen_at = now;
            }
            None => self.pins.push(HostKeyPin {
                host: host.to_string(),
                port,
                key_type: key_type.to_string(),
                fingerprint: fingerprint.to_string(),
                first_trusted_at: now,
                last_seen_at: now,
            }),
        }
    }

    /// Refresh `last_seen_at` after a successful verified connect.
    pub fn touch(&mut self, host: &str, port: u16, now: i64) {
        if let Some(i) = self.index_of(host, port) {
            self.pins[i].last_seen_at = now;
        }
    }

    pub fn forget(&mut self, host: &str, port: u16) -> bool {
        match self.index_of(host, port) {
            Some(i) => {
                self.pins.remove(i);
                true
            }
            None => false,
        }
    }
}

/// The shape the shell actually holds: a shared, mutable pin store.
impl HostKeyVerifier for Arc<Mutex<HostKeyStore>> {
    fn verify(&self, host: &str, port: u16, key_type: &str, fingerprint: &str) -> HostKeyDecision {
        self.lock().decide(host, port, key_type, fingerprint)
    }
}

/// Trust every key. **Tests only**, never wire this into the shell.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct TrustAll;

#[cfg(test)]
impl HostKeyVerifier for TrustAll {
    fn verify(&self, _: &str, _: u16, _: &str, _: &str) -> HostKeyDecision {
        HostKeyDecision::Trusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FP_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn first_contact_is_unknown_then_trusted() {
        let mut store = HostKeyStore::new();
        assert_eq!(
            store.decide("host", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Unknown {
                key_type: "ssh-ed25519".into(),
                fingerprint: FP_A.into(),
            }
        );
        store.trust("host", 22, "ssh-ed25519", FP_A, 100);
        assert_eq!(
            store.decide("host", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Trusted
        );
    }

    #[test]
    fn a_changed_key_is_a_hard_stop_not_a_prompt() {
        let mut store = HostKeyStore::new();
        store.trust("host", 22, "ssh-ed25519", FP_A, 100);
        let decision = store.decide("host", 22, "ssh-ed25519", FP_B);
        assert_eq!(
            decision,
            HostKeyDecision::Changed {
                expected: FP_A.into(),
                actual: FP_B.into(),
                key_type: "ssh-ed25519".into(),
            }
        );
        // A changed key must never degrade into "Unknown" (which would be
        // promptable), that is the whole point of the pin.
        assert!(!matches!(decision, HostKeyDecision::Unknown { .. }));
    }

    #[test]
    fn pins_are_scoped_to_host_and_port() {
        let mut store = HostKeyStore::new();
        store.trust("host", 22, "ssh-ed25519", FP_A, 100);
        assert!(matches!(
            store.decide("host", 2222, "ssh-ed25519", FP_A),
            HostKeyDecision::Unknown { .. }
        ));
        assert!(matches!(
            store.decide("other", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Unknown { .. }
        ));
        // Host names are case-insensitive.
        assert_eq!(
            store.decide("HOST", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Trusted
        );
    }

    #[test]
    fn trusting_a_replacement_resets_first_trusted_at() {
        let mut store = HostKeyStore::new();
        store.trust("host", 22, "ssh-ed25519", FP_A, 100);
        store.touch("host", 22, 150);
        assert_eq!(store.get("host", 22).unwrap().last_seen_at, 150);
        store.trust("host", 22, "ssh-rsa", FP_B, 200);
        let pin = store.get("host", 22).unwrap();
        assert_eq!(pin.first_trusted_at, 200);
        assert_eq!(pin.fingerprint, FP_B);
        assert_eq!(pin.key_type, "ssh-rsa");
        assert_eq!(store.pins.len(), 1);
        assert!(store.forget("host", 22));
        assert!(!store.forget("host", 22));
    }

    #[test]
    fn store_round_trips_through_json() {
        let mut store = HostKeyStore::new();
        store.trust("living-room", 22, "ssh-ed25519", FP_A, 1_700_000_000);
        let json = serde_json::to_string(&store).unwrap();
        assert!(json.contains("\"firstTrustedAt\""), "camelCase: {json}");
        assert!(json.contains("\"keyType\""), "camelCase: {json}");
        let back: HostKeyStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pins, store.pins);
        // An empty/missing file must deserialize to an empty store.
        let empty: HostKeyStore = serde_json::from_str("{}").unwrap();
        assert!(empty.pins.is_empty());
    }

    #[test]
    fn decision_serializes_with_a_kebab_tag_and_camel_fields() {
        let json = serde_json::to_string(&HostKeyDecision::Unknown {
            key_type: "ssh-ed25519".into(),
            fingerprint: FP_A.into(),
        })
        .unwrap();
        assert!(json.contains("\"type\":\"unknown\""), "{json}");
        assert!(json.contains("\"keyType\""), "{json}");
    }

    #[test]
    fn a_closure_is_a_verifier() {
        let verifier = |_: &str, _: u16, _: &str, _: &str| HostKeyDecision::Trusted;
        assert_eq!(
            verifier.verify("h", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Trusted
        );
    }
}
