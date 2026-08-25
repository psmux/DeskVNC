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
//!
//! The key is the *canonical* host ([`crate::canonical_host`]) and the port,
//! so `[::1]`, `::1`, `studio.local.` and `Studio.local` are one endpoint and
//! not four. Both sides of every comparison are canonicalised at lookup time,
//! never only on write, so pins already on disk in an older spelling keep
//! matching. Without that a stale spelling would read as "no pin" for the
//! machine that has one, which is how a second trust prompt turns into a
//! second pin, and later a spurious [`HostKeyDecision::Changed`].

use std::sync::Arc;

use parking_lot::Mutex;

use crate::config::canonical_host;

/// A pinned SSH host key, keyed by the canonical `(host, port)`, the same
/// shape as `vnc_store::CertPin`.
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

    /// The pin for an endpoint, comparing hosts in canonical form.
    ///
    /// The stored host is canonicalised here rather than trusted as written,
    /// because pins predating this rule are still on disk spelled `[::1]` or
    /// `studio.local.`; normalising only the lookup would leave those pins
    /// permanently unfindable, which is a fresh prompt and a duplicate pin.
    ///
    /// The FIRST match wins, deliberately. Only a store written by an older
    /// build can hold two spellings of one endpoint, and
    /// [`HostKeyStore::collapse_duplicates`] resolves those on load; until it
    /// runs, file order is what decides, and it has to be something stable
    /// rather than whichever pin the iterator happens to reach.
    fn index_of(&self, host: &str, port: u16) -> Option<usize> {
        let host = canonical_host(host);
        self.pins
            .iter()
            .position(|p| p.port == port && canonical_host(&p.host) == host)
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
            // New pins are written canonical so the file shows one entry per
            // machine; lookups do not depend on it, see `index_of`.
            None => self.pins.push(HostKeyPin {
                host: canonical_host(host),
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

    /// Fold pins that differ only in spelling into one, returning how many
    /// were dropped. Call it once, on the store loaded from disk.
    ///
    /// A store written before the key was canonical can hold `studio.local`
    /// and `studio.local.` as separate pins for one machine. Comparison-time
    /// canonicalisation already makes those harmless to [`Self::decide`], but
    /// not to [`Self::forget`]: forgetting one leaves the other behind, and
    /// the shadow pin then answers the next connect, which is a `Changed`
    /// hard stop the user cannot clear from the UI.
    ///
    /// TIE-BREAK: when the duplicates disagree on the fingerprint, the one
    /// with the newest `last_seen_at` wins, ties going to the earlier entry.
    /// Both were explicitly trusted by a human, so neither has better
    /// provenance, but only the recently seen one describes a key the machine
    /// actually presented; keeping the other would hard-stop a connection
    /// that has been working. Equal fingerprints, the overwhelmingly common
    /// case since both spellings point at one host key, make the choice moot.
    pub fn collapse_duplicates(&mut self) -> usize {
        let before = self.pins.len();
        let mut kept: Vec<HostKeyPin> = Vec::with_capacity(before);
        for pin in std::mem::take(&mut self.pins) {
            let existing = kept.iter().position(|k| {
                k.port == pin.port && canonical_host(&k.host) == canonical_host(&pin.host)
            });
            match existing {
                Some(i) if pin.last_seen_at > kept[i].last_seen_at => kept[i] = pin,
                Some(_) => {}
                None => kept.push(pin),
            }
        }
        self.pins = kept;
        before - self.pins.len()
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

/// An already-erased verifier, so a caller holding one can pass it anywhere
/// an `impl HostKeyVerifier` is wanted.
///
/// Without this, a component that stores `Arc<dyn HostKeyVerifier>` (because
/// it was handed one and must keep it) cannot hand it on to a constructor
/// taking `impl HostKeyVerifier`, even though it plainly is one. That comes up
/// wherever a driver holds the shared pin store and spawns sessions from it.
impl HostKeyVerifier for Arc<dyn HostKeyVerifier + Send + Sync + 'static> {
    fn verify(&self, host: &str, port: u16, key_type: &str, fingerprint: &str) -> HostKeyDecision {
        (**self).verify(host, port, key_type, fingerprint)
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

    /// A pin written by a build that stored the host as typed must still be
    /// found once the key is canonical, in either direction. Missing it would
    /// re-prompt and pin the same machine twice.
    #[test]
    fn a_pin_stored_in_an_older_spelling_still_matches_a_canonical_lookup() {
        for stored in ["[::1]", "::1", "STUDIO.local.", "studio.local"] {
            let mut store = HostKeyStore::new();
            store.pins.push(HostKeyPin {
                host: stored.to_string(),
                port: 22,
                key_type: "ssh-ed25519".into(),
                fingerprint: FP_A.into(),
                first_trusted_at: 100,
                last_seen_at: 100,
            });
            let lookups: &[&str] = if stored.contains(':') {
                &["::1", "[::1]"]
            } else {
                &["studio.local", "studio.local.", "Studio.Local"]
            };
            for lookup in lookups {
                assert_eq!(
                    store.decide(lookup, 22, "ssh-ed25519", FP_A),
                    HostKeyDecision::Trusted,
                    "stored {stored}, looked up {lookup}"
                );
            }
        }
    }

    /// The mirror image: a canonical pin has to answer a lookup that still
    /// carries the brackets or the mDNS trailing dot the user typed.
    #[test]
    fn a_canonical_pin_matches_a_bracketed_or_dotted_lookup() {
        let mut store = HostKeyStore::new();
        store.trust("[::1]", 22, "ssh-ed25519", FP_A, 100);
        // `trust` writes the canonical spelling for a new pin.
        assert_eq!(store.pins[0].host, "::1");
        assert_eq!(
            store.decide("::1", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Trusted
        );
        assert_eq!(
            store.decide("[::1]", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Trusted
        );

        store.trust("Studio.Local.", 22, "ssh-ed25519", FP_A, 100);
        assert_eq!(store.pins.len(), 2);
        assert_eq!(store.pins[1].host, "studio.local");
        assert_eq!(
            store.decide("studio.local.", 22, "ssh-ed25519", FP_A),
            HostKeyDecision::Trusted
        );
        // Trusting the other spelling updates the existing pin, never adds one.
        store.trust("studio.local.", 22, "ssh-ed25519", FP_A, 200);
        assert_eq!(store.pins.len(), 2);
        assert_eq!(store.get("STUDIO.LOCAL", 22).unwrap().last_seen_at, 200);
        store.touch("[studio.local.]", 22, 300);
        assert_eq!(store.get("studio.local", 22).unwrap().last_seen_at, 300);
        assert!(store.forget("Studio.Local", 22));
        assert_eq!(store.pins.len(), 1);
    }

    /// Canonicalisation must not blur two machines together, nor soften the
    /// one decision in this file that can never be clicked through.
    #[test]
    fn canonicalisation_never_weakens_the_changed_hard_stop() {
        let mut store = HostKeyStore::new();
        store.pins.push(HostKeyPin {
            host: "[::1]".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: FP_A.into(),
            first_trusted_at: 100,
            last_seen_at: 100,
        });

        // Same machine, different key: still a hard stop through the legacy
        // spelling.
        assert_eq!(
            store.decide("::1", 22, "ssh-ed25519", FP_B),
            HostKeyDecision::Changed {
                expected: FP_A.into(),
                actual: FP_B.into(),
                key_type: "ssh-ed25519".into(),
            }
        );

        // Genuinely different endpoints stay unpinned.
        for other in ["::2", "[fe80::1]", "studio.local"] {
            assert!(
                matches!(
                    store.decide(other, 22, "ssh-ed25519", FP_A),
                    HostKeyDecision::Unknown { .. }
                ),
                "{other} must not match the ::1 pin"
            );
        }
        assert!(matches!(
            store.decide("::1", 2222, "ssh-ed25519", FP_A),
            HostKeyDecision::Unknown { .. }
        ));
    }

    /// Duplicates left by an older build collapse to the pin that was most
    /// recently seen, and pins for different machines are left alone.
    #[test]
    fn collapsing_duplicates_keeps_the_most_recently_seen_pin() {
        let pin = |host: &str, fingerprint: &str, last_seen_at: i64| HostKeyPin {
            host: host.to_string(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: fingerprint.to_string(),
            first_trusted_at: 100,
            last_seen_at,
        };
        let mut store = HostKeyStore::new();
        store.pins = vec![
            pin("studio.local", FP_A, 100),
            pin("den.local", FP_A, 100),
            pin("studio.local.", FP_B, 300),
            pin("STUDIO.LOCAL", FP_A, 200),
        ];

        assert_eq!(store.collapse_duplicates(), 2);
        assert_eq!(store.pins.len(), 2);
        assert_eq!(store.get("studio.local", 22).unwrap().fingerprint, FP_B);
        assert_eq!(store.get("den.local", 22).unwrap().fingerprint, FP_A);
        // Idempotent, and a store with nothing to merge is untouched.
        assert_eq!(store.collapse_duplicates(), 0);

        // Ties keep the earlier entry, so the result does not depend on the
        // order two pins happened to be written in.
        let mut tied = HostKeyStore::new();
        tied.pins = vec![pin("[::1]", FP_A, 100), pin("::1", FP_B, 100)];
        assert_eq!(tied.collapse_duplicates(), 1);
        assert_eq!(tied.pins[0].fingerprint, FP_A);
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
