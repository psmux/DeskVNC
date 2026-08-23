//! Trust on first use pins.
//!
//! Moved out of `vnc-core/src/types.rs` unchanged (PRDRDP/02 §2.1), tests
//! included. Phase 1 adds `PinScheme::RdpTls` for the RDP TLS upgrade
//! (PRDRDP/02 §2.2.5); nothing here anticipates it.

use serde::{Deserialize, Serialize};

/// Which server key a trust-on-first-use pin describes.
///
/// Two handshakes authenticate a server identity, and they authenticate
/// *different keys*:
///
/// * [`PinScheme::Tls`], VeNCrypt's TLS upgrade, SHA-256 over the X.509
///   certificate's SubjectPublicKeyInfo.
/// * [`PinScheme::Ra2`], RealVNC RSA-AES, SHA-256 over the server's RSA
///   public key in canonical DER SPKI form.
///
/// A server can offer both (wayvnc does). Their fingerprints are unrelated, so
/// pins must be stored and compared per scheme: matching a TLS pin against an
/// RA2 key would report a changed identity for a server that changed nothing, /// the worst kind of false alarm, because it teaches the user to click through
/// the real one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PinScheme {
    /// TLS / VeNCrypt X.509 certificate SPKI.
    Tls,
    /// RealVNC RSA-AES (RA2 / RA2ne / RA2_256 / RA2ne_256) server RSA key.
    Ra2,
}

impl PinScheme {
    /// Every scheme, for callers that must handle all of them (loading pins
    /// before a security type is negotiated, forgetting an endpoint).
    pub const ALL: [PinScheme; 2] = [PinScheme::Tls, PinScheme::Ra2];

    /// The wire/database spelling. Matches the serde representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            PinScheme::Tls => "tls",
            PinScheme::Ra2 => "ra2",
        }
    }

    /// Parses a stored spelling. `None` for anything unrecognised, a pin row
    /// written by a newer build is ignored, never guessed at.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tls" => Some(PinScheme::Tls),
            "ra2" => Some(PinScheme::Ra2),
            _ => None,
        }
    }
}

impl std::fmt::Display for PinScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The pins available for one endpoint, one per [`PinScheme`].
///
/// At connect time the security type has not been negotiated yet, so whichever
/// handshake runs must be able to find its own pin. Carrying only one would
/// mean either prompting for a key already trusted or, worse, comparing a pin
/// against a key it does not describe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertPins {
    /// SHA-256 SPKI of the pinned X.509 certificate (hex).
    pub tls: Option<String>,
    /// SHA-256 SPKI of the pinned RA2 server RSA key (hex).
    pub ra2: Option<String>,
}

impl CertPins {
    /// The pin a given handshake should verify against, and only that one.
    pub fn for_scheme(&self, scheme: PinScheme) -> Option<&str> {
        match scheme {
            PinScheme::Tls => self.tls.as_deref(),
            PinScheme::Ra2 => self.ra2.as_deref(),
        }
    }

    pub fn set(&mut self, scheme: PinScheme, pin: Option<String>) {
        match scheme {
            PinScheme::Tls => self.tls = pin,
            PinScheme::Ra2 => self.ra2 = pin,
        }
    }

    /// Convenience for a single known pin (tests, probes).
    pub fn one(scheme: PinScheme, pin: impl Into<String>) -> Self {
        let mut pins = Self::default();
        pins.set(scheme, Some(pin.into()));
        pins
    }

    pub fn is_empty(&self) -> bool {
        self.tls.is_none() && self.ra2.is_none()
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use crate::options::ConnectOptions;

    /// The wire spelling is a stored value: the DB, the IPC payload and the
    /// serde representation must all agree, or a pin written by one layer is
    /// invisible to another.
    #[test]
    fn scheme_spelling_is_stable() {
        for scheme in PinScheme::ALL {
            let json = serde_json::to_string(&scheme).unwrap();
            assert_eq!(json, format!("\"{}\"", scheme.as_str()));
            assert_eq!(PinScheme::parse(scheme.as_str()), Some(scheme));
            assert_eq!(
                serde_json::from_str::<PinScheme>(&json).unwrap(),
                scheme,
                "round trip"
            );
        }
        assert_eq!(PinScheme::parse("TLS"), Some(PinScheme::Tls));
        assert_eq!(PinScheme::parse(" ra2 "), Some(PinScheme::Ra2));
    }

    /// Anything unrecognised is ignored, never mapped onto a known scheme, /// a pin applied to the wrong key is worse than no pin at all.
    #[test]
    fn an_unknown_scheme_does_not_degrade_into_a_known_one() {
        for junk in ["", "ssh", "ra", "tls2", "quantum-kem"] {
            assert_eq!(PinScheme::parse(junk), None, "{junk:?}");
        }
    }

    /// The core of the fix: one endpoint, two unrelated keys. Each handshake
    /// sees only the pin for the key it is actually verifying.
    #[test]
    fn a_pin_is_only_visible_to_its_own_scheme() {
        let mut pins = CertPins::default();
        assert!(pins.is_empty());
        assert_eq!(pins.for_scheme(PinScheme::Tls), None);

        pins.set(PinScheme::Tls, Some("aa".repeat(32)));
        assert_eq!(pins.for_scheme(PinScheme::Tls).unwrap(), "aa".repeat(32));
        assert_eq!(
            pins.for_scheme(PinScheme::Ra2),
            None,
            "a TLS pin must not be offered to the RA2 handshake"
        );

        pins.set(PinScheme::Ra2, Some("bb".repeat(32)));
        assert_eq!(pins.for_scheme(PinScheme::Tls).unwrap(), "aa".repeat(32));
        assert_eq!(pins.for_scheme(PinScheme::Ra2).unwrap(), "bb".repeat(32));

        pins.set(PinScheme::Tls, None);
        assert_eq!(pins.for_scheme(PinScheme::Tls), None);
        assert_eq!(
            pins.for_scheme(PinScheme::Ra2).unwrap(),
            "bb".repeat(32),
            "forgetting one scheme must not disturb the other"
        );
    }

    #[test]
    fn connect_options_start_with_no_pins() {
        assert!(ConnectOptions::vnc("h", 5900).cert_pins.is_empty());
        let one = CertPins::one(PinScheme::Ra2, "cc");
        assert_eq!(one.for_scheme(PinScheme::Ra2), Some("cc"));
        assert_eq!(one.for_scheme(PinScheme::Tls), None);
    }
}
