//! The stored and IPC spellings are a contract with SQLite and with
//! `ui/src/lib/types.ts`. A rename on either side is invisible at compile time
//! and breaks a saved profile or a running UI, so pin them literally
//! (PRDRDP/02 §12.2).

use remote_core::{
    CertPins, CredentialKind, CredentialRequest, Credentials, PinScheme, ProtocolKind,
    QualityPreset, RttSource, SessionState, SessionStats,
};

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

fn sample_request() -> CredentialRequest {
    CredentialRequest {
        method: "VNC Authentication".into(),
        kind: CredentialKind::PasswordOnly,
        attempt: 1,
        error: None,
        truncates_password: true,
        username_hint: None,
    }
}

#[test]
fn spellings_are_stable() {
    assert_eq!(
        to_json(&QualityPreset::BlackAndWhite),
        "\"black-and-white\""
    );
    assert_eq!(to_json(&PinScheme::Tls), "\"tls\"");
    assert_eq!(to_json(&PinScheme::Ra2), "\"ra2\"");
    assert_eq!(to_json(&ProtocolKind::Vnc), "\"vnc\"");
    assert_eq!(to_json(&ProtocolKind::Rdp), "\"rdp\"");
    assert_eq!(to_json(&RttSource::UpdatePipeline), "\"update-pipeline\"");
    assert_eq!(to_json(&RttSource::IdleProbe), "\"idle-probe\"");
    assert_eq!(
        to_json(&CredentialKind::UsernameAndPassword),
        "\"username-and-password\""
    );
}

/// `SessionState` is internally tagged on "state" with snake_case INNER
/// fields, which is not the default and is easy to lose in a refactor.
#[test]
fn session_state_keeps_its_tag_and_its_inner_field_names() {
    let s = SessionState::Reconnecting {
        attempt: 2,
        next_retry_ms: 500,
        reason: "x".into(),
    };
    assert_eq!(
        to_json(&s),
        r#"{"state":"reconnecting","attempt":2,"next_retry_ms":500,"reason":"x"}"#
    );
    let d = SessionState::Disconnected {
        reason: "x".into(),
        can_retry: true,
        symbol: None,
    };
    assert_eq!(
        to_json(&d),
        r#"{"state":"disconnected","reason":"x","can_retry":true}"#
    );
    // The symbol is serialized only when there is one, so every RFB
    // disconnect is the object it was before the field existed and the UI
    // reads `symbol` as optional (`ui/src/lib/types.ts:464`).
    let d = SessionState::Disconnected {
        reason: "x".into(),
        can_retry: false,
        symbol: Some("nla-refused".into()),
    };
    assert_eq!(
        to_json(&d),
        r#"{"state":"disconnected","reason":"x","can_retry":false,"symbol":"nla-refused"}"#
    );
    assert_eq!(
        to_json(&SessionState::Connected),
        r#"{"state":"connected"}"#
    );
    assert_eq!(
        to_json(&SessionState::Authenticating { method: "m".into() }),
        r#"{"state":"authenticating","method":"m"}"#
    );
}

/// `SessionStats` has NO `rename_all`. If someone adds one, this fails.
#[test]
fn session_stats_stays_snake_case() {
    let json = to_json(&SessionStats::default());
    assert!(json.contains("\"rtt_ms\""), "{json}");
    assert!(json.contains("\"rtt_source\""), "{json}");
    assert!(json.contains("\"throughput_up_bps\""), "{json}");
    assert!(json.contains("\"current_encoding\""), "{json}");
    assert!(!json.contains("rttMs"), "{json}");
}

/// `CredentialRequest` DOES have camelCase, and the UI reads these keys.
#[test]
fn credential_request_stays_camel_case() {
    let json = to_json(&sample_request());
    assert!(json.contains("\"truncatesPassword\""), "{json}");
    assert!(json.contains("\"usernameHint\""), "{json}");
    assert!(!json.contains("truncates_password"), "{json}");
}

/// Every pin scheme round trips through the spelling the `cert_pins.scheme`
/// column stores.
#[test]
fn pin_schemes_round_trip_through_their_stored_spelling() {
    for scheme in PinScheme::ALL {
        let json = to_json(&scheme);
        assert_eq!(json, format!("\"{}\"", scheme.as_str()));
        assert_eq!(PinScheme::parse(scheme.as_str()), Some(scheme));
        let mut pins = CertPins::default();
        pins.set(scheme, Some("ab".repeat(32)));
        assert_eq!(pins.for_scheme(scheme).unwrap(), "ab".repeat(32));
    }
}

/// D11: credentials never appear in logs.
#[test]
fn debug_redacts_every_secret() {
    let c = Credentials::domain_user_pass("CONTOSO", "alice", "hunter2");
    let s = format!("{c:?}");
    assert!(!s.contains("hunter2"), "{s}");
    assert!(!s.contains("alice"), "{s}");
    assert!(!s.contains("CONTOSO"), "{s}");
    assert!(s.contains("***"), "{s}");
}

/// The same must hold through every container that carries them.
#[test]
fn connect_options_debug_redacts_credentials() {
    let mut o = remote_core::ConnectOptions::rdp("host", 3389);
    o.credentials = Credentials::domain_user_pass("CONTOSO", "alice", "hunter2");
    let s = format!("{o:?}");
    assert!(!s.contains("hunter2"), "{s}");
    assert!(!s.contains("alice"), "{s}");
    assert!(!s.contains("CONTOSO"), "{s}");
}

/// An `RdpOptions` blob written by an older build, or truncated, must read
/// back as today's defaults rather than failing (PRDRDP/02 §12.1 rule 4).
#[test]
fn a_truncated_rdp_settings_blob_fills_in_with_defaults() {
    let parsed: remote_core::RdpOptions = serde_json::from_str(r#"{"domain":"CONTOSO"}"#).unwrap();
    assert_eq!(parsed.domain.as_deref(), Some("CONTOSO"));
    assert_eq!(
        parsed,
        remote_core::RdpOptions {
            domain: Some("CONTOSO".into()),
            ..Default::default()
        }
    );
    let vnc: remote_core::VncOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(vnc, remote_core::VncOptions::default());
}

/// No field of the RDP settings blob may hold a secret: it goes to a SQLite
/// column, and the password lives in the keychain.
#[test]
fn rdp_options_carry_no_secret() {
    let o = remote_core::RdpOptions {
        domain: Some("CONTOSO".into()),
        ..Default::default()
    };
    let json = to_json(&o);
    assert!(!json.contains("password"), "{json}");
    assert!(!json.contains("credential"), "{json}");
}
