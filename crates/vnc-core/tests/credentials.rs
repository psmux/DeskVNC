//! Interactive credentials: the session must PAUSE mid-handshake and ask,
//! not fail (PRD/10 §3.4).
//!
//! These run against the real mock RFB server over a real socket, so they
//! exercise `session::connection`'s command pump, `security::prompt` and each
//! security module's "what do I need from the user" declaration together.
//!
//! The safety property under all of this: re-prompting happens *inside* one
//! supervisor iteration, so an authentication failure still never reaches the
//! auto-reconnect backoff loop. Every test that can assert it, does.

mod common;

use std::time::{Duration, Instant};

use common::*;
use vnc_core::security::ra2;
use vnc_core::security::VeNCryptSubtype;
use vnc_core::types::{
    ClientCommand, CredentialKind, CredentialRequest, SecurityType, SessionEvent, SessionState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wait for the credential prompt the session raises mid-handshake.
async fn wait_prompt(events: &mut Events, within: Duration) -> CredentialRequest {
    events
        .wait(within, "SessionEvent::CredentialsRequired", |ev| match ev {
            SessionEvent::CredentialsRequired(req) => Some(req.clone()),
            _ => None,
        })
        .await
}

fn provide(password: &str) -> ClientCommand {
    ClientCommand::ProvideCredentials {
        username: None,
        password: password.into(),
        save: false,
    }
}

fn provide_user(username: &str, password: &str) -> ClientCommand {
    ClientCommand::ProvideCredentials {
        username: Some(username.into()),
        password: password.into(),
        save: false,
    }
}

/// Wait for the terminal `Disconnected` state, returning `can_retry`.
async fn wait_disconnected(events: &mut Events, within: Duration) -> bool {
    events
        .wait_state(within, "terminal Disconnected", |s| match s {
            SessionState::Disconnected { can_retry, .. } => Some(*can_retry),
            _ => None,
        })
        .await
}

fn saw_reconnecting(events: &Events) -> bool {
    events
        .states()
        .iter()
        .any(|s| matches!(s, SessionState::Reconnecting { .. }))
}

// ---------------------------------------------------------------------------
// The bug: no stored password must not mean "authentication failed"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_stored_password_prompts_and_then_connects() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    // No credentials at all: this is the reported bug's exact setup.
    let (handle, mut events) = spawn_session(options(server.port()));

    let req = wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(req.method, "VNC Authentication");
    assert_eq!(req.kind, CredentialKind::PasswordOnly);
    assert!(
        req.truncates_password,
        "VNC auth is DES: the UI must warn about the 8-character truncation"
    );
    assert_eq!(req.attempt, 1);
    assert_eq!(req.error, None, "nothing has been rejected yet");

    send(&handle, provide("swordfish")).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;

    assert_eq!(server.selected_security(), vec![SEC_VNC_AUTH]);
    assert_eq!(
        server.connection_count(),
        1,
        "prompting must not cost an extra connection"
    );
    assert!(!saw_reconnecting(&events));
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Retry on rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_answer_is_asked_again_with_the_server_reason() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));

    let first = wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(first.attempt, 1);
    send(&handle, provide("not-it")).await;

    let second = wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(second.attempt, 2, "a rejection must re-ask, not dead-end");
    assert!(
        second
            .error
            .as_deref()
            .is_some_and(|e| e.contains("Authentication failed")),
        "the retry must carry the server's reason, got {:?}",
        second.error
    );
    assert_eq!(second.method, "VNC Authentication");
    assert!(second.truncates_password);

    send(&handle, provide("swordfish")).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;

    assert!(
        !saw_reconnecting(&events),
        "re-prompting must not go through the reconnect supervisor: {:?}",
        events.states()
    );
    handle.shutdown();
}

#[tokio::test]
async fn three_rejections_end_in_auth_failed_and_never_reconnect() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    // A 20 ms backoff: any reconnect loop would be unmistakable.
    let mut opts = options(server.port());
    opts.reconnect.initial_delay_ms = 20;
    opts.reconnect.max_delay_ms = 20;
    let (handle, mut events) = spawn_session(opts);

    for expected_attempt in 1..=3u32 {
        let req = wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
        assert_eq!(req.attempt, expected_attempt);
        assert_eq!(req.error.is_some(), expected_attempt > 1);
        send(&handle, provide("still-wrong")).await;
    }

    let can_retry = wait_disconnected(&mut events, DEFAULT_TIMEOUT).await;
    assert!(
        !can_retry,
        "a rejected credential needs user action; can_retry must be false"
    );
    assert!(
        events.any(|e| matches!(e, SessionEvent::Error(m) if m.contains("password"))),
        "expected a password error, saw {:?}",
        events.summary()
    );

    // Give a hypothetical retry loop plenty of time to show itself.
    events.drain_for(Duration::from_millis(500)).await;
    assert!(
        !saw_reconnecting(&events),
        "an auth failure must NEVER emit Reconnecting: {:?}",
        events.states()
    );
    assert_eq!(
        events
            .seen
            .iter()
            .filter(|e| matches!(e, SessionEvent::CredentialsRequired(_)))
            .count(),
        3,
        "exactly three prompts, then stop"
    );
    assert_eq!(
        server.connection_count(),
        3,
        "one connection per attempt, RFB closes the socket on a rejection"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Cancellation and teardown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelling_the_prompt_aborts_the_attempt_promptly() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    wait_prompt(&mut events, DEFAULT_TIMEOUT).await;

    let sent_at = Instant::now();
    send(&handle, ClientCommand::CancelCredentials).await;
    let can_retry = wait_disconnected(&mut events, DEFAULT_TIMEOUT).await;

    assert!(
        sent_at.elapsed() < Duration::from_secs(2),
        "cancelling must tear the attempt down immediately, took {:?}",
        sent_at.elapsed()
    );
    assert!(!can_retry);
    assert!(!saw_reconnecting(&events));
    assert_eq!(server.connection_count(), 1);
    handle.shutdown();
}

#[tokio::test]
async fn disconnect_during_a_prompt_tears_the_session_down() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    wait_prompt(&mut events, DEFAULT_TIMEOUT).await;

    send(&handle, ClientCommand::Disconnect).await;
    wait_disconnected(&mut events, DEFAULT_TIMEOUT).await;
    assert!(!saw_reconnecting(&events));
    handle.shutdown();
}

#[tokio::test]
async fn shutdown_during_a_prompt_does_not_hang() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    wait_prompt(&mut events, DEFAULT_TIMEOUT).await;

    handle.shutdown();
    wait_disconnected(&mut events, DEFAULT_TIMEOUT).await;
}

// ---------------------------------------------------------------------------
// No regression: stored credentials must never raise a prompt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stored_credentials_never_prompt() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let (handle, mut events) = spawn_session(with_password(options(server.port()), "swordfish"));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.drain_for(Duration::from_millis(200)).await;

    assert!(
        !events.any(|e| matches!(e, SessionEvent::CredentialsRequired(_))),
        "a stored password must be used silently: {:?}",
        events.summary()
    );
    assert_eq!(server.connection_count(), 1);
    handle.shutdown();
}

/// The counterpart of `connect::wrong_password_never_enters_a_retry_loop`,
/// stated from the prompt's side: a *stored* password the server rejects must
/// fail once. Re-prompting a credential the user did not just type would loop
/// against a server that locks accounts out after N failures.
#[tokio::test]
async fn a_rejected_stored_password_fails_once_without_prompting() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let (handle, mut events) = spawn_session(with_password(options(server.port()), "wrong"));
    let can_retry = wait_disconnected(&mut events, DEFAULT_TIMEOUT).await;
    assert!(!can_retry);

    events.drain_for(Duration::from_millis(400)).await;
    assert!(
        !events.any(|e| matches!(e, SessionEvent::CredentialsRequired(_))),
        "stored credentials must not be re-prompted: {:?}",
        events.summary()
    );
    assert!(!saw_reconnecting(&events));
    assert_eq!(server.connection_count(), 1);
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// A username+password method end to end (VeNCrypt Plain)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vencrypt_plain_asks_for_a_username_and_a_password() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VENCRYPT])
            .username("alice")
            .password("hunter2"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));

    let req = wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(req.method, "VeNCrypt (Plain)");
    assert_eq!(req.kind, CredentialKind::UsernameAndPassword);
    assert!(
        !req.truncates_password,
        "Plain sends the password verbatim; no truncation warning"
    );
    assert_eq!(req.attempt, 1);

    send(&handle, provide_user("alice", "hunter2")).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;

    assert_eq!(
        server.plain_credentials(),
        vec![("alice".to_string(), "hunter2".to_string())]
    );
    handle.shutdown();
}

#[tokio::test]
async fn vencrypt_plain_reprompts_after_a_bad_username() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VENCRYPT])
            .username("alice")
            .password("hunter2"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));

    wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
    send(&handle, provide_user("bob", "hunter2")).await;

    let retry = wait_prompt(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(retry.attempt, 2);
    assert!(retry.error.is_some());
    assert_eq!(
        retry.username_hint.as_deref(),
        Some("bob"),
        "the retry prompt prefills what the user last typed"
    );

    send(&handle, provide_user("alice", "hunter2")).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert!(!saw_reconnecting(&events));
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// The declaration table the dialog renders from (PRD/10 §3.4)
// ---------------------------------------------------------------------------

/// Every security type must declare the right `kind`/`truncates_password`.
/// Only VncAuth, the VeNCrypt `*Vnc` subtypes and MSLogonII use DES.
#[test]
fn security_types_declare_the_right_truncation() {
    assert!(SecurityType::VncAuth.truncates_password());
    assert!(SecurityType::MsLogonII.truncates_password());
    assert!(!SecurityType::AppleDh.truncates_password());
    assert!(!SecurityType::VeNCrypt.truncates_password());
    assert!(!SecurityType::Ra2.truncates_password());
    assert!(!SecurityType::Ra2_256.truncates_password());

    assert!(VeNCryptSubtype::X509Vnc.truncates_password());
    assert!(VeNCryptSubtype::TlsVnc.truncates_password());
    assert!(!VeNCryptSubtype::X509Plain.truncates_password());
    assert!(!VeNCryptSubtype::Plain.truncates_password());
}

#[test]
fn vencrypt_subtypes_declare_the_right_credential_kind_and_name() {
    assert_eq!(
        VeNCryptSubtype::X509Plain.credential_kind(),
        Some(CredentialKind::UsernameAndPassword)
    );
    assert_eq!(
        VeNCryptSubtype::X509Vnc.credential_kind(),
        Some(CredentialKind::PasswordOnly)
    );
    assert_eq!(VeNCryptSubtype::X509None.credential_kind(), None);
    assert_eq!(
        VeNCryptSubtype::X509Plain.method_name(),
        "VeNCrypt (X509Plain)"
    );
    assert_eq!(VeNCryptSubtype::TlsVnc.method_name(), "VeNCrypt (TlsVnc)");
}

/// RA2 only learns what it needs from the server's subtype byte, mid-handshake.
#[test]
fn ra2_subtypes_declare_the_right_credential_kind() {
    assert_eq!(
        ra2::credential_kind_for_subtype(1),
        Some(CredentialKind::UsernameAndPassword)
    );
    assert_eq!(
        ra2::credential_kind_for_subtype(2),
        Some(CredentialKind::PasswordOnly)
    );
    assert_eq!(ra2::credential_kind_for_subtype(3), None);
    assert_eq!(ra2::METHOD, "RealVNC RSA-AES");
}

#[test]
fn method_names_match_the_dialog_contract() {
    assert_eq!(vnc_core::security::vnc_auth::METHOD, "VNC Authentication");
    assert_eq!(vnc_core::security::apple_dh::METHOD, "Apple Remote Desktop");
    assert_eq!(vnc_core::security::mslogon::METHOD, "UltraVNC MS-Logon");
}
