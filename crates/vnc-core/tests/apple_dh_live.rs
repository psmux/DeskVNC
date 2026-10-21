//! Authenticated live test against real macOS Screen Sharing (security type 30).
//!
//! `interop_live.rs` never authenticates. This one does: it logs in with Apple
//! DH, waits for ServerInit and at least one framebuffer update, and fails on
//! any session error. It runs only when all three variables are set, so CI and
//! a plain `cargo test` skip it.
//!
//! ```sh
//! DVV_LIVE_APPLE=127.0.0.1:15900 DVV_LIVE_APPLE_USER=… DVV_LIVE_APPLE_PASS=… \
//!   cargo test -p vnc-core --test apple_dh_live -- --nocapture
//! ```
//!
//! The account needs Screen Sharing access. When Remote Management is on, a
//! correct password is still refused unless the account has ARD privileges
//! (`kickstart -configure -users <name> -access -on -privs -all`); the Mac's
//! screensharingd log shows that as a failure after "remote management".

use std::time::Duration;

use tokio::sync::mpsc;
use vnc_core::types::{ConnectOptions, Credentials, SessionEvent, SessionState};
use vnc_core::Session;

const DEADLINE: Duration = Duration::from_secs(45);

#[tokio::test]
async fn live_apple_dh_login_reaches_framebuffer() {
    let (Ok(target), Ok(user), Ok(pass)) = (
        std::env::var("DVV_LIVE_APPLE"),
        std::env::var("DVV_LIVE_APPLE_USER"),
        std::env::var("DVV_LIVE_APPLE_PASS"),
    ) else {
        eprintln!("SKIP: set DVV_LIVE_APPLE, DVV_LIVE_APPLE_USER and DVV_LIVE_APPLE_PASS");
        return;
    };
    let (host, port) = target.rsplit_once(':').expect("DVV_LIVE_APPLE is host:port");
    let port: u16 = port.parse().expect("port");

    let mut options = ConnectOptions::vnc(host, port);
    options.credentials = Credentials {
        username: Some(user),
        password: Some(pass),
        domain: None,
    };
    options.reconnect.enabled = false;

    let (tx, mut rx) = mpsc::channel::<SessionEvent>(256);
    let handle = Session::spawn("apple-dh-live".into(), options, tx);

    let mut method = None;
    let mut connected = false;
    let mut frames = 0u32;
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while frames == 0 {
        let event = match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(_) => break,
        };
        match event {
            SessionEvent::StateChanged(SessionState::Authenticating { method: m }) => {
                method = Some(m)
            }
            SessionEvent::StateChanged(SessionState::Connected) => connected = true,
            SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                panic!("disconnected before the first frame: {reason}")
            }
            SessionEvent::Error(e) => panic!("session error: {e}"),
            SessionEvent::CredentialsRequired(req) => {
                panic!("credentials were refused: {:?}", req.error)
            }
            SessionEvent::FramebufferUpdate { .. } => frames += 1,
            _ => {}
        }
    }
    handle.shutdown();

    assert_eq!(method.as_deref(), Some("AppleDh"), "must authenticate with type 30");
    assert!(connected, "never reached Connected");
    assert!(frames > 0, "no framebuffer update within {DEADLINE:?}");
    eprintln!("LIVE {target}: Apple DH login, connected, first frame received");
}
