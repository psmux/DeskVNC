//! Live tests against a **real** SSH server.
//!
//! This is the "test it separately" harness: it drives the whole crate, from
//! dialling to a PTY to the reconnect supervisor, against an actual sshd,
//! without any of the Tauri shell or the UI in the way.
//!
//! ```sh
//! # against your own machine (enable Remote Login first)
//! DVV_LIVE_SSH=you@localhost cargo test -p ssh-core --test live -- --nocapture
//!
//! # against anything else
//! DVV_LIVE_SSH=gj@box.local:22 cargo test -p ssh-core --test live -- --nocapture
//! ```
//!
//! ## Rules, the same ones `vnc-core/tests/interop_live.rs` follows
//!
//! * **Skip, never fail, when no server is configured.** CI has no sshd and
//!   must stay green, so every test returns early with an explanatory
//!   `eprintln!` rather than failing.
//! * **Agent authentication only.** No password is ever read, typed or
//!   prompted for, so nothing here can trip a server-side lockout. If your
//!   agent cannot get you in, neither can this.
//! * **Trust whatever key the server presents.** These tests are about the
//!   PTY and the supervisor, not about TOFU, which `ssh-transport` covers in
//!   its own unit tests. A test host-key store lives only in memory.
//! * **Leave nothing behind.** The multiplexer tests use their own session
//!   name and kill it on the way out.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use ssh_core::{
    MultiplexerConfig, MultiplexerKind, SshEvent, SshSession, SshTermOptions, TerminalState,
};
use ssh_transport::{HostKeyDecision, HostKeyStore, HostKeyVerifier, SshAuth, SshConfig};

/// Long enough for a login shell to print a banner and a prompt on a slow
/// box, short enough that a wedged test does not hold the suite up.
const SETTLE: Duration = Duration::from_secs(10);

/// The session name these tests create and destroy. Deliberately not the
/// app's default (`deskvnc`), so running the suite never touches a session a
/// human is actually using.
const TEST_SESSION: &str = "deskvnc-livetest";

/// Trust anything. See the module header: TOFU is not what these test.
struct TrustAll;

impl HostKeyVerifier for TrustAll {
    fn verify(&self, _: &str, _: u16, _: &str, _: &str) -> HostKeyDecision {
        HostKeyDecision::Trusted
    }
}

/// `$DVV_LIVE_SSH`, as `user@host` or `user@host:port`.
fn target() -> Option<SshConfig> {
    let raw = std::env::var("DVV_LIVE_SSH").ok()?;
    let (user, hostport) = raw.split_once('@')?;
    let (host, port) = match hostport.rsplit_once(':') {
        // Not a port: an unbracketed IPv6 literal. Treat the whole thing as
        // the host and take the default port.
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (hostport.to_string(), 22),
        },
        None => (hostport.to_string(), 22),
    };
    let mut cfg = SshConfig::new(host, user);
    cfg.port = port;
    // Agent only. Never a password, see the module header.
    cfg.auth = SshAuth::Agent;
    Some(cfg)
}

/// Print why we are skipping and return `None`, so a test can `let Some(x) =
/// … else { return }`.
fn skip(what: &str) -> Option<SshConfig> {
    let cfg = target();
    if cfg.is_none() {
        eprintln!("SKIP {what}: set DVV_LIVE_SSH=user@host to run the live tests");
    }
    cfg
}

fn options(cfg: SshConfig, mux: MultiplexerKind) -> SshTermOptions {
    let mut o = SshTermOptions::new(cfg);
    o.multiplexer = MultiplexerConfig {
        kind: mux,
        session_name: TEST_SESSION.to_string(),
        ..MultiplexerConfig::default()
    };
    o.terminal.cols = 100;
    o.terminal.rows = 30;
    o
}

/// Collect output until `needle` shows up, or `SETTLE` elapses.
///
/// Returns everything seen, so a failure message can show what the remote
/// actually said rather than just "timed out".
async fn read_until(
    events: &mut tokio::sync::mpsc::Receiver<SshEvent>,
    needle: &str,
) -> (bool, String, Vec<TerminalState>) {
    let mut seen = String::new();
    let mut states = Vec::new();
    let deadline = tokio::time::Instant::now() + SETTLE;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return (false, seen, states);
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Err(_) | Ok(None) => return (seen.contains(needle), seen, states),
            Ok(Some(SshEvent::Output(bytes))) => {
                seen.push_str(&String::from_utf8_lossy(&bytes));
                if seen.contains(needle) {
                    return (true, seen, states);
                }
            }
            Ok(Some(SshEvent::StateChanged(s))) => states.push(s),
            Ok(Some(_)) => {}
        }
    }
}

/// A remote shell runs a command and we see its output. The most basic claim
/// this crate makes, and the one everything else rests on.
#[tokio::test]
async fn a_command_runs_and_its_output_comes_back() {
    let Some(cfg) = skip("a_command_runs_and_its_output_comes_back") else {
        return;
    };
    let endpoint = cfg.endpoint();
    let (session, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::None), TrustAll);

    let (found, seen, states) = read_until(&mut events, "$").await;
    assert!(
        states
            .iter()
            .any(|s| matches!(s, TerminalState::Connected { .. }))
            || found,
        "never reached a connected state against {endpoint}; saw: {seen:?} / {states:?}"
    );

    session
        .input(b"echo deskvnc-live-marker\n".to_vec())
        .await
        .expect("the session should accept input");

    let (found, seen, _) = read_until(&mut events, "deskvnc-live-marker").await;
    assert!(found, "the remote never echoed the marker; saw: {seen:?}");

    session.shutdown().await;
}

/// The PTY has to be a real terminal, not a pipe. `tty` says so, and a great
/// many remote programs behave differently (or refuse to run) when it does
/// not.
#[tokio::test]
async fn the_remote_really_has_a_tty() {
    let Some(cfg) = skip("the_remote_really_has_a_tty") else {
        return;
    };
    let (session, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::None), TrustAll);
    let _ = read_until(&mut events, "$").await;

    session
        .input(b"tty; echo tty-check-done\n".to_vec())
        .await
        .unwrap();
    let (found, seen, _) = read_until(&mut events, "tty-check-done").await;
    assert!(found, "the tty check never completed; saw: {seen:?}");
    assert!(
        seen.contains("/dev/") && !seen.contains("not a tty"),
        "the session did not get a real pty; saw: {seen:?}"
    );

    session.shutdown().await;
}

/// The size we asked for has to be the size the remote believes it has, or
/// every full-screen program draws into the wrong box.
#[tokio::test]
async fn the_requested_geometry_reaches_the_remote() {
    let Some(cfg) = skip("the_requested_geometry_reaches_the_remote") else {
        return;
    };
    let (session, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::None), TrustAll);
    let _ = read_until(&mut events, "$").await;

    // `options` asked for 100x30.
    session
        .input(b"stty size; echo size-check-done\n".to_vec())
        .await
        .unwrap();
    let (found, seen, _) = read_until(&mut events, "size-check-done").await;
    assert!(found, "the size check never completed; saw: {seen:?}");
    assert!(
        seen.contains("30 100"),
        "the remote pty is not 100x30; `stty size` said: {seen:?}"
    );

    session.shutdown().await;
}

/// A resize has to reach the remote as a `window-change`, otherwise resizing
/// the window leaves the shell wrapping at the old width.
#[tokio::test]
async fn a_resize_reaches_the_remote() {
    let Some(cfg) = skip("a_resize_reaches_the_remote") else {
        return;
    };
    let (session, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::None), TrustAll);
    let _ = read_until(&mut events, "$").await;

    session.resize(132, 43).await.unwrap();
    // The window-change is asynchronous; give the remote a moment to apply it
    // before asking, rather than racing the very next command.
    tokio::time::sleep(Duration::from_millis(400)).await;

    session
        .input(b"stty size; echo resize-check-done\n".to_vec())
        .await
        .unwrap();
    let (found, seen, _) = read_until(&mut events, "resize-check-done").await;
    assert!(found, "the resize check never completed; saw: {seen:?}");
    assert!(
        seen.contains("43 132"),
        "the resize never reached the remote; `stty size` said: {seen:?}"
    );

    session.shutdown().await;
}

/// The point of the multiplexer: work started in one connection is still
/// running in the next one. This is the difference between "it reconnected"
/// and "nothing was lost", so it is worth proving end to end rather than
/// trusting the flag.
///
/// Skips itself (rather than failing) when tmux is not installed on the
/// remote, since that is a property of the test host, not of this crate.
#[tokio::test]
async fn work_survives_a_disconnect_when_a_multiplexer_is_used() {
    let Some(cfg) = skip("work_survives_a_disconnect_when_a_multiplexer_is_used") else {
        return;
    };

    // First connection: leave a marker in a shell variable, which lives only
    // inside the tmux pane and so cannot survive by any other route.
    let (first, mut events) =
        SshSession::spawn(options(cfg.clone(), MultiplexerKind::Tmux), TrustAll);
    let (_, seen, states) = read_until(&mut events, "$").await;

    let fell_back = states.iter().any(|s| {
        matches!(
            s,
            TerminalState::Connected {
                multiplexer: None,
                ..
            }
        )
    });
    if fell_back {
        eprintln!(
            "SKIP work_survives_a_disconnect_when_a_multiplexer_is_used: \
             tmux is not installed on the remote host"
        );
        first.shutdown().await;
        return;
    }
    assert!(
        !seen.is_empty() || !states.is_empty(),
        "the first connection produced nothing at all"
    );

    first
        .input(b"LIVEMARKER=survived-the-drop; echo set-done\n".to_vec())
        .await
        .unwrap();
    let (found, seen, _) = read_until(&mut events, "set-done").await;
    assert!(found, "could not set the marker; saw: {seen:?}");

    // Drop the connection. The tmux server keeps the pane, and the variable,
    // alive on the remote machine.
    first.shutdown().await;
    drop(events);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second connection: reattach and ask for the variable back.
    let (second, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::Tmux), TrustAll);
    let (_, _, states) = read_until(&mut events, "$").await;

    assert!(
        states.iter().any(|s| matches!(
            s,
            TerminalState::Connected {
                resumed: true,
                multiplexer: Some(MultiplexerKind::Tmux),
                ..
            }
        )),
        "the second connection did not report resuming an existing session: {states:?}"
    );

    second
        .input(b"echo \"marker=$LIVEMARKER\"\n".to_vec())
        .await
        .unwrap();
    let (found, seen, _) = read_until(&mut events, "marker=").await;
    assert!(found, "the reattached shell never answered; saw: {seen:?}");
    assert!(
        seen.contains("marker=survived-the-drop"),
        "the shell did not survive the disconnect, so the reattach opened a \
         fresh pane; saw: {seen:?}"
    );

    // Leave nothing behind.
    second
        .input(format!("tmux kill-session -t {TEST_SESSION}\n").into_bytes())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    second.shutdown().await;
}

/// The bug that started this: a session cut while a full-screen program has
/// mouse reporting on leaves the local terminal printing escape garbage on
/// every mouse move. The tracker must have noticed the modes and the session
/// must emit the undo on the way out.
///
/// Uses a bare `printf` of the DECSET sequences rather than launching a real
/// `vim`, so the test does not depend on what is installed or on a particular
/// version's startup behaviour. The bytes are identical either way, which is
/// all the tracker sees.
#[tokio::test]
async fn a_dropped_session_emits_the_terminal_reset() {
    let Some(cfg) = skip("a_dropped_session_emits_the_terminal_reset") else {
        return;
    };
    let (session, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::None), TrustAll);
    let _ = read_until(&mut events, "$").await;

    // Exactly what tmux and vim send: button-event tracking, SGR extended
    // coordinates, bracketed paste, alternate screen.
    session
        .input(
            b"printf '\\033[?1002h\\033[?1006h\\033[?2004h\\033[?1049h'; echo modes-on\n".to_vec(),
        )
        .await
        .unwrap();
    let (found, seen, _) = read_until(&mut events, "modes-on").await;
    assert!(found, "the mode sequences were never echoed; saw: {seen:?}");

    session.shutdown().await;

    // Drain what is left and find the reset.
    let mut reset: Option<Vec<u8>> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(event)) = tokio::time::timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        events.recv(),
    )
    .await
    {
        if let SshEvent::ResetTerminal(bytes) = event {
            reset = Some(bytes);
            break;
        }
    }

    let reset = reset.expect(
        "the session ended without emitting a terminal reset, so a real user \
         would be left with the mouse reporting escape codes at their prompt",
    );
    let text = String::from_utf8_lossy(&reset);
    for mode in ["1002", "1006", "2004", "1049"] {
        assert!(
            text.contains(mode),
            "the reset does not turn off mode {mode}: {text:?}"
        );
    }
    // And the unconditional tail that puts colours, charset and scroll region
    // back, whatever else was left on.
    assert!(text.contains("\x1b[!p"), "no DECSTR soft reset: {text:?}");

    session.shutdown().await;
}

/// A host-key store is shared across every SSH feature in the app, so a
/// terminal connect must leave a pin the Files panel would also accept. This
/// is the one live test that does exercise TOFU, because sharing the store is
/// a property of the integration rather than of `ssh-transport` alone.
#[tokio::test]
async fn a_terminal_connect_pins_the_host_key() {
    let Some(cfg) = skip("a_terminal_connect_pins_the_host_key") else {
        return;
    };
    let host = cfg.host.clone();
    let port = cfg.port;
    let pins = Arc::new(Mutex::new(HostKeyStore::new()));

    // First contact against an empty store must refuse and say why.
    //
    // Matched rather than `expect_err`, because the success type is an SSH
    // handle and `expect_err` would require it to be `Debug`.
    let (key_type, fingerprint) =
        match ssh_transport::connect_and_authenticate(&cfg, Arc::new(pins.clone())).await {
            Err(ssh_transport::Error::HostKeyUnknown {
                key_type,
                fingerprint,
                ..
            }) => (key_type, fingerprint),
            Err(other) => panic!("expected HostKeyUnknown on first contact, got: {other}"),
            Ok(_) => panic!("an unknown host key must not connect silently"),
        };

    // Trust it, exactly as the shell does after the user accepts the prompt.
    pins.lock().trust(
        &host,
        port,
        &key_type,
        &fingerprint,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    );

    // Now the terminal opens against that same store without prompting.
    let (session, mut events) = SshSession::spawn(options(cfg, MultiplexerKind::None), pins);
    let (_, seen, states) = read_until(&mut events, "$").await;
    assert!(
        states
            .iter()
            .any(|s| matches!(s, TerminalState::Connected { .. })),
        "a pinned host key should connect without a prompt; saw: {seen:?} / {states:?}"
    );

    session.shutdown().await;
}
