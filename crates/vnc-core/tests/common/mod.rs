//! Shared helpers for the vnc-core end-to-end integration tests.

#![allow(dead_code)]

pub mod mock_server;

use std::time::Duration;

use tokio::sync::mpsc;

use vnc_core::types::{
    ClientCommand, ConnectOptions, Credentials, ReconnectPolicy, SessionEvent, SessionState,
};
use vnc_core::{Session, SessionHandle};

pub use mock_server::*;

/// Nothing in these tests should ever take longer than this; exceeding it is a
/// hang, and a hang must fail the test rather than block CI.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Connect options
// ---------------------------------------------------------------------------

/// Options pointed at a mock server, with a fast, deterministic reconnect
/// policy (no jitter) so backoff assertions are exact.
pub fn options(port: u16) -> ConnectOptions {
    let mut o = ConnectOptions::vnc("127.0.0.1", port);
    // Deliberately the shipping defaults. This used to set
    // `allow_insecure = true`, which meant every integration test ran with an
    // opt-in no real session has, and `security_none_reaches_connected`
    // therefore proved nothing about the path a user takes: connecting to a
    // passwordless server was broken for releases with that test green
    // (issue #1).
    o.connect_timeout = Duration::from_secs(5);
    o.reconnect = ReconnectPolicy {
        enabled: true,
        max_attempts: None,
        initial_delay_ms: 100,
        max_delay_ms: 400,
        multiplier: 2.0,
        jitter: 0.0,
    };
    o
}

/// Options with the reconnect policy the PRD ships by default (250 ms first
/// retry, ±20% jitter, capped at 15 s).
pub fn options_default_policy(port: u16) -> ConnectOptions {
    let mut o = options(port);
    o.reconnect = ReconnectPolicy::default();
    o
}

pub fn with_password(mut o: ConnectOptions, pw: &str) -> ConnectOptions {
    o.credentials = Credentials::password(pw);
    o
}

// ---------------------------------------------------------------------------
// Event stream helper
// ---------------------------------------------------------------------------

/// Wraps the session event channel with bounded, panicking waits so a stalled
/// session fails the test instead of hanging it. Every event that goes past is
/// retained in [`Events::seen`] for after-the-fact assertions.
pub struct Events {
    rx: mpsc::Receiver<SessionEvent>,
    pub seen: Vec<SessionEvent>,
}

impl Events {
    pub fn new(rx: mpsc::Receiver<SessionEvent>) -> Self {
        Self {
            rx,
            seen: Vec::new(),
        }
    }

    /// Wait for the first event `f` maps to `Some`, consuming (and recording)
    /// everything before it. Panics on timeout or channel close.
    pub async fn wait<T, F>(&mut self, within: Duration, what: &str, f: F) -> T
    where
        F: Fn(&SessionEvent) -> Option<T>,
    {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let ev = match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Err(_) => panic!("timed out waiting for {what}; saw: {:?}", self.summary()),
                Ok(None) => panic!(
                    "event channel closed waiting for {what}; saw: {:?}",
                    self.summary()
                ),
                Ok(Some(ev)) => ev,
            };
            let hit = f(&ev);
            self.seen.push(ev);
            if let Some(v) = hit {
                return v;
            }
        }
    }

    /// Wait for a state matching `f`.
    pub async fn wait_state<T, F>(&mut self, within: Duration, what: &str, f: F) -> T
    where
        F: Fn(&SessionState) -> Option<T>,
    {
        self.wait(within, what, |ev| match ev {
            SessionEvent::StateChanged(s) => f(s),
            _ => None,
        })
        .await
    }

    pub async fn wait_connected(&mut self, within: Duration) {
        self.wait_state(within, "SessionState::Connected", |s| {
            matches!(s, SessionState::Connected).then_some(())
        })
        .await
    }

    /// Wait for the next coalesced framebuffer update.
    pub async fn wait_framebuffer(
        &mut self,
        within: Duration,
    ) -> (Vec<vnc_core::types::DecodedRect>, vnc_core::types::Rect) {
        self.wait(within, "SessionEvent::FramebufferUpdate", |ev| match ev {
            SessionEvent::FramebufferUpdate { rects, damage } => Some((rects.clone(), *damage)),
            _ => None,
        })
        .await
    }

    /// Drain everything currently queued (plus anything arriving within
    /// `quiet`) without asserting on it.
    pub async fn drain_for(&mut self, quiet: Duration) {
        let deadline = tokio::time::Instant::now() + quiet;
        loop {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(ev)) => self.seen.push(ev),
                _ => return,
            }
        }
    }

    /// True if any event seen so far matches.
    pub fn any<F: Fn(&SessionEvent) -> bool>(&self, f: F) -> bool {
        self.seen.iter().any(f)
    }

    pub fn states(&self) -> Vec<SessionState> {
        self.seen
            .iter()
            .filter_map(|e| match e {
                SessionEvent::StateChanged(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn errors(&self) -> Vec<String> {
        self.seen
            .iter()
            .filter_map(|e| match e {
                SessionEvent::Error(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    /// Compact description of what has been seen, for failure messages.
    pub fn summary(&self) -> Vec<String> {
        self.seen
            .iter()
            .map(|e| match e {
                SessionEvent::StateChanged(s) => format!("State({s:?})"),
                SessionEvent::FramebufferUpdate { rects, damage } => {
                    format!("Fb({} rects, damage {damage:?})", rects.len())
                }
                SessionEvent::DesktopResize { width, height } => {
                    format!("Resize({width}x{height})")
                }
                SessionEvent::DesktopName(n) => format!("Name({n})"),
                SessionEvent::ClipboardText(t) => format!("Clipboard({t:?})"),
                SessionEvent::Error(m) => format!("Error({m})"),
                other => format!("{other:?}"),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Session bootstrap
// ---------------------------------------------------------------------------

/// Spawn a session against `options`, returning its handle and event stream.
pub fn spawn_session(options: ConnectOptions) -> (SessionHandle, Events) {
    let (tx, rx) = mpsc::channel(512);
    let handle = Session::spawn("test-session".into(), options, tx);
    (handle, Events::new(rx))
}

/// Send a command, failing the test if the session is already gone.
pub async fn send(handle: &SessionHandle, cmd: ClientCommand) {
    handle
        .send(cmd)
        .await
        .expect("session command channel should still be open");
}
