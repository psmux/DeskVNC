//! The injected-transport path end to end (PRD/10 §5).
//!
//! `ConnectOptions::connector` is how the SSH tunnel carries the RFB stream.
//! These tests stand in a plain TCP dialler for the tunnel: what is under
//! test is the *session core's* contract with a connector, the endpoint is
//! never resolved locally, every byte flows through the stream the connector
//! returns, and the reconnect supervisor asks it again after a drop, exactly
//! what a re-dialled SSH channel needs.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;

use vnc_core::types::{Connector, Rect, SessionState};
use vnc_transport::{BoxedStream, ConnectFuture, StreamConnector};

const RED: Rgb = [255, 0, 0];

/// A host name that must never touch DNS. `.invalid` is reserved (RFC 2606),
/// so if the session ever bypasses the connector the connect fails loudly.
const BEHIND_GATEWAY: &str = "vnc-host-behind-gateway.invalid";

/// Stands in for the SSH tunnel: dials the mock server over loopback and
/// records every endpoint it was asked for.
struct RecordingConnector {
    mock_port: u16,
    dials: AtomicUsize,
    asked_for: Mutex<Vec<(String, u16)>>,
}

impl RecordingConnector {
    fn new(mock_port: u16) -> Self {
        Self {
            mock_port,
            dials: AtomicUsize::new(0),
            asked_for: Mutex::new(Vec::new()),
        }
    }
}

impl StreamConnector for RecordingConnector {
    fn connect(&self, host: &str, port: u16, _timeout: Duration) -> ConnectFuture<'_> {
        self.asked_for
            .lock()
            .unwrap()
            .push((host.to_string(), port));
        let mock_port = self.mock_port;
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", mock_port)).await?;
            Ok(Box::pin(tcp) as BoxedStream)
        })
    }

    fn describe(&self) -> String {
        "test connector".into()
    }
}

fn tunnelled_options(connector: &Arc<RecordingConnector>) -> vnc_core::types::ConnectOptions {
    // Port 1 on an unresolvable name: any local dial attempt fails fast.
    let mut o = options(1);
    o.host = BEHIND_GATEWAY.into();
    o.connector = Some(Connector(connector.clone()));
    o
}

#[tokio::test]
async fn the_session_runs_over_the_injected_connector_not_local_tcp() {
    let rect = Rect::new(0, 0, 8, 8);
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_NONE])
            .size(8, 8)
            .update(vec![RectSpec::Raw { rect, colour: RED }]),
    )
    .await;

    let connector = Arc::new(RecordingConnector::new(server.port()));
    let (handle, mut events) = spawn_session(tunnelled_options(&connector));

    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
    // The connector was handed the profile's endpoint verbatim, resolving it
    // is its business (for the SSH tunnel: the remote server's).
    assert_eq!(
        connector.asked_for.lock().unwrap().as_slice(),
        &[(BEHIND_GATEWAY.to_string(), 1)]
    );

    handle.shutdown();
}

#[tokio::test]
async fn a_reconnect_asks_the_connector_for_a_fresh_stream() {
    let rect = Rect::new(0, 0, 8, 8);
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_NONE])
            .size(8, 8)
            .update(vec![RectSpec::Raw { rect, colour: RED }])
            .drop_after_n_updates(1)
            .max_drops(1),
    )
    .await;

    let connector = Arc::new(RecordingConnector::new(server.port()));
    let (handle, mut events) = spawn_session(tunnelled_options(&connector));

    events.wait_connected(DEFAULT_TIMEOUT).await;
    // The server hangs up after the first update; the supervisor must come
    // back through the connector, never through a local socket.
    events
        .wait_state(DEFAULT_TIMEOUT, "SessionState::Reconnecting", |s| {
            matches!(s, SessionState::Reconnecting { .. }).then_some(())
        })
        .await;
    events.wait_connected(DEFAULT_TIMEOUT).await;

    assert!(
        connector.dials.load(Ordering::SeqCst) >= 2,
        "the reconnect must open a fresh connector stream"
    );

    handle.shutdown();
}
