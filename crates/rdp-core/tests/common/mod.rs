//! Shared test scaffolding (PRDRDP/12 §3.14).

#![allow(dead_code)]

pub mod mock_rdp_server;

use remote_core::{ConnectOptions, NlaPolicy, RdpOptions};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Long enough that a loaded CI box does not fail a test that is working,
/// short enough that a hang is a failure rather than a build timeout. The
/// same figure the RFB integration tests use.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Connect options pointed at a mock, with NLA off.
///
/// The mock has no certificate, so it answers the X.224 negotiation with
/// `PROTOCOL_SSL` and there is no CredSSP exchange to run.
pub fn options_for(addr: SocketAddr) -> ConnectOptions {
    let mut options = ConnectOptions::rdp(addr.ip().to_string(), addr.port());
    options.connect_timeout = DEFAULT_TIMEOUT;
    options.rdp_mut().nla = NlaPolicy::AllowFallback;
    options
}

/// The RDP half of [`options_for`], for a test that needs both.
pub fn rdp_half(options: &ConnectOptions) -> RdpOptions {
    options
        .rdp_options()
        .expect("built with ConnectOptions::rdp")
        .clone()
}

/// Connect to the mock the way the product connects to a server.
///
/// The product dials through `vnc_transport::tcp::connect`, which sets
/// TCP_NODELAY. A bare `TcpStream::connect` leaves Nagle on, and on Linux
/// loopback Nagle holds a small write back until the previous one is acked,
/// which a delayed ack puts tens of milliseconds out. Paced input written
/// 8 ms apart then reaches the mock in one lump, and a timing test measures
/// the harness rather than the client.
pub async fn dial(addr: SocketAddr) -> TcpStream {
    dial_host(&addr.ip().to_string(), addr.port())
        .await
        .expect("the mock is up")
}

/// [`dial`] for a caller that wants the failure back, the way the product's
/// own dial reports it. A dial error keeps the refused, timed out and
/// unresolved classification `vnc_transport` gives it, which is what the
/// reconnect supervisor reads to decide whether to try again.
pub async fn dial_host(host: &str, port: u16) -> vnc_transport::Result<TcpStream> {
    vnc_transport::tcp::connect(host, port, DEFAULT_TIMEOUT).await
}
