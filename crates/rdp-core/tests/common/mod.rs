//! Shared test scaffolding (PRDRDP/12 §3.14).

#![allow(dead_code)]

pub mod mock_rdp_server;

use remote_core::{ConnectOptions, NlaPolicy, RdpOptions};
use std::net::SocketAddr;

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
