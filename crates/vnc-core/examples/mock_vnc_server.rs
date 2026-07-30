//! Run the test mock RFB server as a standalone process.
//!
//! The unit and integration tests drive this same server in-process. Exposing
//! it as a binary lets the packaged application connect to it over a real
//! socket, which is the only way to exercise the shipped build end to end
//! without pointing it at somebody's actual machine.
//!
//! ```sh
//! cargo run -p vnc-core --example mock_vnc_server -- 5999 secret
//! ```
//!
//! Arguments: `[port] [password]`. Port defaults to 5999. Omit the password
//! for a server that offers security type None.
//!
//! It serves a 640x480 desktop with four coloured quadrants so a connected
//! viewer visibly renders something, and keeps accepting connections until
//! interrupted.

#[path = "../tests/common/mock_server.rs"]
mod mock_server;

use mock_server::{MockConfig, MockServer, RectSpec, Rgb};
use vnc_core::types::Rect;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(5999);
    let password = args.next();

    let (w, h) = (640u16, 480u16);
    let quadrant = |x: u16, y: u16, colour: Rgb| RectSpec::Raw {
        rect: Rect::new(x, y, w / 2, h / 2),
        colour,
    };
    let frame = vec![
        quadrant(0, 0, [220, 40, 40]),
        quadrant(w / 2, 0, [40, 180, 60]),
        quadrant(0, h / 2, [50, 90, 220]),
        quadrant(w / 2, h / 2, [230, 200, 40]),
    ];

    let mut cfg = MockConfig::new()
        .size(w, h)
        .name("DeskVNC mock server")
        .update(frame);
    if let Some(pw) = &password {
        // `password` only sets the secret; the advertised security type is
        // separate, so VncAuth (2) has to be selected explicitly.
        cfg = cfg.security(&[2]).password(pw);
    }

    let server = MockServer::start(cfg).await;
    // The listener is bound on an ephemeral port by `start`; report it so the
    // caller can connect. Re-binding on a fixed port is not supported by the
    // test harness, so the actual address is printed instead.
    println!("mock VNC server listening on {}", server.addr());
    println!(
        "  auth: {}",
        password
            .as_deref()
            .map(|_| "VncAuth (password supplied)")
            .unwrap_or("None")
    );
    println!("  requested port {port} is ignored; use the address above");

    // Serve until interrupted.
    tokio::signal::ctrl_c().await.ok();
    println!("shutting down");
}
