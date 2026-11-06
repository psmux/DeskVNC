//! Connect to a real RDP server and report where the sequence stops.
//!
//! The mock server in `tests/` is built from the same reading of MS-RDPBCGR as
//! the client, so a misreading is invisible to it. This example is the other
//! half: it talks to a real Windows host, and everything it finds is a fact
//! rather than an agreement with ourselves.
//!
//! Credentials come from the environment so they are never in a file, in the
//! shell history of a committed script, or in this repository.
//!
//! ```text
//! RDP_HOST=192.168.1.10 RDP_USER=someone RDP_PASS=... \
//!   cargo run -p rdp-core --example rdp_probe
//! ```
//!
//! `RDP_DOMAIN` and `RDP_PORT` are optional. `RDP_CLIP=some text` puts that
//! text on the server's clipboard once the picture is up, and every clipboard
//! text the server offers back is printed, which is how clipboard sharing is
//! checked against a real server. `RDP_SECS` sets how long the probe runs, and `RDP_RESIZE_AFTER=WxH` asks for a second size after the first reactivation. `RUST_LOG` defaults to a level
//! that prints the diagnostic frame dumps, which is the point of running it.

use remote_core::{ConnectOptions, Credentials, SessionEvent};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "rdp_core=debug,rdp_pdu=debug".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    let host = env_or_exit("RDP_HOST");
    let user = env_or_exit("RDP_USER");
    let pass = env_or_exit("RDP_PASS");
    let domain = std::env::var("RDP_DOMAIN").ok().filter(|d| !d.is_empty());
    let port: u16 = std::env::var("RDP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3389);

    println!("connecting to {host}:{port} as {user}");

    let mut options = ConnectOptions::rdp(&host, port);
    // `RDP_LICENSE_DIR=some/folder` keeps the client access licences an RD
    // licence server issues there, the way the viewer keeps them in its data
    // folder, so a second run presents the licence the first one was given.
    if let Some(dir) = std::env::var_os("RDP_LICENSE_DIR").filter(|d| !d.is_empty()) {
        options.rdp_mut().license_dir = Some(dir.into());
    }
    // `RDP_SIZE=1920x1080` asks for a desktop of that size, the way a host
    // profile with a fixed resolution does. Without it the probe measures no
    // window, so the resolver falls back to the specification's own default.
    if let Some((w, h)) = std::env::var("RDP_SIZE").ok().and_then(|s| {
        let (w, h) = s.split_once('x')?;
        Some((w.trim().parse().ok()?, h.trim().parse().ok()?))
    }) {
        options.rdp_mut().resolution = remote_core::RdpResolution::Fixed {
            width: w,
            height: h,
        };
    }
    // `RDP_GATEWAY=gateway.example:443` sends the connection through an RD
    // Gateway, signing in to it with the same account. `RDP_GATEWAY_TRANSPORT=http`
    // skips the WebSocket upgrade and uses the two channel form.
    if let Ok(gateway) = std::env::var("RDP_GATEWAY") {
        let (gw_host, gw_port) = match gateway.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(443)),
            None => (gateway.clone(), 443),
        };
        let mut gw = remote_core::GatewayOptions::new(gw_host);
        gw.port = gw_port;
        if std::env::var("RDP_GATEWAY_TRANSPORT").as_deref() == Ok("http") {
            gw.transport = remote_core::GatewayTransport::Http;
        }
        println!("through the RD Gateway at {gateway}");
        options.rdp_mut().gateway = Some(gw);
    }
    options.credentials = match &domain {
        Some(d) => Credentials::domain_user_pass(d, &user, &pass),
        None => Credentials::user_pass(&user, &pass),
    };

    let (events_tx, mut events_rx) = mpsc::channel::<SessionEvent>(256);

    // Drive the real session, the same entry point the application uses, so
    // this exercises the whole path and not just the connection sequence. An
    // earlier version of this probe stopped at `Connected` and therefore
    // proved nothing about the first frame, which is where the next fault was.
    let handle = rdp_core::RdpSession::spawn("probe".to_owned(), options, events_tx);

    let mut frames = 0usize;
    let mut cursors = 0usize;
    let (mut fb_w, mut fb_h) = (0usize, 0usize);
    let mut fb: Vec<u8> = Vec::new();
    let secs: u64 = std::env::var("RDP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let clip = std::env::var("RDP_CLIP").ok().filter(|c| !c.is_empty());
    // `RDP_RESIZE_AFTER=1600x1200` asks for that size once the server has
    // reactivated for the first time, the way a user resizes the window after
    // the session settled. A server that grants it reactivates again, and the
    // third `desktop` line printed is the proof (issue #26).
    let mut resize_after: Option<(u16, u16)> =
        std::env::var("RDP_RESIZE_AFTER").ok().and_then(|s| {
            let (w, h) = s.split_once('x')?;
            Some((w.trim().parse().ok()?, h.trim().parse().ok()?))
        });
    let mut desktops = 0usize;

    while let Some(ev) = events_rx.recv().await {
        match &ev {
            // The picture. Counted rather than printed: a busy desktop sends
            // hundreds and the interesting fact is that any arrived at all.
            SessionEvent::FramebufferUpdate { rects, .. } => {
                frames += 1;
                if frames == 1 {
                    println!("  FIRST FRAME received");
                    if let Some(text) = &clip {
                        println!("  sending clipboard text to the server: {text}");
                        let _ = handle
                            .send(remote_core::ClientCommand::ClipboardText(text.clone()))
                            .await;
                    }
                }
                // Blit into a framebuffer so the result can be written out and
                // looked at. Judging a decoder by whether frames arrive is how
                // a picture that arrives and is wrong gets shipped.
                for r in rects {
                    if let remote_core::RectPayload::Rgba(px) = &r.payload {
                        blit(
                            &mut fb,
                            fb_w,
                            fb_h,
                            r.rect.x,
                            r.rect.y,
                            r.rect.width,
                            r.rect.height,
                            px,
                        );
                    }
                }
            }
            SessionEvent::DesktopResize { width, height } => {
                fb_w = *width as usize;
                fb_h = *height as usize;
                fb = vec![0u8; fb_w * fb_h * 4];
                println!("  desktop {fb_w}x{fb_h}");
                desktops += 1;
                if desktops == 2 {
                    if let Some((width, height)) = resize_after.take() {
                        println!("  asking for {width}x{height} after the reactivation");
                        let _ = handle
                            .send(remote_core::ClientCommand::RequestResize { width, height })
                            .await;
                    }
                }
            }
            SessionEvent::CursorUpdate(_) => cursors += 1,
            SessionEvent::ClipboardText(text) => println!("  CLIPBOARD FROM SERVER: {text}"),
            SessionEvent::CertificatePrompt {
                fingerprint,
                subject,
                scheme,
                ..
            } => {
                println!("  certificate prompt: {subject} {fingerprint}");
                println!("  (probe approves it for this run only)");
                let _ = handle
                    .send(remote_core::ClientCommand::TrustCertificate {
                        fingerprint: fingerprint.clone(),
                        permanent: false,
                        scheme: *scheme,
                    })
                    .await;
            }
            SessionEvent::StateChanged(state) => {
                println!("  state: {state:?}");
                if matches!(state, remote_core::SessionState::Disconnected { .. }) {
                    break;
                }
            }
            other => println!("  event: {other:?}"),
        }
        if std::time::Instant::now() > deadline {
            println!("  ({secs} seconds elapsed, stopping)");
            let _ = handle.send(remote_core::ClientCommand::Disconnect).await;
            break;
        }
    }

    if fb_w > 0 && frames > 0 {
        let path = std::env::var("RDP_PNG").unwrap_or_else(|_| "/tmp/rdp_frame.png".into());
        match image::RgbaImage::from_raw(fb_w as u32, fb_h as u32, fb) {
            Some(img) => match img.save(&path) {
                Ok(()) => println!("  wrote {path}"),
                Err(e) => println!("  could not write {path}: {e}"),
            },
            None => println!("  framebuffer was the wrong size for an image"),
        }
    }

    println!("\nframes: {frames}, cursor updates: {cursors}");
    if frames > 0 {
        println!("the picture arrived");
    } else {
        println!("NO FRAME ARRIVED");
    }
}

fn env_or_exit(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("{key} must be set. See this example's module comment.");
            std::process::exit(2);
        }
    }
}

/// Copy one decoded rectangle into the framebuffer, clipped to it.
#[allow(clippy::too_many_arguments)]
fn blit(fb: &mut [u8], fb_w: usize, fb_h: usize, x: u16, y: u16, w: u16, h: u16, px: &[u8]) {
    let (x, y, w, h) = (x as usize, y as usize, w as usize, h as usize);
    if w == 0 || h == 0 || px.len() < w * h * 4 {
        return;
    }
    for row in 0..h {
        let dy = y + row;
        if dy >= fb_h {
            break;
        }
        let cols = w.min(fb_w.saturating_sub(x));
        if cols == 0 {
            break;
        }
        let src = &px[row * w * 4..row * w * 4 + cols * 4];
        let start = (dy * fb_w + x) * 4;
        fb[start..start + cols * 4].copy_from_slice(src);
    }
}
