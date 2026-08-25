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
//! `RDP_DOMAIN` and `RDP_PORT` are optional. `RUST_LOG` defaults to a level
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);

    while let Some(ev) = events_rx.recv().await {
        match &ev {
            // The picture. Counted rather than printed: a busy desktop sends
            // hundreds and the interesting fact is that any arrived at all.
            SessionEvent::FramebufferUpdate { rects, .. } => {
                frames += 1;
                if frames == 1 {
                    println!("  FIRST FRAME received");
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
            }
            SessionEvent::CursorUpdate(_) => cursors += 1,
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
            println!("  (20 seconds elapsed, stopping)");
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
