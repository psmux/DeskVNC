//! Listen for unattended helpers the way the sign in screen host does, and
//! print how many threads and open files the process holds every few
//! seconds, so a DNS outage can be watched.
//!
//! ```sh
//! dns_outage <seconds>
//! ```
//!
//! On Linux, make lookups hang the way a dead resolver does: drop this
//! process's packets to port 53 and let glibc wait 30 s per try, twice.
//!
//! ```sh
//! sudo groupadd dnsdrop
//! sudo iptables -I OUTPUT -m owner --gid-owner dnsdrop -p udp --dport 53 -j DROP
//! sudo iptables -I OUTPUT -m owner --gid-owner dnsdrop -p tcp --dport 53 -j DROP
//! RES_OPTIONS="timeout:30 attempts:2" sudo -E -g dnsdrop dns_outage 600
//! ```
//!
//! Deleting the two rules brings DNS back, and the listener should say it is
//! listening and the relay is reachable.
use boundary_session::HostOptions;
use boundary_session::unattended::{self, Notice};
use std::time::{Duration, Instant};

fn threads_and_files() -> (usize, usize) {
    let count = |dir: &str| std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0);
    (count("/proc/self/task"), count("/proc/self/fd"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let dir = std::env::temp_dir().join(format!("dns-outage-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let access = dir.join("access.json");
    std::fs::write(&access, r#"{"enabled":true}"#)?;
    let key = iroh::SecretKey::generate();
    let start = Instant::now();
    let mut peak = (0, 0);
    let mut listener = None;
    let mut wait = Duration::ZERO;
    let mut next = Instant::now();
    let mut report = Instant::now();
    // What the sign in screen host does: listen, and listen again a while
    // after the listener stops.
    while start.elapsed() < Duration::from_secs(seconds) {
        if listener.is_none() && Instant::now() >= next {
            listener = Some(unattended::listen_at_login(
                HostOptions::default(),
                key.clone(),
                access.clone(),
                || Err(anyhow::anyhow!("no screen in this test")),
            ));
        }
        let mut finished = false;
        if let Some(l) = listener.as_mut() {
            while let Ok(notice) = l.notices.try_recv() {
                let t = start.elapsed().as_secs();
                match notice {
                    Notice::Ready { machine, .. } => {
                        println!("{t:>4}s listening as {machine}");
                        wait = Duration::ZERO;
                    }
                    Notice::Status(text) => println!("{t:>4}s {text}"),
                    Notice::Finished(result) => {
                        println!("{t:>4}s stopped listening: {result:?}");
                        finished = true;
                    }
                    _ => {}
                }
            }
        }
        if finished {
            listener = None;
            wait = unattended::relisten_wait(wait);
            next = Instant::now() + wait;
        }
        if report.elapsed() >= Duration::from_secs(5) {
            report = Instant::now();
            let (threads, files) = threads_and_files();
            peak = (peak.0.max(threads), peak.1.max(files));
            println!(
                "{:>4}s threads {threads:>4} files {files:>4} (peak {} / {})",
                start.elapsed().as_secs(),
                peak.0,
                peak.1
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
