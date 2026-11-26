//! Listen for unattended helpers the way the sign in screen host does, and
//! print how many threads and open files the process holds every few
//! seconds, so a DNS outage can be watched.
//!
//! ```sh
//! dns_outage <seconds>
//! # From somewhere DNS works, knock on it by its machine ID. It should be
//! # turned away as a helper nobody paired, which shows it can be reached.
//! dns_outage helper <machine ID> <seconds>
//! ```
//!
//! On Linux, make lookups hang the way a dead resolver does: in a mount
//! namespace, point `/etc/resolv.conf` at a local server that reads every
//! query and never answers (`nameserver 127.0.0.2` with `options timeout:30
//! attempts:2`, so glibc waits a minute a lookup, as a Mac did), and
//! `/etc/nsswitch.conf` at `hosts: files dns` so systemd-resolved is not
//! asked another way. Make that server forward queries to bring DNS back.
//! Dropping port 53 with iptables does not do: a dropped packet fails the
//! send at once rather than leaving the lookup waiting.
use boundary_session::unattended::{self, Notice};
use boundary_session::{Event, HostOptions};
use std::time::{Duration, Instant};

fn threads_and_files() -> (usize, usize) {
    let count = |dir: &str| std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0);
    (count("/proc/self/task"), count("/proc/self/fd"))
}

async fn helper(machine: String, seconds: u64) {
    let mut session = unattended::connect(
        machine,
        "Outage test".into(),
        None,
        iroh::SecretKey::generate(),
        HostOptions::default(),
    );
    let start = Instant::now();
    let deadline = tokio::time::sleep(Duration::from_secs(seconds));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                println!("helper: no answer in {seconds}s");
                return;
            }
            event = session.events.recv() => match event {
                Some(Event::Status(text)) => {
                    println!("helper {:>3}s: {text}", start.elapsed().as_secs())
                }
                Some(Event::Finished(result)) => {
                    println!("helper {:>3}s: finished: {result:?}", start.elapsed().as_secs());
                    return;
                }
                Some(_) => {}
                None => return,
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("helper") {
        let machine = args.get(2).cloned().unwrap_or_default();
        let seconds = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
        helper(machine, seconds).await;
        return Ok(());
    }
    let seconds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(300);
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
                    Notice::Refused { name, reason, .. } => {
                        println!("{t:>4}s turned away {name}: {reason}")
                    }
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
