//! Transfer bookkeeping: the event stream, progress throttling, resume
//! offsets and conflict resolution (PRD/08 §3.3).
//!
//! Everything in this module is pure, no sockets, no filesystem, so the
//! rules that actually decide "restart, resume, skip or rename?" are unit
//! testable without a live SSH server.

use std::time::{Duration, Instant};

use crate::error::Result;
use crate::path;

/// Direction of a queued transfer, from the *local* point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Upload,
    Download,
}

/// Progress and lifecycle notifications for one queue item.
///
/// Serialised onto `files://event` with the same conventions as
/// `session://event`: kebab-case `type` tag, camelCase fields, flat payload
/// (the shell inserts `sessionId` alongside `type`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum TransferEvent {
    /// Queue item accepted and started. `total` is the whole tree's byte
    /// count for a directory transfer.
    Started {
        id: String,
        name: String,
        total: u64,
        direction: Direction,
    },
    /// Throttled to [`PROGRESS_EVENTS_PER_SEC`]; `bytes_per_sec` is a
    /// smoothed rate, not an instantaneous one.
    Progress {
        id: String,
        transferred: u64,
        total: u64,
        bytes_per_sec: f64,
    },
    Completed {
        id: String,
    },
    Failed {
        id: String,
        error: String,
    },
    Cancelled {
        id: String,
    },
}

impl TransferEvent {
    /// The queue-item id every variant carries.
    pub fn id(&self) -> &str {
        match self {
            TransferEvent::Started { id, .. }
            | TransferEvent::Progress { id, .. }
            | TransferEvent::Completed { id }
            | TransferEvent::Failed { id, .. }
            | TransferEvent::Cancelled { id } => id,
        }
    }

    /// True once no further events will follow for this id.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransferEvent::Completed { .. }
                | TransferEvent::Failed { .. }
                | TransferEvent::Cancelled { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Progress throttling
// ---------------------------------------------------------------------------

/// Progress events per second, per transfer. Ten is smooth to the eye and
/// keeps a 100 MB/s transfer at ten IPC messages a second instead of the
/// ~1500 a 64 KiB chunk loop would otherwise produce.
pub const PROGRESS_EVENTS_PER_SEC: u32 = 10;

/// Rate-limits progress emission and smooths the throughput estimate.
///
/// `Instant` is passed in rather than read from the clock so the throttle can
/// be tested deterministically.
#[derive(Debug)]
pub struct ProgressThrottle {
    min_interval: Duration,
    last_emit: Option<Instant>,
    last_bytes: u64,
    /// Exponentially weighted bytes/sec; `None` until the first interval.
    rate: Option<f64>,
}

impl ProgressThrottle {
    /// Smoothing factor for the throughput EWMA (higher = more reactive).
    const ALPHA: f64 = 0.4;

    pub fn new(events_per_sec: u32) -> Self {
        let hz = events_per_sec.max(1);
        Self {
            min_interval: Duration::from_secs_f64(1.0 / f64::from(hz)),
            last_emit: None,
            last_bytes: 0,
            rate: None,
        }
    }

    /// Should a `Progress` event be emitted now?
    ///
    /// Returns the smoothed bytes/sec when yes, `None` when the update should
    /// be coalesced into the next one. `force` bypasses the interval (used for
    /// the first tick and the final one before a terminal event) but still
    /// updates the rate estimate.
    pub fn tick(&mut self, now: Instant, transferred: u64, force: bool) -> Option<f64> {
        let Some(last) = self.last_emit else {
            self.last_emit = Some(now);
            self.last_bytes = transferred;
            self.rate = Some(0.0);
            return Some(0.0);
        };
        let elapsed = now.saturating_duration_since(last);
        if !force && elapsed < self.min_interval {
            return None;
        }
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            let delta = transferred.saturating_sub(self.last_bytes) as f64;
            let instant = delta / secs;
            self.rate = Some(match self.rate {
                Some(prev) => Self::ALPHA * instant + (1.0 - Self::ALPHA) * prev,
                None => instant,
            });
        }
        self.last_emit = Some(now);
        self.last_bytes = transferred;
        Some(self.rate.unwrap_or(0.0))
    }

    /// Latest smoothed rate, without advancing the throttle.
    pub fn rate(&self) -> f64 {
        self.rate.unwrap_or(0.0)
    }
}

impl Default for ProgressThrottle {
    fn default() -> Self {
        Self::new(PROGRESS_EVENTS_PER_SEC)
    }
}

// ---------------------------------------------------------------------------
// Conflicts and resume
// ---------------------------------------------------------------------------

/// What to do when the destination already has a file of the same name.
///
/// `Resume` is the default: it is the only policy that satisfies PRD/08 §5
/// ("an interrupted transfer resumes rather than restarting from zero"),
/// and it degrades to `Skip` for files that are already complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictPolicy {
    #[default]
    Resume,
    Skip,
    Overwrite,
    Rename,
}

/// The decision for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictOutcome {
    /// Write from byte 0, truncating anything already there.
    Fresh,
    /// Append from `offset`; `offset` bytes are already counted as
    /// transferred.
    Resume { offset: u64 },
    /// Leave the destination alone and count the whole file as done.
    Skip,
    /// Write to a different, non-colliding name.
    RenameTo(String),
}

/// Decide how to write `name` given what is already at the destination.
///
/// * `existing`, size of the destination file, `None` if it does not exist.
/// * `total`, size of the source file.
/// * `taken`, "does a file with this name already exist?", used by `Rename`.
pub fn plan_transfer(
    policy: ConflictPolicy,
    name: &str,
    existing: Option<u64>,
    total: u64,
    taken: impl Fn(&str) -> bool,
) -> ConflictOutcome {
    let Some(existing) = existing else {
        return ConflictOutcome::Fresh;
    };
    match policy {
        ConflictPolicy::Skip => ConflictOutcome::Skip,
        ConflictPolicy::Overwrite => ConflictOutcome::Fresh,
        ConflictPolicy::Rename => ConflictOutcome::RenameTo(unique_name(name, taken)),
        ConflictPolicy::Resume => {
            if total == 0 {
                // Nothing to resume into; a zero-byte source is a no-op write.
                ConflictOutcome::Fresh
            } else if existing >= total {
                // Complete (or longer than the source, i.e. not our partial
                // file at all), restarting would destroy user data, so skip.
                ConflictOutcome::Skip
            } else {
                ConflictOutcome::Resume { offset: existing }
            }
        }
    }
}

/// `report.pdf` → `report (1).pdf` → `report (2).pdf` …
///
/// Splits on the last dot, but never on a leading dot, so `.bashrc` becomes
/// `.bashrc (1)` rather than ` (1).bashrc`.
pub fn unique_name(name: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(name) {
        return name.to_string();
    }
    let (stem, ext) = split_extension(name);
    for n in 1..=999u32 {
        let candidate = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        if !taken(&candidate) {
            return candidate;
        }
    }
    // Pathological directory; fall back to something unguessably unique.
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let short = &suffix[..8];
    if ext.is_empty() {
        format!("{stem} ({short})")
    } else {
        format!("{stem} ({short}).{ext}")
    }
}

fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(0) | None => (name, ""),
        Some(i) => (&name[..i], &name[i + 1..]),
    }
}

/// One file inside a (possibly recursive) transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileJob {
    pub local: std::path::PathBuf,
    pub remote: String,
    pub size: u64,
    /// Unix mode of the source, for preserving the executable bit.
    pub mode: u32,
    /// Source mtime as a unix timestamp, for preserving modification times.
    pub mtime: Option<i64>,
}

/// A planned transfer: the directories to create, the files to move, and the
/// total byte count the progress bar is scaled against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferPlan {
    /// Directories to create at the destination, parents first.
    pub dirs: Vec<String>,
    /// Files, in a stable order, PRD/08 §3.3 wants folder trees sequential
    /// and predictable, not raced.
    pub files: Vec<FileJob>,
    pub total_bytes: u64,
}

impl TransferPlan {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty()
    }
}

/// Size above which the UI should warn before starting (PRD/08 §4,
/// "large-file safety").
pub const LARGE_TRANSFER_WARN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Seconds remaining at the current rate, or `None` while the rate is unknown.
pub fn eta_secs(transferred: u64, total: u64, bytes_per_sec: f64) -> Option<f64> {
    if bytes_per_sec <= 0.0 || total <= transferred {
        return None;
    }
    Some((total - transferred) as f64 / bytes_per_sec)
}

/// Validate a batch of remote paths supplied by the webview (which got them
/// from an untrusted server listing) before any of them touches the wire.
pub fn validate_remote_batch(paths: &[String]) -> Result<Vec<String>> {
    paths.iter().map(|p| path::normalize_remote(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ------------------------------------------------------------ throttle

    #[test]
    fn progress_is_throttled_to_ten_per_second() {
        let mut throttle = ProgressThrottle::new(PROGRESS_EVENTS_PER_SEC);
        let t0 = Instant::now();

        // First tick always emits so the bar appears immediately.
        assert!(throttle.tick(t0, 0, false).is_some());

        // Simulate a 64 KiB chunk loop running at 1 kHz for one second.
        let mut emitted = 0;
        let mut transferred = 0u64;
        for ms in 1..=1000u64 {
            transferred += 64 * 1024;
            let now = t0 + Duration::from_millis(ms);
            if throttle.tick(now, transferred, false).is_some() {
                emitted += 1;
            }
        }
        assert!(
            (9..=11).contains(&emitted),
            "expected ~10 events in a second, got {emitted}"
        );
    }

    #[test]
    fn force_bypasses_the_interval() {
        let mut throttle = ProgressThrottle::new(PROGRESS_EVENTS_PER_SEC);
        let t0 = Instant::now();
        throttle.tick(t0, 0, false);
        let soon = t0 + Duration::from_millis(1);
        assert!(throttle.tick(soon, 1024, false).is_none());
        assert!(throttle.tick(soon, 1024, true).is_some());
    }

    #[test]
    fn rate_estimate_converges_on_the_real_throughput() {
        let mut throttle = ProgressThrottle::new(PROGRESS_EVENTS_PER_SEC);
        let t0 = Instant::now();
        throttle.tick(t0, 0, false);
        // Exactly 1 MB/s for three seconds.
        let mut rate = 0.0;
        for tenth in 1..=30u64 {
            let now = t0 + Duration::from_millis(tenth * 100);
            if let Some(r) = throttle.tick(now, tenth * 100_000, false) {
                rate = r;
            }
        }
        assert!(
            (rate - 1_000_000.0).abs() < 50_000.0,
            "rate estimate way off: {rate}"
        );
        assert_eq!(rate, throttle.rate());
    }

    #[test]
    fn eta_is_none_until_there_is_a_rate() {
        assert!(eta_secs(0, 100, 0.0).is_none());
        assert!(eta_secs(100, 100, 10.0).is_none());
        assert_eq!(eta_secs(0, 100, 10.0), Some(10.0));
    }

    // ------------------------------------------------------------- resume

    #[test]
    fn resume_continues_from_the_partial_size() {
        assert_eq!(
            plan_transfer(ConflictPolicy::Resume, "a.bin", Some(400), 1000, |_| true),
            ConflictOutcome::Resume { offset: 400 }
        );
    }

    #[test]
    fn resume_of_a_complete_file_is_a_skip_not_a_restart() {
        assert_eq!(
            plan_transfer(ConflictPolicy::Resume, "a.bin", Some(1000), 1000, |_| true),
            ConflictOutcome::Skip
        );
        // Destination longer than the source: not our partial file. Never
        // silently truncate someone's data.
        assert_eq!(
            plan_transfer(ConflictPolicy::Resume, "a.bin", Some(4000), 1000, |_| true),
            ConflictOutcome::Skip
        );
    }

    #[test]
    fn a_missing_destination_is_always_a_fresh_write() {
        for policy in [
            ConflictPolicy::Resume,
            ConflictPolicy::Skip,
            ConflictPolicy::Overwrite,
            ConflictPolicy::Rename,
        ] {
            assert_eq!(
                plan_transfer(policy, "a.bin", None, 1000, |_| true),
                ConflictOutcome::Fresh,
                "{policy:?}"
            );
        }
    }

    #[test]
    fn zero_byte_sources_never_try_to_resume() {
        assert_eq!(
            plan_transfer(ConflictPolicy::Resume, "empty", Some(0), 0, |_| true),
            ConflictOutcome::Fresh
        );
    }

    // ----------------------------------------------------------- conflicts

    #[test]
    fn skip_and_overwrite_do_what_they_say() {
        assert_eq!(
            plan_transfer(ConflictPolicy::Skip, "a", Some(1), 10, |_| true),
            ConflictOutcome::Skip
        );
        assert_eq!(
            plan_transfer(ConflictPolicy::Overwrite, "a", Some(1), 10, |_| true),
            ConflictOutcome::Fresh
        );
    }

    #[test]
    fn rename_finds_the_first_free_slot() {
        let taken: HashSet<&str> = ["report.pdf", "report (1).pdf", "report (2).pdf"]
            .into_iter()
            .collect();
        assert_eq!(
            plan_transfer(ConflictPolicy::Rename, "report.pdf", Some(1), 10, |n| taken
                .contains(n)),
            ConflictOutcome::RenameTo("report (3).pdf".into())
        );
    }

    #[test]
    fn rename_handles_dotfiles_and_extensionless_names() {
        assert_eq!(unique_name(".bashrc", |n| n == ".bashrc"), ".bashrc (1)");
        assert_eq!(unique_name("Makefile", |n| n == "Makefile"), "Makefile (1)");
        assert_eq!(
            unique_name("archive.tar.gz", |n| n == "archive.tar.gz"),
            "archive.tar (1).gz"
        );
        assert_eq!(unique_name("free.txt", |_| false), "free.txt");
    }

    #[test]
    fn rename_gives_up_gracefully_in_a_pathological_directory() {
        let name = unique_name("x.txt", |n| n.starts_with("x") && n.ends_with(".txt"));
        assert!(name.starts_with("x ("), "{name}");
        assert!(name.ends_with(").txt"), "{name}");
    }

    // -------------------------------------------------------------- events

    #[test]
    fn events_serialize_with_session_event_conventions() {
        let started = serde_json::to_value(TransferEvent::Started {
            id: "t1".into(),
            name: "report.pdf".into(),
            total: 1024,
            direction: Direction::Upload,
        })
        .unwrap();
        assert_eq!(started["type"], "started");
        assert_eq!(started["direction"], "upload");
        assert_eq!(started["total"], 1024);

        let progress = serde_json::to_value(TransferEvent::Progress {
            id: "t1".into(),
            transferred: 512,
            total: 1024,
            bytes_per_sec: 2048.0,
        })
        .unwrap();
        assert_eq!(progress["type"], "progress");
        assert_eq!(progress["bytesPerSec"], 2048.0);
        assert!(progress.get("bytes_per_sec").is_none());

        for (event, tag) in [
            (TransferEvent::Completed { id: "t1".into() }, "completed"),
            (
                TransferEvent::Failed {
                    id: "t1".into(),
                    error: "nope".into(),
                },
                "failed",
            ),
            (TransferEvent::Cancelled { id: "t1".into() }, "cancelled"),
        ] {
            assert!(event.is_terminal());
            assert_eq!(event.id(), "t1");
            assert_eq!(serde_json::to_value(&event).unwrap()["type"], tag);
        }
    }

    #[test]
    fn started_and_progress_are_not_terminal() {
        assert!(!TransferEvent::Progress {
            id: "t".into(),
            transferred: 0,
            total: 1,
            bytes_per_sec: 0.0,
        }
        .is_terminal());
    }

    // --------------------------------------------------------------- batch

    #[test]
    fn a_hostile_batch_is_rejected_before_anything_is_transferred() {
        assert!(validate_remote_batch(&["/home/user/a".into(), "/home/user/b".into()]).is_ok());
        assert!(
            validate_remote_batch(&["/home/user/a".into(), "../../etc/shadow".into()]).is_err()
        );
    }
}
