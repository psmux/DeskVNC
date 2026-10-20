//! The app's log file, and the record a crash leaves behind.
//!
//! Until this, everything the app logged went to stdout, which a desktop app
//! started from the Dock, the Start menu or at sign in does not have. When it
//! crashed there was nothing on disk to say why, so a crash in the field could
//! only be described, never read.
//!
//! The log sits where Tauri's own `app_log_dir` would put it, computed here
//! because logging starts before Tauri does:
//!
//! * macOS: `~/Library/Logs/com.deskvncviewer.desktop/`
//! * Windows: `%LOCALAPPDATA%\com.deskvncviewer.desktop\logs\`
//! * Linux: `~/.local/share/com.deskvncviewer.desktop/logs/`
//!
//! Every run appends to `deskvnc.log`, so the run that crashed is still there
//! after the app is started again. Past a few megabytes it moves aside to
//! `deskvnc.previous.log` and a new one starts. A panic is also written to
//! `crash.log`, kept the same way.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use tracing_subscriber::fmt::writer::MakeWriterExt;

const IDENTIFIER: &str = "com.deskvncviewer.desktop";

/// Past these, a log is moved aside and started again rather than grown forever.
const LOG_LIMIT: u64 = 8 * 1024 * 1024;
const CRASH_LOG_LIMIT: u64 = 1024 * 1024;

/// The directory the log and the crash record go in, when there is one.
pub fn log_dir() -> Option<PathBuf> {
    let base = directories::BaseDirs::new()?;
    if cfg!(target_os = "macos") {
        Some(base.home_dir().join("Library/Logs").join(IDENTIFIER))
    } else {
        Some(base.data_local_dir().join(IDENTIFIER).join("logs"))
    }
}

/// Start logging to stdout and to the log file, and record panics.
///
/// Logging to the file is best effort: a directory that cannot be created
/// leaves the app logging to stdout as before, never failing to start.
pub fn init() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,deskvncviewer_lib=debug"));
    let dir = log_dir();
    let file = dir.as_deref().and_then(LogFile::open);
    match file {
        Some(file) => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::io::stdout.and(Mutex::new(file)))
            .init(),
        None => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
    install_panic_hook(dir);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "DeskVNCViewer started");
}

/// The log file, appended to by every run and moved aside by size.
///
/// Rotated by size, never per run: a second launch that is about to hand over
/// to the copy already running must not move that copy's log out from under
/// it, which macOS and Linux would allow. And by size while running too,
/// since one session left open for days on a link that keeps dropping logs
/// every drop.
struct LogFile {
    dir: PathBuf,
    file: File,
    size: u64,
}

impl LogFile {
    fn open(dir: &Path) -> Option<Self> {
        fs::create_dir_all(dir).ok()?;
        let current = dir.join("deskvnc.log");
        if fs::metadata(&current).is_ok_and(|m| m.len() > LOG_LIMIT) {
            let _ = fs::rename(&current, dir.join("deskvnc.previous.log"));
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current)
            .ok()?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Some(Self {
            dir: dir.to_path_buf(),
            file,
            size,
        })
    }

    fn rotate(&mut self) {
        let current = self.dir.join("deskvnc.log");
        // Renamed before the new one is opened, so a rename that fails (a
        // virus scanner holding the file, say) leaves logging where it was.
        if fs::rename(&current, self.dir.join("deskvnc.previous.log")).is_ok() {
            if let Ok(file) = OpenOptions::new().create(true).append(true).open(&current) {
                self.file = file;
            }
        }
        // Counted from zero either way, so a rotation that failed is tried
        // again a whole log later rather than on every line.
        self.size = 0;
    }
}

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.size > LOG_LIMIT {
            self.rotate();
        }
        let written = self.file.write(buf)?;
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Write every panic to `crash.log` before the usual handling runs.
///
/// A panic on a background task is caught by its runtime and the app carries
/// on, but it still means something went wrong, so it is recorded the same
/// way. The location comes from the panic itself and survives the release
/// build's stripped symbols; the backtrace is as good as those allow.
fn install_panic_hook(dir: Option<PathBuf>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let record = format!(
            "{} DeskVNCViewer {} panicked on thread {}: {}\n{}\n\n",
            utc_now(),
            env!("CARGO_PKG_VERSION"),
            thread.name().unwrap_or("unnamed"),
            info,
            std::backtrace::Backtrace::force_capture(),
        );
        tracing::error!("{record}");
        if let Some(dir) = &dir {
            let path = dir.join("crash.log");
            if fs::metadata(&path).is_ok_and(|m| m.len() > CRASH_LOG_LIMIT) {
                let _ = fs::rename(&path, dir.join("crash.previous.log"));
            }
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = file.write_all(record.as_bytes());
            }
        }
        previous(info);
    }));
}

/// The time now in UTC, as `2026-10-21 14:03:07 UTC`, without a date crate.
fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil conversion.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn formats_utc_dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(1_792_591_387), "2026-10-21 14:03:07 UTC");
    }
}
