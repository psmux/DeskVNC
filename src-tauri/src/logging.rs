//! Where a report of "it was bad last night" can come from.
//!
//! A session that goes wrong over a VPN is gone by the time anyone looks at
//! it: the window has been closed, and stderr was attached to a launcher
//! that threw it away. The log file is what is left afterwards.
//!
//! It is deliberately boring: one file, appended, truncated when it grows
//! past a size a person would still open. No rotation across files and no
//! timestamps in the name, because the useful question is "what happened in
//! the last hour", and that is answered by one file that keeps the tail.
//!
//! Nothing here writes secrets. The log line is produced by the same
//! `tracing` calls the rest of the app makes, and those already redact
//! credentials (`ConnectOptions` does not print them).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// How large the log may grow before it is started over.
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// The log file, and where it is.
pub struct LogFile {
    file: Mutex<std::fs::File>,
    path: PathBuf,
}

impl LogFile {
    /// Open `dir/deskvnc.log`, starting over when it has grown too large.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("deskvnc.log");
        let too_big = std::fs::metadata(&path)
            .map(|m| m.len() > MAX_LOG_BYTES)
            .unwrap_or(false);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if too_big {
            // Kept, not deleted: the previous run is often the one that
            // shows what changed.
            let _ = std::fs::rename(&path, dir.join("deskvnc.previous.log"));
            return Self::open(dir);
        }
        Ok(Self {
            file: Mutex::new(file),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogFile {
    type Writer = LogWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter { file: &self.file }
    }
}

/// One log line's writer, holding the file for as long as it writes.
pub struct LogWriter<'a> {
    file: &'a Mutex<std::fs::File>,
}

impl Write for LogWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.file.lock() {
            Ok(mut file) => file.write(buf),
            // A poisoned lock means a thread died while logging. Losing the
            // line is better than taking the process down over it.
            Err(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.lock() {
            Ok(mut file) => file.flush(),
            Err(_) => Ok(()),
        }
    }
}

/// The log file this run opened, if it opened one.
///
/// Set once at startup and read afterwards by the About command, so a
/// report can name the file without guessing where a framework would have
/// put it. The directory is the shell's own app data directory, the same one
/// the database and the thumbnails live in: a second convention for one
/// directory is how a log ends up somewhere nobody looks.
static LOG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Start logging to `dir/deskvnc.log`, keeping the terminal output too.
pub fn init(app: &tauri::AppHandle) {
    use tauri::Manager;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,deskvncviewer_lib=debug"));
    let registry = tracing_subscriber::registry().with(filter);
    // The terminal gets colours and the file does not; both get the same
    // lines, so a report can quote what a developer would have watched.
    let stderr = tracing_subscriber::fmt::layer();
    let file = app
        .path()
        .app_data_dir()
        .ok()
        .map(|dir| dir.join("logs"))
        .and_then(|dir| LogFile::open(&dir).ok());
    let path = file.as_ref().map(|log| log.path().to_path_buf());
    let _ = LOG_PATH.set(path);
    match file {
        Some(file) => registry
            .with(stderr)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(file),
            )
            .init(),
        None => registry.with(stderr).init(),
    }
}

/// The log file this run writes, once [`init`] has run.
pub fn log_path() -> Option<PathBuf> {
    LOG_PATH.get().cloned().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tracing_subscriber::fmt::MakeWriter as _;

    #[test]
    fn a_fresh_directory_gets_a_log_file() {
        let dir = std::env::temp_dir().join(format!("deskvnc-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = LogFile::open(&dir).expect("the log opens");
        assert!(log.path().ends_with("deskvnc.log"));
        let mut writer = log.make_writer();
        writer.write_all(b"hello\n").unwrap();
        writer.flush().unwrap();
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(text, "hello\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_log_is_kept_as_the_previous_one() {
        let dir = std::env::temp_dir().join(format!("deskvnc-log-big-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("deskvnc.log"),
            vec![b'x'; (MAX_LOG_BYTES + 1) as usize],
        )
        .unwrap();
        let log = LogFile::open(&dir).expect("the log opens");
        assert_eq!(std::fs::metadata(log.path()).unwrap().len(), 0);
        assert!(dir.join("deskvnc.previous.log").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
