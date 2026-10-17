//! Short logs beside the machine ID. An unattended computer has nobody in
//! front of it to read a message on screen, so what happened to a helper who
//! could not get in is written down where whoever looks after it can find it.

use std::io::Write;
use std::path::Path;

/// Append `line` to `name` in `dir`, starting the file again past 64 KB.
pub fn note(dir: &Path, name: &str, line: &str) {
    let path = dir.join(name);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 64 * 1024) {
        let _ = std::fs::remove_file(&path);
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{seconds} {line}");
    }
}
