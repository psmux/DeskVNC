//! Short logs beside the machine ID. An unattended computer has nobody in
//! front of it to read a message on screen, so what happened to a helper who
//! could not get in is written down where whoever looks after it can find it.
//!
//! On macOS the copy at the sign in screen writes these as root in the
//! person's own folder, and on Windows as SYSTEM, so they are written through
//! [`boundary_session::owned`], which never follows a link put there.

use std::path::Path;

/// Append `line` to `name` in `dir`, starting the file again past 64 KB.
pub fn note(dir: &Path, name: &str, line: &str) {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    if let Ok(folder) = boundary_session::owned::Folder::open(dir) {
        let _ = folder.append(name, &format!("{seconds} {line}"), 64 * 1024);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::note;

    #[test]
    fn a_note_never_goes_through_a_link() {
        let dir = std::env::temp_dir().join(format!("journal-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("data")).unwrap();
        // Stands in for a system file the person may not change.
        let other = dir.join("other");
        std::fs::write(&other, "left alone\n").unwrap();
        std::os::unix::fs::symlink(&other, dir.join("data/sign-in-screen.log")).unwrap();
        note(&dir.join("data"), "sign-in-screen.log", "started");
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "left alone\n");
        // Nor is a file made where a dangling link points.
        let made = dir.join("made");
        std::os::unix::fs::symlink(&made, dir.join("data/unattended.log")).unwrap();
        note(&dir.join("data"), "unattended.log", "started");
        assert!(!made.exists());
        // A plain log is written as before.
        note(&dir.join("data"), "plain.log", "started");
        let written = std::fs::read_to_string(dir.join("data/plain.log")).unwrap();
        assert!(written.ends_with(" started\n"), "{written}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
