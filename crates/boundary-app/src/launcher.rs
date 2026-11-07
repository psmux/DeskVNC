//! The app's entry in the Linux app menu and dock.
//!
//! GNOME and KDE match a window to its .desktop file by the Wayland app ID
//! (the X11 class under X11) and take the name and icon from that file.
//! Run from the tarball with no file installed, the dock showed a generic
//! icon. `deskvnc-support --install` writes the file and the icon into the
//! person's own data folder, so it needs no administrator, and points the
//! entry at wherever this copy was unpacked.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The entry shipped in the tarball beside the binary.
pub const DESKTOP: &str = include_str!("../linux/deskvnc-support.desktop");
/// The icon shipped beside it, also the window's own icon.
pub const ICON: &[u8] = include_bytes!("../linux/deskvnc-support.png");

/// The shipped entry, starting `exe` instead of whatever is on `PATH`.
pub fn entry(exe: &Path) -> String {
    DESKTOP
        .lines()
        .map(|line| {
            if line.starts_with("Exec=") {
                format!("Exec={}", quote(&exe.to_string_lossy()))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// An argument quoted the way the Desktop Entry specification reads them.
fn quote(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            quoted.push('\\');
        }
        // A literal percent would be read as a field code.
        if c == '%' {
            quoted.push('%');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// Where the entry and the icon go for `data`, the person's data folder.
fn paths(data: &Path) -> (PathBuf, PathBuf) {
    (
        data.join(format!("applications/{}.desktop", crate::APP_ID)),
        data.join(format!("icons/hicolor/256x256/apps/{}.png", crate::APP_ID)),
    )
}

fn data_home() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
}

/// Write the entry and icon for this copy. Returns the entry's path.
pub fn install() -> Result<PathBuf> {
    // An AppImage runs from a mount that goes when it quits.
    let exe = match std::env::var_os("APPIMAGE") {
        Some(image) => PathBuf::from(image),
        None => std::env::current_exe().context("This app cannot find itself")?,
    };
    let data = data_home().context("No home folder to install into")?;
    write(&data, &exe)
}

fn write(data: &Path, exe: &Path) -> Result<PathBuf> {
    let (desktop, icon) = paths(data);
    for path in [&desktop, &icon] {
        std::fs::create_dir_all(path.parent().context("No folder")?)
            .with_context(|| format!("Cannot create the folder for {}", path.display()))?;
    }
    std::fs::write(&icon, ICON).with_context(|| format!("Cannot write {}", icon.display()))?;
    std::fs::write(&desktop, entry(exe))
        .with_context(|| format!("Cannot write {}", desktop.display()))?;
    Ok(desktop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(entry: &'a str, key: &str) -> Option<&'a str> {
        entry
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    }

    #[test]
    fn the_shipped_entry_matches_the_window() {
        // The dock pairs the window with this file by app ID, so the file's
        // name, its window class and the icon must all be the app ID.
        assert_eq!(value(DESKTOP, "Name"), Some(crate::APP_NAME));
        assert_eq!(value(DESKTOP, "StartupWMClass"), Some(crate::APP_ID));
        assert_eq!(value(DESKTOP, "Icon"), Some(crate::APP_ID));
        assert_eq!(DESKTOP.lines().next(), Some("[Desktop Entry]"));
        assert!(ICON.starts_with(b"\x89PNG"));
    }

    #[test]
    fn the_installed_entry_starts_this_copy_wherever_it_is() {
        let entry = entry(Path::new("/home/sam/Down loads/$x/deskvnc-support"));
        assert_eq!(
            value(&entry, "Exec"),
            Some(r#""/home/sam/Down loads/\$x/deskvnc-support""#)
        );
        assert_eq!(value(&entry, "Icon"), Some(crate::APP_ID));
        assert_eq!(entry.matches("Exec=").count(), 1);
    }

    #[test]
    fn installing_writes_the_entry_and_icon_into_the_data_folder() {
        let data = tempfile::tempdir().unwrap();
        let exe = Path::new("/opt/support/deskvnc-support");
        let desktop = write(data.path(), exe).unwrap();
        assert_eq!(
            desktop,
            data.path().join("applications/deskvnc-support.desktop")
        );
        let written = std::fs::read_to_string(&desktop).unwrap();
        assert_eq!(
            value(&written, "Exec"),
            Some(r#""/opt/support/deskvnc-support""#)
        );
        let icon = data
            .path()
            .join("icons/hicolor/256x256/apps/deskvnc-support.png");
        assert_eq!(std::fs::read(icon).unwrap(), ICON);
        // Running it again from a new place moves the entry there.
        write(data.path(), Path::new("/tmp/new/deskvnc-support")).unwrap();
        let written = std::fs::read_to_string(&desktop).unwrap();
        assert_eq!(
            value(&written, "Exec"),
            Some(r#""/tmp/new/deskvnc-support""#)
        );
    }
}
