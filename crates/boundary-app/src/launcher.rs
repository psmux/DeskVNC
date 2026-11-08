//! The app's entry in the Linux app menu and dock.
//!
//! GNOME and KDE match a window to its .desktop file by the Wayland app ID
//! (the X11 class under X11) and take the name and icon from that file.
//! Run from the tarball with no file installed, the dock showed a generic
//! icon. `deskvnc-support --install` writes the file and the icon into the
//! person's own data folder, so it needs no administrator. It also copies
//! the program there and points the entry at that copy: an entry pointing at
//! the unpacked tarball stopped working as soon as that folder was cleaned
//! out of Downloads.

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

/// Copy this program into the person's data folder and write the entry and
/// icon for that copy. Returns the entry's path and where the program went.
pub fn install() -> Result<(PathBuf, PathBuf)> {
    // An AppImage runs from a mount that goes when it quits, so the image
    // itself is what gets copied.
    let exe = match std::env::var_os("APPIMAGE") {
        Some(image) => PathBuf::from(image),
        None => std::env::current_exe().context("This app cannot find itself")?,
    };
    let data = data_home().context("No home folder to install into")?;
    let program = copy_program(&data, &exe)?;
    Ok((write(&data, &program)?, program))
}

/// Where the installed copy of the program lives under `data`.
fn program_path(data: &Path, exe: &Path) -> PathBuf {
    let name = if exe
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("appimage"))
    {
        format!("{}.AppImage", crate::APP_ID)
    } else {
        crate::APP_ID.to_owned()
    };
    data.join(crate::APP_ID).join(name)
}

/// Copy `exe` to its installed place under `data`, unless it already runs
/// from there. The copy is written beside it and renamed over the old one,
/// so a copy that is running keeps running and the entry never points at
/// half a file.
fn copy_program(data: &Path, exe: &Path) -> Result<PathBuf> {
    let target = program_path(data, exe);
    let same = match (exe.canonicalize(), target.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if same {
        return Ok(target);
    }
    let folder = target.parent().context("No folder")?;
    std::fs::create_dir_all(folder)
        .with_context(|| format!("Cannot create {}", folder.display()))?;
    let partial = folder.join(format!(".{}.partial", crate::APP_ID));
    std::fs::copy(exe, &partial)
        .with_context(|| format!("Cannot copy the program to {}", folder.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Cannot make {} runnable", partial.display()))?;
    }
    std::fs::rename(&partial, &target)
        .with_context(|| format!("Cannot write {}", target.display()))?;
    Ok(target)
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

    #[test]
    fn installing_copies_the_program_so_the_unpacked_folder_can_go() {
        let data = tempfile::tempdir().unwrap();
        let downloads = tempfile::tempdir().unwrap();
        let unpacked = downloads.path().join("deskvnc-support");
        std::fs::write(&unpacked, b"program v1").unwrap();
        let program = copy_program(data.path(), &unpacked).unwrap();
        assert_eq!(program, data.path().join("deskvnc-support/deskvnc-support"));
        let desktop = write(data.path(), &program).unwrap();
        // The folder it was unpacked into is cleaned out.
        drop(downloads);
        assert!(!unpacked.exists());
        let written = std::fs::read_to_string(desktop).unwrap();
        let exec = value(&written, "Exec").unwrap().trim_matches('"');
        assert_eq!(std::fs::read(exec).unwrap(), b"program v1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(exec).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn installing_again_replaces_the_copy_and_from_the_copy_keeps_it() {
        let data = tempfile::tempdir().unwrap();
        let downloads = tempfile::tempdir().unwrap();
        let newer = downloads.path().join("deskvnc-support");
        std::fs::write(&newer, b"program v1").unwrap();
        let program = copy_program(data.path(), &newer).unwrap();
        std::fs::write(&newer, b"program v2").unwrap();
        assert_eq!(copy_program(data.path(), &newer).unwrap(), program);
        assert_eq!(std::fs::read(&program).unwrap(), b"program v2");
        // Run from the installed copy itself, nothing is copied over it.
        assert_eq!(copy_program(data.path(), &program).unwrap(), program);
        assert_eq!(std::fs::read(&program).unwrap(), b"program v2");
        let leftovers: Vec<_> = std::fs::read_dir(program.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["deskvnc-support"]);
    }

    #[test]
    fn an_appimage_is_copied_as_an_appimage() {
        let data = Path::new("/home/sam/.local/share");
        assert_eq!(
            program_path(
                data,
                Path::new("/home/sam/Downloads/DeskVNC-Support.AppImage")
            ),
            data.join("deskvnc-support/deskvnc-support.AppImage")
        );
    }
}
