//! Where the app runs from, on macOS.
//!
//! The support app ships as a zip. Opened straight from Downloads, macOS runs
//! a read only copy under a random AppTranslocation folder instead. That copy
//! moves on every launch, so a sign in item written from it points nowhere
//! after a restart, and a newer download unzipped over the old one is not
//! picked up while the old copy runs. Moving the app to Applications ends all
//! of that, and this offers it with one click.

use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};

/// The real bundle this app was opened from, when macOS is running a
/// translocated copy of it. `None` when it runs from where it is.
pub fn translocated() -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    if !exe.to_string_lossy().contains("/AppTranslocation/") {
        return None;
    }
    let mounts = std::process::Command::new("/sbin/mount").output().ok()?;
    original(&exe, &String::from_utf8_lossy(&mounts.stdout))
}

/// The source of the translocation mount that `exe` runs under. A line of
/// `mount` reads `<original app> on <mount point> (nullfs, ...)`, and the app
/// runs from `<mount point>/d/<name>.app`.
fn original(exe: &Path, mounts: &str) -> Option<PathBuf> {
    mounts.lines().find_map(|line| {
        let (source, rest) = line.split_once(" on ")?;
        let (point, options) = rest.rsplit_once(" (")?;
        if !options.starts_with("nullfs") || !point.contains("/AppTranslocation/") {
            return None;
        }
        // /var is a link to /private/var, and either spelling can turn up.
        let inside = |p: &Path| p.starts_with(point) || p.starts_with(format!("/private{point}"));
        inside(exe).then(|| PathBuf::from(source))
    })
}

/// Copy the app from `source` to Applications, clear the download mark so it
/// is not translocated again, and start that copy. The caller quits after.
pub fn move_to_applications(source: &Path) -> Result<PathBuf> {
    let name = source.file_name().context("The app has no name")?;
    let mut target = PathBuf::from("/Applications").join(name);
    if std::fs::metadata("/Applications").is_ok_and(|m| m.permissions().readonly())
        || copy(source, &target).is_err()
    {
        // Not an administrator: the user's own Applications folder.
        let home = std::env::var_os("HOME").context("No home folder")?;
        let own = PathBuf::from(home).join("Applications");
        std::fs::create_dir_all(&own)?;
        target = own.join(name);
        copy(source, &target)?;
    }
    let _ = std::process::Command::new("/usr/bin/xattr")
        .args(["-dr", "com.apple.quarantine"])
        .arg(&target)
        .status();
    let opened = std::process::Command::new("/usr/bin/open")
        .arg("-n")
        .arg(&target)
        .status()?;
    ensure!(opened.success(), "macOS did not open the moved app");
    Ok(target)
}

fn copy(source: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        std::fs::remove_dir_all(target).context("Could not replace the copy in Applications")?;
    }
    let status = std::process::Command::new("/usr/bin/ditto")
        .arg(source)
        .arg(target)
        .status()?;
    ensure!(
        status.success(),
        "Could not copy the app to {}",
        target.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_the_bundle_behind_a_translocated_copy() {
        let mounts = "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n\
/private/tmp/tl/DeskVNC Support.app on /private/var/folders/tn/w3/T/AppTranslocation/00A1 (nullfs, local, nodev, nosuid, read-only, nobrowse, mounted by someone)\n";
        let exe = Path::new(
            "/private/var/folders/tn/w3/T/AppTranslocation/00A1/d/DeskVNC Support.app/Contents/MacOS/boundary",
        );
        assert_eq!(
            original(exe, mounts),
            Some(PathBuf::from("/private/tmp/tl/DeskVNC Support.app"))
        );
        let elsewhere =
            Path::new("/var/folders/tn/w3/T/AppTranslocation/FFFF/d/X.app/Contents/MacOS/boundary");
        assert_eq!(original(elsewhere, mounts), None);
    }
}
