//! Starting an app in the background when the person signs in, so unattended
//! access is ready without anyone opening it.
//!
//! Each app names its own entry, so DeskVNC and DeskVNC Support are set
//! independently. The entry starts the app with [`BACKGROUND`].

use anyhow::{Context, Result};

/// One app's sign in entry.
#[derive(Clone, Copy)]
pub struct Entry {
    /// The entry's name on Windows and Linux.
    pub name: &'static str,
    /// The launch agent's label on macOS.
    pub label: &'static str,
    /// The Linux autostart file's name, without `.desktop`.
    pub file: &'static str,
}

/// The flag an entry starts the app with.
pub const BACKGROUND: &str = "--background";

fn exe() -> Result<std::path::PathBuf> {
    std::env::current_exe().context("This app cannot find itself")
}

#[cfg(windows)]
const RUN: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
fn reg(args: &[&str]) -> Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    // No console flashing up behind a windowed app.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Ok(std::process::Command::new("reg")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()?)
}
#[cfg(windows)]
pub fn enabled(entry: Entry) -> bool {
    reg(&["query", RUN, "/v", entry.name]).is_ok_and(|o| o.status.success())
}
#[cfg(windows)]
pub fn set(entry: Entry, on: bool) -> Result<()> {
    let status = if on {
        let value = format!("\"{}\" {BACKGROUND}", exe()?.display());
        reg(&[
            "add", RUN, "/v", entry.name, "/t", "REG_SZ", "/d", &value, "/f",
        ])?
        .status
    } else {
        reg(&["delete", RUN, "/v", entry.name, "/f"])?.status
    };
    anyhow::ensure!(
        status.success(),
        "Windows did not accept the sign in setting"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn plist(entry: Entry) -> Result<std::path::PathBuf> {
    Ok(
        std::path::PathBuf::from(std::env::var_os("HOME").context("No home folder")?)
            .join(format!("Library/LaunchAgents/{}.plist", entry.label)),
    )
}
#[cfg(target_os = "macos")]
pub fn enabled(entry: Entry) -> bool {
    plist(entry).is_ok_and(|p| p.exists())
}
#[cfg(target_os = "macos")]
pub fn set(entry: Entry, on: bool) -> Result<()> {
    let path = plist(entry)?;
    if !on {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{}</string>
<key>ProgramArguments</key><array><string>{}</string><string>{BACKGROUND}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
"#,
        entry.label,
        exe()?.display()
    );
    std::fs::create_dir_all(path.parent().context("No LaunchAgents folder")?)?;
    std::fs::write(&path, body)?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_file(entry: Entry) -> Result<std::path::PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .context("No configuration folder")?;
    Ok(config.join(format!("autostart/{}.desktop", entry.file)))
}
#[cfg(all(unix, not(target_os = "macos")))]
pub fn enabled(entry: Entry) -> bool {
    desktop_file(entry).is_ok_and(|p| p.exists())
}
#[cfg(all(unix, not(target_os = "macos")))]
pub fn set(entry: Entry, on: bool) -> Result<()> {
    let path = desktop_file(entry)?;
    if !on {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    // An AppImage runs from a mount that goes when it quits; start the
    // AppImage file itself.
    let exe = std::env::var_os("APPIMAGE")
        .map(std::path::PathBuf::from)
        .map_or_else(exe, Ok)?;
    let body = format!(
        "[Desktop Entry]\nType=Application\nName={}\nExec=\"{}\" {BACKGROUND}\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n",
        entry.name,
        exe.display()
    );
    std::fs::create_dir_all(path.parent().context("No autostart folder")?)?;
    std::fs::write(&path, body)?;
    Ok(())
}
