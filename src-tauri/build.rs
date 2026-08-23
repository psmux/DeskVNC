//! Build script: runs tauri-build and declares every application command in
//! the app ACL manifest so that `allow-<command>`/`deny-<command>` permissions
//! are generated and the capability files under `capabilities/` can grant them
//! per window (deny-by-default, PRD/01 §7).
//!
//! Also stamps the binary with its exact provenance (commit, tag, branch,
//! dirty state, toolchain) so the About dialog can fingerprint any build a
//! user reports from. Everything degrades to "unknown" when git or the
//! repository is absent (release tarballs), never to a build failure.

use std::process::Command;

/// Run `git <args>` in the workspace and return trimmed stdout, or None.
fn git(args: &[&str]) -> Option<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .args(args)
        .current_dir(manifest)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// "clean" / "dirty", or None when git could not tell us.
///
/// Deliberately not routed through `git()`: that treats empty output as
/// failure, and `git status --porcelain` prints nothing precisely when the
/// tree is CLEAN. Every clean checkout, which is to say every release build,
/// therefore stamped "unknown" and the About dialog could not tell a pristine
/// build from an unknowable one.
fn git_dirty() -> Option<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(manifest)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let clean = out.stdout.iter().all(|b| b.is_ascii_whitespace());
    Some(if clean { "clean" } else { "dirty" }.to_string())
}

fn stamp(key: &str, value: Option<String>) {
    println!(
        "cargo:rustc-env={key}={}",
        value.unwrap_or_else(|| "unknown".into())
    );
}

fn stamp_git_provenance() {
    // Re-stamp whenever the checked-out commit or the index changes, so the
    // hash and the dirty flag can never go stale in an incremental build.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/index");
    }

    stamp("DESKVNC_GIT_HASH", git(&["rev-parse", "HEAD"]));
    stamp(
        "DESKVNC_GIT_HASH_SHORT",
        git(&["rev-parse", "--short=9", "HEAD"]),
    );
    // The single most useful fingerprint: nearest tag, commits since it,
    // short hash, and a -dirty suffix when the tree had local edits.
    stamp(
        "DESKVNC_GIT_DESCRIBE",
        git(&["describe", "--tags", "--always", "--dirty"]),
    );
    stamp(
        "DESKVNC_GIT_BRANCH",
        git(&["rev-parse", "--abbrev-ref", "HEAD"]),
    );
    stamp(
        "DESKVNC_GIT_COMMIT_DATE",
        git(&["log", "-1", "--format=%cd", "--date=format:%Y-%m-%d"]),
    );
    stamp("DESKVNC_GIT_DIRTY", git_dirty());
    stamp(
        "DESKVNC_RUSTC_VERSION",
        std::env::var("RUSTC")
            .ok()
            .and_then(|rustc| Command::new(rustc).arg("-V").output().ok())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()),
    );
    stamp("DESKVNC_BUILD_PROFILE", std::env::var("PROFILE").ok());
}

fn main() {
    stamp_git_provenance();
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            // hosts / library
            "list_hosts",
            "get_host",
            "save_host",
            "delete_host",
            "touch_connected",
            "list_groups",
            "save_group",
            "delete_group",
            "list_tags",
            "save_tag",
            "delete_tag",
            "set_host_tags",
            "list_history",
            "get_thumbnail",
            "get_app_setting",
            "set_app_setting",
            // build/system fingerprint for the About dialog and bug reports
            "about_info",
            // the native menu mirrors the session toolbar, so the webview has
            // to push it the state that toolbar would have shown
            "sync_session_menu",
            // credentials (write/query only, passwords never flow back to JS)
            "save_password",
            "has_password",
            "delete_password",
            "credential_backend",
            "unlock_credentials",
            // discovery
            "start_discovery",
            "stop_discovery",
            "scan_network",
            "deep_probe",
            "local_subnets",
            "wake_host",
            // sessions
            "connect_session",
            "disconnect_session",
            "send_input",
            "set_quality",
            "request_resize",
            "refresh_session",
            "set_view_only",
            "set_always_refresh",
            "set_prefer_scancodes",
            "send_clipboard",
            // OS clipboard, natively. `navigator.clipboard` is gesture-gated in
            // the webview, so remote → local text can never land through it.
            "set_local_clipboard",
            "read_local_clipboard",
            "reconnect_now",
            "release_all_keys",
            "capture_thumbnail",
            "trust_certificate",
            "forget_certificate",
            // interactive auth prompt (PRD/10 §3.4), JS → Rust only; the
            // matching read direction deliberately does not exist.
            "provide_credentials",
            "cancel_credentials",
            "pending_credential_request",
            "open_session_window",
            "release_session_claim",
            "fullscreen_session",
            "list_active_sessions",
            // file transfer, SFTP sidecar (PRD/08). The fs plugin stays off;
            // local reads/writes go through these narrow commands and the
            // native dialog only.
            "files_probe",
            "files_connect",
            "files_disconnect",
            "files_status",
            "files_home",
            "files_list",
            "files_mkdir",
            "files_remove",
            "files_rename",
            "files_upload",
            "files_download",
            "files_cancel",
            "files_local_home",
            "files_local_list",
            "files_local_mkdir",
            "files_local_rename",
            "files_local_remove",
            // native keyboard capture, shortcut pass-through (PRD/06 §3
            // Tier 2). `capture_request_permission` is the only one that can
            // surface an OS prompt, so it stays a distinct, grantable command.
            "capture_start",
            "capture_stop",
            "capture_status",
            "capture_permission_granted",
            "capture_request_permission",
        ]),
    ))
    .expect("failed to run tauri-build");
}
