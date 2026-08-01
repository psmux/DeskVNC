//! Build script: runs tauri-build and declares every application command in
//! the app ACL manifest so that `allow-<command>`/`deny-<command>` permissions
//! are generated and the capability files under `capabilities/` can grant them
//! per window (deny-by-default, PRD/01 §7).

fn main() {
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
