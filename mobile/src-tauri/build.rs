//! Declares every command the phone UI may call, so each one gets an
//! `allow-<command>` permission and `capabilities/default.json` grants them
//! by name, deny by default like the desktop shell.

/// The command surface of `mobile/CONTRACT.md`, and nothing else.
pub const COMMANDS: &[&str] = &[
    "hosts_list",
    "hosts_save",
    "hosts_delete",
    "hosts_set_secret",
    "hosts_set_ssh_secret",
    "hosts_thumbnail",
    "scan_start",
    "scan_stop",
    "identify",
    "session_connect",
    "boundary_resolve",
    "session_input",
    "session_text",
    "session_key_combo",
    "session_credentials",
    "session_trust",
    "session_quality",
    "session_clipboard",
    "session_snapshot",
    "session_disconnect",
    "session_save_host",
    "local_network_state",
    "local_network_ask",
    "app_settings_open",
    "system_bars",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri-build");
}
