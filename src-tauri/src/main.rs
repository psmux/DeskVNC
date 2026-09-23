// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // The Windows shortcut capture helper is this same executable started with
    // a flag. It must branch off before any window, runtime or webview exists.
    if let Some(code) = vnc_input_capture::run_helper_if_requested() {
        std::process::exit(code);
    }
    deskvncviewer_lib::run()
}
