// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // AppRun restricts GStreamer's system search path to the bundle, which
    // omits appsink and distro hardware decoders. Restore host plugin discovery
    // before any GTK/WebKit thread or child process is started.
    #[cfg(target_os = "linux")]
    if std::env::var_os("APPDIR").is_some() {
        let mut paths: Vec<std::path::PathBuf> = std::env::var_os("GST_PLUGIN_PATH_1_0")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        for path in [
            "/usr/lib/gstreamer-1.0",
            "/usr/lib/x86_64-linux-gnu/gstreamer-1.0",
            "/usr/lib/aarch64-linux-gnu/gstreamer-1.0",
            "/usr/lib64/gstreamer-1.0",
        ] {
            let path = std::path::PathBuf::from(path);
            if path.is_dir() && !paths.contains(&path) {
                paths.push(path);
            }
        }
        if let Ok(path) = std::env::join_paths(paths) {
            std::env::set_var("GST_PLUGIN_PATH_1_0", path);
        }
    }
    // Mesa's tiled AMD DMA-BUF modifier produces transparent WebCodecs frames
    // in WebKitGTK 2.54. Restrict to linear NV12; VA decoding stays on the GPU,
    // with a mapped NV12 output surface that WebGL/canvas can actually read.
    #[cfg(target_os = "linux")]
    if std::env::var_os("WEBKIT_GST_DMABUF_FORMATS").is_none() {
        std::env::set_var("WEBKIT_GST_DMABUF_FORMATS", "NV12");
    }
    // The Windows shortcut capture helper is this same executable started with
    // a flag. It must branch off before any window, runtime or webview exists.
    if let Some(code) = vnc_input_capture::run_helper_if_requested() {
        std::process::exit(code);
    }
    deskvncviewer_lib::run()
}
