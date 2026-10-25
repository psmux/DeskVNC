fn main() {
    // The ScreenCaptureKit capture calls into these directly, and the
    // bindings leave linking them to whoever else uses them. CoreMedia's own
    // functions are looked up when the app runs instead (see `sck.rs`).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        for framework in ["ScreenCaptureKit", "CoreMedia", "CoreVideo"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
}
