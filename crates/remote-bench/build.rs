fn main() {
    // The same fix as the Support app's build script: newer Xcode releases
    // autolink Swift overlays such as libswiftCoreMedia into the x86_64 slice
    // with no path to find them, so the bench would not start on an Intel
    // Mac. The system copies live in /usr/lib/swift.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bins=-Wl,-rpath,/usr/lib/swift");
    }
}
