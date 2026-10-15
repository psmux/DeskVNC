fn main() {
    // Newer Xcode releases autolink Swift overlays such as libswiftCoreMedia
    // into the x86_64 slice and leave the loader no path to find them, so the
    // app dies at launch with "no LC_RPATH's found". The system copies live
    // in /usr/lib/swift on every macOS this app supports.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bins=-Wl,-rpath,/usr/lib/swift");
    }
}
