fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Newer Xcode releases autolink Swift overlays such as
        // libswiftCoreMedia into the x86_64 slice and leave the loader no
        // path to find them, so the app dies at launch with "no LC_RPATH's
        // found". The system copies live in /usr/lib/swift on every macOS
        // this app supports.
        println!("cargo:rustc-link-arg-bins=-Wl,-rpath,/usr/lib/swift");
        // The window server lets a program talk to it at the sign in screen
        // only when its executable carries this empty section, as
        // loginwindow and Apple's own screen sharing agent do. Without it the
        // copy at the sign in screen could show the screen but every click
        // and key it posted was dropped: "This program is not permitted to
        // connect to or launch Window Server before login".
        println!(
            "cargo:rustc-link-arg-bins=-Wl,-sectcreate,__CGPreLoginApp,__cgpreloginapp,/dev/null"
        );
    }
}
