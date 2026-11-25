//! The copy at the sign in screen reads who may connect from the person's
//! data folder as root on macOS. A link the person put there must not let
//! root read a file of somebody else's in its place.

#[cfg(unix)]
#[test]
fn settings_are_never_read_through_a_link() {
    use boundary_session::unattended::Access;
    use std::os::unix::fs::symlink;
    let dir = std::env::temp_dir().join(format!("data-links-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    let access = dir.join("data/access.json");
    // Somebody else's file, which happens to read as settings.
    std::fs::write(dir.join("elsewhere.json"), br#"{"enabled":true}"#).unwrap();
    symlink(dir.join("elsewhere.json"), &access).unwrap();
    assert!(Access::load(&access).is_err(), "read through the link");
    // The real file reads as before, and a missing one is no access.
    std::fs::remove_file(&access).unwrap();
    assert!(!Access::load(&access).unwrap().enabled);
    std::fs::copy(dir.join("elsewhere.json"), &access).unwrap();
    assert!(Access::load(&access).unwrap().enabled);
    // A huge file is refused, not read whole.
    std::fs::write(&access, vec![b' '; 2 * 1024 * 1024]).unwrap();
    assert!(Access::load(&access).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
