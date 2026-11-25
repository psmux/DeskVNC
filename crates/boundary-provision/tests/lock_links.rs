//! The unattended lock lives in the person's data folder, which the copy at
//! the sign in screen opens as root on macOS. A link the person put there in
//! place of the lock must not make root create or open the file it points to.

#[cfg(unix)]
#[test]
fn the_unattended_lock_is_never_taken_through_a_link() {
    use std::os::unix::fs::symlink;
    let scratch = std::env::temp_dir().join(format!("lock-links-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    // The only test in this file, so nothing else reads these at the same
    // time.
    unsafe {
        std::env::set_var("HOME", &scratch);
        std::env::set_var("XDG_DATA_HOME", scratch.join(".local/share"));
    }
    let dir = boundary_provision::platform::data_dir().unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    let target = scratch.join("made-through-the-link");
    symlink(&target, dir.join("unattended.lock")).unwrap();
    let claimed = boundary_provision::platform::claim_unattended();
    assert!(
        !target.exists(),
        "the lock was made through the link: {claimed:?}"
    );
    assert!(claimed.is_err());
    // Without the link the lock is made and taken as before.
    std::fs::remove_file(dir.join("unattended.lock")).unwrap();
    let held = boundary_provision::platform::claim_unattended().unwrap();
    assert!(held.is_some());
    assert!(
        boundary_provision::platform::claim_unattended()
            .unwrap()
            .is_none()
    );
    drop(held);
    let _ = std::fs::remove_dir_all(&scratch);
}
