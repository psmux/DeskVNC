//! Every command the app registers has to be granted, or Tauri refuses it at
//! run time with "not allowed by ACL" and the UI quietly gets nothing back.
//! That happened twice (`boundary_permission`, `agent_setup_agents`) and no
//! test noticed, because a refused call looks like an empty answer.

use std::collections::BTreeSet;

fn read(path: &str) -> String {
    let root = env!("CARGO_MANIFEST_DIR");
    std::fs::read_to_string(format!("{root}/{path}")).expect(path)
}

/// The text between `start` and the next `end`.
fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text.find(start).expect(start) + start.len();
    let len = text[from..].find(end).expect(end);
    &text[from..from + len]
}

/// The command names in `generate_handler![...]`.
fn registered() -> BTreeSet<String> {
    let lib = read("src/lib.rs");
    between(&lib, "generate_handler![", "])")
        .lines()
        .map(|l| l.split("//").next().unwrap().trim().trim_end_matches(','))
        .filter(|l| !l.is_empty())
        .map(|l| l.rsplit("::").next().unwrap().to_string())
        .collect()
}

/// The command names `build.rs` puts in the app manifest.
fn manifest() -> BTreeSet<String> {
    let build = read("build.rs");
    between(&build, "AppManifest::new().commands(&[", "])")
        .lines()
        .map(|l| l.split("//").next().unwrap().trim())
        .filter_map(|l| l.strip_prefix('"')?.strip_suffix("\",").map(str::to_string))
        .collect()
}

#[test]
fn every_registered_command_is_in_the_manifest() {
    let missing: Vec<_> = registered().difference(&manifest()).cloned().collect();
    assert!(
        missing.is_empty(),
        "add these to build.rs and a capability: {missing:?}"
    );
}

#[test]
fn the_main_window_is_granted_every_command() {
    let default = read("capabilities/default.json");
    let missing: Vec<_> = manifest()
        .into_iter()
        .filter(|c| !default.contains(&format!("\"allow-{}\"", c.replace('_', "-"))))
        .collect();
    assert!(
        missing.is_empty(),
        "grant these in capabilities/default.json: {missing:?}"
    );
}
