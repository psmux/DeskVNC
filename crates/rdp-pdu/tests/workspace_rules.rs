//! Workspace rules for the RDP crates (PRDRDP/12 §2.5 and AGENT_BRIEF D3).
//!
//! This is the workspace's only D3 enforcement test. PRDRDP/11 §3.5 and
//! PRDRDP/09 §7.7 each specified one under a different name, which is three
//! lists of forbidden crate names drifting apart from the first rebase. There
//! is one list and one file, and both of those documents cite this path.
//!
//! The properties, none of which the type system can express and none of
//! which clippy can see (PRDRDP/12 §2.6):
//!
//! 1. `rdp-pdu`, `rdp-codecs` and `rdp-auth` have no tokio and no I/O, so
//!    they build in a second and fuzz without a runtime (D12).
//! 2. Only the crates PRDRDP/00 R44 and R45 name reach into the RDP set, and
//!    only as far as `rdp-pdu`.
//! 3. `rdp-auth` names `rdp_pdu::io` and `rdp_pdu::asn1` and nothing else.
//! 4. No crate anywhere in this workspace depends on a third party RDP,
//!    CredSSP, SPNEGO, NTLM or Kerberos implementation, and none arrives
//!    transitively either, which is what the `Cargo.lock` half checks.
//! 5. `openssl` and `openssl-src` are named by `vnc-transport` and by no
//!    other crate, and they are optional there, so a default build compiles
//!    no OpenSSL at all (PRDRDP/00 R55, PRDRDP/11 §3.10).
//!
//! Note what rule 4 does not say. PRDRDP/00 R54 requires that every
//! cryptographic operation come from a library, and the forbidden list is the
//! wrong instrument for that: R54 wants more third party crypto in the tree,
//! not less. The R54 side is held by `rdp-auth`'s manifest being an allow
//! list, by the citation rule, and by review.
//!
//! These tests live in `rdp-pdu` because it is the crate with the smallest
//! dependency tree in the workspace, so `cargo test -p rdp-pdu` is the
//! fastest thing CI can run and a bad push fails within seconds rather than
//! after the whole workspace has linked.
//!
//! The manifests parsed here are ours, they are small, and they are formatted
//! by hand. A real TOML parser would be more correct and would add a
//! dependency to the crate that is meant to have the fewest. The heuristic
//! parser below reads section headers and the name before the first `=` on
//! each line, which is exactly enough for manifests of this shape, and it
//! errs towards flagging rather than towards passing. The precedent for a
//! test that reads the source tree is
//! `crates/vnc-core/src/input/scancode.rs:201`, the `ui_table_agreement`
//! module, which parses `ui/src/render/keysyms.ts` from a Rust test and says
//! of itself: "Parsing TypeScript from a Rust test is admittedly crude, but
//! the alternative is a build-time generator, and this catches the exact
//! class of mistake that has now happened twice in one afternoon."
//!
//! Every test reports every offence at once rather than failing on the first,
//! because the failure mode is usually a rebase that dragged in three lines.

use std::path::{Path, PathBuf};

/// The workspace root, two levels up from `crates/rdp-pdu`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> under a workspace root")
        .to_path_buf()
}

/// Every `Cargo.toml` under the workspace, excluding `target/`.
fn manifests(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                // `target/` holds vendored manifests of every dependency in
                // the graph, which would make this test assert things about
                // crates we merely link. `.git` is large and irrelevant.
                if name != "target" && name != ".git" && name != "node_modules" {
                    stack.push(path);
                }
            } else if name == "Cargo.toml" {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The dependency names declared in `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]` and their `target.*` and `workspace.*` variants.
///
/// Heuristic, deliberately: it reads the section header and then the name
/// before the first `=` on each following line. It does not understand inline
/// tables spread over several lines, and there are none in our manifests. A
/// dependency renamed with `package = "..."` would be reported under its
/// local name, which is the safe direction to be wrong in.
fn declared_dependencies(manifest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).to_string();
            continue;
        }
        if !section.ends_with("dependencies") {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            let name = name.trim().trim_matches('"');
            if !name.is_empty() {
                out.push((section.clone(), name.to_string()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. The leaf crates stay pure (D12, PRDRDP/12 §2.1)
// ---------------------------------------------------------------------------

/// Crates that own no socket and no runtime, and the workspace crates each is
/// allowed to name.
///
/// Adding an entry to a value here is a design decision, not a fix for a
/// failing test. It needs a sentence in PRDRDP/12 §2.1 saying why, and the
/// reviewer of that diff should ask for one.
const LEAVES: &[(&str, &[&str])] = &[
    ("rdp-pdu", &[]),
    // PRDRDP/00 R37: pixel conversion is one leaf crate shared with vnc-core.
    ("rdp-codecs", &["remote-pixel"]),
    // The two ASN.1 and Reader modules only; see PRDRDP/12 §2.1 rule 3 and
    // the source side of that rule in `rdp_auth_names_only_pdu_asn1_and_io`.
    ("rdp-auth", &["rdp-pdu"]),
    // PRDRDP/00 R37: remote-pixel is the leaf everything else stands on.
    ("remote-pixel", &[]),
];

/// Crates outside the RDP set that PRDRDP/00 rules may name `rdp-pdu`, and
/// nothing else in the RDP set.
///
/// R45: `vnc-transport` for `rdp_pdu::asn1::der`, because the DER walker
/// moved there rather than being written twice.
/// R44: `vnc-discovery` for the 3389 probe's X.224 encoder and Connection
/// Confirm parser, so hostile input meets one fuzzed parser.
///
/// These two edges are the whole exception. Adding a third is a design
/// decision and needs a ruling in PRDRDP/00, not an entry here.
const RDP_PDU_CONSUMERS_OUTSIDE_THE_SET: &[&str] = &["vnc-transport", "vnc-discovery"];

/// The RDP crates that no crate outside the set may depend on, at any depth.
const RDP_SET_INTERNAL: &[&str] = &["rdp-auth", "rdp-codecs", "rdp-core"];

/// The vendored OpenSSL TLS backend (PRDRDP/00 R55), and the one crate
/// allowed to name it.
///
/// The rule is positive rather than a `FORBIDDEN` entry on purpose. `openssl`
/// is not a name we are banning, it is a name with exactly one legitimate
/// home, and the failure message has to say which home rather than "this is
/// forbidden". Nothing anywhere may name `openssl-sys` directly: it arrives
/// underneath `openssl`, and a direct edge means somebody is linking a system
/// OpenSSL, which is the thing R55 vendors in order to avoid.
const OPENSSL_NAMES: &[&str] = &["openssl", "openssl-src", "openssl-sys", "openssl-probe"];
const OPENSSL_HOME: &str = "vnc-transport";

/// Anything that implies a runtime, a socket, a file, or a clock we cannot
/// fake. `mio` and `socket2` are here because they are how a dependency
/// smuggles a socket in without naming tokio.
const IO_CRATES: &[&str] = &[
    "tokio",
    "tokio-util",
    "tokio-rustls",
    "async-std",
    "smol",
    "mio",
    "socket2",
    "reqwest",
    "hyper",
    "ureq",
    "rustls",
    "russh",
    "mdns-sd",
    "rusqlite",
    "keyring",
    "directories",
    "notify",
];

#[test]
fn leaf_crates_have_no_runtime_and_no_io() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for (crate_name, allowed_workspace_deps) in LEAVES {
        let path = root.join("crates").join(crate_name).join("Cargo.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        for (section, dep) in declared_dependencies(&text) {
            if IO_CRATES.contains(&dep.as_str()) {
                offences.push(format!(
                    "{crate_name}/Cargo.toml [{section}] names `{dep}`: \
                     leaf crates do no I/O (PRDRDP/12 §2.1)"
                ));
            }
            // A crate naming itself is Cargo's way of turning a feature on
            // for its own tests and benches only: `rdp-codecs` does it for
            // its reference encoders (PRDRDP/04 §11.4). It is not an edge to
            // another crate, so it is not what this rule is about.
            if dep == **crate_name {
                continue;
            }
            // A path dependency is a workspace crate by definition.
            let is_workspace_dep = text
                .lines()
                .any(|l| l.trim_start().starts_with(&dep) && l.contains("path = "));
            if is_workspace_dep && !allowed_workspace_deps.contains(&dep.as_str()) {
                offences.push(format!(
                    "{crate_name}/Cargo.toml [{section}] depends on workspace \
                     crate `{dep}`, which PRDRDP/12 §2.1 does not allow"
                ));
            }
        }
    }

    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// PRDRDP/00 R44 and R45 let `vnc-discovery` and `vnc-transport` depend on
/// `rdp-pdu`. Both edges are deliberate and both are narrow, so the test does
/// not merely tolerate them: it asserts that no crate outside the RDP set
/// reaches any of the other three.
///
/// Without this, R44 and R45 would be the first two entries on a list that
/// grows every time somebody wants "just one type" from `rdp-core`.
#[test]
fn only_the_ruled_crates_reach_into_the_rdp_set() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for manifest in manifests(&root) {
        let Some(name) = crate_name(&manifest) else {
            continue;
        };
        // Inside the set, and the shell, which reaches rdp-core through the
        // registry (D2, PRDRDP/02 §4.4).
        if LEAVES.iter().any(|(l, _)| *l == name) || name == "rdp-core" || name == "src-tauri" {
            continue;
        }
        let text = std::fs::read_to_string(&manifest).expect("read manifest");
        for (section, dep) in declared_dependencies(&text) {
            if RDP_SET_INTERNAL.contains(&dep.as_str()) {
                offences.push(format!(
                    "{name}/Cargo.toml [{section}] depends on `{dep}`: only \
                     `rdp-core` and the crates named in PRDRDP/00 R44 and R45 \
                     may reach into the RDP set"
                ));
            }
            if dep == "rdp-pdu" && !RDP_PDU_CONSUMERS_OUTSIDE_THE_SET.contains(&name.as_str()) {
                offences.push(format!(
                    "{name}/Cargo.toml [{section}] depends on `rdp-pdu`: \
                     PRDRDP/00 R44 and R45 allow that for `vnc-discovery` and \
                     `vnc-transport` only, and a third needs its own ruling"
                ));
            }
        }
    }

    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// PRDRDP/00 R55 puts a second, vendored TLS stack in `vnc-transport` behind
/// the `legacy-tls` feature, and nowhere else. Two things have to stay true:
/// only that crate names it, and it stays optional so a default build does
/// not compile OpenSSL.
///
/// The second assertion is the one that matters for PRDRDP/11 §3.10's
/// exposure argument. "The code is not reachable when the feature is off" is
/// only worth saying if the dependency is genuinely optional, and
/// `optional = true` on the line is what makes it so. It is also the half
/// most likely to be lost in a rebase, because dropping `optional` is the
/// quickest way to make a local build compile.
#[test]
fn only_vnc_transport_names_openssl() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for manifest in manifests(&root) {
        let Some(name) = crate_name(&manifest) else {
            continue;
        };
        let text = std::fs::read_to_string(&manifest).expect("read manifest");
        for (section, dep) in declared_dependencies(&text) {
            let lower = dep.to_ascii_lowercase().replace('_', "-");
            if !OPENSSL_NAMES.contains(&lower.as_str()) {
                continue;
            }
            if name != OPENSSL_HOME {
                offences.push(format!(
                    "{name}/Cargo.toml [{section}] names `{dep}`: the vendored \
                     OpenSSL backend lives in `{OPENSSL_HOME}` only \
                     (PRDRDP/00 R55). A second crate linking a TLS stack means \
                     a second verifier and a second place a protocol version \
                     can be chosen."
                ));
                continue;
            }
            if lower == "openssl-sys" || lower == "openssl-probe" {
                offences.push(format!(
                    "{name}/Cargo.toml [{section}] names `{dep}` directly: it \
                     arrives underneath `openssl`, and a direct edge means a \
                     system OpenSSL is being linked instead of the vendored \
                     one (PRDRDP/11 §3.10)."
                ));
                continue;
            }
            let declared_optional = text
                .lines()
                .any(|l| l.trim_start().starts_with(&dep) && l.contains("optional = true"));
            if !declared_optional {
                offences.push(format!(
                    "{name}/Cargo.toml [{section}] names `{dep}` without \
                     `optional = true`: the `legacy-tls` feature is what keeps \
                     OpenSSL out of a default build (PRDRDP/00 R55)."
                ));
            }
        }
    }

    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// The source half of PRDRDP/12 §2.1 rule 3: `rdp-auth` may reach into
/// `rdp_pdu::io` and `rdp_pdu::asn1`, and nothing else in that crate. An
/// `rdp_pdu::mcs` import means protocol sequencing has moved into the
/// authentication crate, which compiles fine and is a design mistake.
#[test]
fn rdp_auth_names_only_pdu_asn1_and_io() {
    let src = workspace_root().join("crates/rdp-auth/src");
    let mut offences = Vec::new();
    for file in rust_files(&src) {
        let text = std::fs::read_to_string(&file).expect("read source");
        for (n, line) in text.lines().enumerate() {
            let code = strip_comment(line);
            let Some(at) = code.find("rdp_pdu::") else {
                continue;
            };
            let rest = &code[at + "rdp_pdu::".len()..];
            if !(rest.starts_with("io") || rest.starts_with("asn1")) {
                offences.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "rdp-auth may name only rdp_pdu::io and rdp_pdu::asn1 \
         (PRDRDP/12 §2.1 rule 3):\n{}",
        offences.join("\n")
    );
}

// ---------------------------------------------------------------------------
// 2. D3: no third party RDP or authentication implementation, anywhere
// ---------------------------------------------------------------------------

/// Substrings that name somebody else's implementation of a protocol we are
/// required to write ourselves (`AGENT_BRIEF.md` D3).
///
/// Substrings rather than exact names, so `ironrdp-pdu`, `ironrdp_core` and a
/// future `ironrdp-whatever` are all caught by one entry, and so a fork
/// published under `my-ntlm` is caught too.
///
/// This list is the whole of D3 that a machine can check. The rest of D3, the
/// part that says the bytes were written from the specification rather than
/// copied out of a repository with a compatible licence, is a human review
/// question and always will be.
///
/// A backstop, not the control (PRDRDP/00 R65). It catches the names we know
/// about. `libkrimes` is here because it is a Kerberos implementation whose
/// name contains none of the other substrings, and the next such crate will
/// not be here at all. What enforces D3 and R54 is review of every new entry
/// in a `[dependencies]` table against the two rules. A green run says the
/// known names are absent; it never says the rule was followed.
const FORBIDDEN: &[&str] = &[
    "ironrdp",
    "sspi",
    "picky",
    "rdp-rs",
    "freerdp",
    "libkrimes",
    "ntlm",
    "kerberos",
    "krb5",
    "gssapi",
    "credssp",
    "spnego",
];

#[test]
fn no_workspace_crate_depends_on_a_third_party_rdp_stack() {
    let root = workspace_root();
    let mut offences = Vec::new();

    for manifest in manifests(&root) {
        let text = std::fs::read_to_string(&manifest).expect("read manifest");
        let shown = manifest.strip_prefix(&root).unwrap_or(&manifest);
        for (section, dep) in declared_dependencies(&text) {
            let lower = dep.to_ascii_lowercase().replace('_', "-");
            if let Some(hit) = FORBIDDEN.iter().find(|f| lower.contains(*f)) {
                offences.push(format!(
                    "{}: [{section}] `{dep}` matches the forbidden name `{hit}`. \
                     D3: every byte of RDP and NLA is written in this workspace.",
                    shown.display()
                ));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "D3 violation. If this crate is genuinely unrelated to RDP (a name \
         collision), add it to an allowlist here with a sentence saying so, \
         and expect the reviewer to ask.\n{}",
        offences.join("\n")
    );
}

/// The manifests say what we declared. `Cargo.lock` says what we resolved,
/// which is the other half: a forbidden crate can arrive underneath somebody
/// else's dependency without appearing in any manifest of ours.
///
/// PRDRDP/12 §2.7 gives this half to a `cargo tree` invocation in CI. It is
/// here as well because a test that runs on every `cargo test` catches it on
/// the developer's machine, and because reading the lock file needs neither a
/// network nor a resolver run.
#[test]
fn no_forbidden_crate_is_resolved_into_the_lock_file() {
    let root = workspace_root();
    let lock = root.join("Cargo.lock");
    let text =
        std::fs::read_to_string(&lock).unwrap_or_else(|e| panic!("read {}: {e}", lock.display()));

    let mut offences = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("name") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let name = rest
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase()
            .replace('_', "-");
        if let Some(hit) = FORBIDDEN.iter().find(|f| name.contains(*f)) {
            offences.push(format!(
                "Cargo.lock resolves `{name}`, which matches the forbidden \
                 name `{hit}`. It is not in any of our manifests, so it \
                 arrived underneath another dependency: find the edge with \
                 `cargo tree -i {name}` and remove it."
            ));
        }
    }

    offences.sort();
    offences.dedup();
    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// The `name = "..."` line of a manifest's `[package]` section. `None` for a
/// virtual manifest such as the workspace root.
fn crate_name(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = line.strip_prefix("name") {
                let rest = rest.trim_start().strip_prefix('=')?;
                return Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// Everything after `//` on a line, and any line that is wholly a doc or
/// block comment, is not code. A comment naming a forbidden crate is
/// encouraged: D3 explicitly allows recording an interop behaviour learned by
/// reading FreeRDP, as long as the comment cites the behaviour and never the
/// code.
fn strip_comment(line: &str) -> &str {
    let t = line.trim_start();
    if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
        return "";
    }
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}
