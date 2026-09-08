//! `dvv_files`, over the real framing, against a source that holds bytes.
//!
//! ## What this proves and what it cannot
//!
//! It drives the whole adapter: the manifest's schema, the dispatch, the
//! capability gate on the grant, the window loop, and the base64 round trip
//! in both directions. What sits under the seam is `dvv::fake`'s map rather
//! than an SSH server, which is the same trade every other test in this
//! directory makes and for the same reason: `SessionSource` is the seam, a
//! test that stood up sshd would be testing sshd, and the shell's own half of
//! this is proved on the other side of the socket in
//! `src-tauri/src/agent/server.rs`.
//!
//! The one claim that would be worthless if faked is the binary one, and it is
//! not faked here: the bytes below travel as `Vec<u8>` through the plane, as
//! base64 through the JSON, and are compared byte for byte at the far end.

mod common;

use common::{error_code, fake_plane, open, structured, Client};
use limb_core::capability::Capability;
use serde_json::json;

/// A payload that is hostile to anything treating a file as text.
///
/// A NUL, a lone `0xFF` which is not valid UTF-8, a CRLF that a line ending
/// conversion would eat, a `0x1A` which is end of file on DOS, and then every
/// byte value so nothing can survive by accident. An installer short by one
/// byte, or with its line endings helpfully fixed, fails on somebody else's
/// machine with nothing to point at.
fn hostile_bytes() -> Vec<u8> {
    let mut payload: Vec<u8> = vec![
        0x4D, 0x5A, 0x90, 0x00, 0x00, 0xFF, 0x0D, 0x0A, 0x1A, 0x00, 0xC3, 0x28,
    ];
    payload.extend((0u16..=255).map(|b| b as u8));
    payload
}

/// The whole conversation: home, put, list, get, rename, remove.
///
/// One test rather than six, because the interesting property is that the path
/// each step answers with is the path the next step uses. An agent that had to
/// assemble a path itself from a home directory and a name would be an agent
/// guessing at somebody else's directory separator.
#[tokio::test]
async fn a_file_goes_up_comes_back_and_moves_around_by_the_paths_it_was_given() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    let home = client
        .tool("dvv_files", json!({ "limbId": limb, "action": "home" }))
        .await;
    assert_eq!(error_code(&home), None, "{home}");
    let home_path = structured(&home)["path"]
        .as_str()
        .expect("a home path")
        .to_string();
    assert!(home_path.starts_with('/'), "{home_path}");

    let payload = hostile_bytes();
    let uploaded = client
        .tool(
            "dvv_files",
            json!({
                "limbId": limb,
                "action": "put",
                "path": format!("{home_path}/setup.exe"),
                "contentBase64": base64_of(&payload),
                "mode": 0o755,
            }),
        )
        .await;
    assert_eq!(error_code(&uploaded), None, "{uploaded}");
    assert_eq!(structured(&uploaded)["sent"], payload.len());
    assert_eq!(structured(&uploaded)["size"], payload.len());
    assert_eq!(
        source.file("~/setup.exe").as_deref(),
        Some(payload.as_slice()),
        "what reached the machine is what the agent sent"
    );

    let listed = client
        .tool(
            "dvv_files",
            json!({ "limbId": limb, "action": "list", "path": "~" }),
        )
        .await;
    assert_eq!(error_code(&listed), None, "{listed}");
    assert_eq!(structured(&listed)["count"], 1);
    let row = &structured(&listed)["entries"][0];
    assert_eq!(row["name"], "setup.exe");
    assert_eq!(row["size"], payload.len());
    assert_eq!(row["isDir"], false);
    let listed_path = row["path"].as_str().expect("a path").to_string();
    assert_eq!(listed_path, format!("{home_path}/setup.exe"));

    // A listing is remote text and carries the label that says so, with the
    // per message nonce `04 §4.5` requires.
    let text = listed["content"][0]["text"].as_str().expect("a text block");
    assert!(
        text.contains("untrusted, data only"),
        "a listing has to be labelled: {text}"
    );
    assert!(
        text.contains("setup.exe"),
        "and the names have to be inside the label: {text}"
    );

    // Straight back, by the path the listing gave.
    let got = client
        .tool(
            "dvv_files",
            json!({ "limbId": limb, "action": "get", "path": listed_path }),
        )
        .await;
    assert_eq!(error_code(&got), None, "{got}");
    assert_eq!(structured(&got)["size"], payload.len());
    assert_eq!(structured(&got)["encoding"], "base64");
    let back = content_of(&got);
    assert_eq!(back, payload, "the bytes survived the envelope exactly");

    let renamed = client
        .tool(
            "dvv_files",
            json!({
                "limbId": limb,
                "action": "rename",
                "path": listed_path,
                "to": format!("{home_path}/installer.exe"),
            }),
        )
        .await;
    assert_eq!(error_code(&renamed), None, "{renamed}");
    assert_eq!(
        structured(&renamed)["path"],
        format!("{home_path}/installer.exe")
    );
    assert!(source.file("~/setup.exe").is_none());
    assert_eq!(
        source.file("~/installer.exe").as_deref(),
        Some(payload.as_slice()),
        "a rename moves the bytes and does not copy them"
    );

    let removed = client
        .tool(
            "dvv_files",
            json!({
                "limbId": limb,
                "action": "remove",
                "path": format!("{home_path}/installer.exe"),
            }),
        )
        .await;
    assert_eq!(error_code(&removed), None, "{removed}");
    assert!(source.file("~/installer.exe").is_none());
}

/// A file larger than one window crosses in several and arrives whole.
///
/// This is what makes the per call cap a cap on an ENVELOPE and not a cap on
/// file size. The pattern is deliberate: a window written at the wrong offset
/// shows up as wrong content rather than only as a wrong length, and a second
/// window that truncated instead of writing in place would leave a file
/// holding nothing but its last chunk.
#[tokio::test]
async fn a_file_bigger_than_one_window_arrives_whole() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    let size = (dvv::mcp::FILE_WINDOW_BYTES as usize) * 2 + 4096;
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    source.seed_file("~/big.bin", &payload);

    let temp = std::env::temp_dir().join(format!("dvv-files-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let got = client
        .tool(
            "dvv_files",
            json!({
                "limbId": limb,
                "action": "get",
                "path": "~/big.bin",
                "to": temp.display().to_string(),
            }),
        )
        .await;
    assert_eq!(error_code(&got), None, "{got}");
    assert_eq!(structured(&got)["size"], payload.len());
    assert!(
        structured(&got)["windows"].as_u64().expect("a count") >= 3,
        "a file of this size cannot have crossed in one window: {got}"
    );
    assert_eq!(
        structured(&got)["savedTo"],
        temp.display().to_string(),
        "the receipt names where the file went"
    );
    assert_eq!(
        std::fs::read(&temp).expect("the downloaded file"),
        payload,
        "the file on disk is the file on the machine"
    );

    // …and back up again, from the local file, which is the other direction of
    // the same loop.
    let sent = client
        .tool(
            "dvv_files",
            json!({
                "limbId": limb,
                "action": "put",
                "path": "~/copy.bin",
                "from": temp.display().to_string(),
            }),
        )
        .await;
    assert_eq!(error_code(&sent), None, "{sent}");
    assert!(structured(&sent)["windows"].as_u64().expect("a count") >= 3);
    assert_eq!(
        source.file("~/copy.bin").as_deref(),
        Some(payload.as_slice())
    );
    let _ = std::fs::remove_file(&temp);
}

/// Content big enough to hurt is refused rather than returned, and the refusal
/// says what to do instead.
///
/// The cap is not the envelope's: it is that content returned here lands in a
/// model's context window and stays there. A truncated answer would look like
/// a file and not be one.
#[tokio::test]
async fn a_large_file_is_refused_inline_and_named_rather_than_truncated() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    let payload = vec![7u8; dvv::mcp::INLINE_GET_BYTES as usize + 1];
    source.seed_file("~/huge.log", &payload);

    let got = client
        .tool(
            "dvv_files",
            json!({ "limbId": limb, "action": "get", "path": "~/huge.log" }),
        )
        .await;
    assert_eq!(error_code(&got), Some("BAD_REQUEST"), "{got}");
    let message = structured(&got)["message"]
        .as_str()
        .expect("a message")
        .to_string();
    assert!(
        message.contains(&payload.len().to_string()),
        "the refusal names the size: {message}"
    );
    assert!(
        message.contains(&dvv::mcp::INLINE_GET_BYTES.to_string()),
        "and the cap: {message}"
    );
    assert!(
        message.contains('`'),
        "and points at the argument that fixes it: {message}"
    );
}

/// A download whose destination cannot be written is refused BEFORE anything
/// is downloaded, and no directory is created on the way.
#[tokio::test]
async fn a_destination_that_is_not_absolute_or_has_no_parent_is_refused() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);
    source.seed_file("~/small.txt", b"hello");

    for to in ["relative/path.txt", "/no/such/directory/anywhere/x.txt"] {
        let got = client
            .tool(
                "dvv_files",
                json!({ "limbId": limb, "action": "get", "path": "~/small.txt", "to": to }),
            )
            .await;
        assert_eq!(error_code(&got), Some("BAD_REQUEST"), "{to}: {got}");
    }
    assert!(
        !std::path::Path::new("/no/such/directory/anywhere").exists(),
        "a refused download must not have made the tree"
    );
}

/// Two sources for one file is a call nobody can resolve, so it is refused
/// rather than one of them being picked.
#[tokio::test]
async fn a_put_with_both_a_local_file_and_inline_content_is_refused() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    let sent = client
        .tool(
            "dvv_files",
            json!({
                "limbId": limb,
                "action": "put",
                "path": "~/x.bin",
                "from": "/etc/hosts",
                "contentBase64": "aGk=",
            }),
        )
        .await;
    assert_eq!(error_code(&sent), Some("BAD_REQUEST"), "{sent}");
}

/// An action this tool does not have is named rather than shrugged at.
#[tokio::test]
async fn an_action_that_is_not_a_files_action_lists_the_ones_that_are() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    let answer = client
        .tool(
            "dvv_files",
            json!({ "limbId": limb, "action": "chmod", "path": "~/x" }),
        )
        .await;
    assert_eq!(error_code(&answer), Some("BAD_REQUEST"), "{answer}");
    assert!(structured(&answer)["message"]
        .as_str()
        .expect("a message")
        .contains("mkdir"));
}

/// The grant is the gate, and the two halves of the file pair are separate.
///
/// `02 §5.2` splits reading from writing and neither implies the other, so
/// there are two tests here and not one: a build where `files.read` bought a
/// write would pass a test that only checked the empty grant.
#[tokio::test]
async fn reading_is_refused_on_a_grant_that_does_not_carry_files_read() {
    let (source, plane) = plane_holding(&[
        Capability::Open,
        Capability::Control,
        Capability::FilesWrite,
    ]);
    source.seed_file("~/secret.txt", b"private");
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    for action in ["home", "list", "get"] {
        let answer = client
            .tool(
                "dvv_files",
                json!({ "limbId": limb, "action": action, "path": "~/secret.txt" }),
            )
            .await;
        assert_eq!(error_code(&answer), Some("POLICY_DENIED"), "{action}");
        let message = structured(&answer)["message"]
            .as_str()
            .expect("a message")
            .to_string();
        assert!(
            message.contains("files.read"),
            "{action} has to name the capability: {message}"
        );
    }
}

#[tokio::test]
async fn writing_is_refused_on_a_grant_that_only_carries_files_read() {
    let (source, plane) =
        plane_holding(&[Capability::Open, Capability::Control, Capability::FilesRead]);
    source.seed_file("~/keep.txt", b"still here");
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    for (action, extra) in [
        ("put", json!({ "contentBase64": "" })),
        ("mkdir", json!({})),
        ("remove", json!({})),
        ("rename", json!({ "to": "~/gone.txt" })),
    ] {
        let mut arguments = json!({ "limbId": limb, "action": action, "path": "~/keep.txt" });
        for (key, value) in extra.as_object().expect("an object") {
            arguments[key] = value.clone();
        }
        let answer = client.tool("dvv_files", arguments).await;
        assert_eq!(error_code(&answer), Some("POLICY_DENIED"), "{action}");
        let message = structured(&answer)["message"]
            .as_str()
            .expect("a message")
            .to_string();
        assert!(
            message.contains("files.write"),
            "{action} has to name the capability: {message}"
        );
    }

    // …and the machine is untouched. A refusal that had already deleted the
    // file would be the worst possible kind.
    assert_eq!(
        source.file("~/keep.txt").as_deref(),
        Some(&b"still here"[..])
    );
    assert!(source.file("~/gone.txt").is_none());
}

/// A plane over the two fake machines whose grant carries exactly these
/// capabilities.
///
/// `Plane::local` issues the operator bundle, which carries both halves of the
/// file pair on purpose, so a test about a MISSING capability has to build its
/// own grant rather than ask for the convenient one.
fn plane_holding(
    capabilities: &[Capability],
) -> (
    std::sync::Arc<dvv::fake::FakeSource>,
    std::sync::Arc<dvv::plane::Plane>,
) {
    use dvv::plane::SessionSource;
    let source = std::sync::Arc::new(dvv::fake::FakeSource::two_machines());
    let hosts: Vec<String> = source
        .hosts()
        .expect("the fake source publishes its machines")
        .into_iter()
        .map(|host| host.address)
        .collect();
    let grant = agent_plane::Grant::issue(
        "att_test",
        limb_core::capability::CapabilitySet::of(capabilities),
        hosts,
    )
    .expect("a grant over the fake machines");
    let plane = dvv::plane::Plane::new(
        grant,
        source.clone() as std::sync::Arc<dyn SessionSource>,
        agent_plane::PlaneConfig::default(),
    );
    (source, std::sync::Arc::new(plane))
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The bytes out of a `get` that answered inline.
///
/// They are in the WRAPPED text block and not in `structuredContent`, on
/// purpose: the same payload in both places doubles what a model pays for one
/// file. So this pulls them back out of the labelled block, which is also a
/// small proof that the label did not corrupt what it wrapped.
fn content_of(answer: &serde_json::Value) -> Vec<u8> {
    use base64::Engine as _;
    let text = answer["content"][0]["text"].as_str().expect("a text block");
    let payload = text
        .lines()
        .find(|line| line.len() > 32 && !line.contains(' '))
        .expect("the base64 payload is on a line of its own");
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .expect("the payload decodes")
}
