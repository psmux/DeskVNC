//! No secret reaches a `Debug` rendering, no error carries remote bytes, and
//! no source file in this crate has grown a hand written primitive or a
//! predictable generator.
//!
//! PRDRDP/14 §8.1, §8.3 and §2.10. The last three tests are source greps.
//! They are crude, they produce false positives in principle, and they catch
//! the mistake that actually happens, which is somebody making a value
//! deterministic for a test and leaving it that way. A hit is a review
//! conversation and the failure message says so.

use std::fs;
use std::path::{Path, PathBuf};

use rdp_auth::gss::GssMechanism;
use rdp_auth::ntlm::{flags, NtlmSession};
use rdp_auth::{AuthError, ChannelBindings, Identity, NtlmClient, NtlmConfig};

/// A password distinctive enough that a substring search for it is meaningful.
const PASSWORD: &str = "hunter2-correct-horse-battery-staple";

fn config() -> NtlmConfig {
    NtlmConfig {
        identity: Identity::from_prompt("alice", "CORP", PASSWORD).unwrap(),
        spn: "TERMSRV/server.example.com".to_owned(),
        workstation: Some("laptop".to_owned()),
        channel_bindings: Some(ChannelBindings::from_certificate_hash(&[0x11u8; 32])),
    }
}

/// A CHALLENGE with an `MsvAvTimestamp`, which is what our policy requires.
fn challenge() -> Vec<u8> {
    use rdp_auth::ntlm::{av_pair, crypto, messages, version::Version};
    let mut pairs = av_pair::AvPairs::default();
    pairs.set(av_pair::MSV_AV_NB_DOMAIN_NAME, crypto::unicode("CORP"));
    pairs.set(av_pair::MSV_AV_TIMESTAMP, vec![0x77; 8]);
    messages::encode_challenge(&messages::ChallengeMessage {
        target_name: crypto::unicode("SERVER"),
        flags: flags::CLIENT_NEGOTIATE_FLAGS,
        server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        target_info: pairs.encode(),
        version: Some(Version::CLIENT),
        raw: Vec::new(),
    })
}

#[test]
fn debug_never_prints_a_secret() {
    let id = Identity::from_prompt("alice", "CORP", PASSWORD).unwrap();
    for rendered in [format!("{id:?}"), format!("{id:#?}")] {
        assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
        assert!(rendered.contains("***"), "the redaction marker is missing");
        // The user and the domain are not secrets and are useful in a
        // diagnostic, so they are expected to be there.
        assert!(rendered.contains("alice"));
    }

    let cfg = config();
    for rendered in [format!("{cfg:?}"), format!("{cfg:#?}")] {
        assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
    }

    // The client after both rounds holds the password, the derived keys and
    // the session, and none of them may render.
    let mut client = NtlmClient::new(config());
    let _ = client.step(&[]).unwrap();
    let _ = client.step(&challenge()).unwrap();
    for rendered in [format!("{client:?}"), format!("{client:#?}")] {
        assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
        assert!(rendered.contains("***"), "the redaction marker is missing");
    }

    // And a session on its own.
    let session = NtlmSession::new(&[0x5Au8; 16], flags::CLIENT_NEGOTIATE_FLAGS);
    let rendered = format!("{session:?}");
    assert!(
        !rendered.contains("5a") && !rendered.contains("90"),
        "{rendered}"
    );
}

#[test]
fn no_error_from_any_failure_path_carries_remote_bytes() {
    // Every `AuthError` variant is a unit variant or carries a `&'static str`,
    // so a token cannot ride along into a log file (PRDRDP/00 R63).
    // Driving the real failure paths is what proves it rather than reading the
    // type: an error built by hand would prove nothing about the call sites.
    let secret_looking = b"NTLMSSP\0\x02\x00\x00\x00hunter2-correct-horse-battery-staple";

    let mut client = NtlmClient::new(config());
    let e = client.step(secret_looking).unwrap_err();
    assert_no_secret(e);

    let mut client = NtlmClient::new(config());
    let _ = client.step(&[]).unwrap();
    let e = client.step(secret_looking).unwrap_err();
    assert_no_secret(e);
    // And after failing, it stays failed with the same shape of error.
    assert_no_secret(client.step(secret_looking).unwrap_err());

    let mut client = NtlmClient::new(config());
    assert_no_secret(client.wrap(b"pubKeyAuth").unwrap_err());

    let mut client = NtlmClient::new(config());
    let _ = client.step(&[]).unwrap();
    let _ = client.step(&challenge()).unwrap();
    let mut token = client.wrap(b"pubKeyAuth").unwrap();
    let last = token.len() - 1;
    token[last] ^= 0xff;
    assert_no_secret(client.unwrap(&token).unwrap_err());
}

fn assert_no_secret(e: AuthError) {
    for rendered in [format!("{e:?}"), format!("{e}"), e.user_message()] {
        assert!(
            !rendered.contains("hunter2"),
            "secret in an error: {rendered}"
        );
        assert!(
            !rendered.contains("NTLMSSP"),
            "a token fragment in an error: {rendered}"
        );
    }
}

#[test]
fn the_user_message_never_names_an_ntstatus_or_a_field() {
    // The symbol goes in the log line, never in the sentence (PRDRDP/14 §8.4).
    for e in [
        AuthError::MalformedMessage("TargetInfo"),
        AuthError::LegacyServerRefused,
        AuthError::UnexpectedToken,
        AuthError::ContextNotEstablished,
        AuthError::MessageOutOfSequence,
        AuthError::SignatureMismatch,
        AuthError::NoUserName,
        AuthError::AlreadyFailed,
    ] {
        let msg = e.user_message();
        assert!(!msg.contains("STATUS_"), "{msg}");
        assert!(!msg.contains("TargetInfo"), "{msg}");
        assert!(msg.ends_with('.'), "a user message is a sentence: {msg}");
        assert_eq!(e.nt_status_symbol(), None, "phase 1a has no NTSTATUS table");
    }
}

// ---------------------------------------------------------------------------
// The source greps
// ---------------------------------------------------------------------------

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn every_source_file(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    for entry in fs::read_dir(dir).expect("the source directory is readable") {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            every_source_file(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).expect("a readable source file");
            out.push((path, text));
        }
    }
}

/// The half of a source file above `#[cfg(test)]`. Test code may compare with
/// `==` and may use a fixed key; production code may not.
fn production_half(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

/// The same, with comment lines removed.
///
/// The doc comments in this crate name the forbidden generators and the
/// forbidden shapes, because saying which mistake a rule prevents is most of
/// what makes the rule stick. Grepping the prose that explains a rule for a
/// violation of it is the one false positive these greps do produce, and
/// dropping comment lines is the narrowest way to remove it. A generator named
/// in code rather than in prose still fails.
fn production_code(text: &str) -> String {
    production_half(text)
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_source_file_uses_a_predictable_generator() {
    // PRDRDP/14 §2.10: every random value in this crate comes from
    // `rand::rng()` and from nothing else. `SmallRng` is the dangerous one
    // because it is one import away and its name does not say "not for keys".
    let mut files = Vec::new();
    every_source_file(&src_dir(), &mut files);
    assert!(!files.is_empty(), "the grep found no source files");
    for (path, text) in &files {
        for needle in ["SmallRng", "seed_from_u64", "from_seed", "rand_chacha"] {
            assert!(
                !production_code(text).contains(needle),
                "{} names `{needle}`. Every key and nonce in this crate comes from \
                 rand::rng() (PRDRDP/14 §2.10). If this is deliberate, it is a review \
                 conversation, not a test to edit.",
                path.display()
            );
        }
    }
}

#[test]
fn no_source_file_looks_like_a_hand_written_primitive() {
    // PRDRDP/14 §2.11: the shapes a hand written primitive takes are a 256
    // entry `u8` table (an S-box or an RC4 state) and a `rotate_left` on a
    // word inside a loop. The protocol code here shuffles bytes and does not
    // rotate words, so neither has produced a false positive. A hit is a
    // review conversation and not an automatic failure.
    let mut files = Vec::new();
    every_source_file(&src_dir(), &mut files);
    for (path, text) in &files {
        let src = production_code(text);
        assert!(
            !src.contains("rotate_left") && !src.contains("rotate_right"),
            "{} rotates a word. AGENT_BRIEF V3-A forbids writing a primitive here; \
             which row of PRDRDP/14 §2.10 does this correspond to?",
            path.display()
        );
        assert!(
            !src.contains("[u8; 256]"),
            "{} declares a 256 byte table, which is the shape of an S-box or an RC4 \
             state. AGENT_BRIEF V3-A forbids writing a primitive here.",
            path.display()
        );
    }
}

#[test]
fn the_mac_comparison_goes_through_subtle() {
    // PRDRDP/14 §8.1: every comparison of a MAC or a binding uses
    // `subtle::ConstantTimeEq`, never `==` and never a hand written fold over
    // an XOR accumulator. `hmac`'s own `verify_slice` is preferred where it
    // fits; it does not fit in `seal.rs`, because the tag is RC4 encrypted
    // after truncation and has to be decrypted before comparison.
    let seal = fs::read_to_string(src_dir().join("ntlm").join("seal.rs"))
        .expect("ntlm/seal.rs is readable");
    let src = production_code(&seal);
    assert_eq!(
        src.matches("ct_eq").count(),
        2,
        "ntlm/seal.rs should compare exactly two MACs in constant time, one in \
         `unwrap` and one in `verify_mic`"
    );
    for shape in [
        "expected ==",
        "== expected",
        "received ==",
        "== received",
        "assert_eq!",
    ] {
        assert!(
            !src.contains(shape),
            "ntlm/seal.rs compares a MAC with `{shape}` instead of `ct_eq`"
        );
    }
}

#[test]
fn the_crate_forbids_unsafe_code() {
    let lib = fs::read_to_string(src_dir().join("lib.rs")).expect("lib.rs is readable");
    assert!(lib.contains("#![forbid(unsafe_code)]"), "D11");
}
