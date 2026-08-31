//! `dvvp.v1` framing, and the one place a wire object becomes a
//! [`ClientCommand`].
//!
//! ## Why there is an envelope at all
//!
//! `PRDAgentPlug/04 §2.2`. On the webview path every message is a discrete
//! `ArrayBuffer` handed to a `tauri::ipc::Channel`, so its length is implicit
//! in the delivery. A stream socket has no such boundary, so every message on
//! this socket is an 8 byte envelope followed by its payload:
//!
//! ```text
//!   [u8  msg_type]
//!   [u8  flags]
//!   [u16 reserved = 0]
//!   [u32 len]
//!   [len bytes of payload]
//! ```
//!
//! Little endian, matching `FRAME_FORMAT.md`'s opening rule. Eight bytes rather
//! than seven keeps the payload 4 byte aligned, which is the same reason
//! `FRAME_FORMAT.md` gives for the PTY header.
//!
//! Only `msg_type` 0, the JSON-RPC control lane, is carried in this build.
//! Types 1 to 4 are the pixel and PTY lanes and they are not built yet; an
//! unknown `msg_type` is IGNORED rather than refused, which is the rule
//! `FRAME_FORMAT.md` and `IPC_CONTRACT.md` both already state and the reason
//! the two sides can ship in separate commits.
//!
//! ## Why [`decode_command`] is a hand written match
//!
//! `crates/remote-core/src/commands.rs` says it deliberately does not derive
//! `Serialize`, so that a new variant is a compile error where somebody has to
//! decide what happens to it. That discipline is kept here rather than dropped
//! at the socket: this decoder names each command it accepts, and a name it
//! does not know is an error with a sentence rather than a silently ignored
//! message.
//!
//! Two commands are deliberately absent and their absence is the design.
//! `ProvideCredentials` and `TrustCertificate` are how a PERSON answers a
//! prompt, and D7 says credentials never reach the agent. The way to enforce
//! that is not a capability check, it is not having an arm.
//!
//! ## The exec pair
//!
//! [`decode_exec`] and [`served_json`] are the two halves of `00 R51b` on this
//! wire. `ClientCommand::Agent(AgentIntent)` is not decoded here as a
//! `limb.command`, and that is deliberate: an intent is the one thing in
//! `ClientCommand` with somebody blocked on the far end of it, so it gets a
//! method of its own that returns the driver's answer as the reply, rather
//! than a `{ "delivered": true }` for a question nobody would ever hear the
//! answer to (`00 R7`, `00 R28`).

use base64::Engine as _;
use remote_core::intent::{
    CommandExit, CommandSpec, Dropped, ExitTier, IntentServed, ServedAnswer, Truncation, Unanswered,
};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use vnc_core::{ClientCommand, QualityPreset};

/// The control lane: one JSON-RPC 2.0 message, UTF-8, per envelope.
pub const MSG_JSONRPC: u8 = 0;

/// Envelope length, in bytes.
pub const HEADER: usize = 8;

/// The largest payload this build will read.
///
/// A cap rather than a trust: the peer is a local process the user started,
/// but a bug in it must not be able to make the application allocate until it
/// dies. Eight megabytes is far above any control message and far below
/// anything that would hurt.
pub const MAX_PAYLOAD: u32 = 8 * 1024 * 1024;

/// Wrap a payload in its envelope.
pub fn encode(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.push(msg_type);
    // `flags` is reserved: sent as zero, ignored on receipt. It exists so a
    // compression or fragmentation scheme has somewhere to live without a
    // version bump (`04 §2.2`).
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Read one message, or `None` at a clean end of stream.
///
/// # Errors
///
/// An [`std::io::Error`] on a short read, or on a length above
/// [`MAX_PAYLOAD`].
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; HEADER];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let msg_type = header[0];
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if len > MAX_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("dvvp.v1 message of {len} bytes is above the {MAX_PAYLOAD} byte cap"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some((msg_type, payload)))
}

/// One wire command, as [`ClientCommand`].
///
/// # Errors
///
/// A sentence naming what was wrong, which the caller returns to the agent as
/// a JSON-RPC error. Never a silently dropped command: an intent that ends
/// silently makes an agent wait rather than retry (`00 R7`, `00 R28`).
pub fn decode_command(value: &Value) -> Result<ClientCommand, String> {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("a command needs a string `kind`")?;
    match kind {
        "pointer" => Ok(ClientCommand::Pointer {
            x: number(value, "x")?,
            y: number(value, "y")?,
            button_mask: number(value, "buttonMask")?,
        }),
        "key" => Ok(ClientCommand::Key {
            keysym: number(value, "keysym")?,
            keycode: match value.get("keycode") {
                Some(Value::Null) | None => None,
                Some(_) => Some(number(value, "keycode")?),
            },
            down: flag(value, "down")?,
        }),
        "release-all-keys" => Ok(ClientCommand::ReleaseAllKeys),
        "clipboard-text" => Ok(ClientCommand::ClipboardText(
            text(value, "text")?.to_string(),
        )),
        "clipboard-request" => Ok(ClientCommand::ClipboardRequest {
            formats: number(value, "formats")?,
        }),
        "set-quality" => Ok(ClientCommand::SetQuality(quality(text(value, "preset")?)?)),
        "request-resize" => Ok(ClientCommand::RequestResize {
            width: number(value, "width")?,
            height: number(value, "height")?,
        }),
        "refresh" => Ok(ClientCommand::Refresh),
        "set-always-refresh" => Ok(ClientCommand::SetAlwaysRefresh(flag(value, "on")?)),
        "set-view-only" => Ok(ClientCommand::SetViewOnly(flag(value, "on")?)),
        "set-prefer-scancodes" => Ok(ClientCommand::SetPreferScancodes(flag(value, "on")?)),
        "terminal-input" => Ok(ClientCommand::TerminalInput(bytes::Bytes::from(byte_array(
            value, "bytes",
        )?))),
        "resize-terminal" => Ok(ClientCommand::ResizeTerminal {
            cols: number(value, "cols")?,
            rows: number(value, "rows")?,
        }),
        // The two that are absent by design, named rather than lumped into the
        // catch all, because "this build does not know that command" and "this
        // surface will never carry that command" are different claims and an
        // agent should stop asking for the second.
        "provide-credentials" | "trust-certificate" | "cancel-credentials" => Err(format!(
            "{kind} is not carried on dvvp.v1 and never will be: answering a credential or a certificate prompt is a PERSON's act, in DeskVNCViewer, and the way to keep a secret away from an agent is not having the message"
        )),
        other => Err(format!(
            "this build does not know the command `{other}`; it is refused rather than ignored, because a command that ends silently makes an agent wait instead of retrying"
        )),
    }
}

/// The largest command output this lane carries back, per stream.
///
/// The envelope caps a payload at [`MAX_PAYLOAD`] and base64 costs a third, so
/// two streams at this size plus the object around them still fit with room to
/// spare. It is a CAP and never a silent trim: a driver that hit its own
/// `max_output_bytes` reports the drop in `dropped`, and a caller that asks for
/// more than this is given this number in the reply rather than being quietly
/// served less than it asked for (`00 R24`).
pub const MAX_EXEC_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;

/// The fields that name a secret, refused by name on every exec and open.
///
/// D7 and `09 §4`. The way to keep a credential away from an agent is not a
/// capability check, it is refusing the field, and refusing it BY NAME rather
/// than ignoring it, because an agent whose password field was ignored will
/// conclude the password was used and report a machine as reachable that is
/// not.
pub const NEVER_FROM_AN_AGENT: &[&str] = &[
    "password",
    "passphrase",
    "username",
    "user",
    "domain",
    "privateKey",
    "private_key",
    "credential",
    "credentials",
    "secret",
    "keyPath",
];

/// Refuse any field that would carry a secret across this socket.
///
/// # Errors
///
/// A sentence naming the field, which the caller returns to the agent. It
/// never quotes the value: a refusal that echoes the password back has copied
/// the secret into a log line and into a model's context, which is the thing
/// the refusal exists to prevent.
pub fn refuse_credentials(params: &Value) -> Result<(), String> {
    for field in NEVER_FROM_AN_AGENT {
        if params.get(field).is_some() {
            return Err(format!(
                "`{field}` is not carried on dvvp.v1 and never will be: an agent names a saved machine and DeskVNCViewer resolves the secret from the keychain, exactly as it does for a person clicking the machine in the library (00 R19, 09 §4). Nothing was opened and nothing was run"
            ));
        }
    }
    Ok(())
}

/// One `limb.exec` request, as [`CommandSpec`].
///
/// `05 §4.1`'s five requirements are all here and `timeoutMs` is the one with
/// no default: a command with no timeout on a machine an agent cannot see is a
/// hang nobody notices, and defaulting one would be this file choosing how long
/// somebody else's build should block.
///
/// # Errors
///
/// A sentence naming what was wrong. Never a silently corrected value: a
/// command run with a timeout the caller did not choose is a command the
/// caller cannot reason about.
pub fn decode_exec(params: &Value) -> Result<CommandSpec, String> {
    refuse_credentials(params)?;
    let command = text(params, "command")?;
    if command.trim().is_empty() {
        return Err("`command` is empty; there is nothing to run".to_string());
    }
    let timeout_ms = params
        .get("timeoutMs")
        .and_then(Value::as_u64)
        .ok_or("`timeoutMs` is required and has no default: a command with no timeout on a machine an agent cannot see is a hang nobody notices (05 §4.1)")?;
    if timeout_ms == 0 {
        return Err("`timeoutMs` of 0 would end the command before it started".to_string());
    }
    let cwd = match params.get("cwd") {
        Some(Value::Null) | None => None,
        Some(_) => Some(text(params, "cwd")?.to_string()),
    };
    let env = match params.get("env") {
        Some(Value::Null) | None => Vec::new(),
        Some(Value::Array(pairs)) => pairs
            .iter()
            .map(|pair| match pair.as_array().map(Vec::as_slice) {
                Some([Value::String(name), Value::String(value)]) => {
                    Ok((name.clone(), value.clone()))
                }
                _ => Err("`env` is an array of [name, value] string pairs".to_string()),
            })
            .collect::<Result<Vec<_>, String>>()?,
        Some(_) => return Err("`env` is an array of [name, value] string pairs".to_string()),
    };
    // Base64 rather than the byte array `terminal-input` uses, and the reason
    // is size: a keystroke is a handful of bytes and four characters each is
    // nothing, while a here document piped into a command is not, and this
    // side already links base64 for the image lane.
    let stdin = match params.get("stdinBase64") {
        Some(Value::Null) | None => None,
        Some(_) => Some(bytes::Bytes::from(
            base64::engine::general_purpose::STANDARD
                .decode(text(params, "stdinBase64")?)
                .map_err(|e| format!("`stdinBase64` is not base64: {e}"))?,
        )),
    };
    Ok(CommandSpec {
        command: command.to_string(),
        cwd,
        env,
        timeout: std::time::Duration::from_millis(timeout_ms),
        stdin,
        // Clamped rather than honoured without question, and the number is
        // reported back in `dropped.cap` so a caller that asked for more is
        // TOLD what it got instead of discovering it by counting bytes.
        max_output_bytes: Some(
            params
                .get("maxOutputBytes")
                .and_then(Value::as_u64)
                .unwrap_or(MAX_EXEC_OUTPUT_BYTES)
                .clamp(1, MAX_EXEC_OUTPUT_BYTES),
        ),
    })
}

/// A driver's served answer, as this socket spells it.
///
/// Every one of `05 §4.1`'s five is here: stdout, stderr, an exit status with
/// its provenance, a duration and a truncation record. None of them is
/// optional and none is inferred from another, which is `05 §3`'s rule that
/// the plane never invents a status made concrete on a wire.
pub fn served_json(served: &IntentServed) -> Value {
    match &served.answer {
        ServedAnswer::Ran(run) => json!({
            "served": true,
            // Computed from the status rather than set to false, because a
            // driver whose own deadline passed served the intent and hit the
            // deadline, and both halves are true. This is the case `00 R7`
            // cares most about: the output that DID arrive is here, beside a
            // status that says there is no exit code and why.
            "timedOut": run.status.unanswered == Some(Unanswered::Deadline),
            "status": exit_json(&run.status),
            "stdoutBase64": encode_output(&run.stdout),
            "stderrBase64": encode_output(&run.stderr),
            "stdoutBytes": run.stdout.len(),
            "stderrBytes": run.stderr.len(),
            "durationMs": run.duration.as_millis().min(u128::from(u64::MAX)) as u64,
            "dropped": truncation_json(&run.dropped),
        }),
        // `ServedAnswer` is `#[non_exhaustive]`. An answer shape a later build
        // adds is reported as unknown rather than flattened onto `Ran`,
        // because a caller told a `declare` was a command run would read an
        // exit status that nothing measured.
        _ => json!({
            "served": true,
            "timedOut": false,
            "unknownAnswerShape": true,
            "why": "the driver answered with a shape this build of the dvvp.v1 plane cannot describe; it is reported as unknown rather than described as a command run, because an invented exit status is worse than a missing one (05 §3)",
        }),
    }
}

/// The answer to an exec this socket stopped waiting for.
///
/// **A timeout, never a success and never a silence** (`00 R7`, `05 §3`). The
/// status carries no code and no signal and says `deadline` instead, and the
/// output fields are present and empty rather than absent, so a caller reads
/// "nothing arrived" as a fact it was told rather than as a field it forgot to
/// look at. The tier is `exec` because that is the tier that was RUNNING, which
/// is a different claim from the tier having answered.
pub fn timed_out_json(waited: std::time::Duration) -> Value {
    json!({
        "served": false,
        "timedOut": true,
        "status": {
            "code": Value::Null,
            "signal": Value::Null,
            "source": tier_name(ExitTier::Exec),
            "unanswered": "deadline",
            "why": Unanswered::Deadline.as_str(),
        },
        "stdoutBase64": "",
        "stderrBase64": "",
        "stdoutBytes": 0,
        "stderrBytes": 0,
        "durationMs": waited.as_millis().min(u128::from(u64::MAX)) as u64,
        "dropped": truncation_json(&Truncation::default()),
    })
}

fn encode_output(bytes: &bytes::Bytes) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn exit_json(exit: &CommandExit) -> Value {
    json!({
        "code": exit.code,
        // Never coerced into `code`. `128 + signum` is a shell's convention for
        // squeezing a signal through a byte wide status, and this answer is
        // neither a byte nor a shell's (RFC 4254 §6.10).
        "signal": exit.signal,
        "source": tier_name(exit.source),
        "unanswered": exit.unanswered.map(unanswered_name),
        "why": exit.unanswered.map(Unanswered::as_str),
    })
}

fn truncation_json(dropped: &Truncation) -> Value {
    let stream = |d: Dropped| json!({ "bytes": d.bytes, "lines": d.lines });
    json!({
        "cap": dropped.cap,
        "stdout": stream(dropped.stdout),
        "stderr": stream(dropped.stderr),
        "any": dropped.any(),
    })
}

/// Which tier produced a status, by the name the far side parses back.
///
/// `ExitTier` is `#[non_exhaustive]`, so the wildcard is not optional. It
/// answers `unknown` rather than picking the nearest name, and the far side
/// refuses an `unknown` rather than guessing: `exec` is the exact tier and a
/// sentinel is a reported one, and a client told the second was the first would
/// trust a number it should have questioned (`05 §3`).
pub fn tier_name(tier: ExitTier) -> &'static str {
    match tier {
        ExitTier::Exec => "exec",
        ExitTier::Osc133 => "osc133",
        ExitTier::Sentinel => "sentinel",
        ExitTier::Helper => "helper",
        _ => "unknown",
    }
}

/// Why a run came back with no number, by the name the far side parses back.
pub fn unanswered_name(why: Unanswered) -> &'static str {
    match why {
        Unanswered::Deadline => "deadline",
        Unanswered::LinkLost => "link-lost",
        Unanswered::Tier => "tier",
        // `Unanswered` is `#[non_exhaustive]` for the same reason and gets the
        // same treatment: an unknown reason is named as unknown, not mapped
        // onto the nearest one, because "the link went" and "the tier cannot
        // say" lead an agent to do different things.
        _ => "unknown",
    }
}

fn number<T: TryFrom<u64>>(value: &Value, field: &str) -> Result<T, String> {
    let raw = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("`{field}` is required and must be a non negative integer"))?;
    T::try_from(raw).map_err(|_| format!("`{field}` of {raw} is out of range for this field"))
}

fn flag(value: &Value, field: &str) -> Result<bool, String> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("`{field}` is required and must be a boolean"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{field}` is required and must be a string"))
}

/// Terminal input, as an array of byte values.
///
/// An array rather than base64 because neither side of this socket carries a
/// base64 dependency and `00 R40`'s constraints apply to every dependency. It
/// costs about four characters per byte, which is real and which is bounded by
/// what a terminal input actually is: a keystroke, a short line, a paste an
/// agent composed. A megabyte paste belongs on `msg_type` 3, which is the
/// binary lane and is not built yet.
fn byte_array(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    let array = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("`{field}` is required and must be an array of byte values"))?;
    array
        .iter()
        .map(|v| {
            v.as_u64()
                .filter(|n| *n <= u64::from(u8::MAX))
                .map(|n| n as u8)
                .ok_or_else(|| format!("`{field}` must hold only values from 0 to 255"))
        })
        .collect()
}

/// One word for a command, for a log line and for the `03 §3.4` order this
/// surface reports having sent.
///
/// An exhaustive match with no wildcard for the reason the module comment
/// gives: `ClientCommand` does not derive `Serialize` precisely so that a new
/// variant is a decision somebody has to make, and a `_ =>` here would throw
/// that away at the boundary where it matters.
pub fn command_name(command: &ClientCommand) -> &'static str {
    match command {
        ClientCommand::Pointer { .. } => "pointer",
        ClientCommand::Key { .. } => "key",
        ClientCommand::ReleaseAllKeys => "release-all-keys",
        ClientCommand::ClipboardText(_) => "clipboard-text",
        ClientCommand::ClipboardRequest { .. } => "clipboard-request",
        ClientCommand::SetQuality(_) => "set-quality",
        ClientCommand::RequestResize { .. } => "request-resize",
        ClientCommand::Refresh => "refresh",
        ClientCommand::SetAlwaysRefresh(_) => "set-always-refresh",
        ClientCommand::SetViewOnly(_) => "set-view-only",
        ClientCommand::SetPreferScancodes(_) => "set-prefer-scancodes",
        ClientCommand::TerminalInput(_) => "terminal-input",
        ClientCommand::ResizeTerminal { .. } => "resize-terminal",
        ClientCommand::ProvideCredentials { .. } => "provide-credentials",
        ClientCommand::CancelCredentials => "cancel-credentials",
        ClientCommand::TrustCertificate { .. } => "trust-certificate",
        ClientCommand::ReconnectNow => "reconnect-now",
        ClientCommand::Disconnect => "disconnect",
        ClientCommand::Agent(_) => "agent-intent",
    }
}

/// A quality preset by the same spelling the profile column uses.
///
/// The strings are `commands::session::parse_quality`'s, deliberately, so the
/// agent surface and the host library cannot disagree about what "medium"
/// means. Unlike that function this one REFUSES an unknown value rather than
/// falling back to Auto: a person's mistyped profile should still connect, and
/// an agent's mistyped argument should be told.
pub fn quality(preset: &str) -> Result<QualityPreset, String> {
    match preset {
        "auto" => Ok(QualityPreset::Auto),
        "high" => Ok(QualityPreset::High),
        "medium" => Ok(QualityPreset::Medium),
        "low" => Ok(QualityPreset::Low),
        "bw" | "black-and-white" => Ok(QualityPreset::BlackAndWhite),
        other => Err(format!(
            "`{other}` is not a quality preset; the presets are auto, high, medium, low and bw"
        )),
    }
}

/// The other direction, so `limb.detach` can name the preset it put back.
///
/// The inverse of [`quality`] and asserted to be, because a preset reported
/// under a name the same wire will not parse is worse than reporting nothing:
/// a client that echoes it back gets a refusal for a value we gave it.
pub fn quality_name(preset: QualityPreset) -> &'static str {
    match preset {
        QualityPreset::Auto => "auto",
        QualityPreset::High => "high",
        QualityPreset::Medium => "medium",
        QualityPreset::Low => "low",
        QualityPreset::BlackAndWhite => "bw",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_is_eight_little_endian_bytes_and_then_the_payload() {
        let framed = encode(MSG_JSONRPC, b"{}");
        assert_eq!(framed[0], MSG_JSONRPC);
        assert_eq!(framed[1], 0, "flags are reserved and sent as zero");
        assert_eq!(&framed[2..4], &[0, 0], "reserved is zero");
        assert_eq!(&framed[4..8], &2u32.to_le_bytes());
        assert_eq!(&framed[8..], b"{}");
    }

    #[tokio::test]
    async fn a_message_reads_back_exactly_as_it_was_written() {
        let mut framed = encode(MSG_JSONRPC, b"hello").as_slice().to_vec();
        framed.extend_from_slice(&encode(9, b"a lane this build does not know"));
        let mut cursor = std::io::Cursor::new(framed);

        let (kind, payload) = read_message(&mut cursor).await.unwrap().unwrap();
        assert_eq!(kind, MSG_JSONRPC);
        assert_eq!(payload, b"hello");

        // An unknown msg_type still frames correctly, which is what lets the
        // caller ignore it rather than losing sync with the stream.
        let (kind, _) = read_message(&mut cursor).await.unwrap().unwrap();
        assert_eq!(kind, 9);

        assert!(read_message(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_oversized_length_is_refused_before_anything_is_allocated() {
        let mut header = vec![MSG_JSONRPC, 0, 0, 0];
        header.extend_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        let mut cursor = std::io::Cursor::new(header);
        assert!(read_message(&mut cursor).await.is_err());
    }

    #[test]
    fn a_pointer_and_a_key_decode_to_the_commands_a_session_takes() {
        let pointer = decode_command(
            &serde_json::json!({ "kind": "pointer", "x": 10, "y": 20, "buttonMask": 1 }),
        )
        .unwrap();
        assert!(matches!(
            pointer,
            ClientCommand::Pointer {
                x: 10,
                y: 20,
                button_mask: 1
            }
        ));

        let key = decode_command(
            &serde_json::json!({ "kind": "key", "keysym": 97, "keycode": null, "down": true }),
        )
        .unwrap();
        assert!(matches!(
            key,
            ClientCommand::Key {
                keysym: 97,
                keycode: None,
                down: true
            }
        ));
    }

    #[test]
    fn terminal_input_survives_bytes_that_are_not_text() {
        let command =
            decode_command(&serde_json::json!({ "kind": "terminal-input", "bytes": [0, 255, 3] }))
                .unwrap();
        match command {
            ClientCommand::TerminalInput(bytes) => assert_eq!(&bytes[..], &[0u8, 255, 3]),
            other => panic!("expected terminal input, got {other:?}"),
        }
    }

    /// D7 in one test. There is no way to put a password on this socket, and
    /// the refusal says so rather than saying "unknown method", because an
    /// agent told the second will look for another spelling.
    #[test]
    fn a_credential_can_never_cross_this_socket() {
        let refused = decode_command(&serde_json::json!({
            "kind": "provide-credentials", "password": "hunter2"
        }))
        .expect_err("credentials are not carried here");
        assert!(refused.contains("never will be"), "{refused}");
        assert!(!refused.contains("hunter2"), "{refused}");
    }

    #[test]
    fn an_unknown_command_is_an_error_rather_than_a_shrug() {
        let refused = decode_command(&serde_json::json!({ "kind": "teleport" })).unwrap_err();
        assert!(refused.contains("teleport"), "{refused}");
    }

    /// A preset reported under a name this same wire will not parse is worse
    /// than reporting nothing: a client that echoes it back gets a refusal for
    /// a value we handed it.
    #[test]
    fn every_preset_name_parses_back_to_the_preset_it_named() {
        for preset in [
            QualityPreset::Auto,
            QualityPreset::High,
            QualityPreset::Medium,
            QualityPreset::Low,
            QualityPreset::BlackAndWhite,
        ] {
            assert_eq!(quality(quality_name(preset)), Ok(preset));
        }
    }

    #[test]
    fn an_out_of_range_coordinate_is_refused_rather_than_truncated() {
        let refused = decode_command(
            &serde_json::json!({ "kind": "pointer", "x": 70000, "y": 0, "buttonMask": 0 }),
        )
        .unwrap_err();
        assert!(refused.contains("out of range"), "{refused}");
    }
}
