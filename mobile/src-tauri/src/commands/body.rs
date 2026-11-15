//! Binary command bodies in every shape Tauri can hand them over.
//!
//! On iOS the webview posts an `ArrayBuffer` argument over the `ipc://`
//! custom protocol and it arrives as `InvokeBody::Raw`. Android's webview
//! cannot read a request body there, so Tauri never uses the custom protocol
//! on Android (`canUseCustomProtocol = osName !== 'android'` in tauri 2.12.5
//! `scripts/ipc-protocol.js`). The call goes through `window.ipc.postMessage`
//! as JSON instead, and the replacer in `scripts/process-ipc-message-fn.js`
//! turns the `ArrayBuffer` or `Uint8Array` into
//! `Array.from(new Uint8Array(val))`. `handle_ipc_message` in
//! `src/ipc/protocol.rs` then wraps the parsed payload as `InvokeBody::Json`,
//! so the body is a JSON array of numbers. iOS takes the same path if the
//! custom protocol ever fails.
//!
//! A base64 string is accepted as well. Tauri's own docs suggest it for large
//! bodies on Android, and the UI sends thumbnails that way there.

use std::borrow::Cow;

use base64::Engine as _;
use serde_json::Value;
use tauri::ipc::InvokeBody;

/// The bytes of a binary body, borrowed when the webview sent them raw.
/// `command` names the caller in the error.
pub(crate) fn bytes<'a>(body: &'a InvokeBody, command: &str) -> Result<Cow<'a, [u8]>, String> {
    match body {
        InvokeBody::Raw(raw) => Ok(Cow::Borrowed(raw.as_slice())),
        InvokeBody::Json(value) => json_bytes(value).map(Cow::Owned).ok_or_else(|| {
            format!(
                "{command} expects a binary body: raw bytes, an array of bytes or a base64 string"
            )
        }),
    }
}

fn json_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        Value::String(text) => base64::engine::general_purpose::STANDARD.decode(text).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_body_is_borrowed() {
        let body = InvokeBody::Raw(vec![0, 1, 0, 1, 0, 0, 0]);
        let got = bytes(&body, "session_input").unwrap();
        assert!(matches!(got, Cow::Borrowed(_)));
        assert_eq!(&*got, &[0, 1, 0, 1, 0, 0, 0]);
    }

    /// What Android delivers for `invoke(cmd, new Uint8Array([...]).buffer)`.
    #[test]
    fn json_number_array_is_accepted() {
        let body = InvokeBody::Json(json!([0, 1, 0, 1, 0, 0, 0]));
        assert_eq!(
            &*bytes(&body, "session_input").unwrap(),
            &[0, 1, 0, 1, 0, 0, 0]
        );
    }

    /// The payload text Android posts, parsed and wrapped the way Tauri does.
    #[test]
    fn json_array_from_posted_text_is_accepted() {
        let value: Value = serde_json::from_str("[1,1,13,255,0,0,28,0,0,0]").unwrap();
        let body = InvokeBody::from(value);
        assert_eq!(
            &*bytes(&body, "session_input").unwrap(),
            &[1, 1, 13, 255, 0, 0, 28, 0, 0, 0]
        );
    }

    #[test]
    fn empty_array_is_an_empty_body() {
        let body = InvokeBody::Json(json!([]));
        assert!(bytes(&body, "session_input").unwrap().is_empty());
    }

    #[test]
    fn base64_string_is_accepted() {
        let body = InvokeBody::Json(json!("AAEAAQAAAA=="));
        assert_eq!(
            &*bytes(&body, "session_snapshot").unwrap(),
            &[0, 1, 0, 1, 0, 0, 0]
        );
    }

    #[test]
    fn out_of_range_numbers_are_rejected() {
        for bad in [
            json!([0, 256]),
            json!([-1]),
            json!([1.5]),
            json!(["1"]),
            json!([null]),
        ] {
            assert!(bytes(&InvokeBody::Json(bad), "session_input").is_err());
        }
    }

    #[test]
    fn other_json_shapes_are_rejected_with_the_command_name() {
        for bad in [
            json!(null),
            json!({ "0": 1 }),
            json!(7),
            json!("not base64!"),
        ] {
            let err = bytes(&InvokeBody::Json(bad), "session_input").unwrap_err();
            assert!(
                err.starts_with("session_input expects a binary body"),
                "{err}"
            );
        }
    }
}
