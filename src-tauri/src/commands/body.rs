//! Binary command bodies in every shape Tauri can hand them over.
//!
//! The webview normally posts an `ArrayBuffer` argument over the `ipc://`
//! custom protocol and it arrives as `InvokeBody::Raw`. When a webview blocks
//! that protocol (a CSP error, a WebView2 policy), Tauri falls back to
//! `window.ipc.postMessage` with a JSON payload, and the replacer in tauri
//! 2.12.5 `scripts/process-ipc-message-fn.js` turns the `ArrayBuffer` into
//! `Array.from(new Uint8Array(val))`. `handle_ipc_message` in
//! `src/ipc/protocol.rs` wraps that as `InvokeBody::Json`, a JSON array of
//! numbers. A base64 string is accepted too, the form Tauri's docs suggest
//! for large bodies over JSON.

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
        let got = bytes(&body, "send_input").unwrap();
        assert!(matches!(got, Cow::Borrowed(_)));
        assert_eq!(&*got, &[0, 1, 0, 1, 0, 0, 0]);
    }

    /// What the postMessage fallback delivers for an `ArrayBuffer`.
    #[test]
    fn json_number_array_is_accepted() {
        let value: Value = serde_json::from_str("[0,1,0,1,0,0,0]").unwrap();
        let body = InvokeBody::from(value);
        assert_eq!(
            &*bytes(&body, "send_input").unwrap(),
            &[0, 1, 0, 1, 0, 0, 0]
        );
    }

    #[test]
    fn base64_string_is_accepted() {
        let body = InvokeBody::Json(json!("AAEAAQAAAA=="));
        assert_eq!(
            &*bytes(&body, "capture_thumbnail").unwrap(),
            &[0, 1, 0, 1, 0, 0, 0]
        );
    }

    #[test]
    fn bad_bodies_are_rejected_with_the_command_name() {
        for bad in [
            json!([0, 256]),
            json!([-1]),
            json!([1.5]),
            json!(["1"]),
            json!(null),
            json!({ "0": 1 }),
            json!("not base64!"),
        ] {
            let err = bytes(&InvokeBody::Json(bad), "send_input").unwrap_err();
            assert!(err.starts_with("send_input expects a binary body"), "{err}");
        }
    }
}
