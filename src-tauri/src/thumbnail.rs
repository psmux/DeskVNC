//! Library-thumbnail capture policy (PRD/03 §3.1).
//!
//! The pixels themselves come from the session window's renderer and are
//! downscaled + PNG-encoded by `vnc_store::save_thumbnail`; what lives here is
//! the *policy* around that: which captures are allowed to reach the store, and
//! how the rest of the app hears that a tile image changed.

use std::time::{Duration, Instant};

/// Broadcast after a thumbnail file is written, so every window showing the
/// Library can drop its cached blob URL and re-read the PNG without a restart.
///
/// Payload: `{ "hostId": string, "capturedAt": number /* unix seconds */ }`.
pub const THUMBNAIL_EVENT: &str = "library://thumbnail";

/// Upper bound on the framebuffer geometry the webview may claim.
const MAX_DIMENSION: u32 = 16_384;

/// Minimum gap between two stored thumbnails for the same session.
///
/// A session captures twice by design, once when the desktop has settled and
/// once on the way out, so this is deliberately short. It exists to stop a
/// buggy (or hostile) webview from making us re-encode a PNG per frame, not to
/// police the two legitimate captures.
pub const MIN_CAPTURE_GAP: Duration = Duration::from_millis(500);

/// Debounce predicate: has enough time passed since the last stored capture?
pub fn should_store(last: Option<Instant>, now: Instant, min_gap: Duration) -> bool {
    match last {
        None => true,
        Some(last) => now.saturating_duration_since(last) >= min_gap,
    }
}

/// Validate the webview-supplied geometry against the body it actually sent.
///
/// Both are untrusted: the length must be exactly RGBA8888 for the claimed
/// dimensions, or the store would read past the buffer.
pub fn validate_frame(width: u32, height: u32, body_len: usize) -> Result<(), String> {
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err("invalid thumbnail dimensions".into());
    }
    let expected = width as usize * height as usize * 4;
    if body_len != expected {
        return Err("thumbnail body length does not match width*height*4".into());
    }
    Ok(())
}

/// Per-session bookkeeping for [`should_store`].
///
/// Lives on the session registry entry, so it dies with the session, a new
/// connection to the same host always gets a fresh budget.
/// Thumbnail key for a host that has not been saved to the library.
///
/// Namespaced so it can never collide with a profile UUID, and stable for a
/// given endpoint so reconnecting to the same discovered machine refreshes the
/// same image.
pub fn discovered_key(address: &str, port: u16) -> String {
    format!("discovered:{address}:{port}")
}

#[derive(Default, Debug)]
pub struct ThumbnailPolicy {
    last: Option<Instant>,
}

impl ThumbnailPolicy {
    /// Claim the right to store a thumbnail at `now`, returning the key to
    /// store it under.
    ///
    /// `None` means "silently do nothing", the capture arrived inside the
    /// debounce window.
    ///
    /// A session started from the Nearby list has no host profile, but the user
    /// still expects to recognise that machine next time they see it. Those are
    /// keyed by endpoint via [`discovered_key`] instead, so a discovered tile
    /// shows a real picture without first having to be saved.
    pub fn claim(
        &mut self,
        profile_id: Option<&str>,
        endpoint: Option<(&str, u16)>,
        now: Instant,
    ) -> Option<String> {
        let key = match (profile_id, endpoint) {
            (Some(id), _) => id.to_string(),
            (None, Some((addr, port))) => discovered_key(addr, port),
            (None, None) => return None,
        };
        if !should_store(self.last, now, MIN_CAPTURE_GAP) {
            return None;
        }
        self.last = Some(now);
        Some(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_sessions_are_keyed_by_endpoint_not_skipped() {
        // Connecting straight from the Nearby list has no profile UUID. It must
        // still capture, or the unfamiliar machine you most need to recognise
        // is the only one without a picture.
        let mut policy = ThumbnailPolicy::default();
        let now = Instant::now();
        assert_eq!(
            policy.claim(None, Some(("192.168.77.150", 5900)), now),
            Some("discovered:192.168.77.150:5900".to_string())
        );
    }

    #[test]
    fn a_saved_profile_wins_over_the_endpoint_key() {
        let mut policy = ThumbnailPolicy::default();
        let now = Instant::now();
        assert_eq!(
            policy.claim(Some("uuid-1"), Some(("10.0.0.5", 5901)), now),
            Some("uuid-1".to_string())
        );
    }

    #[test]
    fn discovered_key_is_namespaced_and_stable() {
        assert_eq!(discovered_key("10.0.0.5", 5901), "discovered:10.0.0.5:5901");
        // Never collides with a profile UUID.
        assert!(discovered_key("10.0.0.5", 5901).starts_with("discovered:"));
    }

    /// The two halves of the feature live in different crates: this module
    /// decides the key, `vnc_store` turns it into a file name. A key the store
    /// cannot write (or writes outside its cache) means a discovered tile that
    /// is blank forever, so assert the pair actually agrees, including across
    /// the restart the whole cache exists for.
    #[test]
    fn the_store_can_persist_a_discovered_key_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let key = discovered_key("192.168.77.150", 5900);
        let rgba = vec![200u8; 64 * 64 * 4];

        {
            let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).unwrap();
            store.save_thumbnail(&key, &rgba, 64, 64).unwrap();
            assert!(store.load_thumbnail(&key).unwrap().is_some());
        }

        let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).unwrap();
        let png = store
            .load_thumbnail(&key)
            .unwrap()
            .expect("the Nearby tile still has its picture after a relaunch");
        assert_eq!(&png[1..4], b"PNG");
    }

    #[test]
    fn nothing_to_key_against_still_does_nothing() {
        let mut policy = ThumbnailPolicy::default();
        assert_eq!(policy.claim(None, None, Instant::now()), None);
    }

    #[test]
    fn first_capture_always_stores() {
        assert!(should_store(None, Instant::now(), MIN_CAPTURE_GAP));
    }

    #[test]
    fn repeat_capture_inside_the_gap_is_dropped() {
        let now = Instant::now();
        let last = now - Duration::from_millis(50);
        assert!(!should_store(Some(last), now, MIN_CAPTURE_GAP));
    }

    #[test]
    fn capture_after_the_gap_stores() {
        let now = Instant::now();
        let last = now - MIN_CAPTURE_GAP - Duration::from_millis(1);
        assert!(should_store(Some(last), now, MIN_CAPTURE_GAP));
    }

    #[test]
    fn ad_hoc_sessions_never_store() {
        let mut policy = ThumbnailPolicy::default();
        let now = Instant::now();
        assert_eq!(policy.claim(None, None, now), None);
        // …and a refusal must not consume the budget for a later saved host.
        assert_eq!(
            policy.claim(Some("host-1"), None, now).as_deref(),
            Some("host-1")
        );
    }

    #[test]
    fn policy_debounces_a_frame_storm_but_allows_the_exit_capture() {
        let mut policy = ThumbnailPolicy::default();
        let t0 = Instant::now();
        // Settle capture.
        assert_eq!(policy.claim(Some("h"), None, t0).as_deref(), Some("h"));
        // A renderer looping on every frame gets nothing.
        for ms in [1, 16, 33, 120, 400] {
            assert_eq!(
                policy.claim(Some("h"), None, t0 + Duration::from_millis(ms)),
                None
            );
        }
        // The capture on the way out, seconds later, still lands.
        assert_eq!(
            policy
                .claim(Some("h"), None, t0 + Duration::from_secs(9))
                .as_deref(),
            Some("h")
        );
    }

    #[test]
    fn frame_validation_matches_the_ipc_contract() {
        assert!(validate_frame(2, 2, 16).is_ok());
        assert!(validate_frame(0, 2, 0).is_err());
        assert!(validate_frame(2, 0, 0).is_err());
        assert!(validate_frame(MAX_DIMENSION + 1, 1, 0).is_err());
        // Truncated body for the claimed geometry.
        assert!(validate_frame(2, 2, 15).is_err());
        // …and an over-long one, which would silently store the wrong pixels.
        assert!(validate_frame(2, 2, 17).is_err());
    }
}
