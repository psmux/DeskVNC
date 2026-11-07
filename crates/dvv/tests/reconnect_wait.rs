//! Waiting for a limb to come back after a reconnect.
//!
//! `dvv_reconnect`, and `dvv_screen` when a mirror will not fill, wait for
//! the limb to report connected again. The limb's copy of its state is
//! refreshed only when something asks the source, and the wait used to read
//! that copy for its whole timeout, so a session that was back in a second
//! was reported, 15 s later, as whatever it had been when the wait began.

use dvv::fake::{FakeHost, FakeSource};
use dvv::plane::{OpenRequest, Plane, Selector, SessionSource};
use remote_core::state::SessionState;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test]
async fn a_reconnect_is_seen_as_soon_as_the_session_is_back() {
    let source = Arc::new(FakeSource::new(vec![FakeHost::desktop(
        "h_mac", "10.0.0.9",
    )]));
    let plane = Plane::local(source.clone() as Arc<dyn SessionSource>)
        .expect("a grant over the machines the source publishes");
    let card = plane
        .open(&OpenRequest {
            host_id: Some("h_mac".to_string()),
            ..OpenRequest::default()
        })
        .expect("the machine opens");
    let limb = plane
        .resolve(&Selector {
            limb_id: Some(card.limb_id.clone()),
            ..Selector::default()
        })
        .expect("the limb just opened");

    // The session drops; the plane's copy says so.
    source.set_state(
        &card.limb_id,
        SessionState::Reconnecting {
            attempt: 1,
            next_retry_ms: 200,
            reason: "a drop".into(),
        },
    );
    plane.refresh(&limb);
    let back = source.clone();
    let id = card.limb_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(700)).await;
        back.set_state(&id, SessionState::Connected);
    });

    let started = Instant::now();
    let connected = plane.until_connected(&limb, Duration::from_secs(6)).await;
    let took = started.elapsed();
    assert!(connected);
    assert!(
        took < Duration::from_secs(2),
        "took {took:?} to see the session back"
    );
}
