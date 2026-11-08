//! A screen read that waits for a mirror still filling.
//!
//! A new mirror waits for one full refresh of the screen. On a 4K Mac over a
//! slow link that took 10.9 s, and dvv reconnected the session at six
//! seconds, throwing away the refresh that was arriving.

mod common;

use common::{error_code, Client};
use dvv::fake::{FakeHost, FakeSource};
use dvv::plane::{Nudge, Plane, SessionSource};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn a_slow_refresh_is_waited_for_rather_than_reconnected_over() {
    let source = Arc::new(FakeSource::new(vec![FakeHost::desktop(
        "h_mac", "10.0.0.9",
    )]));
    let plane = Arc::new(
        Plane::local(source.clone() as Arc<dyn SessionSource>)
            .expect("a grant over the machines the source publishes"),
    );
    let mut client = Client::connect(plane.clone());
    let opened = client
        .tool("dvv_open", json!({ "hostId": "h_mac", "perceive": true }))
        .await;
    assert_eq!(error_code(&opened), None, "{opened}");
    let limb = plane.limbs()[0].limb_id.clone();
    source
        .mirror(&limb)
        .expect("a mirror was asked for")
        .priming_for(Duration::from_millis(7500));

    let screen = client.tool("dvv_screen", json!({ "limbId": limb })).await;
    assert_eq!(error_code(&screen), None, "{screen}");
    let reconnects = source
        .nudges()
        .into_iter()
        .filter(|(_, n)| *n == Nudge::Reconnect)
        .count();
    assert_eq!(
        reconnects, 0,
        "reconnected over a refresh that was arriving"
    );
}
