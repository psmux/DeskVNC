//! A Mac desktop larger than 4K.
//!
//! A 4.5K iMac shares 4096x2304, which is more than the application's mirror
//! budget used to allow, and every verb that named it, even `dvv status`,
//! failed with BUDGET_REFUSED: naming an available limb attaches it with a
//! mirror, and a refused mirror refused the attach.

mod common;

use common::{error_code, Client};
use dvv::fake::{FakeHost, FakeSource};
use dvv::plane::{Plane, SessionSource};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn status_answers_for_a_desktop_too_large_to_mirror() {
    let mut imac = FakeHost::desktop("h_imac", "10.0.0.9");
    imac.size = (4096, 2304);
    let source = Arc::new(FakeSource::new(vec![imac]));
    // An application whose budget is smaller than this desktop.
    source.refuse_mirrors_over(8_300_000);
    let plane = Arc::new(
        Plane::local(source.clone() as Arc<dyn SessionSource>)
            .expect("a grant over the machines the source publishes"),
    );
    let limb = source.open_in_app("h_imac");
    let mut client = Client::connect(plane.clone());

    let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
    assert_eq!(error_code(&status), None, "{status}");
    assert_eq!(plane.limbs().len(), 1, "the limb is attached");

    // A screen read says why there are no pixels rather than failing on the
    // budget again.
    let screen = client
        .tool("dvv_screen", json!({ "limbId": limb, "scale": 0.5 }))
        .await;
    assert_ne!(error_code(&screen), Some("BUDGET_REFUSED"), "{screen}");
}
