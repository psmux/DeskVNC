//! The cap on attached limbs, and what counts against it.
//!
//! A limb `dvv_limbs` lists as available is attached the moment a call names
//! it, so an agent that read the status of the sessions a person had open, to
//! learn which window was which, had used up its four limbs on them and could
//! not open the machine it was asked to work on. The refusal said to raise a
//! setting the agent cannot reach.

mod common;

use common::{error_code, structured, Client};
use dvv::fake::{FakeHost, FakeSource};
use dvv::plane::{OpenRequest, Plane, SessionSource};
use serde_json::json;
use std::sync::Arc;

/// Five desktops, one more than an agent may drive at once, all on one
/// address the way five VNC servers on different ports of one box are. An
/// address is not a machine, and telling them apart by it is a bug this
/// shape catches.
fn five_machines() -> (Arc<FakeSource>, Arc<Plane>) {
    let source = Arc::new(FakeSource::new(
        (1..=5)
            .map(|n| FakeHost::desktop(&format!("h_lab0{n}"), "10.0.0.5"))
            .collect(),
    ));
    let plane = Plane::local(source.clone() as Arc<dyn SessionSource>)
        .expect("a grant over the machines the source publishes");
    (source, Arc::new(plane))
}

#[tokio::test]
async fn limbs_only_looked_at_do_not_keep_an_agent_from_opening_the_one_it_needs() {
    let (source, plane) = five_machines();
    let theirs: Vec<String> = (1..=4)
        .map(|n| source.open_in_app(&format!("h_lab0{n}")))
        .collect();
    let mut client = Client::connect(plane.clone());

    client.tool("dvv_limbs", json!({})).await;
    for limb in &theirs {
        let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
        assert_eq!(error_code(&status), None, "{status}");
    }
    assert_eq!(
        plane.limbs().len(),
        4,
        "naming an available limb attaches it"
    );

    let opened = client
        .tool("dvv_open", json!({ "hostId": "h_lab05" }))
        .await;
    assert_eq!(error_code(&opened), None, "{opened}");
    assert_eq!(plane.limbs().len(), 4);

    // The one let go was only detached: the person's session is still open,
    // and naming it again attaches it again.
    assert!(source.closed_sessions().is_empty());
    let back = client
        .tool("dvv_status", json!({ "limbId": theirs[0] }))
        .await;
    assert_eq!(error_code(&back), None, "{back}");
}

#[tokio::test]
async fn a_full_cap_of_limbs_the_agent_opened_says_how_to_free_one() {
    let (source, plane) = five_machines();
    for n in 1..=4 {
        plane
            .open(&OpenRequest {
                host_id: Some(format!("h_lab0{n}")),
                ..OpenRequest::default()
            })
            .expect("room for four");
    }
    let mut client = Client::connect(plane.clone());

    let refused = client
        .tool("dvv_open", json!({ "hostId": "h_lab05" }))
        .await;
    assert_eq!(error_code(&refused), Some("TOO_MANY_LIMBS"), "{refused}");
    let message = structured(&refused)["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("dvv_close") && message.contains("only detaches"),
        "{message}"
    );
    assert!(
        !message.contains("max_driven_limbs"),
        "an agent cannot raise a setting, so the refusal must not tell it to: {message}"
    );
    // Refused before anything was dialled.
    assert!(
        source
            .live()
            .iter()
            .all(|s| s.host_id.as_deref() != Some("h_lab05")),
        "the fifth machine was opened although it could not be attached"
    );
}
