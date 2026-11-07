//! What a text read or a text condition is told on a terminal limb.
//!
//! A terminal limb used to be refused with "this limb has no character grid
//! ... ask the terminal limb on the same machine", while its own card said
//! its grounding was cells. That sent an agent in a circle. The refusal stays,
//! because this build's plane is not handed a terminal's output, and the
//! sentence now says what is true and which tool does answer.

mod common;

use agent_lease::LeaseInstant;
use agent_plane::PlaneConfig;
use common::{connected, intent, operator, TestLimb};
use limb_core::intent::{IntentKind, ReadForm, WaitUntil};
use limb_core::observation::Outcome;
use std::time::Duration;

fn refusal(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Refused { because, .. } => because.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_text_wait_on_a_terminal_names_the_terminal_and_dvv_run() {
    let grant = operator("att_term_text", "shell.example");
    let (_registry, limb, _rx) = connected(
        PlaneConfig::default(),
        &grant,
        "shell.example",
        TestLimb::terminal(),
        64,
    );
    let now = LeaseInstant::from_millis(1_000);
    let asked = intent(
        &limb,
        &grant,
        IntentKind::Wait {
            until: WaitUntil::Text("lab$".to_string()),
            quiet: None,
            timeout: Some(Duration::from_millis(200)),
        },
    );
    let why = refusal(&limb.dispatch(&grant, asked, now).await.outcome);
    assert!(why.contains("terminal limb"), "{why}");
    assert!(why.contains("dvv_run"), "{why}");
    assert!(!why.contains("no character grid"), "{why}");
    assert!(!why.contains("ask the terminal"), "{why}");
}

#[tokio::test]
async fn a_text_wait_on_a_desktop_does_not_send_the_agent_to_a_terminal_that_cannot_answer() {
    let grant = operator("att_desk_text", "desk.example");
    let (_registry, limb, _rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        64,
    );
    let now = LeaseInstant::from_millis(1_000);
    let asked = intent(
        &limb,
        &grant,
        IntentKind::Wait {
            until: WaitUntil::Text("Ready".to_string()),
            quiet: None,
            timeout: Some(Duration::from_millis(200)),
        },
    );
    let why = refusal(&limb.dispatch(&grant, asked, now).await.outcome);
    assert!(why.contains("desktop"), "{why}");
    assert!(why.contains("dvv_run"), "{why}");
    assert!(!why.contains("ask the terminal"), "{why}");
}

#[tokio::test]
async fn a_text_read_on_a_terminal_names_the_terminal_and_dvv_run() {
    let grant = operator("att_term_read", "shell.example");
    let (_registry, limb, _rx) = connected(
        PlaneConfig::default(),
        &grant,
        "shell.example",
        TestLimb::terminal(),
        64,
    );
    let now = LeaseInstant::from_millis(1_000);
    let asked = intent(
        &limb,
        &grant,
        IntentKind::ReadScreen {
            form: ReadForm::Text,
            region: None,
        },
    );
    let why = refusal(&limb.dispatch(&grant, asked, now).await.outcome);
    assert!(why.contains("terminal limb"), "{why}");
    assert!(why.contains("dvv_run"), "{why}");
}
