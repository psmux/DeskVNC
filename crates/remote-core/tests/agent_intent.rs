//! The intent vocabulary now that it lives beside the commands, and the two
//! failures a non blocking send can have.
//!
//! `PRDAgentPlug/00 R28` and `00 R49a`.

use remote_core::commands::ClientCommand;
use remote_core::driver::{ProtocolKind, SessionGone, SessionHandle, TrySendFailed};
use remote_core::intent::{AgentIntent, IntentId, IntentKind, IntentName, IntentSequence, PartyId};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn intent(id: u64, kind: IntentKind) -> AgentIntent {
    AgentIntent {
        id: IntentId(id),
        grant: PartyId::from("att_test"),
        deadline: Some(Duration::from_secs(5)),
        fence: None,
        kind,
    }
}

fn exec(id: u64) -> AgentIntent {
    intent(
        id,
        IntentKind::Exec {
            spec: remote_core::intent::CommandSpec {
                command: "uname -a".into(),
                cwd: None,
                env: Vec::new(),
                timeout: Duration::from_secs(5),
                stdin: None,
                max_output_bytes: None,
            },
        },
    )
}

fn handle(commands: mpsc::Sender<ClientCommand>) -> SessionHandle {
    SessionHandle {
        id: "s1".into(),
        kind: ProtocolKind::Ssh,
        commands,
        cancel: CancellationToken::new(),
    }
}

/// The whole point of the move. `ClientCommand::Agent(AgentIntent)` could not
/// be written while the vocabulary sat in `limb-core`, because `limb-core`
/// depends on `remote-core` and the reverse would be a cycle (`00 R47a`). If
/// this file compiles at all, the cycle is gone.
#[test]
fn an_intent_goes_into_a_client_command() {
    let cmd = ClientCommand::Agent(exec(1));
    match cmd {
        ClientCommand::Agent(carried) => {
            assert_eq!(carried.id, IntentId(1));
            assert_eq!(carried.kind.name(), IntentName::Exec);
        }
        other => panic!("expected the agent variant, got {other:?}"),
    }
}

/// A refusal carries the id the agent is blocked on and the name a log line
/// needs, so neither reader has to hold the plane's in flight table.
#[test]
fn a_refusal_names_the_intent_and_the_reason() {
    let refusal = exec(41).refuse("no command channel in this build");
    assert_eq!(refusal.id, IntentId(41));
    assert_eq!(refusal.name, IntentName::Exec);
    let line = refusal.to_string();
    assert!(line.contains("41"), "{line}");
    assert!(line.contains("exec"), "{line}");
    assert!(line.contains("no command channel"), "{line}");
}

/// `00 R49a`. A full queue and a closed one used to be one `SessionGone`, and
/// `08 §4.3` gives them opposite repairs: full means shed or wait and say how
/// much was lost, closed means the limb is gone and every outstanding intent
/// settles as `LinkLost`. Treating a stalled session as a dead one abandons
/// work that would have gone through a moment later.
#[tokio::test]
async fn a_full_queue_and_a_closed_one_are_different_answers() {
    let (tx, mut rx) = mpsc::channel(1);
    let handle = handle(tx);

    // One slot, filled.
    handle
        .try_send(ClientCommand::Agent(exec(1)))
        .expect("room");
    assert_eq!(
        handle.try_send(ClientCommand::Agent(exec(2))),
        Err(TrySendFailed::Full),
        "a queue at its bound is not a session that has gone away"
    );

    // The receiver is still there and the first command is still in it, which
    // is exactly why `Full` had to be recoverable.
    assert!(matches!(rx.recv().await, Some(ClientCommand::Agent(_))));

    drop(rx);
    assert_eq!(
        handle.try_send(ClientCommand::Agent(exec(3))),
        Err(TrySendFailed::Gone)
    );
}

/// The two are not just different values, they answer different questions.
#[test]
fn only_one_of_the_two_means_the_limb_is_finished() {
    assert!(!TrySendFailed::Full.is_gone());
    assert!(TrySendFailed::Gone.is_gone());
    // The conversion exists so a caller whose error type is already
    // `SessionGone` keeps its plain `?` rather than churning every call site.
    assert_eq!(SessionGone::from(TrySendFailed::Gone), SessionGone);
    assert_eq!(SessionGone::from(TrySendFailed::Full), SessionGone);
}

/// Nothing about the vocabulary changed in the move, so the properties the
/// old home asserted still hold at the new one.
#[test]
fn the_vocabulary_survived_the_move_intact() {
    assert_eq!(IntentName::ALL.len(), 18);
    let mut seq = IntentSequence::new();
    assert_eq!(seq.mint(), IntentId(1));
    assert_eq!(seq.mint(), IntentId(2));
    // The named key table came with it, because `Press` holds `&'static
    // NamedKey` and could not travel alone.
    let escape = remote_core::keys::NamedKey::lookup("Escape").expect("in the table");
    assert_eq!(escape.keysym, 0xff1b);
    let press = intent(7, IntentKind::Press { keys: vec![escape] });
    assert_eq!(press.kind.name(), IntentName::Press);
    assert!(press.kind.needs_control_lease());
    assert!(!press.kind.is_grounded());
}
