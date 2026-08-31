//! The intents the plane does not rewrite, and the answer each one gets.
//!
//! `00 R28` and `05 §4.1`. Three intents have no lowering at all, because
//! nothing in `ClientCommand` can carry them: `exec` wants a channel of its own
//! with a real exit status, `pty_run` wants a bounded run that is answered, and
//! `declare` is state a limb holds between commands. They travel whole, as
//! `ClientCommand::Agent`, and the driver either serves one or refuses it.
//!
//! The assertion that matters here is not that the command went. It is that
//! whatever the driver does next, the agent is told something. `00 R7` and
//! `00 R28` are one requirement stated twice: an intent is ANSWERED, never
//! dropped, and the failure being designed out is an agent that waits forever
//! because nothing ever came back.

mod common;

use agent_lease::LeaseInstant;
use agent_plane::PlaneConfig;
use common::{as_agent, connected, drain, exec, intent, operator, TestLimb};
use limb_core::intent::{AgentIntent, IntentKind, IntentName};
use limb_core::observation::{Outcome, Progress, RefusalCode};
use std::time::Duration;

/// The sentence `ssh-core` answers all three of these with today, shortened.
/// A test that asserted the plane's own words would prove nothing: the whole
/// point is that the DRIVER's reason is what the agent reads (`00 R50a`).
const NO_COMMAND_CHANNEL: &str =
    "this build's SSH session owns one PTY channel and no command channel, so exec, pty_run and declare cannot be served: nothing was delivered";

/// An intent with the agent's own deadline on it, which is what bounds the wait
/// for the driver's answer.
fn waiting_for(
    limb: &agent_plane::AttachedLimb,
    grant: &agent_plane::Grant,
    kind: IntentKind,
    patience: Duration,
) -> AgentIntent {
    AgentIntent {
        deadline: Some(patience),
        ..intent(limb, grant, kind)
    }
}

#[tokio::test]
async fn an_intent_the_driver_serves_itself_reaches_it_whole() {
    // The change this file exists for. This used to be `NO_NATIVE_VARIANT`, a
    // refusal, because `remote-core` had nowhere to put an agent intent. The
    // vocabulary moved down beside the commands (`00 R47a`), the variant landed
    // with it, and the intent now goes.
    let grant = operator("att_native_wire", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drain(&mut rx);

    let asked = waiting_for(
        &limb,
        &grant,
        IntentKind::Declare {
            cwd: Some("/tmp".to_string()),
            env: Vec::new(),
        },
        Duration::from_millis(20),
    );
    let id = asked.id;
    let settlement = limb.dispatch(&grant, asked, now).await;

    let sent = drain(&mut rx);
    assert_eq!(
        sent.len(),
        1,
        "one command, and it is the intent itself: {sent:?}"
    );
    let carried = as_agent(&sent[0]).expect("the intent travels as ClientCommand::Agent");
    assert_eq!(
        carried.id, id,
        "the driver is handed the id the agent is blocked on, so its answer can name it"
    );
    assert_eq!(carried.kind.name(), IntentName::Declare);
    assert_eq!(carried.grant, *grant.id(), "and who asked");
    assert_eq!(
        settlement.id, id,
        "one settlement, for the intent that was asked"
    );
    assert_eq!(settlement.gaps.commands_dropped, 0);
}

#[tokio::test]
async fn a_driver_refusal_settles_the_intent_with_the_driver_s_words() {
    // `Support::Native` is a limb's CLAIM and not a guarantee. `ssh-core` says
    // it serves `exec` and then refuses every one, because it owns one PTY
    // channel and no command channel, and typing at the prompt would give no
    // exit status, no stderr split and no output bound (`00 R50a`). The plane's
    // job is that the refusal finds the intent that is waiting for it.
    let grant = operator("att_native_refused", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drain(&mut rx);

    // Patient enough that a timeout cannot be what produced the settlement.
    let asked = waiting_for(
        &limb,
        &grant,
        IntentKind::Declare {
            cwd: None,
            env: vec![("TERM".to_string(), "xterm".to_string())],
        },
        Duration::from_secs(30),
    );
    let id = asked.id;

    // The two halves a real session has: the plane submitting on one side, and
    // the shell reading the driver's event stream on the other. There is no
    // server anywhere in this crate's tests and there must not be one.
    let (settlement, delivered) = tokio::join!(limb.dispatch(&grant, asked, now), async {
        let command = rx.recv().await.expect("the intent reaches the session");
        let carried = as_agent(&command).expect("as ClientCommand::Agent").clone();
        limb.note_refused(carried.refuse(NO_COMMAND_CHANNEL))
    });

    assert!(
        delivered,
        "the refusal found the intent that was waiting for it"
    );
    assert_eq!(settlement.id, id);
    match &settlement.outcome {
        Outcome::Refused { because, code } => {
            assert_eq!(
                because, NO_COMMAND_CHANNEL,
                "the driver's sentence, verbatim: it is the only party that knows why"
            );
            // `04 §4.3`. Not an error: an agent handed an error for something a
            // limb simply does not do will treat a working machine as a broken
            // one, and "not here" is a fact it can plan around.
            assert_eq!(*code, RefusalCode::NotSupported);
        }
        other => panic!("expected the driver's refusal, got {other:?}"),
    }
    assert!(
        settlement.refused(),
        "and it reads as a refusal rather than as a slow success"
    );
}

#[tokio::test]
async fn an_intent_nobody_answers_settles_as_a_timeout_rather_than_waiting_forever() {
    // The failure `00 R7` and `00 R28` are written against, reproduced one
    // layer up and refused there too. A driver that never speaks must not turn
    // into an agent that never returns.
    //
    // A timeout and not `Done`. `SessionEvent` can carry a driver's refusal and
    // nothing else about an intent, so silence is not evidence that the work
    // happened, and reporting it as delivered would be the plane inventing the
    // one thing nobody told it.
    let grant = operator("att_native_silent", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drain(&mut rx);

    // A `declare` rather than a `pty_run`, so that the grant is not what this
    // test is about: `exec` and `pty_run` both cost the capability no bundle
    // carries, and a test that had to name it by hand would be asserting two
    // things at once.
    let asked = waiting_for(
        &limb,
        &grant,
        IntentKind::Declare {
            cwd: Some("/var/log".to_string()),
            env: Vec::new(),
        },
        Duration::from_millis(20),
    );
    let settlement = limb.dispatch(&grant, asked, now).await;

    match settlement.outcome {
        Outcome::TimedOut { observed } => assert_eq!(
            observed.quiet_ms, 20,
            "the window it waited, which is the agent's own deadline"
        ),
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert_eq!(
        settlement.progress,
        Progress::Delivered(1),
        "the command went, which is all the plane knows and all it claims"
    );
    assert!(
        !settlement.refused(),
        "an unanswered intent is not a refusal: nobody refused it"
    );
    assert_eq!(drain(&mut rx).len(), 1);
}

#[tokio::test]
async fn a_refusal_nobody_is_waiting_for_is_reported_rather_than_swallowed() {
    // A refusal can arrive after its intent has already settled, because the
    // agent's deadline passed or the limb closed underneath it. The caller is
    // told so it can log it. A refusal that disappears quietly is the thing
    // this path exists to prevent, and it would be a poor joke to rebuild it
    // here.
    let grant = operator("att_native_late", "desk.example");
    let (_registry, limb, _rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let orphan = intent(&limb, &grant, exec("uname -a"));
    assert!(!limb.note_refused(orphan.refuse("too late, nobody is listening")));
}

/// A grant that carries `exec`.
///
/// Named on the token rather than expanded from a bundle, because `exec` is in
/// NO bundle (`00 R19`): it is arbitrary code execution on somebody's machine,
/// and `RoleBundle::Owner` deliberately stops short of it. A test that wanted a
/// bundle to carry it would be asserting the wrong thing.
fn may_run(id: &str, host: &str) -> agent_plane::Grant {
    use limb_core::capability::{Capability, CapabilitySet};

    // `open` because attaching a limb needs it, `control` because a run takes
    // the control lease, and `exec` because that is what this is.
    agent_plane::Grant::issue(
        id,
        CapabilitySet::of(&[
            Capability::View,
            Capability::Open,
            Capability::Control,
            Capability::Exec,
        ]),
        [host.to_string()],
    )
    .expect("a legal grant")
}

/// Take the control lease, which every `exec` needs (`02 §2.4`'s L column).
///
/// Its own function because all four served tests want it and none of them is
/// about arbitration: a run that could not take the lease would be refused
/// before anything reached the driver, and the answer these tests are about
/// would never be asked for.
async fn holding_the_lease(
    limb: &agent_plane::AttachedLimb,
    grant: &agent_plane::Grant,
    now: LeaseInstant,
) {
    use agent_lease::{AcquireRequest, HolderKind, Party};

    let party = Party::new(grant.id().clone(), HolderKind::Agent, "a served run");
    let transition = limb
        .acquire(AcquireRequest::new(party), now)
        .expect("an unheld lease is granted");
    limb.honour(&transition, now).await;
}

/// The answer of a served run, for the assertions below.
fn ran(
    observations: &[limb_core::observation::Observation],
) -> &limb_core::observation::Observation {
    observations
        .iter()
        .find(|o| matches!(o, limb_core::observation::Observation::Ran { .. }))
        .expect("a served run produces a Ran observation")
}

#[tokio::test]
async fn a_driver_that_serves_an_intent_settles_it_as_served_rather_than_as_a_timeout() {
    // `00 R51b`, and the bug it names is worth restating because it is the
    // whole point of this test. There was a way for a driver to say no and no
    // way at all to say yes, so a driver that genuinely served an intent had
    // nothing to send: the plane heard silence, waited out the deadline and
    // settled as `TimedOut`. The first driver to implement a native intent
    // therefore looked exactly like a driver that had failed.
    use limb_core::intent::{CommandExit, CommandRun, Dropped, ExitTier, ServedAnswer, Truncation};
    use limb_core::limb::Confidence;
    use limb_core::observation::{ExitSource, Observation};

    let grant = may_run("att_native_served", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    holding_the_lease(&limb, &grant, now).await;
    drain(&mut rx);

    // Patient, so that a timeout cannot be what produced the settlement: if
    // this test passes in under thirty seconds it passed on the answer.
    let asked = waiting_for(&limb, &grant, exec("ls /etc"), Duration::from_secs(30));
    let id = asked.id;

    let answer = ServedAnswer::Ran(CommandRun {
        status: CommandExit::code(ExitTier::Exec, 0),
        stdout: bytes::Bytes::from_static(b"hosts\npasswd\n"),
        stderr: bytes::Bytes::new(),
        dropped: Truncation {
            cap: 65_536,
            stdout: Dropped::default(),
            stderr: Dropped::default(),
        },
        duration: Duration::from_millis(12),
    });

    // The two halves a real session has: the plane submitting on one side, and
    // the shell reading the driver's event stream on the other.
    let (settlement, delivered) = tokio::join!(limb.dispatch(&grant, asked, now), async {
        let command = rx.recv().await.expect("the intent reaches the session");
        let carried = as_agent(&command).expect("as ClientCommand::Agent").clone();
        limb.note_served(carried.serve(answer))
    });

    assert!(delivered, "the answer found the intent that was waiting");
    assert_eq!(settlement.id, id);
    match &settlement.outcome {
        Outcome::Done {
            delivered,
            verified,
        } => {
            assert!(delivered, "the command ran and the driver said so");
            assert!(verified.is_none(), "nothing asked for verification");
        }
        Outcome::TimedOut { .. } => {
            panic!("a served intent settled as a timeout, which is exactly 00 R51b")
        }
        other => panic!("expected a served run, got {other:?}"),
    }
    assert!(!settlement.refused(), "nobody refused this");
    assert_eq!(settlement.progress, Progress::Delivered(1));

    // And the answer itself reaches the agent, with the tier that produced it.
    match ran(&settlement.payload) {
        Observation::Ran {
            status,
            stdout,
            duration_ms,
            ..
        } => {
            assert_eq!(status.code, Some(0));
            assert_eq!(status.signal, None);
            assert_eq!(status.source, ExitSource::Exec);
            // An `exit-status` off the wire is exact whoever read it, and the
            // confidence is derived from the tier for exactly that reason.
            assert_eq!(status.confidence, Confidence::Exact);
            assert_eq!(*duration_ms, 12);
            // Untrusted on the way out: the plane wraps it here because this is
            // the first point at which anything could act on it.
            let out = stdout.clone().into_inner_untrusted();
            assert_eq!(&out.bytes[..], b"hosts\npasswd\n");
            assert!(out.complete, "nothing was dropped");
        }
        other => panic!("expected a run, got {other:?}"),
    }
}

#[tokio::test]
async fn a_run_whose_output_was_capped_says_how_much_went() {
    // `00 R24`. The plane never drops output without saying how much it
    // dropped, and a truncation an agent is not told about is an agent
    // reasoning confidently about the wrong half of a file.
    use limb_core::intent::{CommandExit, CommandRun, Dropped, ExitTier, ServedAnswer, Truncation};
    use limb_core::observation::{Observation, TruncationPoint};

    let grant = may_run("att_native_truncated", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    holding_the_lease(&limb, &grant, now).await;
    drain(&mut rx);

    let asked = waiting_for(&limb, &grant, exec("cat big.log"), Duration::from_secs(30));
    let answer = ServedAnswer::Ran(CommandRun {
        status: CommandExit::code(ExitTier::Exec, 0),
        stdout: bytes::Bytes::from_static(b"the first page"),
        stderr: bytes::Bytes::new(),
        dropped: Truncation {
            cap: 14,
            stdout: Dropped {
                bytes: 200_000,
                lines: 4_000,
            },
            stderr: Dropped::default(),
        },
        duration: Duration::from_millis(90),
    });

    let (settlement, _) = tokio::join!(limb.dispatch(&grant, asked, now), async {
        let command = rx.recv().await.expect("the intent reaches the session");
        let carried = as_agent(&command).expect("as ClientCommand::Agent").clone();
        limb.note_served(carried.serve(answer))
    });

    let truncated = settlement
        .payload
        .iter()
        .find_map(|o| match o {
            Observation::Truncated {
                dropped_bytes,
                dropped_lines,
                at,
                ..
            } => Some((*dropped_bytes, *dropped_lines, *at)),
            _ => None,
        })
        .expect("a capped run must say how much went (00 R24)");
    assert_eq!(truncated, (200_000, 4_000, TruncationPoint::Stdout));

    // And the run itself is marked incomplete, so a consumer that reads only
    // the bytes still cannot mistake them for all of them.
    match ran(&settlement.payload) {
        Observation::Ran { stdout, .. } => assert!(
            !stdout.clone().into_inner_untrusted().complete,
            "a truncated stream is not complete"
        ),
        other => panic!("expected a run, got {other:?}"),
    }
}

#[tokio::test]
async fn a_run_that_outlived_its_deadline_settles_as_a_timeout_with_no_invented_status() {
    // `00 R7` and `05 R5.10`. There is no default of 0 and no default of 1: a
    // tier that cannot answer says so, the settlement says the deadline passed,
    // and the output that did arrive still travels, because it is still the
    // agent's output (`00 R24`).
    use limb_core::intent::{
        CommandExit, CommandRun, ExitTier, ServedAnswer, Truncation, Unanswered,
    };
    use limb_core::observation::Observation;

    let grant = may_run("att_native_deadline", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    holding_the_lease(&limb, &grant, now).await;
    drain(&mut rx);

    let asked = waiting_for(&limb, &grant, exec("sleep 600"), Duration::from_secs(30));
    let answer = ServedAnswer::Ran(CommandRun {
        status: CommandExit::unanswered(ExitTier::Exec, Unanswered::Deadline),
        stdout: bytes::Bytes::from_static(b"starting\n"),
        stderr: bytes::Bytes::new(),
        dropped: Truncation::default(),
        duration: Duration::from_millis(2_000),
    });

    let (settlement, _) = tokio::join!(limb.dispatch(&grant, asked, now), async {
        let command = rx.recv().await.expect("the intent reaches the session");
        let carried = as_agent(&command).expect("as ClientCommand::Agent").clone();
        limb.note_served(carried.serve(answer))
    });

    match &settlement.outcome {
        Outcome::TimedOut { observed } => {
            assert_eq!(
                observed.quiet_ms, 2_000,
                "the time the command actually ran, not the agent's whole patience"
            );
            assert_eq!(observed.bytes, 9, "and what arrived before the deadline");
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
    match ran(&settlement.payload) {
        Observation::Ran { status, stdout, .. } => {
            assert_eq!(status.code, None, "no code was invented");
            assert_eq!(status.signal, None, "and no signal was either");
            assert_eq!(
                &stdout.clone().into_inner_untrusted().bytes[..],
                b"starting\n",
                "output from before the deadline is not thrown away with it"
            );
        }
        other => panic!("expected a run, got {other:?}"),
    }
}

#[tokio::test]
async fn a_signal_reaches_the_agent_as_a_signal_and_never_as_a_number() {
    // `00 R7`. `128 + signum` is a shell's convention for squeezing a signal
    // through a byte wide exit status. An agent handed 137 cannot tell a
    // process that was killed from one that chose to exit 137, so the plane
    // never computes it.
    use limb_core::intent::{CommandExit, CommandRun, ExitTier, ServedAnswer, Truncation};
    use limb_core::observation::Observation;

    let grant = may_run("att_native_signal", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    holding_the_lease(&limb, &grant, now).await;
    drain(&mut rx);

    let asked = waiting_for(&limb, &grant, exec("./oom-me"), Duration::from_secs(30));
    let answer = ServedAnswer::Ran(CommandRun {
        status: CommandExit::signal(ExitTier::Exec, "KILL"),
        stdout: bytes::Bytes::new(),
        stderr: bytes::Bytes::new(),
        dropped: Truncation::default(),
        duration: Duration::from_millis(400),
    });

    let (settlement, _) = tokio::join!(limb.dispatch(&grant, asked, now), async {
        let command = rx.recv().await.expect("the intent reaches the session");
        let carried = as_agent(&command).expect("as ClientCommand::Agent").clone();
        limb.note_served(carried.serve(answer))
    });

    // Being killed is an ANSWER: the far side said how it ended, so the intent
    // is done rather than timed out.
    assert!(matches!(settlement.outcome, Outcome::Done { .. }));
    match ran(&settlement.payload) {
        Observation::Ran { status, .. } => {
            assert_eq!(status.signal.as_deref(), Some("KILL"));
            assert_eq!(
                status.code, None,
                "a signal must never be coerced into an exit code"
            );
        }
        other => panic!("expected a run, got {other:?}"),
    }
}
