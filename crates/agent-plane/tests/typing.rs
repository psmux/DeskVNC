//! `00 R8`, asserted on the wire rather than in a comment.
//!
//! A scancode types what the REMOTE layout says that key is, so an agent
//! asking for `a` types `q` on an AZERTY remote and NOTHING ANYWHERE REPORTS
//! AN ERROR. It is silent in the way that matters: the agent's next
//! observation shows a text field with characters in it, so the loop proceeds
//! and the wrong text is committed.
//!
//! There is no test on a developer's machine that catches that, because a
//! developer's remote is usually US layout. This is the test that does: it
//! asserts on the bytes, and it fails the moment somebody optimises a keycode
//! back in.

mod common;

use agent_lease::{AcquireRequest, HolderKind, LeaseInstant, Party};
use agent_plane::PlaneConfig;
use common::{as_key, connected, drain, intent, operator, TestLimb};
use limb_core::intent::IntentKind;
use limb_core::observation::Outcome;

#[tokio::test]
async fn typing_is_keysyms_and_never_a_scancode() {
    let grant = operator("att_typing", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );

    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb
        .acquire(AcquireRequest::new(party), now)
        .expect("an unheld lease is granted");
    limb.honour(&transition, now).await;
    drain(&mut rx);

    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Type {
                    text: "aA1!".to_string(),
                    wpm: None,
                },
            ),
            now,
        )
        .await;

    assert!(
        matches!(
            settlement.outcome,
            Outcome::Done {
                delivered: true,
                ..
            }
        ),
        "a four character type on a connected limb is delivered: {:?}",
        settlement.outcome
    );

    let sent = drain(&mut rx);
    assert_eq!(sent.len(), 8, "one press and one release per code point");

    // `codePointToKeysym`: a code point below 0x100 is its own keysym. So `A`
    // is 0x41 and NOT Shift plus 0x61. No Shift for uppercase, because the
    // keysym IS the character and reaching for a modifier reintroduces the
    // layout problem for no gain (`06 §2.4`).
    let expected = [0x61u32, 0x41, 0x31, 0x21];
    for (index, keysym) in expected.iter().enumerate() {
        let press = as_key(&sent[index * 2]).expect("a key command");
        let release = as_key(&sent[index * 2 + 1]).expect("a key command");
        assert_eq!(press, (*keysym, None, true), "press {index}");
        assert_eq!(release, (*keysym, None, false), "release {index}");
    }

    // The assertion this file exists for, stated once more over the whole run
    // so a future variant of the loop above cannot slip past it.
    for command in &sent {
        let (_, keycode, _) = as_key(command).expect("a key command");
        assert!(
            keycode.is_none(),
            "a typed character must never carry a scancode: {command:?}"
        );
    }
}

#[tokio::test]
async fn a_multi_byte_character_is_one_code_point_and_not_a_surrogate_pair() {
    let grant = operator("att_astral", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    limb.honour(&transition, now).await;
    drain(&mut rx);

    // An astral character is one iteration rather than a surrogate pair, which
    // is the bug `keyEventToIds` had to fix on the webview side
    // (`ui/src/render/keysyms.ts:147`).
    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Type {
                    text: "\u{1F600}".to_string(),
                    wpm: None,
                },
            ),
            now,
        )
        .await;
    assert!(!settlement.refused());

    let sent = drain(&mut rx);
    assert_eq!(sent.len(), 2, "one press and one release, not four");
    // The Unicode keysym convention: 0x01000000 plus the code point.
    assert_eq!(
        as_key(&sent[0]).unwrap(),
        (0x0100_0000 + 0x1F600, None, true)
    );
}

#[tokio::test]
async fn both_spellings_of_a_line_ending_press_return_once() {
    let grant = operator("att_crlf", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    limb.honour(&transition, now).await;
    drain(&mut rx);

    // A caller pasting Windows text sends "\r\n" and must not press Return
    // twice. Both spellings map to the Return keysym, and the count is what
    // proves it is one press per code point rather than one press per line.
    limb.dispatch(
        &grant,
        intent(
            &limb,
            &grant,
            IntentKind::Type {
                text: "\r\n".to_string(),
                wpm: None,
            },
        ),
        now,
    )
    .await;

    let sent = drain(&mut rx);
    assert_eq!(sent.len(), 4);
    for command in &sent {
        assert_eq!(as_key(command).unwrap().0, 0xff0d, "Return, both times");
    }
}
