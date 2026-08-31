//! Deny by default, no hierarchy, no wildcard, no inheritance (`00 R19`,
//! `00 R20`, `00 R29`, `00 R30`, `02 §5`).
//!
//! The rule that is easiest to lose is the one about implication. Every
//! capability system that has ever grown a hierarchy grew it one reasonable
//! step at a time: `admin` obviously implies `view`, and `exec` obviously
//! implies `terminal.read`, and by the fourth obvious step nobody can say what
//! a grant authorises without reading the expansion code. BrowserGlass took
//! the other road and so does this, so the test walks every ordered pair and
//! asserts that holding one grants nothing else at all.

use limb_core::{
    capabilities_for, Capability, CapabilitySet, CaptureForm, Grounding, IntentKind, IntentName,
    PerceptionSet, ReadForm, RoleBundle, WaitUntil, PARAM_RULES,
};

fn desktop() -> PerceptionSet {
    PerceptionSet {
        frames: true,
        cells: false,
        structure: false,
    }
}

fn terminal() -> PerceptionSet {
    PerceptionSet {
        frames: false,
        cells: true,
        structure: false,
    }
}

#[test]
fn there_are_seventeen_of_them() {
    // The number is quoted in four documents. A silently grown enum makes all
    // four wrong at once.
    assert_eq!(Capability::ALL.len(), 17);

    let mut seen = std::collections::BTreeSet::new();
    for cap in Capability::ALL {
        assert!(seen.insert(cap.as_str()), "{cap} is spelled twice");
        assert_eq!(Capability::parse(cap.as_str()), Some(*cap));
    }
}

#[test]
fn an_unrecognised_name_grants_nothing() {
    // Guessing here would be granting an authority nobody wrote down, which
    // is the reason `ProtocolKind::parse` already refuses to guess.
    for junk in ["", "views", "control.pointer", "*", "clipboard", "EXEC"] {
        assert_eq!(Capability::parse(junk), None, "{junk:?}");
    }
    // Trimmed, because a grant read out of a config file carries whitespace.
    assert_eq!(Capability::parse(" exec "), Some(Capability::Exec));
}

#[test]
fn a_grant_starts_holding_nothing() {
    let nothing = CapabilitySet::default();
    assert!(nothing.is_empty());
    assert_eq!(nothing, CapabilitySet::DENY_ALL);
    for cap in Capability::ALL {
        assert!(!nothing.allows(*cap), "an empty set allowed {cap}");
    }
}

#[test]
fn holding_one_capability_grants_no_other() {
    for held in Capability::ALL {
        let set = CapabilitySet::of(&[*held]);
        for other in Capability::ALL {
            if held == other {
                assert!(set.allows(*other));
                continue;
            }
            assert!(
                !set.allows(*other),
                "{held} implied {other}, and this design has no hierarchy"
            );
        }
    }
}

#[test]
fn the_four_implications_the_documents_name_are_all_false() {
    // Named explicitly as well as covered by the sweep above, because these
    // are the four somebody will argue for (`02 §5.4`).
    let admin = CapabilitySet::of(&[Capability::Admin]);
    assert!(!admin.allows(Capability::View));

    let control = CapabilitySet::of(&[Capability::Control]);
    assert!(!control.allows(Capability::View));
    assert!(!control.allows(Capability::Exec));

    let exec = CapabilitySet::of(&[Capability::Exec]);
    assert!(!exec.allows(Capability::TerminalRead));

    let terminal_write = CapabilitySet::of(&[Capability::TerminalWrite]);
    assert!(!terminal_write.allows(Capability::Exec));
}

#[test]
fn exec_and_scancode_are_in_no_bundle() {
    // `02 AC-10`. The two powers that can only be granted by naming the
    // literal string, which is BrowserGlass's treatment of `evaluate` and
    // `cdp` copied for the same reason.
    for bundle in RoleBundle::ALL {
        let caps = bundle.expand();
        for dangerous in Capability::NEVER_BUNDLED {
            assert!(
                !caps.allows(*dangerous),
                "the {bundle} bundle carries {dangerous}"
            );
        }
        assert!(!caps.is_empty(), "the {bundle} bundle grants nothing");
    }
    assert_eq!(Capability::NEVER_BUNDLED.len(), 2);
    assert!(Capability::Exec.is_never_bundled());
    assert!(Capability::Scancode.is_never_bundled());
}

#[test]
fn the_bundle_asymmetries_are_the_ones_that_were_argued_for() {
    let observer = RoleBundle::Observer.expand();
    // A watcher sees that a terminal is connected and does not see what it
    // printed.
    assert!(observer.allows(Capability::View));
    assert!(!observer.allows(Capability::TerminalRead));

    let driver = RoleBundle::Driver.expand();
    // Writing puts something known onto a machine. Reading takes whatever the
    // person at that machine last copied, which is a password more often than
    // anyone would like.
    assert!(driver.allows(Capability::ClipboardWrite));
    assert!(!driver.allows(Capability::ClipboardRead));

    let agent = RoleBundle::Agent.expand();
    // A desktop agent without `capture` is blind, so a bundle that omits it is
    // a bundle nobody uses, and a bundle nobody uses is one people work around
    // by naming capabilities by hand.
    assert!(agent.allows(Capability::Capture));
    // An agent drives what it was given. An agent that opens its own machines
    // is an operator and the person granting that should have to say so.
    assert!(!agent.allows(Capability::Open));
    assert!(!agent.allows(Capability::Close));
    // Both are exfiltration paths that need no screen, and neither is needed
    // to click on things.
    assert!(!agent.allows(Capability::FilesRead));
    assert!(!agent.allows(Capability::ClipboardRead));

    let owner = RoleBundle::Owner.expand();
    assert!(owner.allows(Capability::Admin));
    assert_eq!(owner.iter().count(), Capability::ALL.len() - 2);
}

#[test]
fn a_limb_that_cannot_do_a_thing_refuses_a_grant_that_asks_for_it() {
    // The whole of "capabilities per limb": the intersection of what the grant
    // carries and what the limb can ever offer. No table keyed on protocol.
    let grant = RoleBundle::Owner.expand().with(Capability::Exec);
    let a_desktop_limb = CapabilitySet::of(&[
        Capability::View,
        Capability::Capture,
        Capability::Control,
        Capability::ClipboardRead,
        Capability::ClipboardWrite,
    ]);

    let effective = grant.intersect(a_desktop_limb);
    assert!(!effective.allows(Capability::Exec));
    assert!(effective.allows(Capability::Control));
    assert_eq!(
        effective.missing(CapabilitySet::of(&[Capability::Exec])),
        vec![Capability::Exec]
    );
}

#[test]
fn a_refusal_names_what_was_missing() {
    let held = CapabilitySet::of(&[Capability::View]);
    let needed = CapabilitySet::of(&[Capability::View, Capability::Capture]);
    // A boolean would tell an agent it was refused. This tells it which
    // capability to ask a person for.
    assert_eq!(held.missing(needed), vec![Capability::Capture]);
    assert!(!held.allows_all(needed));
    assert!(needed.allows_all(held));
}

#[test]
fn reading_pixels_costs_capture_and_reading_text_does_not() {
    // `PARAM_RULES[0]`, the one place this design copies BrowserGlass's
    // parameter dependent rules.
    let pixels = capabilities_for(
        &IntentKind::ReadScreen {
            form: ReadForm::Pixels,
            region: None,
        },
        &desktop(),
    );
    assert!(pixels.allows(Capability::View) && pixels.allows(Capability::Capture));

    for form in [ReadForm::Text, ReadForm::Cells] {
        let caps = capabilities_for(&IntentKind::ReadScreen { form, region: None }, &terminal());
        assert!(caps.allows(Capability::View));
        assert!(!caps.allows(Capability::Capture), "{form:?}");
    }
}

#[test]
fn waiting_for_text_costs_capture_on_a_limb_with_no_character_grid() {
    // `PARAM_RULES[1]`, and it is a consequence of `03 §6.5` recommending no
    // OCR in version 1. An agent holding `view` and not `capture` can wait for
    // a terminal to print a string and cannot wait for a dialog to say one,
    // which is the honest division.
    let waiting_for_text = IntentKind::Wait {
        until: WaitUntil::Text("Password:".into()),
        quiet: None,
        timeout: None,
    };

    let on_a_terminal = capabilities_for(&waiting_for_text, &terminal());
    assert!(!on_a_terminal.allows(Capability::Capture));

    let on_a_desktop = capabilities_for(&waiting_for_text, &desktop());
    assert!(on_a_desktop.allows(Capability::Capture));

    // Waiting for the screen to stop moving is free either way: it is damage
    // arithmetic the run loop already does, not a pixel read.
    let stable = IntentKind::Wait {
        until: WaitUntil::ScreenStable,
        quiet: None,
        timeout: None,
    };
    assert!(!capabilities_for(&stable, &desktop()).allows(Capability::Capture));

    assert_eq!(PARAM_RULES.len(), 2);
    assert_eq!(PARAM_RULES[0].intent, IntentName::ReadScreen);
    assert_eq!(PARAM_RULES[1].intent, IntentName::Wait);
    for rule in PARAM_RULES {
        assert_eq!(rule.base, Capability::View);
        assert_eq!(rule.additional, Capability::Capture);
        assert!(!rule.when.is_empty());
    }
}

#[test]
fn a_raw_scancode_costs_the_capability_that_is_in_no_bundle_and_a_named_key_does_not() {
    // `00 R30`. `Press` against the fixed named key table needs only
    // `control`; a numeric code outside that table needs `scancode`.
    let named = capabilities_for(
        &IntentKind::Press {
            keys: vec![limb_core::NamedKey::lookup("F4").unwrap()],
        },
        &desktop(),
    );
    assert_eq!(named, CapabilitySet::of(&[Capability::Control]));

    let raw = capabilities_for(
        &IntentKind::Scancode {
            code: 0x1e,
            down: true,
        },
        &desktop(),
    );
    assert_eq!(raw, CapabilitySet::of(&[Capability::Scancode]));
    assert!(!raw.allows(Capability::Control));
}

#[test]
fn cancelling_your_own_request_is_not_a_privilege() {
    // Gating it would mean an agent that has lost a capability mid task cannot
    // stop the work it already started.
    let caps = capabilities_for(
        &IntentKind::Cancel {
            target: limb_core::IntentId(1),
        },
        &desktop(),
    );
    assert!(caps.is_empty());
}

#[test]
fn every_intent_that_drives_needs_the_control_lease_and_no_read_does() {
    let drives = [
        IntentKind::Type {
            text: "x".into(),
            wpm: None,
        },
        IntentKind::Scancode {
            code: 1,
            down: true,
        },
        IntentKind::Move {
            to: limb_core::Point::new(0, 0),
        },
        IntentKind::SendBytes {
            bytes: bytes::Bytes::from_static(b"ls\n"),
        },
    ];
    for kind in drives {
        let name = kind.name();
        assert!(kind.needs_control_lease(), "{name}");
    }

    let reads = [
        IntentKind::ReadScreen {
            form: ReadForm::Text,
            region: None,
        },
        IntentKind::Capture {
            form: CaptureForm::DamageCrop,
            region: None,
            scale: None,
        },
        IntentKind::ClipboardGet,
        IntentKind::Cancel {
            target: limb_core::IntentId(1),
        },
    ];
    for kind in reads {
        let name = kind.name();
        assert!(
            !kind.needs_control_lease(),
            "{name} took the lease, so a watcher and a driver can no longer coexist"
        );
    }
}

#[test]
fn a_limb_may_offer_two_perception_families_at_once() {
    // `02 §8.4`: an ADB device is one limb offering both a character stream
    // (`shell`) and a bitmap (`screencap`), actuated in pixels. Had
    // `perception` been an enum it would have had to declare itself a terminal
    // that lies about screenshots or a desktop that lies about text.
    let android = PerceptionSet {
        frames: true,
        cells: true,
        structure: false,
    };
    // And the combination changes what a wait costs, which is the practical
    // consequence rather than a taxonomy point: text on this limb is free.
    let waiting = IntentKind::Wait {
        until: WaitUntil::Text("root@".into()),
        quiet: None,
        timeout: None,
    };
    assert!(!capabilities_for(&waiting, &android).allows(Capability::Capture));
    assert_eq!(Grounding::Pixels, Grounding::Pixels);
}
