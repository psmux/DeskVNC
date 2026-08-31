//! A worked limb, compiled against the trait as written (`02 AC-2`, `AC-13`).
//!
//! The subject is `02 §8`'s serial console, because it is the hardest test
//! available: it breaks assumptions the other four limbs share. There is no
//! authentication event, no resize, no reconnect that preserves anything, and
//! no addressing that fits a host and a port. Its quiescence signal is
//! actively misleading, since a serial line is silent when the far side is
//! idle and equally silent when it is wedged, which is the exact case an agent
//! most needs to tell apart.
//!
//! Two things are being asserted here and neither is about serial ports.
//!
//! First, that the trait is IMPLEMENTABLE without changing it. Six of the
//! eight methods below are constants and `supports` is a match with a sentence
//! in every refusal. If a fifth limb had needed a method that only one
//! protocol answers usefully, the extension point would have stopped being
//! one.
//!
//! Second, that `Limb` is OBJECT SAFE, which the supertrait ruling depends on:
//! the registry holds `Vec<Arc<dyn ProtocolDriver>>`, and a `Limb` that could
//! not be reached as `&dyn Limb` would force a downcast through `Any`, which
//! is a runtime failure mode standing in for a compile time one.
//!
//! `02 §8.3`'s one honest cost is visible here too: this driver has to answer
//! `default_port` for a device that has no port. `ConnectOptions` carries
//! `host: String` and `port: u16`, and a serial console is a device path at a
//! baud rate, so the endpoint refactor `02 §8.3` prices at about 200 lines is
//! still owed. Encoding a device path in `host` would work and would be a lie
//! every future reader has to be told about.

use limb_core::{
    Capability, Confidence, Degraded, Grounding, IntentName, Limb, LimbDescription, LimbLimits,
    PerceptionSet, Preference, QuiescencePolicy, QuiescenceSignal, SessionStats, Slot, Support,
};
use remote_core::driver::{OptionsMismatch, ProtocolDriver, ProtocolKind, SessionHandle};
use remote_core::events::SessionEvent;
use remote_core::options::ConnectOptions;
use std::time::Duration;
use tokio::sync::mpsc;

struct SerialDriver;

impl ProtocolDriver for SerialDriver {
    fn kind(&self) -> ProtocolKind {
        // `ProtocolKind::Serial` does not exist in this build and adding it is
        // step 2 of the limb author's checklist, not something a test may do.
        // A serial console is a byte stream on a PTY shaped channel, so `Ssh`
        // is the nearest existing kind and it is enough to compile against.
        ProtocolKind::Ssh
    }

    fn spawn(
        &self,
        _id: String,
        _options: ConnectOptions,
        _events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch> {
        unimplemented!("this limb exists to be compiled against, not to be run")
    }
}

impl Limb for SerialDriver {
    fn describe(&self) -> LimbDescription {
        LimbDescription {
            what: "A serial console on a directly attached line.",
            coordinates: "",
            settling: "Settled means no bytes for the quiet window. A serial line is equally \
                       silent when the far side is idle and when it has stopped responding, so \
                       a settled result here is weaker evidence than on any other limb.",
            preference: Preference::Preferred,
            preference_reason: "Text perception and exact bytes, but no exit status and no way \
                                to tell idle from hung.",
            steer_away: None,
        }
    }

    fn capabilities(&self) -> &'static [Capability] {
        // No `Exec`, so a grant carrying it gets a refusal naming this limb
        // rather than a silent no-op. That is the whole of capabilities per
        // limb and it needs no table keyed on protocol.
        &[
            Capability::View,
            Capability::TerminalRead,
            Capability::TerminalWrite,
        ]
    }

    fn supports(&self, intent: IntentName) -> Support {
        use IntentName::*;
        match intent {
            Type | Press | SendBytes => Support::Native,
            Wait | ReadScreen | Cancel => Support::Observed,
            Move | Click | Drag | Scroll => Support::Unsupported {
                because: "a serial console has no pointer",
            },
            Capture => Support::Unsupported {
                because: "a serial console has no framebuffer; use read_screen",
            },
            Exec | PtyRun => Support::Unsupported {
                because: "a serial line carries no command channel and no exit status; send the \
                          command and read what comes back",
            },
            Scancode => Support::Unsupported {
                because: "a serial console carries characters, not scancodes",
            },
            ClipboardGet | ClipboardSet => Support::Unsupported {
                because: "a serial console has no clipboard",
            },
            Declare => Support::Unsupported {
                because: "there is no shell on this side to declare anything to",
            },
            Tune => Support::Unsupported {
                because: "line parameters are set at connect and never renegotiated",
            },
            // `IntentName` is `#[non_exhaustive]`, so a limb outside this
            // workspace needs this arm. Refusing by default is right for a
            // limb that has not been taught a new intent: the settlement rule
            // says a limb that cannot settle an intent must refuse it.
            _ => Support::Unsupported {
                because: "this limb was written before that intent existed",
            },
        }
    }

    fn perception(&self) -> PerceptionSet {
        PerceptionSet {
            frames: false,
            cells: true,
            structure: false,
        }
    }

    fn grounding(&self) -> Grounding {
        Grounding::Cells
    }

    fn quiescence(&self) -> QuiescencePolicy {
        QuiescencePolicy {
            signal: QuiescenceSignal::OutputBytes,
            default_quiet: Duration::from_millis(1500),
            // Not `Exact`, unlike SSH, and the difference is the honest part.
            // On SSH a closed channel is a positive statement that the far
            // side finished. A serial line has no channel and no EOF: silence
            // is silence.
            confidence: Confidence::Inferred,
        }
    }

    fn limits(&self) -> LimbLimits {
        LimbLimits {
            max_in_flight: 1,
            pointer_per_sec: 0,
            keys_per_sec: 120,
            // 115200 8N1 is 11,520 bytes a second and the far side has no flow
            // control worth trusting. Half of line rate.
            bytes_per_sec: 5_760,
            // A serial port is exclusive at the OS level. There is exactly one.
            max_slots: Some(1),
        }
    }

    fn degraded(&self, _stats: &SessionStats) -> Option<Degraded> {
        // `SessionStats` measures a socket. There is no round trip to measure
        // and no server duty cycle to read, so answering `None` is more useful
        // than answering with a number derived from nothing.
        None
    }
}

#[test]
fn a_limb_is_reachable_through_a_trait_object() {
    // The property the supertrait ruling rests on. If this did not compile,
    // the registry would need a downcast through `Any` and "does this build
    // speak that protocol" would have two answers.
    let limb: &dyn Limb = &SerialDriver;
    assert_eq!(limb.kind(), ProtocolKind::Ssh);
    assert_eq!(limb.describe().preference, Preference::Preferred);
}

#[test]
fn every_intent_gets_an_answer_and_every_refusal_gets_a_sentence() {
    let limb = SerialDriver;
    for intent in IntentName::ALL {
        match limb.supports(*intent) {
            Support::Unsupported { because } => {
                // A refusal with no sentence is the difference between an
                // agent that stops asking and an agent that retries a pointer
                // event on a serial line forever.
                assert!(!because.is_empty(), "{intent} was refused with no reason");
                assert!(
                    because.chars().next().unwrap().is_lowercase(),
                    "{intent}'s reason reads as an error code rather than a sentence"
                );
            }
            Support::Native | Support::Lowered | Support::Observed => {}
        }
    }
}

#[test]
fn a_protocol_with_one_session_refuses_a_second_slot_with_its_reason() {
    let limb = SerialDriver;
    assert_eq!(limb.max_slots(), Some(1));
    assert!(limb.admits_slot(Slot::ATTACH).is_ok());

    let refused = limb.admits_slot(Slot(1)).unwrap_err();
    assert_eq!(refused.slot, Slot(1));
    // Without this refusal an agent discovers the policy by watching seven of
    // its eight limbs disconnect the eighth.
    let sentence = refused.to_string();
    assert!(sentence.contains("1 concurrent session"), "{sentence}");
}

#[test]
fn an_unbounded_protocol_admits_any_slot() {
    // SSH is the one protocol here that genuinely is unbounded, which is why
    // `max_slots` is an `Option` rather than a number with a sentinel.
    let unbounded = LimbLimits {
        max_in_flight: 1,
        pointer_per_sec: 0,
        keys_per_sec: 120,
        bytes_per_sec: 65_536,
        max_slots: None,
    };
    assert!(unbounded.admits_slot(Slot(u16::MAX)).is_ok());
}
