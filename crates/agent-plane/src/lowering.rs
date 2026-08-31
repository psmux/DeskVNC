//! Turning an [`AgentIntent`] into the commands a driver already understands.
//!
//! This is the heart of the crate and it is deliberately PURE: every function
//! here is a function of what it was handed, it opens nothing, sends nothing
//! and reads no clock. The dispatcher walks what comes back. That split is not
//! tidiness, it is the reason a lowering rule can be asserted in a test with no
//! runtime and no server, and it is the same discipline `limb-core` and
//! `agent-lease` follow one layer down.
//!
//! ## The rules that are not negotiable
//!
//! **`00 R8`. A type intent is keysyms, never a scancode.** A scancode types
//! what the REMOTE layout says that key is
//! (`crates/vnc-core/src/session/run_loop.rs:1733`), so an agent asking for
//! `a` types `q` on an AZERTY remote and nothing anywhere reports an error.
//! [`limb_core::keys::lower_type`] is where that is enforced and argued, and
//! this file calls it rather than writing a second table. There is exactly one
//! keysym table in this workspace and it is not here.
//!
//! **`00 R47c`. A scroll is a direction and a click count.** There is no scroll
//! magnitude on the RFB wire: it is button bits 3 to 6 with nowhere to put a
//! number (`ui/src/render/input.ts:772`). A model asking to scroll by pixels
//! is refused by [`pixel_scroll_refusal`] rather than served an invented
//! ratio, which is `00 R7`'s "never invent a value" applied to a second place.
//!
//! **`15 §4.5`. A drag is atomic and its ordering is exact.** Step 1 arrives
//! before the press because the mask is applied at whatever coordinate the
//! message carries, so a press that has not first moved presses wherever the
//! pointer happened to be. Step 5's intermediate points are not decoration
//! either: drag thresholds and drop targets are driven by intermediate motion
//! events, and a drag that teleports is not a drag on most toolkits.
//!
//! **`06 §5.5`. A coordinate outside the framebuffer is rejected, never
//! clamped.** A clamped click lands on whatever is at the edge, which is a
//! different action performed silently, and silent is the property this whole
//! design exists to remove.

use crate::backpressure::SendPolicy;
use crate::config::PlaneConfig;
use crate::error::Refusal;
use bytes::Bytes;
use limb_core::intent::{AgentIntent, Button, IntentKind, Point, ScrollDirection, Tuning};
use limb_core::keys::{lower_press, type_keysyms, NamedKey};
use limb_core::limb::Grounding;
use limb_core::observation::RefusalCode;
use limb_core::ClientCommand;
use std::time::Duration;

/// Which part of a gesture one command is, so an interrupted plan can settle
/// with an honest [`Progress`](limb_core::observation::Progress).
///
/// A count of "commands delivered" is not enough for two of the intents.
/// `type` settles with the number of CODE POINTS that went (`02 §2.3`), which
/// is half the command count, and `drag` settles with the number of
/// intermediate points and the coordinate the button was released at
/// (`15 §4.5` WA-6), which no command count can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepMark {
    /// Nothing special. Counted only in `Progress::Delivered`.
    Plain,
    /// The release half of one typed code point. Marked on the release rather
    /// than the press so that a plan cut between a press and its release does
    /// not claim the character went.
    CodePoint,
    /// The press that starts a drag. After this the remote machine is holding
    /// a button and the plane owes it a release whatever happens next.
    DragPress,
    /// One of the intermediate points, carrying where the button now is.
    DragPoint(Point),
    /// The drag's own release. A plan that reached this needs no synthesised
    /// one.
    DragRelease,
}

/// One command, with what to do when there is no room for it and how long to
/// wait after it went.
#[derive(Debug, Clone)]
pub struct Step {
    pub command: ClientCommand,
    pub policy: SendPolicy,
    /// The pause AFTER this command. Zero for most of them. It is where the
    /// wpm throttle lives for a type, and where `15 §4.5`'s settle windows
    /// live for a drag, and it is the only place a plan can be interrupted,
    /// which is why the marks above sit on the commands either side of it.
    pub pause: Duration,
    pub mark: StepMark,
}

impl Step {
    fn plain(command: ClientCommand, policy: SendPolicy) -> Step {
        Step {
            command,
            policy,
            pause: Duration::ZERO,
            mark: StepMark::Plain,
        }
    }

    fn marked(command: ClientCommand, policy: SendPolicy, mark: StepMark) -> Step {
        Step {
            command,
            policy,
            pause: Duration::ZERO,
            mark,
        }
    }

    fn after(mut self, pause: Duration) -> Step {
        self.pause = pause;
        self
    }

    /// How many bytes this command carries, for the drop accounting. A dropped
    /// 64 KiB paste and a dropped key event are one command each and are not
    /// the same loss (`08 §4.6`).
    pub fn payload_bytes(&self) -> u64 {
        match &self.command {
            ClientCommand::TerminalInput(bytes) => bytes.len() as u64,
            ClientCommand::ClipboardText(text) => text.len() as u64,
            _ => 0,
        }
    }
}

/// What an intent turned into.
#[derive(Debug, Clone)]
pub enum Lowered {
    /// A run of commands, in submission order, never reordered and never
    /// batched (`08 §7.5`). Reordering two key events changes what was typed
    /// and reordering a press and a move turns a click into a drag, so there
    /// is no clever scheduler here that is not a bug.
    Commands(Vec<Step>),
    /// Answered from the plane's own bookkeeping and the mirror, with no wire
    /// traffic at all. Every wait and every read is one of these.
    Observed,
    /// The intent has no lowering at all and travels whole, as
    /// [`ClientCommand::Agent`].
    ///
    /// The three of `05 §4.1`, and the reason they are the three is that
    /// nothing in `ClientCommand` can carry them: `exec` wants a channel of its
    /// own with a real exit status, `pty_run` wants a bounded run that is
    /// answered, and `declare` is state a limb holds between commands. A limb
    /// that offers any of them reports [`Support::Native`] for it, which means
    /// precisely this: the driver's own command pump serves it (`00 R28`).
    ///
    /// This was `NoNativeVariant`, a refusal, and it was a refusal because
    /// `remote-core` had no `ClientCommand::Agent` to put an intent into.
    /// `00 R47a` moved the intent vocabulary down beside the commands and the
    /// variant landed with it, so the command goes and the refusal is gone.
    ///
    /// What has not changed is that `Support::Native` is a limb's CLAIM and not
    /// a guarantee. A driver handed the command that cannot serve it answers
    /// with `SessionEvent::AgentRefused`, which the dispatcher correlates back
    /// to this intent and settles on. `ssh-core` refuses all three today and
    /// says why (`00 R50a`): it owns one PTY channel and no command channel, so
    /// serving `exec` would mean typing at the prompt somebody is watching and
    /// reading the scrollback for an answer, which gives no exit status, no
    /// stderr split and no output bound.
    ///
    /// [`Support::Native`]: limb_core::limb::Support::Native
    Native(Step),
}

/// Everything lowering needs to know about the limb, gathered so the functions
/// below stay pure.
#[derive(Debug, Clone, Copy)]
pub struct LowerContext {
    /// What a coordinate means here.
    pub grounding: Grounding,
    /// The framebuffer, in whatever unit `grounding` names. A coordinate
    /// outside it is rejected.
    pub size: (u16, u16),
    /// The button mask the plane last put on the wire for this limb.
    ///
    /// A move carries it rather than zero, because zeroing it mid gesture
    /// would release a button the caller is still holding, and the plane is
    /// the only thing that knows what it sent: the VNC pointer path remembers
    /// nothing (`00 B8`).
    pub resting_mask: u16,
    /// Where the pointer was last put, for the synthesised release.
    pub last_point: Point,
    /// The drag and double click numbers.
    pub drag_points: u8,
    pub drag_settle: Duration,
    pub double_click_gap: Duration,
}

impl LowerContext {
    /// A context for a freshly attached limb, with nothing held and the
    /// pointer at the origin.
    pub fn new(grounding: Grounding, size: (u16, u16), config: &PlaneConfig) -> LowerContext {
        LowerContext {
            grounding,
            size,
            resting_mask: 0,
            last_point: Point::new(0, 0),
            drag_points: config.drag_points,
            drag_settle: Duration::from_millis(config.drag_settle_ms),
            double_click_gap: Duration::from_millis(config.double_click_gap_ms),
        }
    }

    fn admits(&self, at: Point) -> Result<(), Refusal> {
        let (w, h) = self.size;
        if at.x < w && at.y < h {
            return Ok(());
        }
        Err(Refusal::limb(
            RefusalCode::OutOfBounds,
            format!(
                "({}, {}) is outside this limb's {w}x{h} space; the coordinate is rejected rather than clamped, because a clamped click lands on whatever is at the edge and that is a different action performed silently",
                at.x, at.y
            ),
        ))
    }
}

/// The two commands a lease change owes the limb, in the one order that is
/// correct.
///
/// **Buttons before keys** (`00 R11`, `00 B8`, `15 §4.5` WA-5). The RDP driver
/// already does it this way and its own comment records the bug that made
/// somebody add the buttons: a button held when focus went away stayed held on
/// the server, and a right button stuck that way turns an ordinary left click
/// into a left press underneath a held right button, which the desktop shows
/// as a context menu (`crates/rdp-core/src/session/input.rs` above
/// `release_all`).
///
/// The VNC path never received that fix. `release_all_keys`
/// (`crates/vnc-core/src/session/run_loop.rs:1748`) drains `self.pressed`,
/// which is keyed by `(keysym, Option<keycode>)`, so it is keys only, and the
/// VNC pointer arm encodes whatever mask arrived and remembers nothing. An RFB
/// server holds the last button state it was told until a `PointerEvent`
/// clears the bit. So for a preempted agent mid drag, nothing follows at all
/// until the new holder moves the mouse, and the interval is unbounded.
///
/// This is the plane level repair and it needs no change inside `vnc-core`.
/// It is defence in depth rather than the only guard now that `vnc-core` has
/// been fixed to release buttons internally, and it stays because the plane
/// is the only layer that knows a lease changed.
///
/// Both carry [`SendPolicy::Jump`]: they go ahead of anything queued and they
/// are exempt from the rate buckets, because a queued repair is not a repair
/// and because a limiter running before the handler never sees the kind and
/// silently defeats the asymmetry above it.
pub fn release_sequence(at: Point) -> [Step; 2] {
    [
        Step::plain(
            ClientCommand::Pointer {
                x: at.x,
                y: at.y,
                button_mask: 0,
            },
            SendPolicy::Jump,
        ),
        Step::plain(ClientCommand::ReleaseAllKeys, SendPolicy::Jump),
    ]
}

/// The refusal a model asking to scroll by pixels gets.
///
/// A function rather than a conversion, because there is no conversion. This
/// is the whole of `00 R47c`: `02 §2.4` originally carried pixel deltas,
/// `15 §4.1` is right that there is no scroll magnitude on the RFB wire, and a
/// ratio invented here would be a number nothing measured, applied silently,
/// producing a scroll distance that is wrong by a factor nobody can see.
///
/// Fara-7B is the model this refusal is aimed at: its `scroll` takes pixels,
/// which is one of the reasons `00 R45` ships it as an example adapter with
/// its refusals wired rather than putting it in the evaluation set.
pub fn pixel_scroll_refusal(dx: i32, dy: i32) -> Refusal {
    Refusal::limb(
        RefusalCode::NotExpressible,
        format!(
            "a scroll of ({dx}, {dy}) pixels cannot be expressed: RFB encodes the wheel as button bits 3 to 6 with nowhere to put a magnitude, and RDP converts that same bit form into WHEEL_DELTA rotation flags, so there is no pixel count on either wire. Ask for a direction and a number of clicks. The plane will not invent a pixels per click ratio, because a wrong one is invisible"
        ),
    )
}

/// Lower one intent.
///
/// The geometry fence is NOT checked here, and that is on purpose: the fence
/// is live state and this function is pure. [`limb_core::fence::GeometryFence::admit`]
/// is the one place the comparison is written and the dispatcher calls it
/// before it calls this.
///
/// # Errors
///
/// A [`Refusal`] for anything the wire cannot express or the limb cannot
/// address. Never a silent no-op.
pub fn lower(intent: &AgentIntent, ctx: &LowerContext) -> Result<Lowered, Refusal> {
    match &intent.kind {
        IntentKind::Type { text, wpm } => lower_type(text, *wpm, ctx),
        IntentKind::Press { keys } => lower_press_intent(keys, ctx),
        IntentKind::Scancode { code, down } => Ok(Lowered::Commands(vec![Step::plain(
            // Keysym zero, keycode present. `send_key`'s match routes on the
            // keycode when the server honours QEMU Extended Key Event, and a
            // fabricated keysym beside a raw scancode would be a second,
            // disagreeing claim about which key this is. This whole intent
            // needs `Capability::Scancode`, which is in no bundle (`00 R30`).
            ClientCommand::Key {
                keysym: 0,
                keycode: Some(*code),
                down: *down,
            },
            SendPolicy::Await,
        )])),
        IntentKind::Move { to } => lower_move(*to, ctx),
        IntentKind::Click {
            at,
            button,
            count,
            modifiers,
        } => lower_click(*at, *button, *count, modifiers, ctx),
        IntentKind::Drag { from, to, button } => lower_drag(*from, *to, *button, ctx),
        IntentKind::Scroll {
            at,
            direction,
            clicks,
        } => lower_scroll(*at, *direction, *clicks, ctx),
        IntentKind::SendBytes { bytes } => lower_send_bytes(bytes, ctx),
        IntentKind::ClipboardSet { text } => Ok(Lowered::Commands(vec![Step::plain(
            ClientCommand::ClipboardText(text.clone()),
            SendPolicy::Await,
        )])),
        IntentKind::ClipboardGet => Ok(Lowered::Commands(vec![Step::plain(
            // The format bits are text and nothing else, which is what both
            // paths in this build support: the RDP arm ignores them and says
            // so, and the RFB arm sends an extended clipboard request only
            // when the server offered the extension.
            ClientCommand::ClipboardRequest { formats: 1 },
            SendPolicy::Await,
        )])),
        IntentKind::Tune { tuning } => lower_tune(tuning, ctx),
        // Answered from the plane's own bookkeeping. `Wait` never reaches a
        // limb at all: the plane holds the damage stream and the mirror and
        // evaluates the condition itself.
        IntentKind::Wait { .. } | IntentKind::ReadScreen { .. } | IntentKind::Capture { .. } => {
            Ok(Lowered::Observed)
        }
        // Withdrawing an earlier intent is bookkeeping in the plane's own
        // in flight table. Nothing goes on the wire, and nothing needs a
        // capability, because stopping work you started is not a privilege.
        IntentKind::Cancel { .. } => Ok(Lowered::Observed),
        // A real exit status comes from a second SSH channel with `exec`
        // (`00 R7`), and a declared cwd and env are state the SSH limb holds.
        // Neither is expressible as any of the commands above, so both are
        // `Support::Native` on the limbs that offer them and both go to the
        // driver whole (`00 R28`).
        //
        // `SendPolicy::Await` and never `Shed`, because a shed intent is the
        // dropped intent this whole design exists to remove, and never
        // `Coalesce`, because coalescing folds a command out of a plan and a
        // folded intent is an intent nobody answers.
        IntentKind::Exec { .. } | IntentKind::PtyRun { .. } | IntentKind::Declare { .. } => {
            Ok(Lowered::Native(Step::plain(
                ClientCommand::Agent(intent.clone()),
                SendPolicy::Await,
            )))
        }
        // `IntentKind` is `#[non_exhaustive]`. A new intent this build has
        // never heard of is REFUSED with a sentence rather than dropped, which
        // is the whole of `00 R7`: an intent a driver cannot serve is answered,
        // never dropped.
        other => Err(Refusal::limb(
            RefusalCode::NotSupported,
            format!(
                "this build was written before the {} intent existed and has no lowering for it",
                other.name()
            ),
        )),
    }
}

fn lower_type(text: &str, wpm: Option<u16>, ctx: &LowerContext) -> Result<Lowered, Refusal> {
    if text.is_empty() {
        return Err(Refusal::limb(
            RefusalCode::NotExpressible,
            "an empty type changes nothing and would still consume a lease and a settlement",
        ));
    }
    let pause = per_code_point(wpm);
    let mut steps = Vec::new();
    for (c, keysym) in type_keysyms(text) {
        match ctx.grounding {
            // A framebuffer limb gets keysyms. `keycode: None` on every one of
            // them, which is `00 R8` and is the single most damaging silent
            // failure a desktop limb can produce if it is got wrong.
            Grounding::Pixels => {
                steps.push(Step::plain(
                    ClientCommand::Key {
                        keysym,
                        keycode: None,
                        down: true,
                    },
                    SendPolicy::Await,
                ));
                steps.push(
                    Step::marked(
                        ClientCommand::Key {
                            keysym,
                            keycode: None,
                            down: false,
                        },
                        SendPolicy::Await,
                        StepMark::CodePoint,
                    )
                    .after(pause),
                );
            }
            // A terminal's input is simply bytes, and `ClientCommand::Key` has
            // nowhere to put a multi byte character
            // (`crates/remote-core/src/commands.rs:76`). One command per code
            // point rather than one for the string, so that the interruption
            // granularity and the settled character count are the same on both
            // groundings: `02 §2.3` settles a half typed string with the count
            // that WENT, and a count is only truthful if the sequence was
            // consumed one code point at a time. A caller pasting a block
            // wants `send_bytes`, which is one command.
            Grounding::Cells | Grounding::None => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf).as_bytes().to_vec();
                steps.push(
                    Step::marked(
                        ClientCommand::TerminalInput(Bytes::from(encoded)),
                        SendPolicy::Await,
                        StepMark::CodePoint,
                    )
                    .after(pause),
                );
            }
        }
    }
    Ok(Lowered::Commands(steps))
}

/// How long to wait after each code point.
///
/// A word is five characters by the usual convention, so `wpm` times five is
/// characters per minute. The throttle is not politeness: a remote machine
/// that drops characters under a fast synthetic type does it SILENTLY, because
/// neither an RFB KeyEvent nor an RDP fast path input event carries an
/// acknowledgement (`06 §2.5`).
///
/// A `wpm` of zero would divide by zero and means the same thing a caller who
/// wrote it meant, which is "as slowly as possible", so it is read as one.
fn per_code_point(wpm: Option<u16>) -> Duration {
    match wpm {
        None => Duration::ZERO,
        Some(w) => Duration::from_millis(60_000 / (u64::from(w.max(1)) * 5)),
    }
}

fn lower_press_intent(keys: &[&'static NamedKey], ctx: &LowerContext) -> Result<Lowered, Refusal> {
    if keys.is_empty() {
        return Err(Refusal::limb(
            RefusalCode::UnknownKey,
            "a press names at least one key",
        ));
    }
    if !matches!(ctx.grounding, Grounding::Pixels) {
        // A named key on a PTY is an escape sequence, and there is no keysym
        // to escape sequence table anywhere in this workspace. Inventing one
        // here would be a second, private key table, which is exactly what
        // `limb-core::keys` exists to prevent. Refused with the sentence that
        // says what to do instead.
        return Err(Refusal::limb(
            RefusalCode::NotExpressible,
            "this limb takes bytes rather than key positions, and there is no named key to escape sequence table in this build; send the bytes the terminal expects with send_bytes",
        ));
    }
    // `lower_press` carries the XT scancode as well as the keysym, and the
    // difference from a type is argued on `NamedKey`: a chord genuinely IS a
    // set of key positions. `sendKeyCombo` used to send keycode 0 for every
    // key, so Ctrl+Alt+Del from the toolbar degraded to a keysym only KeyEvent
    // and did nothing at all on a server that only understands scancodes.
    let steps = lower_press(keys)
        .into_iter()
        .map(|c| Step::plain(c, SendPolicy::Await))
        .collect();
    Ok(Lowered::Commands(steps))
}

fn lower_move(to: Point, ctx: &LowerContext) -> Result<Lowered, Refusal> {
    pointer_limb(ctx)?;
    ctx.admits(to)?;
    // `SendPolicy::Shed` only because the mask is unchanged. This is the one
    // command in the vocabulary that is stateless: a dropped motion event is
    // corrected by the next motion event, which is exactly why `send_input`
    // already sheds it and nothing else (`08 §4.1`).
    Ok(Lowered::Commands(vec![Step::plain(
        ClientCommand::Pointer {
            x: to.x,
            y: to.y,
            button_mask: ctx.resting_mask,
        },
        SendPolicy::Shed,
    )]))
}

fn lower_click(
    at: Point,
    button: Button,
    count: u8,
    modifiers: &[&'static NamedKey],
    ctx: &LowerContext,
) -> Result<Lowered, Refusal> {
    pointer_limb(ctx)?;
    ctx.admits(at)?;
    if count == 0 {
        return Err(Refusal::limb(
            RefusalCode::NotExpressible,
            "a click of zero presses nothing",
        ));
    }
    if count > 2 {
        // No toolkit agrees on what a triple click means and the remote's own
        // double click interval is something we cannot query (`15 §4.1`).
        return Err(Refusal::limb(
            RefusalCode::NotExpressible,
            format!(
                "a click count of {count} cannot be expressed: no toolkit agrees what a triple click means and the remote's double click interval cannot be queried. Send single clicks and read the screen between them"
            ),
        ));
    }

    let mut steps = Vec::new();
    // Modifiers down first, outside in, and up last, inside out, which is how
    // a hand actually releases a chord. A server that sees Ctrl released
    // before the click's own button sees a different gesture.
    for key in modifiers {
        steps.push(Step::plain(
            ClientCommand::Key {
                keysym: key.keysym,
                keycode: (key.scancode != 0).then_some(key.scancode),
                down: true,
            },
            SendPolicy::Await,
        ));
    }

    let held = ctx.resting_mask | button.mask();
    // Arrive first. The mask is applied at whatever coordinate the message
    // carries, so a press that has not moved presses wherever the pointer
    // happened to be (`06 §2.1`).
    steps.push(Step::plain(
        ClientCommand::Pointer {
            x: at.x,
            y: at.y,
            button_mask: ctx.resting_mask,
        },
        SendPolicy::Await,
    ));
    for edge in 0..count {
        steps.push(Step::plain(
            ClientCommand::Pointer {
                x: at.x,
                y: at.y,
                button_mask: held,
            },
            SendPolicy::Await,
        ));
        let release = Step::plain(
            ClientCommand::Pointer {
                x: at.x,
                y: at.y,
                button_mask: ctx.resting_mask,
            },
            SendPolicy::Await,
        );
        // The gap goes between the two press EDGES, so it is the pause after
        // the first release and there is none after the last.
        steps.push(if edge + 1 < count {
            release.after(ctx.double_click_gap)
        } else {
            release
        });
    }

    for key in modifiers.iter().rev() {
        steps.push(Step::plain(
            ClientCommand::Key {
                keysym: key.keysym,
                keycode: (key.scancode != 0).then_some(key.scancode),
                down: false,
            },
            SendPolicy::Await,
        ));
    }
    Ok(Lowered::Commands(steps))
}

/// The exact drag ordering of `15 §4.5`, with nothing left to the caller.
///
/// ```text
///   1. Pointer { x: x0, y: y0, button_mask: resting }  // arrive, no button
///   2. wait  drag_settle
///   3. Pointer { x: x0, y: y0, button_mask: held }     // press at the origin
///   4. wait  drag_settle
///   5. Pointer { x: xi, y: yi, button_mask: held }     // N intermediate points
///   6. Pointer { x: x1, y: y1, button_mask: held }     // arrive at the target
///   7. wait  drag_settle
///   8. Pointer { x: x1, y: y1, button_mask: resting }  // release
/// ```
///
/// Every step after 3 is fenced by the caller's lease check, which is where
/// `15 §4.5`'s interruption case is answered: if the lease goes away between
/// step 3 and step 8, the plane synthesises the release, and the settlement
/// says the drop landed somewhere the agent did not choose. There is no honest
/// way to undo it and nothing above this pretends there is.
fn lower_drag(
    from: Point,
    to: Point,
    button: Button,
    ctx: &LowerContext,
) -> Result<Lowered, Refusal> {
    pointer_limb(ctx)?;
    // Both endpoints, because a drag whose target is off screen is as wrong as
    // one whose origin is.
    ctx.admits(from)?;
    ctx.admits(to)?;

    let held = ctx.resting_mask | button.mask();
    let mut steps = vec![
        Step::plain(
            ClientCommand::Pointer {
                x: from.x,
                y: from.y,
                button_mask: ctx.resting_mask,
            },
            SendPolicy::Await,
        )
        .after(ctx.drag_settle),
        Step::marked(
            ClientCommand::Pointer {
                x: from.x,
                y: from.y,
                button_mask: held,
            },
            SendPolicy::Await,
            StepMark::DragPress,
        )
        .after(ctx.drag_settle),
    ];

    for i in 1..=u32::from(ctx.drag_points) {
        let at = interpolate(from, to, i, u32::from(ctx.drag_points) + 1);
        steps.push(Step::marked(
            ClientCommand::Pointer {
                x: at.x,
                y: at.y,
                button_mask: held,
            },
            // Intermediate points are AWAITED and not shed, even though their
            // mask matches the one before. Shedding is safe for a stateless
            // motion and these are not stateless: they are the gesture. A drag
            // missing its middle is a drag most toolkits never recognised.
            SendPolicy::Await,
            StepMark::DragPoint(at),
        ));
    }

    steps.push(
        Step::marked(
            ClientCommand::Pointer {
                x: to.x,
                y: to.y,
                button_mask: held,
            },
            SendPolicy::Await,
            StepMark::DragPoint(to),
        )
        .after(ctx.drag_settle),
    );
    steps.push(Step::marked(
        ClientCommand::Pointer {
            x: to.x,
            y: to.y,
            button_mask: ctx.resting_mask,
        },
        SendPolicy::Await,
        StepMark::DragRelease,
    ));
    Ok(Lowered::Commands(steps))
}

/// Point `i` of `divisions` along the straight line from `from` to `to`.
///
/// Integer arithmetic in `u32` so a 4K width times a division count cannot
/// overflow a `u16` part way through, and rounded rather than truncated so the
/// path is symmetric: truncation biases every intermediate point toward the
/// origin, which on a short drag puts them all on top of the press.
fn interpolate(from: Point, to: Point, i: u32, divisions: u32) -> Point {
    let lerp = |a: u16, b: u16| -> u16 {
        let (a, b) = (u32::from(a), u32::from(b));
        let value = if b >= a {
            a + ((b - a) * i + divisions / 2) / divisions
        } else {
            a - ((a - b) * i + divisions / 2) / divisions
        };
        value as u16
    };
    Point::new(lerp(from.x, to.x), lerp(from.y, to.y))
}

fn lower_scroll(
    at: Point,
    direction: ScrollDirection,
    clicks: u8,
    ctx: &LowerContext,
) -> Result<Lowered, Refusal> {
    pointer_limb(ctx)?;
    ctx.admits(at)?;
    if clicks == 0 {
        return Err(Refusal::limb(
            RefusalCode::NotExpressible,
            "a scroll of zero clicks turns the wheel not at all",
        ));
    }
    let wheel = ctx.resting_mask | direction.mask();
    let mut steps = vec![Step::plain(
        ClientCommand::Pointer {
            x: at.x,
            y: at.y,
            button_mask: ctx.resting_mask,
        },
        SendPolicy::Await,
    )];
    // One press and release pair per click, which is what `sendWheel` already
    // does (`ui/src/render/input.ts:772`) and the only shape the wire has.
    for _ in 0..clicks {
        steps.push(Step::plain(
            ClientCommand::Pointer {
                x: at.x,
                y: at.y,
                button_mask: wheel,
            },
            SendPolicy::Await,
        ));
        steps.push(Step::plain(
            ClientCommand::Pointer {
                x: at.x,
                y: at.y,
                button_mask: ctx.resting_mask,
            },
            SendPolicy::Await,
        ));
    }
    Ok(Lowered::Commands(steps))
}

fn lower_send_bytes(bytes: &Bytes, ctx: &LowerContext) -> Result<Lowered, Refusal> {
    if matches!(ctx.grounding, Grounding::Pixels) {
        return Err(Refusal::limb(
            RefusalCode::NotSupported,
            "this limb has a framebuffer and no PTY, so there is nothing for raw bytes to reach; type the text instead",
        ));
    }
    Ok(Lowered::Commands(vec![Step::plain(
        ClientCommand::TerminalInput(bytes.clone()),
        SendPolicy::Await,
    )]))
}

fn lower_tune(tuning: &Tuning, ctx: &LowerContext) -> Result<Lowered, Refusal> {
    let mut steps = Vec::new();
    if let Some(quality) = tuning.quality {
        steps.push(Step::plain(
            ClientCommand::SetQuality(quality),
            SendPolicy::Coalesce,
        ));
    }
    if let Some(view_only) = tuning.view_only {
        steps.push(Step::plain(
            ClientCommand::SetViewOnly(view_only),
            SendPolicy::Coalesce,
        ));
    }
    if let Some((w, h)) = tuning.size {
        // The unit split is already in the tree with its reason written down:
        // 80 columns is not 80 pixels and nothing in the type system would
        // catch the mix up (`crates/remote-core/src/commands.rs:84`). This
        // intent inherits it rather than inventing a third unit.
        let command = match ctx.grounding {
            Grounding::Pixels => ClientCommand::RequestResize {
                width: w,
                height: h,
            },
            Grounding::Cells => ClientCommand::ResizeTerminal { cols: w, rows: h },
            Grounding::None => {
                return Err(Refusal::limb(
                    RefusalCode::NotSupported,
                    "this limb has no addressable space, so it has no size to change",
                ))
            }
        };
        steps.push(Step::plain(command, SendPolicy::Coalesce));
    }
    if steps.is_empty() {
        // A tune that changes nothing still consumes a lease and a settlement,
        // so it is refused rather than sent (`02 §2.4`).
        return Err(Refusal::limb(
            RefusalCode::NotExpressible,
            "this tune sets no quality, no view only flag and no size, so there is nothing to change",
        ));
    }
    Ok(Lowered::Commands(steps))
}

fn pointer_limb(ctx: &LowerContext) -> Result<(), Refusal> {
    if matches!(ctx.grounding, Grounding::Pixels) {
        return Ok(());
    }
    Err(Refusal::limb(
        RefusalCode::NotSupported,
        "this limb's coordinate space is not pixels, so it has no pointer to move",
    ))
}

/// Fold the idempotent settings in a plan down to the last of each kind
/// (`08 §4.3`).
///
/// Three queued `SetQuality` calls should apply the last one, not all three.
/// Returns how many were folded out, for [`Gaps::settings_coalesced`].
///
/// This is the ONLY coalescing the plane does on the intent side. `08 §7.5` is
/// absolute about the rest: within one limb, intents dispatch in submission
/// order, one at a time, with no merging of any kind, because reordering two
/// key events changes what was typed and batching two pointer events loses the
/// intermediate position, which for a drag is the whole gesture.
///
/// [`Gaps::settings_coalesced`]: crate::backpressure::Gaps::settings_coalesced
pub fn coalesce_settings(steps: &mut Vec<Step>) -> u32 {
    let before = steps.len();
    let mut seen = Vec::new();
    let mut keep = vec![true; steps.len()];
    // Walked backwards so the LAST of each kind is the one kept.
    for (index, step) in steps.iter().enumerate().rev() {
        if step.policy != SendPolicy::Coalesce {
            continue;
        }
        let kind = setting_kind(&step.command);
        if seen.contains(&kind) {
            keep[index] = false;
        } else {
            seen.push(kind);
        }
    }
    let mut index = 0;
    steps.retain(|_| {
        let kept = keep[index];
        index += 1;
        kept
    });
    (before - steps.len()) as u32
}

/// Which idempotent setting this is, for the fold above.
///
/// A discriminant rather than the command, because two `SetQuality` calls with
/// different presets are the same setting and must fold to one.
fn setting_kind(command: &ClientCommand) -> u8 {
    match command {
        ClientCommand::SetQuality(_) => 0,
        ClientCommand::SetViewOnly(_) => 1,
        ClientCommand::RequestResize { .. } => 2,
        ClientCommand::ResizeTerminal { .. } => 3,
        ClientCommand::SetAlwaysRefresh(_) => 4,
        ClientCommand::SetPreferScancodes(_) => 5,
        ClientCommand::Refresh => 6,
        _ => u8::MAX,
    }
}
