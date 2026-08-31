//! The action space, and the two things the adapter does with it that the
//! plane must not.
//!
//! `15 §4.1` tabulates eleven model facing actions and `00 R44` (WA-17) folds
//! the seven pointer ones into `dvv_click`'s `action` argument so the tool
//! count stays where `04 §4.1` argued it should. This module is that argument
//! turned into code: one place that turns a verb and a bag of arguments into an
//! [`IntentKind`], used by the MCP tool and by the CLI verb alike, so the two
//! cannot drift.
//!
//! ## The two adapter only behaviours
//!
//! **`terminate` never reaches the plane** (`00 R43` WA-7). Three model
//! families emit it meaning "I have finished the task". Lowering it to
//! `ClientCommand::Disconnect` would let a model drop somebody's RDP session,
//! possibly logging them out, with no user gesture behind it, and the machines
//! an agent drives here are frequently machines a person is also looking at in
//! a pane. [`lower`] answers it with [`Lowered::EndOfEpisode`], which carries
//! no intent at all, and `15 §4.6`'s recommended default follows: release the
//! lease, do not close the limb. Releasing costs nothing and stops an idle
//! agent holding a machine hostage; closing destroys work.
//!
//! **A modifier alias is resolved here and reported, never resolved quietly.**
//! `limb_core::keys` is a fixed table with no aliases and its own comment says
//! why: `Control` is not a key, `ControlLeft` and `ControlRight` are, and a
//! PLANE that quietly resolved the first to the second would be choosing a
//! physical key on the agent's behalf in the one intent whose whole purpose is
//! to name a physical key. That ruling is about the plane and it stands. An
//! adapter is allowed to be ergonomic provided it is not silent, so `ctrl+c`
//! resolves to `ControlLeft` plus `c` and the result says so under `resolved`,
//! and an agent that meant the other side names `ControlRight` and gets it.
//!
//! ## What is not here, and why it is refused rather than approximated
//!
//! `visit_url`, `web_search`, `history_back`, `open_app`, `focus_window`,
//! `close_window`, `minimize`, `maximize` and `resize_window` are in three
//! of the four model families `15 §5` surveys and in none of ours. The first
//! three are browser verbs and `00 R4` puts no browser limb in version 1. The
//! rest need window structure, and `00 R42` (WA-4) rules that this build does
//! not have it and must not fabricate it. Each gets a refusal naming which of
//! those two it is, because an agent told "unknown action" retries with a
//! different spelling.

use crate::error::{codes, ToolError};
use limb_core::intent::{
    Button, CommandSpec, IntentKind, Point, ReadForm, ScrollDirection, WaitUntil,
};
use limb_core::keys::NamedKey;
use std::time::Duration;

/// What `dvv_click`'s `action` argument takes (`00 R44` WA-17).
///
/// Seven values on one tool rather than seven tools. `04 §4.1` argues that
/// tool count is a cost and that a large manifest degrades tool selection
/// measurably, and this is that argument applied to the half of the action
/// space that is all the same gesture with different buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerAction {
    /// Move without pressing anything. An ACTION and not an observation: hover
    /// opens menus and fires handlers, so it needs `control` and a lease.
    Move,
    /// Left button, once.
    Click,
    /// Left button, twice, inside a double click interval we cannot query.
    Double,
    /// Right button, once.
    Right,
    /// Middle button, once.
    Middle,
    /// Press, travel, release. Atomic, and an interrupted one is a COMPLETED
    /// drag to the wrong place rather than a cancelled one.
    Drag,
    /// Turn the wheel, in clicks. There is no pixel magnitude on either wire.
    Scroll,
}

impl PointerAction {
    /// Every value, for the tool schema's `enum` and for the test that walks
    /// it. One list, so a value added to the enum and forgotten in the schema
    /// fails a test rather than confusing a model.
    pub const ALL: &'static [PointerAction] = &[
        PointerAction::Move,
        PointerAction::Click,
        PointerAction::Double,
        PointerAction::Right,
        PointerAction::Middle,
        PointerAction::Drag,
        PointerAction::Scroll,
    ];

    /// The spelling on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            PointerAction::Move => "move",
            PointerAction::Click => "click",
            PointerAction::Double => "double",
            PointerAction::Right => "right",
            PointerAction::Middle => "middle",
            PointerAction::Drag => "drag",
            PointerAction::Scroll => "scroll",
        }
    }

    /// Parse one, with a refusal naming the whole set rather than saying no.
    pub fn parse(s: &str) -> Result<PointerAction, ToolError> {
        PointerAction::ALL
            .iter()
            .copied()
            .find(|a| a.as_str() == s.trim())
            .ok_or_else(|| {
                ToolError::bad_request(format!(
                    "{s:?} is not a pointer action; it is one of {}",
                    PointerAction::ALL
                        .iter()
                        .map(|a| a.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }
}

/// The arguments a pointer action reads, already parsed out of the tool call.
///
/// A struct rather than seven positional parameters, because six of the seven
/// actions ignore most of them and a call site with four `None`s in a row is
/// where the wrong one gets passed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PointerArgs {
    pub x: Option<u16>,
    pub y: Option<u16>,
    /// The far end of a drag.
    pub to_x: Option<u16>,
    pub to_y: Option<u16>,
    /// `up`, `down`, `left` or `right`, for a scroll.
    pub direction: Option<String>,
    /// Wheel clicks. There is no other unit.
    pub clicks: Option<u8>,
    /// A pixel delta, which is refused rather than converted. Accepted into
    /// this struct on purpose: a model that sends one has to be told WHY it
    /// cannot be served, and a parser that never saw the field would say
    /// "unknown argument" instead.
    pub dx: Option<i32>,
    pub dy: Option<i32>,
    /// Modifiers held for the duration, as named keys or as the aliases this
    /// module resolves.
    pub modifiers: Vec<String>,
    /// Which button a drag uses. Left when absent.
    pub button: Option<String>,
}

/// A pointer action lowered, with whatever the adapter resolved on the way.
#[derive(Debug, Clone)]
pub struct LoweredPointer {
    pub kind: IntentKind,
    /// Every alias this call resolved, as `asked => got`. Empty when the caller
    /// named real keys. Reported in the result so no resolution is silent.
    pub resolved: Vec<String>,
}

/// Turn one pointer action into an intent.
///
/// # Errors
///
/// A [`ToolError`] for a coordinate that is missing, a direction that is not
/// one of four, a click count above two, or a scroll expressed in pixels.
/// Never a silent substitution.
pub fn lower_pointer(
    action: PointerAction,
    args: &PointerArgs,
) -> Result<LoweredPointer, ToolError> {
    // A pixel scroll is refused before anything else is parsed, so the model
    // gets the sentence that explains the wire rather than a complaint about a
    // missing `direction` (`00 R47c`, `15 §4.1`).
    if action == PointerAction::Scroll && (args.dx.is_some() || args.dy.is_some()) {
        let refusal = agent_plane::pixel_scroll_refusal(args.dx.unwrap_or(0), args.dy.unwrap_or(0));
        return Err(ToolError::new(refusal.reason.as_str(), refusal.because));
    }

    let at = point(args.x, args.y, "x and y")?;
    let (modifiers, resolved) = parse_modifiers(&args.modifiers)?;

    let kind = match action {
        PointerAction::Move => IntentKind::Move { to: at },
        PointerAction::Click => IntentKind::Click {
            at,
            button: Button::Left,
            count: 1,
            modifiers,
        },
        PointerAction::Double => IntentKind::Click {
            at,
            button: Button::Left,
            count: 2,
            modifiers,
        },
        PointerAction::Right => IntentKind::Click {
            at,
            button: Button::Right,
            count: 1,
            modifiers,
        },
        PointerAction::Middle => IntentKind::Click {
            at,
            button: Button::Middle,
            count: 1,
            modifiers,
        },
        PointerAction::Drag => IntentKind::Drag {
            from: at,
            to: point(args.to_x, args.to_y, "toX and toY")?,
            button: parse_button(args.button.as_deref())?,
        },
        PointerAction::Scroll => {
            let direction = args.direction.as_deref().ok_or_else(|| {
                ToolError::bad_request(
                    "a scroll needs a direction of up, down, left or right; there is no pixel delta on either wire, so a magnitude goes in clicks",
                )
            })?;
            IntentKind::Scroll {
                at,
                direction: parse_direction(direction)?,
                clicks: args.clicks.unwrap_or(1),
            }
        }
    };
    Ok(LoweredPointer { kind, resolved })
}

/// What a computer use verb turned into.
#[derive(Debug, Clone)]
pub enum Lowered {
    /// Send it.
    Intent(IntentKind),
    /// The agent says it is finished. **Nothing goes on the wire** (`00 R43`
    /// WA-7).
    EndOfEpisode(Episode),
}

/// The agent's own report that it is done, absorbed by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Episode {
    /// Whatever the model said: `success`, `failure`, or its own word for it.
    /// Passed through untouched, because it is the model's claim and not ours.
    pub status: String,
    pub summary: Option<String>,
    /// `15 §4.6`'s recommended default: release the lease, do not close the
    /// limb. Releasing costs nothing and stops an idle agent holding a machine
    /// hostage; closing destroys work.
    pub release_lease: bool,
    /// Always false, and it is a field rather than an absence so that a reader
    /// of this struct sees the ruling rather than having to know it.
    pub close_limb: bool,
}

impl Episode {
    fn new(status: String, summary: Option<String>) -> Episode {
        Episode {
            status,
            summary,
            release_lease: true,
            close_limb: false,
        }
    }
}

/// Lower one computer use verb from `15 §4.1`'s table.
///
/// Used by a model adapter that speaks somebody else's action space rather than
/// ours. The MCP tools call [`lower_pointer`] directly; this exists so that
/// `terminate` has exactly one place it can arrive and exactly one thing that
/// happens to it.
///
/// # Errors
///
/// A [`ToolError`] for a verb this build refuses, naming which of the two
/// reasons it is: a browser verb with no browser limb, or a window verb with no
/// window structure.
pub fn lower(verb: &str, args: &PointerArgs, text: Option<&str>) -> Result<Lowered, ToolError> {
    match verb.trim() {
        // The one that never reaches the plane.
        "terminate" => Ok(Lowered::EndOfEpisode(Episode::new(
            text.unwrap_or("finished").to_string(),
            None,
        ))),
        "mouse_move" => pointer(PointerAction::Move, args),
        "left_click" => pointer(PointerAction::Click, args),
        "right_click" => pointer(PointerAction::Right, args),
        "middle_click" => pointer(PointerAction::Middle, args),
        "double_click" => pointer(PointerAction::Double, args),
        "drag" => pointer(PointerAction::Drag, args),
        "scroll" => pointer(PointerAction::Scroll, args),
        "type" => Ok(Lowered::Intent(IntentKind::Type {
            text: text
                .ok_or_else(|| ToolError::bad_request("type needs text"))?
                .to_string(),
            wpm: None,
        })),
        "key" => {
            let (keys, _) = parse_keys(&[text
                .ok_or_else(|| ToolError::bad_request("key needs a key name or a chord"))?
                .to_string()])?;
            Ok(Lowered::Intent(IntentKind::Press { keys }))
        }
        "screenshot" => Ok(Lowered::Intent(IntentKind::ReadScreen {
            form: ReadForm::Pixels,
            region: None,
        })),
        "wait" => Ok(Lowered::Intent(IntentKind::Wait {
            until: WaitUntil::ScreenStable,
            quiet: None,
            timeout: None,
        })),
        "visit_url" | "web_search" | "history_back" | "goto" => Err(ToolError::new(
            codes::NOT_IMPLEMENTED,
            format!(
                "{verb} is a browser verb and this build has no browser limb (00 R4). Drive a browser through the desktop limb that is already showing it, or ask the user to open one"
            ),
        )),
        "open_app" | "focus_window" | "close_window" | "minimize" | "maximize"
        | "resize_window" | "list_windows" => Err(ToolError::new(
            codes::NOT_IMPLEMENTED,
            format!(
                "{verb} needs per window structure and neither RFB nor RDP carries it on this build, so there is nothing to name a window with. This build states that absence rather than fabricating a window list: read signals.window_structure. Act on what is on the screen instead"
            ),
        )),
        other => Err(ToolError::bad_request(format!(
            "{other:?} is not an action this adapter knows; the set is in 15 §4.1 and dvv_click's action argument carries the pointer half of it"
        ))),
    }
}

fn pointer(action: PointerAction, args: &PointerArgs) -> Result<Lowered, ToolError> {
    Ok(Lowered::Intent(lower_pointer(action, args)?.kind))
}

/// A command to run, with the timeout `05 §4.1` insists on.
///
/// Required, with no default, and the insistence is right: a command with no
/// timeout on a machine an agent cannot see is a hang nobody notices.
pub fn command_spec(
    command: String,
    cwd: Option<String>,
    timeout_ms: Option<u64>,
    max_output_bytes: Option<u64>,
) -> Result<CommandSpec, ToolError> {
    let timeout = timeout_ms.ok_or_else(|| {
        ToolError::bad_request(
            "a command needs timeoutMs, with no default: a command with no timeout on a machine you cannot see is a hang nobody notices",
        )
    })?;
    Ok(CommandSpec {
        command,
        cwd,
        env: Vec::new(),
        timeout: Duration::from_millis(timeout),
        stdin: None,
        max_output_bytes,
    })
}

/// The modifier aliases this adapter resolves, and the key each resolves to.
///
/// Left hand side, always, because it is the one a keyboard shortcut is
/// normally pressed with and because picking one and reporting it beats picking
/// one and hiding it. An agent that means the other side names `ControlRight`
/// and this table never sees it.
const ALIASES: &[(&str, &str)] = &[
    ("ctrl", "ControlLeft"),
    ("control", "ControlLeft"),
    ("shift", "ShiftLeft"),
    ("alt", "AltLeft"),
    ("option", "AltLeft"),
    ("altgr", "AltRight"),
    ("meta", "MetaLeft"),
    ("cmd", "MetaLeft"),
    ("command", "MetaLeft"),
    ("super", "MetaLeft"),
    ("win", "MetaLeft"),
    ("esc", "Escape"),
    ("return", "Enter"),
    ("del", "Delete"),
    ("ins", "Insert"),
    ("pgup", "PageUp"),
    ("pgdn", "PageDown"),
];

/// Resolve a list of key names or chords into named keys.
///
/// Every element may itself be a chord, so `["ctrl+alt+Delete"]` and
/// `["ctrl", "alt", "Delete"]` mean the same thing. The second return value is
/// every alias that was resolved, so the caller can report it.
///
/// # Errors
///
/// A [`ToolError`] with `UNKNOWN_KEY` for a name outside the table, naming the
/// two spellings a caller most often means when it fails.
pub fn parse_keys(names: &[String]) -> Result<(Vec<&'static NamedKey>, Vec<String>), ToolError> {
    let (keys, resolved) = parse_modifiers(names)?;
    if keys.is_empty() {
        return Err(ToolError::bad_request(
            "no key was named; give one name or a chord such as ctrl+alt+Delete",
        ));
    }
    Ok((keys, resolved))
}

/// The same, for a list that is allowed to be empty.
///
/// Held apart from [`parse_keys`] rather than given a flag, because the two
/// have opposite failure modes and a boolean argument at the call site does not
/// say which one is in force. A `dvv_key` with no key is a caller mistake worth
/// a refusal; a click with no modifiers is the ordinary case.
///
/// # Errors
///
/// A [`ToolError`] with `UNKNOWN_KEY` for a name outside the table.
pub fn parse_modifiers(
    names: &[String],
) -> Result<(Vec<&'static NamedKey>, Vec<String>), ToolError> {
    let mut keys = Vec::new();
    let mut resolved = Vec::new();
    for element in names {
        for part in element.split('+') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(key) = NamedKey::lookup(part) {
                keys.push(key);
                continue;
            }
            let alias = ALIASES
                .iter()
                .find(|(from, _)| from.eq_ignore_ascii_case(part));
            match alias.and_then(|(_, to)| NamedKey::lookup(to)) {
                Some(key) => {
                    resolved.push(format!("{part} => {}", key.name));
                    keys.push(key);
                }
                None => {
                    return Err(ToolError::new(
                        "UNKNOWN_KEY",
                        format!(
                            "{part:?} is not in the named key table. The table is the DOM code and key spellings, so a modifier is ControlLeft or ControlRight rather than Control, and a letter goes through dvv_type rather than here. A numeric code is a different action and needs the scancode capability, which is in no role bundle"
                        ),
                    ))
                }
            }
        }
    }
    Ok((keys, resolved))
}

fn point(x: Option<u16>, y: Option<u16>, which: &str) -> Result<Point, ToolError> {
    match (x, y) {
        (Some(x), Some(y)) => Ok(Point::new(x, y)),
        _ => Err(ToolError::bad_request(format!(
            "this action needs {which} in framebuffer pixels; read the size from dvv_status first, because they are not screen pixels and not CSS pixels"
        ))),
    }
}

fn parse_button(name: Option<&str>) -> Result<Button, ToolError> {
    match name.map(str::trim).unwrap_or("left") {
        "left" => Ok(Button::Left),
        "middle" => Ok(Button::Middle),
        "right" => Ok(Button::Right),
        other => Err(ToolError::bad_request(format!(
            "{other:?} is not a button; the wire carries three, left, middle and right, and an agent gets no more than a person does"
        ))),
    }
}

fn parse_direction(name: &str) -> Result<ScrollDirection, ToolError> {
    match name.trim() {
        "up" => Ok(ScrollDirection::Up),
        "down" => Ok(ScrollDirection::Down),
        "left" => Ok(ScrollDirection::Left),
        "right" => Ok(ScrollDirection::Right),
        other => Err(ToolError::bad_request(format!(
            "{other:?} is not a scroll direction; it is up, down, left or right, and the magnitude goes in clicks"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminate_produces_no_intent_at_all() {
        // `00 R43` WA-7. The assertion is on the SHAPE and not on a flag: there
        // is no intent inside a `Lowered::EndOfEpisode`, so there is nothing a
        // later edit could accidentally dispatch.
        let lowered = lower("terminate", &PointerArgs::default(), Some("success")).unwrap();
        match lowered {
            Lowered::EndOfEpisode(episode) => {
                assert_eq!(episode.status, "success");
                assert!(episode.release_lease);
                assert!(
                    !episode.close_limb,
                    "closing a limb on terminate would drop somebody's session with no user gesture behind it"
                );
            }
            Lowered::Intent(kind) => panic!("terminate lowered to {}", kind.name()),
        }
    }

    #[test]
    fn a_pixel_scroll_is_refused_rather_than_converted() {
        let args = PointerArgs {
            x: Some(10),
            y: Some(10),
            dy: Some(-240),
            ..PointerArgs::default()
        };
        let error = lower_pointer(PointerAction::Scroll, &args).unwrap_err();
        assert_eq!(error.code, "NOT_EXPRESSIBLE");
        assert!(error.message.contains("clicks"));
        assert!(error.message.contains("will not invent"));
    }

    #[test]
    fn an_alias_is_resolved_and_reported() {
        let (keys, resolved) = parse_keys(&["ctrl+alt+Delete".to_string()]).unwrap();
        assert_eq!(
            keys.iter().map(|k| k.name).collect::<Vec<_>>(),
            ["ControlLeft", "AltLeft", "Delete"]
        );
        assert_eq!(resolved, ["ctrl => ControlLeft", "alt => AltLeft"]);
    }

    #[test]
    fn naming_a_side_never_reaches_the_alias_table() {
        // An agent that means the right hand key says so and gets it, with
        // nothing resolved on its behalf.
        let (keys, resolved) = parse_keys(&["ControlRight+Delete".to_string()]).unwrap();
        assert_eq!(
            keys.iter().map(|k| k.name).collect::<Vec<_>>(),
            ["ControlRight", "Delete"]
        );
        assert!(resolved.is_empty());
    }

    #[test]
    fn a_letter_is_steered_to_type_rather_than_guessed_at() {
        // The table is special keys only. A refusal that says where to go
        // instead is the difference between an agent that stops asking and one
        // that tries three spellings.
        let error = parse_keys(&["c".to_string()]).unwrap_err();
        assert_eq!(error.code, "UNKNOWN_KEY");
        assert!(error.message.contains("dvv_type"));
    }

    #[test]
    fn a_window_verb_is_refused_with_the_reason_rather_than_approximated() {
        let error = lower("focus_window", &PointerArgs::default(), None).unwrap_err();
        assert_eq!(error.code, codes::NOT_IMPLEMENTED);
        assert!(error.message.contains("window_structure"));
    }

    #[test]
    fn a_browser_verb_names_the_ruling_that_removed_it() {
        let error = lower("visit_url", &PointerArgs::default(), None).unwrap_err();
        assert!(error.message.contains("no browser limb"));
    }

    #[test]
    fn every_pointer_action_round_trips_its_spelling() {
        for action in PointerAction::ALL {
            assert_eq!(PointerAction::parse(action.as_str()).unwrap(), *action);
        }
    }
}
