//! The canonical capability vocabulary.
//!
//! `00 R20` settles who owns this: `02 §5` defines the enum, `09` owns the
//! threat model and the policy that sits on it, `04` owns the mapping onto MCP
//! and onto tokens, and `07` owns the mapping onto BrowserGlass's twenty one
//! member enum. Nobody defines a second one. The reason is placement rather
//! than seniority: this is what [`Limb::capabilities`] returns, and a security
//! document that owned a type in the contract crate would be a document that
//! has to be edited every time a limb is added.
//!
//! Seventeen members. Deny by default, no hierarchy, no wildcard, no
//! inheritance, which is BrowserGlass's rule taken literally: `admin` does not
//! imply `view`, `control` does not imply `view`, `exec` does not imply
//! `terminal.read`. A test walks every pair and asserts it.
//!
//! [`Limb::capabilities`]: crate::limb::Limb::capabilities

use crate::intent::{IntentKind, IntentName, ReadForm};
use crate::limb::PerceptionSet;

/// One thing a grant may authorise.
///
/// The ordering of the variants is the numbering in `02 §5.2` and it is load
/// bearing in one place only: [`CapabilitySet`] uses the discriminant as a bit
/// index, so inserting a member in the middle renumbers a set that has been
/// written down. Add at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// Limb state, protocol, size, lease holder, damage, waits, and a
    /// terminal's STATE as opposed to its output. The floor.
    View,
    /// Pixels leaving the process: a screenshot, a region, a diff.
    Capture,
    /// Driving: pointer, named keys, typed text, quality and resize. Also the
    /// right to ever hold a control lease.
    ///
    /// Undivided, and `00 R29` overrode `07`'s proposed split to say so. A
    /// pointer that may move but not click is not a safety boundary: hover
    /// opens menus, reveals tooltips, triggers drag targets, and on Windows
    /// raises focus follows mouse behaviour where it is configured. More
    /// mechanically, `ClientCommand::Pointer` carries `x`, `y` and
    /// `button_mask` in one message
    /// (`crates/remote-core/src/commands.rs:13`), so the split would have to
    /// be enforced by inspecting a payload field rather than by refusing a
    /// message.
    Control,
    /// Opening a limb against a machine.
    Open,
    /// Closing one.
    Close,
    /// Force claiming a lease, revoking another party's. `08 §5.2` reserves it
    /// for the shell's own force release paths.
    Admin,
    /// The saved machine library and what discovery found. Never a secret.
    ///
    /// There is no `hosts.write`, deliberately. A limb the plane opened never
    /// adopts its endpoint into the host library, so nothing an agent can do
    /// writes a host row and a capability for it would be a capability for a
    /// tool that does not exist (`02 §5.6`).
    HostsRead,
    /// Reading the remote clipboard.
    ClipboardRead,
    /// Writing it.
    ClipboardWrite,
    /// Terminal output and scrollback.
    TerminalRead,
    /// Bytes into the PTY, and the declared cwd and env.
    TerminalWrite,
    /// Listing and downloading over the SFTP sidecar.
    FilesRead,
    /// Uploading, renaming, removing.
    FilesWrite,
    /// Navigation on a browser limb. Offered by no other limb, which is the
    /// general rule rather than an exception: a limb kind may contribute
    /// capabilities only it can ever offer.
    BrowserNavigate,
    /// Tab management on a browser limb.
    BrowserTabs,
    /// Running an arbitrary command on a remote machine. **In no bundle.**
    ///
    /// This is our `evaluate`, and `02 §5.4` gives the argument point by
    /// point. It is not implied by `terminal.read`, because reading what a
    /// shell prints is observation and running a command is authorship. It is
    /// not implied by `terminal.write`, because bytes into a PTY reach a shell
    /// a person may be watching in a pane, while a command run over a second
    /// SSH `exec` channel leaves no trace on any screen at all. It is not
    /// implied by `control`, because holding the keyboard is not authority to
    /// author code. It is not implied by `admin`, because being able to throw
    /// an agent off a machine is not the same authority as reading that
    /// machine's files.
    ///
    /// It is also the only member of this enum with no counterpart anywhere in
    /// the existing product: there is no command in `src-tauri/src/lib.rs`'s
    /// `invoke_handler` that runs an arbitrary command on a remote machine,
    /// because the interactive product never needed one. This is a genuinely
    /// new power the design creates, and saying so is the honest half of
    /// shipping it.
    Exec,
    /// Synthesising a raw scancode outside the named key table. **In no
    /// bundle.**
    ///
    /// `00 R30` draws the line. A keysym is what a key produces and a scancode
    /// is which physical key it is, so a numeric code outside
    /// [`crate::keys::NAMED_KEYS`] drives the remote's keymap directly. Three
    /// things stop being true when it does: the layout independent path is
    /// bypassed, the plane's record of what is held stops matching what the
    /// remote believes, and `ClientCommand::ReleaseAllKeys` can no longer be
    /// trusted to clean up, which matters because a stuck modifier is the
    /// specific bug that command exists for.
    ///
    /// Note what is not claimed. Raw scancodes are already reachable from the
    /// webview today: `framing::decode_input`
    /// (`src-tauri/src/framing.rs:232`) reads a full `u32` keycode and passes
    /// it through. The webview is trusted and a grant is not, and that is the
    /// entire difference.
    Scancode,
}

impl Capability {
    /// Every capability, in `02 §5.2`'s numbering. A test asserts the count is
    /// seventeen, because the number is quoted in four documents and a
    /// silently grown enum makes all four wrong at once.
    pub const ALL: &'static [Capability] = &[
        Capability::View,
        Capability::Capture,
        Capability::Control,
        Capability::Open,
        Capability::Close,
        Capability::Admin,
        Capability::HostsRead,
        Capability::ClipboardRead,
        Capability::ClipboardWrite,
        Capability::TerminalRead,
        Capability::TerminalWrite,
        Capability::FilesRead,
        Capability::FilesWrite,
        Capability::BrowserNavigate,
        Capability::BrowserTabs,
        Capability::Exec,
        Capability::Scancode,
    ];

    /// The two that appear in no role bundle and can only be granted by
    /// naming the literal string, which is BrowserGlass's treatment of
    /// `evaluate`, `cdp` and `intercept` copied for the same reason.
    pub const NEVER_BUNDLED: &'static [Capability] = &[Capability::Exec, Capability::Scancode];

    /// The name on the wire and in a grant. Dotted where the capability is one
    /// half of a read and write pair, flat where it is not, which is `04`'s
    /// working set adopted verbatim so that `04` needs no edit.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::View => "view",
            Capability::Capture => "capture",
            Capability::Control => "control",
            Capability::Open => "open",
            Capability::Close => "close",
            Capability::Admin => "admin",
            Capability::HostsRead => "hosts.read",
            Capability::ClipboardRead => "clipboard.read",
            Capability::ClipboardWrite => "clipboard.write",
            Capability::TerminalRead => "terminal.read",
            Capability::TerminalWrite => "terminal.write",
            Capability::FilesRead => "files.read",
            Capability::FilesWrite => "files.write",
            Capability::BrowserNavigate => "browser.navigate",
            Capability::BrowserTabs => "browser.tabs",
            Capability::Exec => "exec",
            Capability::Scancode => "scancode",
        }
    }

    /// Parse a name from a grant. `None` for anything unrecognised, following
    /// the rule `ProtocolKind::parse` already sets: a value written by a newer
    /// build is ignored, never guessed at. Guessing here would be granting an
    /// authority nobody wrote down.
    pub fn parse(s: &str) -> Option<Capability> {
        Capability::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == s.trim())
    }

    /// Whether this capability is absent from every bundle in
    /// [`RoleBundle::ALL`].
    pub fn is_never_bundled(self) -> bool {
        Capability::NEVER_BUNDLED.contains(&self)
    }

    const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a grant, or a limb, holds.
///
/// Deny by default is the whole behaviour: [`CapabilitySet::default`] is
/// empty, [`CapabilitySet::allows`] is a membership test and nothing else, and
/// there is no path through this type by which holding one capability produces
/// another. That is not an accident of the implementation, it is the
/// implementation: a bitset cannot express a hierarchy, so nobody can add one
/// without changing the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CapabilitySet(u32);

impl CapabilitySet {
    /// A grant that may do nothing at all. The starting point for every
    /// approval.
    pub const DENY_ALL: CapabilitySet = CapabilitySet(0);

    /// Build a set from a list of capabilities.
    pub fn of(caps: &[Capability]) -> CapabilitySet {
        caps.iter()
            .fold(CapabilitySet::DENY_ALL, |set, c| set.with(*c))
    }

    /// The same set with one more capability in it.
    pub const fn with(self, cap: Capability) -> CapabilitySet {
        CapabilitySet(self.0 | cap.bit())
    }

    /// The same set with one removed.
    pub const fn without(self, cap: Capability) -> CapabilitySet {
        CapabilitySet(self.0 & !cap.bit())
    }

    /// Is this capability held? No inheritance, no wildcard, no prefix match.
    pub const fn allows(self, cap: Capability) -> bool {
        self.0 & cap.bit() != 0
    }

    /// Are all of these held? The question a capability check actually asks,
    /// since `read_screen` in a pixel form needs two (`§5.5`).
    pub fn allows_all(self, caps: CapabilitySet) -> bool {
        self.0 & caps.0 == caps.0
    }

    /// What an attachment may ACTUALLY do on a limb: the intersection of what
    /// the grant carries and what the limb can ever offer.
    ///
    /// This is the whole of "capabilities per limb". The plane needs no table
    /// keyed on `ProtocolKind`, which is what keeps the MCP layer free of a
    /// `match kind` (`01 §5 I2`), and a grant carrying `exec` against a limb
    /// that cannot execute anything gets a refusal naming the limb rather than
    /// a silent no-op.
    pub const fn intersect(self, other: CapabilitySet) -> CapabilitySet {
        CapabilitySet(self.0 & other.0)
    }

    /// Which capabilities in `needed` this set does not hold. Empty means the
    /// check passed. Returned rather than a boolean because the refusal has to
    /// name what was missing or the agent learns nothing.
    pub fn missing(self, needed: CapabilitySet) -> Vec<Capability> {
        needed.iter().filter(|c| !self.allows(*c)).collect()
    }

    /// Nothing is held.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Every capability in the set, in `02 §5.2`'s order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .iter()
            .copied()
            .filter(move |c| self.allows(*c))
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        iter.into_iter()
            .fold(CapabilitySet::DENY_ALL, |set, c| set.with(c))
    }
}

/// A named group of capabilities, expanded at approval time and then
/// discarded: never stored, never sent, never consulted in a decision.
///
/// Five, keeping BrowserGlass's names so the concept transfers. The
/// asymmetries between them are deliberate and each has a reason, recorded on
/// the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RoleBundle {
    /// A watcher. Carries `view` and NOT `terminal.read`, so it sees that a
    /// terminal is connected and does not see what it printed. That is a real
    /// product shape: showing somebody the wall without showing them the
    /// contents.
    Observer,
    /// Carries `clipboard.write` and not `clipboard.read`, which is
    /// BrowserGlass's asymmetry copied exactly. Writing puts something known
    /// onto a machine. Reading takes whatever the person at that machine last
    /// copied, which is a password more often than anyone would like.
    Driver,
    /// Everything in `driver`, plus the capabilities that open, close,
    /// photograph and move files.
    Operator,
    /// What an unattended agent gets.
    ///
    /// Carries `capture`, which is a deliberate divergence from BrowserGlass,
    /// whose `agent` bundle omits it. Their agents have a DOM to read. A
    /// desktop agent without `capture` is blind, so a bundle that omits it is
    /// a bundle nobody will use, and a bundle nobody uses is one people work
    /// around by naming capabilities by hand, which loses the review value the
    /// bundle existed for.
    ///
    /// Carries neither `open` nor `close`: an agent drives what it was given,
    /// and an agent that opens its own machines is an operator and the person
    /// granting that should have to say so. Carries no `files.*` and no
    /// `clipboard.read`, because both are exfiltration paths that need no
    /// screen and neither is needed to click on things.
    Agent,
    /// Every capability except the two in [`Capability::NEVER_BUNDLED`].
    Owner,
}

impl RoleBundle {
    /// Every bundle. The test that proves `exec` and `scancode` are in none of
    /// them walks this slice, so a sixth bundle is covered the day it is
    /// added rather than the day somebody remembers.
    pub const ALL: &'static [RoleBundle] = &[
        RoleBundle::Observer,
        RoleBundle::Driver,
        RoleBundle::Operator,
        RoleBundle::Agent,
        RoleBundle::Owner,
    ];

    /// The name a person picks in the approval UI.
    pub const fn as_str(self) -> &'static str {
        match self {
            RoleBundle::Observer => "observer",
            RoleBundle::Driver => "driver",
            RoleBundle::Operator => "operator",
            RoleBundle::Agent => "agent",
            RoleBundle::Owner => "owner",
        }
    }

    /// What this bundle expands to.
    ///
    /// Written out per bundle rather than composed from the others, even
    /// though `operator` is described as "everything in driver plus". A
    /// composition would mean adding a capability to `driver` silently adds it
    /// to `operator`, which is inheritance arriving through the back door in a
    /// design whose first rule is that there is none.
    pub fn expand(self) -> CapabilitySet {
        use Capability::*;
        match self {
            RoleBundle::Observer => CapabilitySet::of(&[View]),
            RoleBundle::Driver => CapabilitySet::of(&[
                View,
                Control,
                ClipboardWrite,
                TerminalRead,
                TerminalWrite,
                BrowserNavigate,
                BrowserTabs,
            ]),
            RoleBundle::Operator => CapabilitySet::of(&[
                View,
                Control,
                ClipboardWrite,
                TerminalRead,
                TerminalWrite,
                BrowserNavigate,
                BrowserTabs,
                Open,
                Close,
                Capture,
                ClipboardRead,
                HostsRead,
                FilesRead,
                FilesWrite,
            ]),
            RoleBundle::Agent => CapabilitySet::of(&[
                View,
                Control,
                Capture,
                TerminalRead,
                TerminalWrite,
                BrowserNavigate,
                BrowserTabs,
            ]),
            RoleBundle::Owner => Capability::ALL
                .iter()
                .copied()
                .filter(|c| !c.is_never_bundled())
                .collect(),
        }
    }
}

impl std::fmt::Display for RoleBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule whose capability depends on an argument rather than on the intent.
///
/// Two of them, expressed as data so a caller can enumerate them, which is the
/// shape BrowserGlass's `ParamCapabilityRule` uses
/// (`packages/protocol/src/wire/capabilities.ts`). Enumerable matters because
/// an agent that cannot discover why a call it is allowed to make was refused
/// will make it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamRule {
    pub intent: IntentName,
    pub base: Capability,
    pub additional: Capability,
    /// The condition, in the words shown to the agent.
    pub when: &'static str,
}

/// The two parameter dependent rules of `02 §5.5`.
///
/// The second is the more interesting one and it is a consequence of `03 §6.5`
/// recommending no OCR in version 1. On a terminal limb, waiting for text is
/// free and exact. On a desktop limb it is a pixel operation with a confidence
/// of inferred at best, and it costs the capability that pixels cost. An agent
/// holding `view` and not `capture` can wait for a terminal to print a string
/// and cannot wait for a dialog to say one, which is the honest division.
pub const PARAM_RULES: &[ParamRule] = &[
    ParamRule {
        intent: IntentName::ReadScreen,
        base: Capability::View,
        additional: Capability::Capture,
        when: "the requested form is pixels rather than text or cells",
    },
    ParamRule {
        intent: IntentName::Wait,
        base: Capability::View,
        additional: Capability::Capture,
        when: "the condition matches text on a limb with no character grid, because matching text on a desktop means reading pixels",
    },
];

/// What this intent costs, on this limb.
///
/// One function rather than a table on the caller's side, because the
/// parameter dependent rules mean the answer is not a property of the intent
/// alone: the same `read_screen` costs `view` or `view` plus `capture`
/// depending on an argument, and the same `wait` costs one or two depending on
/// whether the limb has a character grid.
pub fn capabilities_for(kind: &IntentKind, perception: &PerceptionSet) -> CapabilitySet {
    use Capability::*;
    match kind {
        IntentKind::Type { .. } | IntentKind::Press { .. } => CapabilitySet::of(&[Control]),
        IntentKind::Scancode { .. } => CapabilitySet::of(&[Scancode]),
        IntentKind::Move { .. }
        | IntentKind::Click { .. }
        | IntentKind::Drag { .. }
        | IntentKind::Scroll { .. }
        | IntentKind::Tune { .. } => CapabilitySet::of(&[Control]),
        IntentKind::Wait { until, .. } => {
            // PARAM_RULES[1]. Text on a limb with no cells is a pixel
            // operation, so it costs what pixels cost.
            if until.reads_text() && !perception.cells {
                CapabilitySet::of(&[View, Capture])
            } else {
                CapabilitySet::of(&[View])
            }
        }
        // PARAM_RULES[0].
        IntentKind::ReadScreen { form, .. } => match form {
            ReadForm::Pixels => CapabilitySet::of(&[View, Capture]),
            ReadForm::Text | ReadForm::Cells => CapabilitySet::of(&[View]),
        },
        IntentKind::Capture { .. } => CapabilitySet::of(&[Capture]),
        IntentKind::Exec { .. } | IntentKind::PtyRun { .. } => CapabilitySet::of(&[Exec]),
        IntentKind::Declare { .. } | IntentKind::SendBytes { .. } => {
            CapabilitySet::of(&[TerminalWrite])
        }
        IntentKind::ClipboardGet => CapabilitySet::of(&[ClipboardRead]),
        IntentKind::ClipboardSet { .. } => CapabilitySet::of(&[ClipboardWrite]),
        // Withdrawing your own request is not a privilege. Gating it would
        // mean an agent that has lost a capability mid task cannot stop the
        // work it already started (`02 §2.4`).
        IntentKind::Cancel { .. } => CapabilitySet::DENY_ALL,
        // An intent variant this build's table has never heard of.
        //
        // This arm is new and it is a cost of the move: [`IntentKind`] is
        // `#[non_exhaustive]` and now lives in `remote-core`, so a match here
        // is a match on another crate's enum and the compiler stops proving
        // the table total. `02 AC-3` still holds for the eighteen that exist,
        // and the test that walks `IntentName::ALL` is what keeps proving it.
        //
        // It fails CLOSED, and not with `DENY_ALL`: that constant is the empty
        // set, which is "costs nothing" (what `cancel` above wants) and would
        // hand a brand new intent to every grant for free. The two capabilities
        // no role bundle contains are what it asks for instead (`00 R30`), so
        // an intent nobody has written a rule for cannot be exercised by a
        // bundle at all.
        _ => CapabilitySet::of(Capability::NEVER_BUNDLED),
    }
}
