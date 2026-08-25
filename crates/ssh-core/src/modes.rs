//! Undo whatever xterm private modes a dead SSH session left switched on.
//!
//! The concrete bug this exists to prevent: the user runs tmux, vim, htop, or
//! `less` over SSH. Any of those programs turns on mouse reporting
//! (`CSI ? 1000 h`, `?1002h`, `?1003h`, `?1006h`), bracketed paste (`?2004h`),
//! focus event reporting (`?1004h`), or the alternate screen (`?1049h`), all
//! DEC private modes set with DECSET and cleared with DECRST (`CSI ? Pm h`
//! and `CSI ? Pm l`; ECMA-48 calls the non-private form SM/RM). A
//! well-behaved program resets everything it turned on before it exits. A
//! severed link does not give it the chance: the SSH connection drops mid
//! session and the local terminal emulator is left believing the mouse still
//! reports, paste is still bracketed, and the screen is still the alternate
//! buffer. The user then sees raw escape garbage every time the mouse moves,
//! pasted text arriving wrapped in `ESC [200~` / `ESC [201~`, or a screen
//! that never comes back from `less`.
//!
//! [`ModeTracker`] watches the bytes flowing from the remote to the local
//! terminal (it never sees local keystrokes, it does not need to), keeping a
//! live account of which private modes are currently on. When the link dies,
//! the caller asks it for [`ModeTracker::reset_sequence`] and writes those
//! bytes straight to the local terminal, putting it back to a sane state
//! without waiting for, or trusting, the remote program to have cleaned up
//! after itself.

use std::collections::BTreeSet;

/// Hard ceiling on how many `;`-separated parameters a single CSI sequence
/// can contribute. xterm itself caps CSI parameters at 16; anything past
/// that is a hostile or corrupted stream, not a real terminal program, so
/// once the count is reached the rest of the sequence is swallowed and
/// ignored rather than grown without bound. Without a cap, a stream of
/// `CSI ?1;1;1;1;1;...` could otherwise make the parameter buffer grow
/// forever off a link that never disconnects.
const MAX_CSI_PARAMS: usize = 16;

/// The unconditional tail of every reset this module ever emits: DECSTR
/// (soft terminal reset, `CSI ! p`), selecting ASCII back into G0
/// (`ESC ( B`, undoing a line-drawing charset a curses program left
/// selected), an SGR reset (`CSI 0 m`, in case colors or reverse video were
/// left on), and clearing any scrolling region DECSTBM left behind
/// (`CSI r` with no parameters restores the full screen as the scroll
/// region). DECSTR alone does not reliably clear all of these on every
/// terminal, which is why each is spelled out rather than trusted to DECSTR.
const TAIL_RESET: &[u8] = b"\x1b[!p\x1b(B\x1b[0m\x1b[r";

/// xterm mouse tracking and coordinate-encoding modes (see xterm's
/// `ctlseqs.txt`, "Mouse Tracking"): 1000 (VT200 mouse tracking), 1001
/// (highlight tracking), 1002 (button-event tracking), 1003 (any-event
/// tracking), 1005 (UTF-8 extended coordinates), 1006 (SGR extended
/// coordinates), 1015 (urxvt extended coordinates), 1016 (SGR-pixels
/// coordinates). Deliberately excludes 1004 (focus events) and 2004
/// (bracketed paste): those are real modes tmux and friends also enable, but
/// they are not mouse modes, and callers that only want to know "is this a
/// mouse mode" should not have to special case them.
pub const MOUSE_MODES: &[u16] = &[1000, 1001, 1002, 1003, 1005, 1006, 1015, 1016];

/// Bracketed paste mode (`CSI ? 2004 h/l`). Left on, pasted text arrives at
/// the shell wrapped in `ESC [200~ ... ESC [201~` with no program left alive
/// to strip it, so the user's next paste appears as literal garbage.
pub const PASTE_MODE: u16 = 2004;

/// Is `n` one of [`MOUSE_MODES`]?
pub fn is_mouse_mode(n: u16) -> bool {
    MOUSE_MODES.contains(&n)
}

/// Alternate screen modes: 47 (the original xterm alternate screen), 1047
/// (alternate screen that also clears on entry), 1049 (1047 plus save and
/// restore of the cursor position, the one full-screen programs like tmux
/// and vim actually use today). All three are DECRST-cleared the same way,
/// `CSI ? <n> l`, they only differ in what entering them does to the saved
/// screen and cursor, which is irrelevant once we are just trying to leave.
fn is_alt_screen_mode(n: u16) -> bool {
    matches!(n, 47 | 1047 | 1049)
}

/// Where [`ModeTracker::feed`] currently is inside the byte stream.
///
/// This is a deliberately shallow version of the Paul Williams DEC ANSI
/// parser state table: it keeps only the states needed to (a) correctly
/// recognize `CSI ? Pm h` / `CSI ? Pm l` and (b) correctly *not* recognize
/// them when the same bytes appear inside an OSC, DCS, SOS, PM, or APC
/// string. It does not attempt to interpret SGR, cursor movement, or any
/// other control function; those bytes are consumed for the sake of correct
/// state transitions and then discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No sequence in progress. Plain text (the vast majority of a
    /// terminal session) is discarded here without inspection.
    Ground,
    /// Just saw `ESC` (0x1b). The next byte decides what kind of sequence
    /// this is.
    Escape,
    /// Just saw `ESC [`, no parameter or intermediate byte read yet. This
    /// is where the private marker `?` is recognized; once any digit,
    /// `;`, or intermediate byte arrives the parser moves on to
    /// [`State::CsiParam`] and a `?` there is no longer a private marker,
    /// it is malformed input.
    CsiEntry,
    /// Collecting `;`-separated parameter digits after the CSI marker
    /// byte (if any) and the first parameter byte.
    CsiParam,
    /// Saw an intermediate byte (0x20-0x2f) inside a CSI sequence. SM and
    /// RM never carry an intermediate byte, so a sequence that reaches
    /// this state is some other control function; its final byte is
    /// consumed but never dispatched as a mode change.
    CsiIntermediate,
    /// The CSI sequence is malformed or has exceeded [`MAX_CSI_PARAMS`].
    /// Everything up to the final byte is swallowed and the whole
    /// sequence is discarded rather than partially applied.
    CsiIgnore,
    /// Consuming the payload of an OSC, DCS, SOS, PM, or APC string. This
    /// is the state that keeps a window title or a DCS payload from ever
    /// reaching the CSI parameter logic, no matter what bytes it contains.
    StringConsume(StringKind),
    /// Saw `ESC` while consuming a string payload. The only byte that
    /// means anything special here is `\` (String Terminator, ST); any
    /// other byte means the `ESC` was not a terminator after all, so the
    /// string is abandoned and that byte is reprocessed as the start of a
    /// brand new escape sequence. This is what "ESC restarts a sequence"
    /// means for a string payload: the string sequence does not resume,
    /// it is simply over, and normal escape parsing takes over again from
    /// the byte that follows.
    StringEscape,
}

/// Which kind of string-payload sequence [`State::StringConsume`] is
/// swallowing. Only OSC recognizes BEL as a terminator; the others are
/// unconditionally read out here since this tracker has no use for their
/// contents, it only needs to keep them from leaking into the CSI parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringKind {
    /// Operating System Command (`ESC ]`). Terminated by BEL or ST.
    Osc,
    /// Device Control String (`ESC P`). Terminated by ST.
    Dcs,
    /// Start of String, Privacy Message, or Application Program Command
    /// (`ESC X`, `ESC ^`, `ESC _`). All three are read the same way here.
    SosPmApc,
}

/// Tracks which xterm private modes a remote session has left on, so the
/// exact bytes needed to turn them back off can be produced on disconnect.
///
/// Feed it every byte the remote sends, in order, as it arrives; it does
/// not need whole lines or whole escape sequences at a time; see
/// [`ModeTracker::feed`].
#[derive(Debug, Clone)]
pub struct ModeTracker {
    state: State,

    /// Whether the CSI sequence currently being collected began with the
    /// private marker `?`. Only `CSI ? Pm h/l` mutates tracked state;
    /// `CSI Pm h/l` without the marker is a different, non-private mode
    /// number space that this tracker has no business touching.
    csi_private: bool,
    /// Finished parameters of the CSI sequence in progress, in order.
    /// `None` marks an empty (elided) parameter, which is meaningfully
    /// different from a parameter of zero and must not be treated as one.
    csi_params: Vec<Option<u16>>,
    /// The parameter currently being read, accumulated digit by digit.
    csi_current: u32,
    /// Whether any digit has been seen for `csi_current` yet. Needed to
    /// tell an elided parameter (`;;`) apart from an explicit `0`.
    csi_current_has_digits: bool,

    /// Private modes currently believed to be on, DECTCEM (mode 25)
    /// excepted; see the field below for why that one is tracked
    /// separately. This includes the alternate screen modes (47, 1047,
    /// 1049) when they are set: their "on" state is abnormal exactly the
    /// same way a mouse mode's is, so the same on/off bookkeeping applies.
    active_modes: BTreeSet<u16>,
    /// DECTCEM, cursor visibility, needs the opposite sense from every
    /// other mode tracked here: its default state is visible (as if
    /// `?25h` had already been sent), and a program hides the cursor with
    /// `?25l`. Folding it into `active_modes` the same way as the others
    /// would mean a session that never touches mode 25 looks identical to
    /// one that turned it on, so it gets its own flag: `true` only once an
    /// explicit `?25l` has actually been seen and not yet undone by a
    /// `?25h`. A hidden cursor left behind reads as a terminal that has
    /// hung, which is exactly the kind of thing this module exists to fix.
    cursor_hidden: bool,
}

impl ModeTracker {
    /// A tracker with nothing outstanding, parser at [`State::Ground`].
    pub fn new() -> Self {
        Self {
            state: State::Ground,
            csi_private: false,
            csi_params: Vec::new(),
            csi_current: 0,
            csi_current_has_digits: false,
            active_modes: BTreeSet::new(),
            cursor_hidden: false,
        }
    }

    /// Feed the next chunk of remote-to-local bytes through the parser.
    ///
    /// Safe to call with any slice length, including one byte at a time:
    /// a TCP read can split an escape sequence at any byte boundary, and
    /// the parser state carries over from one call to the next, so a
    /// sequence split across many `feed` calls parses exactly the same as
    /// one delivered whole.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.advance(byte);
        }
    }

    /// Forget everything tracked: every mode, the hidden-cursor flag, and
    /// any partially parsed sequence. Call this once the bytes from
    /// [`ModeTracker::reset_sequence`] have actually been written to the
    /// local terminal, or when starting to track a brand new connection.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// True when nothing needs undoing: no private mode is tracked as on,
    /// the cursor was never hidden, and the parser is not stranded part way
    /// through a sequence.
    pub fn is_clean(&self) -> bool {
        self.active_modes.is_empty() && !self.cursor_hidden && !self.mid_sequence()
    }

    /// Is the parser part way through an escape sequence?
    ///
    /// This matters at exactly one moment: the link dropping. The remote's
    /// last write is cut wherever the TCP segment happened to end, so the
    /// local terminal can be left holding an incomplete `ESC [ 3 8 ; 2 ;`
    /// with no final byte coming. A terminal in that position is not
    /// finished parsing, so it consumes whatever arrives next as the rest of
    /// the sequence: the first line of our own "reconnecting..." notice
    /// silently disappears into it, and so does the reset we are trying to
    /// send. That is the same class of bug as the stuck mouse modes, and it
    /// is why [`ModeTracker::reset_sequence`] leads with `CAN`.
    pub fn mid_sequence(&self) -> bool {
        self.state != State::Ground
    }

    /// Every private mode currently tracked as on, sorted ascending. Does
    /// not include DECTCEM (mode 25); use [`ModeTracker::in_alt_screen`]
    /// for the alternate screen and read [`ModeTracker::reset_sequence`]
    /// for the cursor. Exposed for tests that want to assert on exactly
    /// which modes were picked up.
    pub fn active_modes(&self) -> Vec<u16> {
        self.active_modes.iter().copied().collect()
    }

    /// Is the remote currently believed to have the local terminal on the
    /// alternate screen buffer (mode 47, 1047, or 1049)?
    pub fn in_alt_screen(&self) -> bool {
        self.active_modes.iter().copied().any(is_alt_screen_mode)
    }

    /// The bytes to write to the local terminal to undo everything
    /// currently outstanding. Empty when [`ModeTracker::is_clean`] is
    /// true, there is nothing to fix and nothing should be written.
    ///
    /// Otherwise, in order:
    /// 1. every outstanding non-alt-screen private mode, reset together in
    ///    one grouped `CSI ? a;b;c l` (this is what real terminals do
    ///    themselves, and it is fewer bytes than one sequence per mode);
    /// 2. the alternate screen, if entered, left with the same mode
    ///    number(s) it was entered with;
    /// 3. the cursor shown again, if it was hidden;
    /// 4. the unconditional tail described on [`TAIL_RESET`].
    pub fn reset_sequence(&self) -> Vec<u8> {
        if self.is_clean() {
            return Vec::new();
        }

        let mut out = Vec::new();

        // CAN (0x18) aborts a control sequence in progress, which is exactly
        // what it is for (ECMA-48 8.3.5). If the link died half way through
        // a sequence the local terminal is still waiting for a final byte,
        // and everything below would be eaten as sequence parameters rather
        // than obeyed. One byte, and only when it is actually needed.
        if self.mid_sequence() {
            out.push(0x18);
        }

        let generic: Vec<u16> = self
            .active_modes
            .iter()
            .copied()
            .filter(|&n| !is_alt_screen_mode(n))
            .collect();
        if !generic.is_empty() {
            write_csi_private(&mut out, &generic, b'l');
        }

        // 1049 first, then whichever of 47/1047 was also set: this mirrors
        // how the modes are named in xterm's own documentation and keeps
        // the more specific, more commonly used mode's reset first.
        for &n in &[1049u16, 1047, 47] {
            if self.active_modes.contains(&n) {
                write_csi_private(&mut out, &[n], b'l');
            }
        }

        if self.cursor_hidden {
            write_csi_private(&mut out, &[25], b'h');
        }

        out.extend_from_slice(TAIL_RESET);
        out
    }

    /// The reset to use when there is no [`ModeTracker`] state at all, for
    /// example the very first connection attempt failed before any bytes
    /// were ever fed to a tracker. Unlike [`ModeTracker::reset_sequence`]
    /// this is unconditional and always non-empty: with no tracked state
    /// to consult, the safe assumption is that any of the modes a remote
    /// session commonly leaves on might be set, so all of them are turned
    /// off, followed by the same [`TAIL_RESET`] tail every other reset in
    /// this module ends with.
    pub fn safety_reset() -> Vec<u8> {
        // Leads with CAN for the reason given on [`ModeTracker::mid_sequence`]:
        // with no tracker to ask, we cannot know the terminal is not stranded
        // part way through a sequence, and a wasted byte costs nothing.
        let mut out = vec![0x18];
        write_csi_private(
            &mut out,
            &[
                1000, 1001, 1002, 1003, 1004, 1005, 1006, 1015, 1016, PASTE_MODE,
            ],
            b'l',
        );
        out.extend_from_slice(TAIL_RESET);
        out
    }

    /// Advance the parser by exactly one byte.
    fn advance(&mut self, byte: u8) {
        match self.state {
            State::Ground => self.on_ground(byte),
            State::Escape => self.on_escape(byte),
            State::CsiEntry => self.on_csi_entry(byte),
            State::CsiParam => self.on_csi_param(byte),
            State::CsiIntermediate => self.on_csi_intermediate(byte),
            State::CsiIgnore => self.on_csi_ignore(byte),
            State::StringConsume(kind) => self.on_string(kind, byte),
            State::StringEscape => self.on_string_escape(byte),
        }
    }

    fn on_ground(&mut self, byte: u8) {
        if byte == 0x1b {
            self.state = State::Escape;
        }
        // CAN/SUB and ordinary text: nothing is in progress to abort or
        // track, so there is nothing to do.
    }

    fn on_escape(&mut self, byte: u8) {
        match byte {
            // A second ESC restarts the escape sequence; staying in this
            // same state achieves exactly that.
            0x1b => {}
            0x18 | 0x1a => self.state = State::Ground,
            b'[' => {
                self.reset_csi_collect();
                self.state = State::CsiEntry;
            }
            b']' => self.state = State::StringConsume(StringKind::Osc),
            b'P' => self.state = State::StringConsume(StringKind::Dcs),
            b'X' | b'^' | b'_' => self.state = State::StringConsume(StringKind::SosPmApc),
            // Intermediate byte of some other two-or-more-byte escape
            // sequence (for example the `(` of `ESC ( B`): keep collecting,
            // nothing here is a mode-mutating sequence.
            0x20..=0x2f => {}
            // Other C0 controls arriving mid-escape-sequence are not part
            // of the DEC private mode grammar, they are simply not
            // meaningful here and are dropped.
            0x00..=0x1f => {}
            // Final byte of a two-character escape sequence such as
            // `ESC c` or `ESC 7`: nothing left to track, back to ground.
            _ => self.state = State::Ground,
        }
    }

    fn on_csi_entry(&mut self, byte: u8) {
        match byte {
            0x1b => self.state = State::Escape,
            0x18 | 0x1a => {
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            // `?` is the DEC private marker this tracker cares about;
            // `<`, `=`, `>` are the other CSI parameter-prefix bytes
            // ECMA-48 reserves for private use elsewhere and are accepted
            // here only so the sequence still parses to its final byte
            // instead of derailing into CsiIgnore, they never set
            // `csi_private`.
            b'?' | b'<' | b'=' | b'>' => {
                if byte == b'?' {
                    self.csi_private = true;
                }
                self.state = State::CsiParam;
            }
            b'0'..=b'9' => {
                self.csi_current = u32::from(byte - b'0');
                self.csi_current_has_digits = true;
                self.state = State::CsiParam;
            }
            b';' => {
                self.finish_param();
                self.state = State::CsiParam;
            }
            0x20..=0x2f => {
                self.finish_param();
                self.state = State::CsiIntermediate;
            }
            0x40..=0x7e => {
                self.finish_param();
                self.dispatch_sm_rm(byte);
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            0x00..=0x1f => {}
            _ => self.state = State::CsiIgnore,
        }
    }

    fn on_csi_param(&mut self, byte: u8) {
        match byte {
            0x1b => self.state = State::Escape,
            0x18 | 0x1a => {
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            b'0'..=b'9' => {
                // Clamp rather than let a hostile stream of digits grow
                // this without bound; xterm's own parameters never exceed
                // 16 bits worth of meaning for a mode number, so nothing
                // legitimate is ever lost by capping here.
                self.csi_current = self
                    .csi_current
                    .saturating_mul(10)
                    .saturating_add(u32::from(byte - b'0'))
                    .min(u32::from(u16::MAX));
                self.csi_current_has_digits = true;
            }
            b';' => {
                self.finish_param();
                if self.csi_params.len() >= MAX_CSI_PARAMS {
                    self.state = State::CsiIgnore;
                }
            }
            // A marker byte here, after parameter collection has already
            // started, is not valid CSI grammar; treat the sequence as
            // malformed rather than guess at what was meant.
            b'?' | b'<' | b'=' | b'>' => self.state = State::CsiIgnore,
            0x20..=0x2f => {
                self.finish_param();
                self.state = State::CsiIntermediate;
            }
            0x40..=0x7e => {
                self.finish_param();
                self.dispatch_sm_rm(byte);
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            0x00..=0x1f => {}
            _ => self.state = State::CsiIgnore,
        }
    }

    fn on_csi_intermediate(&mut self, byte: u8) {
        match byte {
            0x1b => self.state = State::Escape,
            0x18 | 0x1a => {
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            0x20..=0x2f => {}
            // SM and RM never carry an intermediate byte, so whatever
            // control function this final byte names, it is not a private
            // mode change; nothing is dispatched.
            0x40..=0x7e => {
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            0x00..=0x1f => {}
            _ => self.state = State::CsiIgnore,
        }
    }

    fn on_csi_ignore(&mut self, byte: u8) {
        match byte {
            0x1b => self.state = State::Escape,
            0x18 | 0x1a => {
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            0x40..=0x7e => {
                self.reset_csi_collect();
                self.state = State::Ground;
            }
            _ => {}
        }
    }

    fn on_string(&mut self, kind: StringKind, byte: u8) {
        match byte {
            // Only OSC recognizes BEL as its terminator; DCS, SOS, PM, and
            // APC payloads only end at ST.
            0x07 if kind == StringKind::Osc => self.state = State::Ground,
            0x1b => self.state = State::StringEscape,
            0x18 | 0x1a => self.state = State::Ground,
            _ => {}
        }
    }

    fn on_string_escape(&mut self, byte: u8) {
        if byte == b'\\' {
            // String Terminator recognized: the payload is over.
            self.state = State::Ground;
        } else {
            // Not a terminator after all: the string is abandoned, and
            // this byte is the one right after a fresh ESC, so it is
            // reprocessed exactly as if the parser had just entered
            // `State::Escape` from ground.
            self.state = State::Escape;
            self.on_escape(byte);
        }
    }

    /// Push the parameter accumulated so far (or `None` if it was elided)
    /// onto `csi_params`, then reset the accumulator for the next one.
    /// Silently drops the parameter once [`MAX_CSI_PARAMS`] has already
    /// been reached; by that point the sequence has already moved, or is
    /// about to move, into [`State::CsiIgnore`], so nothing that would
    /// otherwise be dispatched is lost.
    fn finish_param(&mut self) {
        if self.csi_params.len() < MAX_CSI_PARAMS {
            let value = if self.csi_current_has_digits {
                Some(self.csi_current as u16)
            } else {
                None
            };
            self.csi_params.push(value);
        }
        self.csi_current = 0;
        self.csi_current_has_digits = false;
    }

    /// Apply SM (`h`) or RM (`l`) to every present parameter, but only for
    /// a CSI sequence that began with the private marker `?`; every other
    /// final byte, and every non-private sequence, is not a mode change
    /// and is left alone.
    fn dispatch_sm_rm(&mut self, final_byte: u8) {
        if self.csi_private && (final_byte == b'h' || final_byte == b'l') {
            let on = final_byte == b'h';
            let params = std::mem::take(&mut self.csi_params);
            for n in params.into_iter().flatten() {
                self.apply_mode(n, on);
            }
        }
    }

    /// Record that private mode `n` was just set (`on = true`) or reset
    /// (`on = false`).
    fn apply_mode(&mut self, n: u16, on: bool) {
        if n == 25 {
            // DECTCEM: `h` shows the cursor (the default, nothing
            // outstanding), `l` hides it (outstanding until shown again).
            self.cursor_hidden = !on;
        } else if on {
            self.active_modes.insert(n);
        } else {
            self.active_modes.remove(&n);
        }
    }

    /// Clear everything to do with the CSI sequence currently being
    /// collected. Called both when a new CSI sequence begins and when one
    /// finishes or aborts, so stale parameters from one sequence can never
    /// bleed into the next.
    fn reset_csi_collect(&mut self) {
        self.csi_private = false;
        self.csi_params.clear();
        self.csi_current = 0;
        self.csi_current_has_digits = false;
    }
}

impl Default for ModeTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Write `CSI ? <nums, joined by ;> <final_byte>` onto `out`.
fn write_csi_private(out: &mut Vec<u8>, nums: &[u16], final_byte: u8) {
    out.extend_from_slice(b"\x1b[?");
    for (i, n) in nums.iter().enumerate() {
        if i > 0 {
            out.push(b';');
        }
        out.extend_from_slice(n.to_string().as_bytes());
    }
    out.push(final_byte);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// True when `needle` appears somewhere in `haystack`, byte for byte.
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Every run of ASCII digits in `bytes`, parsed as `u16`. Used instead
    /// of a substring check so a test does not care whether a mode number
    /// happened to land at the start of a grouped sequence (with a leading
    /// `?`) or in the middle of one (with a leading `;`).
    fn digit_tokens(bytes: &[u8]) -> Vec<u16> {
        String::from_utf8_lossy(bytes)
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u16>().ok())
            .collect()
    }

    #[test]
    fn setting_then_resetting_a_mode_leaves_nothing_outstanding() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1002h");
        assert!(!tracker.is_clean());
        assert_eq!(tracker.active_modes(), vec![1002]);

        tracker.feed(b"\x1b[?1002l");
        assert!(tracker.is_clean());
        assert!(tracker.reset_sequence().is_empty());
    }

    #[test]
    fn a_csi_sequence_split_one_byte_at_a_time_still_registers() {
        let mut tracker = ModeTracker::new();
        for &byte in b"\x1b[?1002h" {
            tracker.feed(&[byte]);
        }
        assert_eq!(tracker.active_modes(), vec![1002]);
    }

    #[test]
    fn an_escape_sequence_split_across_three_awkward_feed_calls_still_registers() {
        let mut tracker = ModeTracker::new();
        tracker.feed(&[0x1b]);
        tracker.feed(b"[?100");
        tracker.feed(b"2h");
        assert_eq!(tracker.active_modes(), vec![1002]);
    }

    #[test]
    fn multiple_parameters_in_one_sequence_all_get_set() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1002;1006;2004h");
        assert_eq!(tracker.active_modes(), vec![1002, 1006, 2004]);
    }

    #[test]
    fn an_osc_title_that_looks_like_a_mode_sequence_does_not_mutate_state() {
        let mut tracker = ModeTracker::new();
        // A window title whose text happens to contain "?1002h", with no
        // real ESC preceding it: a parser that is not properly tracking
        // OSC-string state could mistake this for a real DECSET.
        tracker.feed(b"\x1b]0;now set ?1002h please\x07");
        assert!(tracker.active_modes().is_empty());
        assert!(tracker.is_clean());
    }

    #[test]
    fn a_dcs_payload_that_looks_like_a_mode_sequence_does_not_mutate_state() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1bPq?1002h garbage payload\x1b\\");
        assert!(tracker.active_modes().is_empty());
        assert!(tracker.is_clean());
    }

    #[test]
    fn csi_without_the_private_marker_does_not_mutate_state() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[1002h");
        assert!(tracker.active_modes().is_empty());
    }

    #[test]
    fn entering_and_leaving_the_alternate_screen_is_tracked() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1049h");
        assert!(tracker.in_alt_screen());

        tracker.feed(b"\x1b[?1049l");
        assert!(!tracker.in_alt_screen());
    }

    #[test]
    fn a_tmux_like_session_produces_a_reset_with_mouse_modes_and_the_decstr_tail() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1049h\x1b[?1000h\x1b[?1002h\x1b[?1006h\x1b[?2004h");

        let reset = tracker.reset_sequence();
        let tokens = digit_tokens(&reset);
        for mode in [1000, 1002, 1006, 2004] {
            assert!(tokens.contains(&mode), "missing mode {mode} in {reset:?}");
        }
        assert!(
            tokens.contains(&1049),
            "missing alt screen exit in {reset:?}"
        );
        assert!(contains_bytes(&reset, b"\x1b[!p"), "missing DECSTR tail");
        assert!(contains_bytes(&reset, b"\x1b[r"), "missing DECSTBM clear");
    }

    #[test]
    fn safety_reset_is_non_empty_and_turns_off_every_mouse_mode() {
        let reset = ModeTracker::safety_reset();
        assert!(!reset.is_empty());
        let tokens = digit_tokens(&reset);
        for &mode in MOUSE_MODES {
            assert!(
                tokens.contains(&mode),
                "missing mouse mode {mode} in {reset:?}"
            );
        }
        assert!(tokens.contains(&PASTE_MODE));
        assert!(contains_bytes(&reset, b"\x1b[!p"));
    }

    #[test]
    fn a_hostile_stream_of_thousands_of_parameters_does_not_grow_without_bound() {
        let mut tracker = ModeTracker::new();
        let mut hostile = b"\x1b[?".to_vec();
        for _ in 0..50_000 {
            hostile.extend_from_slice(b"1;");
        }
        hostile.extend_from_slice(b"9999h");
        tracker.feed(&hostile);
        // The parameter count overflowed MAX_CSI_PARAMS partway through,
        // which pushes the parser into CsiIgnore for the rest of the
        // sequence, so the whole malformed sequence is discarded rather
        // than partially applied.
        assert!(tracker.active_modes().is_empty());
    }

    #[test]
    fn can_aborts_a_partial_sequence_and_parsing_recovers_afterward() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?100");
        tracker.feed(&[0x18]); // CAN
        tracker.feed(b"2h");
        assert!(tracker.active_modes().is_empty());

        // The abort must leave the parser back at ground, not stuck.
        tracker.feed(b"\x1b[?1002h");
        assert_eq!(tracker.active_modes(), vec![1002]);
    }

    #[test]
    fn sub_aborts_a_partial_sequence_and_parsing_recovers_afterward() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1006");
        tracker.feed(&[0x1a]); // SUB
        tracker.feed(b"h");
        assert!(tracker.active_modes().is_empty());

        tracker.feed(b"\x1b[?1006h");
        assert_eq!(tracker.active_modes(), vec![1006]);
    }

    #[test]
    fn a_bare_esc_restarts_a_sequence() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?100"); // partial, mid-digit
        tracker.feed(&[0x1b]); // fresh ESC: abandons the partial CSI
        tracker.feed(b"[?1002h");
        assert_eq!(tracker.active_modes(), vec![1002]);
    }

    #[test]
    fn decset_1049_sets_and_clear_can_be_read_back_from_a_fed_reset() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1049h\x1b[?1000h");
        let reset = tracker.reset_sequence();

        // Feeding the tracker's own reset back into itself, the way a
        // real terminal would receive it, must clear everything it says
        // it clears.
        let mut echo = ModeTracker::new();
        echo.feed(b"\x1b[?1049h\x1b[?1000h");
        echo.feed(&reset);
        assert!(echo.is_clean(), "{reset:?} did not clean up after itself");
    }

    #[test]
    fn hiding_the_cursor_is_tracked_and_restored() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?25l");
        assert!(!tracker.is_clean());
        assert!(!tracker.active_modes().contains(&25));

        let reset = tracker.reset_sequence();
        assert!(contains_bytes(&reset, b"\x1b[?25h"));

        tracker.feed(b"\x1b[?25h");
        assert!(tracker.is_clean());
    }

    #[test]
    fn a_mode_never_touched_is_never_reported_as_outstanding() {
        let tracker = ModeTracker::new();
        assert!(tracker.is_clean());
        assert!(tracker.reset_sequence().is_empty());
        assert!(tracker.active_modes().is_empty());
        assert!(!tracker.in_alt_screen());
    }

    #[test]
    fn clear_forgets_everything_including_a_partial_sequence() {
        let mut tracker = ModeTracker::new();
        tracker.feed(b"\x1b[?1002h\x1b[?25l\x1b[?100");
        tracker.clear();
        assert!(tracker.is_clean());
        assert!(tracker.active_modes().is_empty());

        // The partial sequence from before clear() must not resume.
        tracker.feed(b"2h");
        assert!(tracker.active_modes().is_empty());
    }
}

#[cfg(test)]
mod truncation_tests {
    use super::*;

    /// The link can die at any byte, including the middle of a sequence the
    /// remote was writing. A terminal left mid-sequence eats whatever comes
    /// next, so "nothing outstanding" is not the same as "nothing to do".
    #[test]
    fn a_link_cut_mid_sequence_is_not_clean_even_with_no_modes_set() {
        let mut t = ModeTracker::new();
        t.feed(b"hello\x1b[38;2;");
        assert!(t.active_modes().is_empty());
        assert!(t.mid_sequence());
        assert!(!t.is_clean(), "a stranded parser still needs a reset");
        assert!(!t.reset_sequence().is_empty());
    }

    /// CAN must come first, before anything that would otherwise be consumed
    /// as the tail of the abandoned sequence.
    #[test]
    fn the_reset_leads_with_can_when_the_parser_was_stranded() {
        let mut t = ModeTracker::new();
        t.feed(b"\x1b[?1002h\x1b[38;2;");
        let seq = t.reset_sequence();
        assert_eq!(seq[0], 0x18, "CAN must lead: {seq:?}");
        assert!(seq.windows(2).any(|w| w == b"1002" || w == b"?1"));
    }

    /// A tracker that ended cleanly on a sequence boundary must not pay for
    /// a CAN it does not need.
    #[test]
    fn a_clean_boundary_emits_no_can() {
        let mut t = ModeTracker::new();
        t.feed(b"\x1b[?1002h");
        let seq = t.reset_sequence();
        assert_ne!(seq[0], 0x18, "no CAN when the parser finished a sequence");
    }

    #[test]
    fn the_safety_reset_also_leads_with_can() {
        assert_eq!(ModeTracker::safety_reset()[0], 0x18);
    }

    /// Plain text must still leave the tracker clean, otherwise every idle
    /// disconnect would write a reset nobody asked for.
    #[test]
    fn ordinary_output_leaves_nothing_to_undo() {
        let mut t = ModeTracker::new();
        t.feed(b"total 48\r\ndrwxr-xr-x  3 gj staff  96 Aug 25 14:40 .\r\n");
        assert!(t.is_clean());
        assert!(t.reset_sequence().is_empty());
    }
}
