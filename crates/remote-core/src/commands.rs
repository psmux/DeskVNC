//! Commands sent into a running session.
//!
//! Moved out of `vnc-core/src/types.rs` unchanged (PRDRDP/02 §2.1). This enum
//! deliberately does not derive `Serialize`: the shell builds each command
//! from a Tauri argument by hand, so a new variant is a compile error where it
//! has to be decided rather than a silently dropped message.

use crate::intent::AgentIntent;
use crate::options::QualityPreset;
use crate::pins::PinScheme;

#[derive(Debug, Clone)]
pub enum ClientCommand {
    Pointer {
        x: u16,
        y: u16,
        button_mask: u16,
    },
    Key {
        keysym: u32,
        keycode: Option<u32>,
        down: bool,
    },
    /// Release every key we believe is pressed (blur / disconnect safety).
    ReleaseAllKeys,
    ClipboardText(String),
    ClipboardRequest {
        formats: u32,
    },
    SetQuality(QualityPreset),
    RequestResize {
        width: u16,
        height: u16,
    },
    /// Force a full non-incremental update.
    Refresh,
    /// Keep forcing a full non-incremental update every stats tick.
    ///
    /// The escape hatch for servers whose damage tracking cannot be trusted:
    /// it stops the client relying on the server to say what changed and
    /// simply re-fetches the screen, at a real bandwidth cost, so a picture
    /// can never stay stale no matter what the server forgot to send.
    SetAlwaysRefresh(bool),
    SetViewOnly(bool),
    /// Keyboard mode. `true` (the default) prefers QEMU scancodes when the
    /// server supports them, so the SERVER's keymap decides what a physical
    /// key types ("match the remote layout"). `false` suppresses scancodes
    /// and sends only layout-aware keysyms, so keys type what they type
    /// LOCALLY ("match my local layout"). The distinction only matters when
    /// the two machines' layouts differ; RealVNC and TigerVNC expose the
    /// same choice.
    SetPreferScancodes(bool),
    /// User accepted a server key at the TOFU prompt. `scheme` is echoed back
    /// from the prompt that raised it, never inferred here.
    TrustCertificate {
        fingerprint: String,
        permanent: bool,
        scheme: PinScheme,
    },
    /// User answered a [`SessionEvent::CredentialsRequired`] prompt.
    ///
    /// `save` is the "remember these credentials" checkbox. The core never
    /// touches the keychain, the shell persists them only after the session
    /// actually reaches `Connected`, so a rejected password is never stored.
    ProvideCredentials {
        username: Option<String>,
        password: String,
        save: bool,
    },
    /// User dismissed the credentials prompt, abandon the connection attempt.
    CancelCredentials,
    /// Reset backoff and retry immediately (network came back / user clicked).
    ReconnectNow,
    Disconnect,

    /// Keystrokes and pastes for a remote shell, already encoded as the bytes
    /// the PTY should receive.
    ///
    /// Not expressible as [`ClientCommand::Key`]: that carries a keysym and a
    /// keycode for a framebuffer protocol to translate, and it has nowhere to
    /// put a multi-byte character or a pasted block. A terminal's input is
    /// simply bytes.
    TerminalInput(bytes::Bytes),

    /// The terminal was resized, in **character cells**.
    ///
    /// Deliberately separate from [`ClientCommand::RequestResize`], which is
    /// in pixels and asks a remote *desktop* to change resolution. Reusing it
    /// would be a silent unit mismatch: 80 columns is not 80 pixels, and
    /// nothing in the type system would catch it.
    ResizeTerminal {
        cols: u16,
        rows: u16,
    },

    /// An agent intent the driver serves natively rather than as lowered
    /// input.
    ///
    /// `PRDAgentPlug/00 R28`. Most intents never arrive this way: the plane
    /// lowers a `click` into [`ClientCommand::Pointer`] and a `type` into a
    /// run of [`ClientCommand::Key`], because a driver that already knows how
    /// to move a pointer should not learn a second vocabulary for it. This
    /// variant is for the ones that have no lowering at all, the three
    /// `05 §4.1` names: `exec` needs a channel of its own with a real exit
    /// status, and `declare` is state a limb holds between commands. Neither
    /// is expressible as any command above.
    ///
    /// One variant rather than eighteen flat ones, and the reason is in
    /// [`crate::intent`]: wrapped, the place a driver could drop an intent is
    /// ONE arm in one match, so it can be found and it can be made to answer.
    /// Flat, it would be eighteen chances for a driver to say nothing.
    ///
    /// A driver that will not serve one must say so with
    /// [`AgentIntent::refuse`], never by ignoring it.
    Agent(AgentIntent),
}
