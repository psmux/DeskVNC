# Clipboard over Boundary: plan

Status: planned, not built. Until it lands, Boundary limbs no longer offer
`clipboard.read` or `clipboard.write`, and `dvv_clipboard` on one is refused
with a reason instead of reporting success for text that went nowhere.

## What is there today

The session protocol (`crates/boundary-session/src/wire.rs`, `Message`) has no
clipboard message in either direction. The DeskVNC viewer's Boundary driver
(`crates/boundary-driver/src/lib.rs`, `drive`) drops `ClientCommand::ClipboardText`
in its catch all arm, and nothing on the host ever reads the person's
clipboard. DeskVNC Support as a helper sends a paste as typed text
(`Input::Text`, in 200 character chunks), which is the only thing that works.

## Wire

Both directions are new messages, each sent only to a peer that said it reads
them, because an older peer ends the session on a message it does not know
(the same rule `Tools`, `Shown` and `Refresh` follow).

* `Hello` and `Knock` gain `#[serde(default)] clipboard: bool`: the helper
  understands clipboard messages.
* `Granted` gains `#[serde(default, skip_serializing_if = "Option::is_none")]
  clipboard: Option<bool>`, present only from a host that serves them, and
  only to a helper that said `clipboard`. The value is whether the person
  allows it right now.
* `Clipboard(String)` in both directions, UTF-8 text only, at most 1 MiB
  (`MAX_CONTROL` is too small, so it needs its own cap checked on read).
  Images and files are out of scope.
* `ClipboardAllowed(bool)` from host to helper when the person changes it, as
  `Tools(bool)` does.

An old helper with a new host: no `clipboard` in its hello, so the host never
sends one. A new helper with an old host: no `clipboard` in the grant, so the
helper never sends one and its limb card leaves the capabilities off.

## The person's say

Reading the person's clipboard hands over whatever they last copied, which is
a password often enough to matter. So:

* Helper to host (setting their clipboard) follows control: allowed while the
  helper may use the mouse and keyboard, since it can type the same text.
* Host to helper (reading theirs) needs its own tick in the approval prompt and
  on the sharing screen, off by default, worded like the tools one: "Also let
  them see what I copy". For unattended helpers it is a per helper setting
  beside tools in `Access`, off by default, and always off at the sign in
  screen, as tools are.
* The host sends only what the person copies while the session runs, never
  what was on the clipboard before it started.

## Platforms on the host

* Windows and macOS: `arboard`, which Support already links at 3.7.0 through
  `egui-winit` and the viewer through `tauri-plugin-clipboard-manager`, polled on change count (macOS `NSPasteboard.changeCount`, Windows
  `GetClipboardSequenceNumber`) once a second while allowed.
* Linux X11: `arboard`'s X11 backend, which runs its own selection owner
  thread, so the text stays pasteable after a write.
* Linux Wayland, GNOME and KDE: a background app cannot read the clipboard
  through `wl_data_device` without focus, and GNOME has no data control
  protocol. The RemoteDesktop portal has a Clipboard interface (version 1 on
  GNOME 50, measured with `busctl`), and `ashpd` 0.13 has it behind its
  `clipboard` feature. `RequestClipboard` has to be called on the session
  before `Start`, so it belongs in `portal::remote_with`, and the restore
  token path must ask for it the same way. `SelectionOwnerChanged` tells the
  host when the person copied; `SelectionRead` returns a file descriptor to
  read the text from. Writing is `SetSelection` then `SelectionWrite` and
  `SelectionWriteDone` when the compositor asks for the data.
* wlroots (screencast portal only, no RemoteDesktop): no clipboard, said so.

## Helpers

* DeskVNC Support as helper: send `Clipboard` on Ctrl+V into the remote view
  instead of typing it, when the host allows it, and fall back to typing when
  it does not. Show what came back from the host as a "Copy what they copied"
  button rather than writing the helper's own clipboard unasked.
* DeskVNC viewer: map `ClientCommand::ClipboardText` to `Clipboard` in the
  driver, and `Clipboard` from the host to `SessionEvent::ClipboardText` so the
  existing remote clipboard plumbing and `clipboard.read` work. The limb card
  offers `clipboard.write` when the grant said `clipboard`, and
  `clipboard.read` only while the person allows reading.

## Tests

* wire: serde round trips, and an old `Hello` without the field decoding to
  `clipboard: false` (the `before_video` module already does this for tiles).
* session: a fake desktop with a fake clipboard; a helper without the flag is
  never sent a clipboard message; a host that does not allow reading sends
  nothing when the fake clipboard changes; turning it off mid session stops it.
* driver: `ClipboardText` reaches the host's fake clipboard; text the host
  copies reaches `clipboard.read`.
* real: GNOME 50 Wayland, X11, Windows and macOS, both directions, with the
  tick on and off.

## Size

Roughly 600 to 900 lines across five crates, plus a new feature on `ashpd`
and a direct dependency on `arboard` in `boundary-platform`. That is why it is
a plan and not part of the papercut fixes.
