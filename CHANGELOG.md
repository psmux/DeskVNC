# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version stays below 1.0, minor releases may contain breaking changes
to stored data and to the IPC contract between the Rust core and the frontend.

## [Unreleased]

## [0.8.0] - 2026-08-07

### Added

- **The view scrolls itself when you push against an edge** ([#1]). At 1:1 on
  a desktop larger than the window, everything past the edge was simply
  unreachable: panning existed, but only as a space-drag nobody could be
  expected to discover. Moving the pointer into the edge of the view now
  scrolls toward it, faster the closer you get, the way RealVNC does. It is
  inert whenever the desktop already fits, and it only scrolls in a direction
  that has something left to show. The remote pointer keeps up with the
  moving view rather than lagging behind it.

### Fixed

- **The Session and Connection menus did nothing at all** ([#1]). Every
  custom menu item is emitted to the frontend to be routed, and the library
  window and app shell each handled their own, but nothing ever listened for
  the session's. So Show/Hide Toolbar, Actual Size, Fit to Window, the
  Quality items, View Only, Refresh Screen, Send Ctrl+Alt+Del, Release All
  Keys, Reconnect and Disconnect were all dead from the menu bar, while the
  same actions worked from the session toolbar. Only the view in front acts,
  so the item does what you would expect with several tabs open.
- **The connection status reported "0ms" on servers that cannot be
  measured** ([#1]). Round-trip time is probed with the Fence extension,
  which the libvncserver family (x11vnc among others) does not implement, so
  the figure sat at its initial zero for the whole session and was displayed
  as though it were real. Those servers are now probed with a one-pixel
  non-incremental update request, which any RFB server must answer, and the
  status shows "-" until a measurement actually exists rather than claiming
  an instant connection.

[#1]: https://github.com/psmux/DeskVNC/issues/1


## [0.7.0] - 2026-08-06

### Added

- **A Pointers menu in the session toolbar.** "Show the remote pointer" is
  now reachable while you are looking at the desktop rather than only from
  Preferences, and it is joined by a choice of how your own pointer is drawn
  over the session: the standard arrow, a small dot, or hidden entirely. The
  arrow covers the pixels under its own tip, which is exactly where the
  remote pointer sits, so with both drawn the two crowd each other; the dot
  is a ring centred on the hotspot with a light outline, which stays legible
  on dark and light desktops. Hidden leaves only the remote pointer, which is
  the closest thing to sitting at the machine itself. Both settings are
  remembered, and the remote pointer still defaults to shown.

- **"Lock zoom (ignore pinch)" in the session toolbar's Scaling menu.** A
  trackpad pinch is easy to start by accident in the middle of a two-finger
  scroll, and rescaling the view is rarely what was meant. With the lock on,
  the gesture is swallowed: it neither rescales the view nor reaches the
  remote as scroll clicks. The zoom controls in the same menu keep working,
  so this stops accidents rather than taking the feature away. The setting is
  remembered, since a gesture that gets in the way once gets in the way every
  time.


### Fixed

- **A server with no password could not be connected to at all** ([#1]). A
  stock `x11vnc` started without a password offers exactly one security type,
  "None", and the client refused it and hung up before choosing one, which is
  why the server logged `rfbProcessClientSecurityType: client gone`. Four
  separate places refused it, and VeNCrypt Plain was refused the same way, all
  gated behind an "allow insecure" opt-in that **no part of the app could set**:
  every refusal told the user to enable *"Allow an unencrypted connection" for
  this host*, a control that never existed. The client now takes the security
  type the server offers when it is the only one; that is not a downgrade,
  since anything stronger is always preferred, and it matches how VncAuth has
  been treated since the start, whose session is equally cleartext. The
  session's unencrypted badge remains the honest signal.
- **The failure was reported as "Incorrect password"** on a server that has no
  password, because any message containing "auth" was matched, including "no
  *auth*entication at all". Only messages that really mean rejected
  credentials are reported that way now.
- **The host editor's "Security type" setting did nothing.** It was written to
  the database and never read when connecting, so pinning a type (including
  "None", the workaround the old error implied) had no effect.

Why the tests were green through all of this: the shared integration-test
helper switched the insecure opt-in **on**, so the test that connects to a
"None"-only server proved nothing about the path a real session takes. It now
runs on the shipping defaults, which is what turned this red.

[#1]: https://github.com/psmux/DeskVNC/issues/1

## [0.6.1] - 2026-08-05

### Fixed

- **Two-finger tap on a Mac trackpad now right-clicks the remote desktop.**
  The gesture every Mac laptop uses for a secondary click reaches the page as
  a lone `contextmenu` event, with none of the button-2 press/release the
  client was listening for, so it produced nothing at all on the remote while
  a physical right button worked. The click is now synthesised from the
  gesture itself, and a real right button still cancels it so one gesture can
  never right-click twice.


## [0.6.0] - 2026-08-03

### Added

- **Dictation and IME text now reaches the remote desktop.** Session keyboard
  focus moved from the canvas to a hidden capture element, which is what
  dictation tools (macOS dictation, Wispr Flow), CJK input methods, and
  accessibility software need: they insert text into the focused editable
  element rather than pressing keys, and a canvas cannot receive text at all.
  Inserted and composed strings are forwarded keystroke by keystroke, synthetic
  key events that carry a whole word (the other way dictation tools type) are
  recognised and forwarded too, and ordinary typing is unaffected because
  forwarded keys never reach the element. This also makes Chinese, Japanese,
  and Korean input methods work in a session for the first time. Preferences ▸
  Input ▸ "Type text inserted by dictation tools" turns the software-insertion
  half off; accents and CJK input methods are deliberately not behind the
  switch, since those are the user typing.
- **A forwarded paste now carries the clipboard as it is at that moment.**
  Pressing Cmd/Ctrl+V (or Shift+Insert) into a session first pushes the
  current local clipboard to the remote, holding that one chord until the
  text is ordered ahead of it on the wire, with a 300 ms ceiling so a wedged
  clipboard read can never freeze typing. Previously the clipboard was only
  synced when the window regained focus, so anything that wrote the clipboard
  mid-session, dictation tools in clipboard mode, clipboard managers,
  scripts, pasted stale text on the remote. Preferences ▸ Clipboard ▸ "Push
  clipboard when pasting into the remote" is its own switch, and the master
  "Sync clipboard automatically" also gates it: with either off, nothing is
  sent implicitly.

## [0.5.0] - 2026-08-03

### Added

- **The About dialog now fingerprints the exact build.** Alongside the version
  it shows the `git describe` stamp (nearest tag, commits since, short hash,
  and a dirty marker for locally modified builds), the full commit, branch and
  commit date, the build profile and toolchain (tauri, rustc), and the machine
  it is running on (OS and version, architecture, webview engine version). A
  "Copy report for a bug ticket" button puts the whole block on the clipboard
  as preformatted text, so an issue report identifies the precise code it came
  from even when the version number hasn't moved. The stamp is compiled into
  the binary at build time and degrades to "unknown" outside a git checkout
  rather than failing the build. A small ? button in the library toolbar opens
  the dialog, and the macOS app menu's About item now opens it as well: the
  native About panel is gone, so there is exactly one About surface and it is
  the one with the fingerprint.
- **A keyboard mode: Preferences ▸ Input ▸ "Match my local keyboard layout".**
  Against a server that speaks the QEMU extended key extension, the client
  prefers scancodes, which means the *server's* layout decides what a physical
  key types; a German ö on an en-US server types `;`. The new switch suppresses
  scancodes and sends layout-aware keysyms instead, so keys type what they type
  locally. Off by default, because scancode mode is what makes remote shortcuts
  and games behave, and the two only disagree when the layouts differ. Toggling
  it mid-chord releases held keys first so nothing sticks in the old encoding.
- **AltGr, Option-composed characters, and dead keys now work.** The webview
  key path previously sent the composing modifier along with the character
  (AltGr+Q arrived as Ctrl+Alt+@ and typed nothing) and discarded dead keys
  outright, so every accented character on French, German, Spanish and Nordic
  layouts was unreachable. Composed characters are now delivered with the
  standard fake-modifier dance, the Windows AltGr pair is detected and sent as
  ISO_Level3_Shift, and dead-key sequences compose through a hidden overlay and
  arrive as the finished character.

### Fixed

- **A mid-session pixel-format switch could kill the session against
  TigerVNC-family servers.** The switch was guarded by a fence that never
  requested a response, and the decoder flipped formats immediately, so every
  rectangle still in flight was decoded in the wrong format and the connection
  died with "decompressed data exceeds cap", then reconnected, then died again:
  the window is widest on slow links, which is exactly when the Auto tuner
  triggers the switch. The fence now demands an answer and the decoder holds
  the old format until it arrives, which is the synchronisation point the
  protocol provides for exactly this.
- **Input froze for the length of every large framebuffer update.** The run
  loop read an entire update before looking at the command queue again, so on
  a slow link the remote pointer stopped for seconds and then jumped. Pointer
  and key events are now serviced between rectangles while an update streams
  in. Relatedly, when the input queue filled during a stall, *all* input was
  silently dropped, including key-ups and button releases, leaving the remote
  with stuck keys; now only stale pointer motion is shed, and state-changing
  events are always delivered.
- **Growing the remote desktop left the new area permanently blank.** Neither
  continuous updates (still scoped to the old geometry) nor the one-outstanding
  request pipeline (already spent on the old rect) covered the newly exposed
  strip. Continuous updates are re-armed and an update for the new geometry is
  requested on every real resize.
- **The automatic lossless refresh never actually sharpened anything.** The
  adaptive encodings were restored on the wire before the server had encoded
  the refresh, so the "sharp" repaint came back as JPEG, re-marked the region
  as lossy, and the cycle repeated every five seconds forever, a permanent
  bandwidth leak on idle sessions. The restore now waits until the answering
  update has been consumed. H.264 regions now count as lossy and are refreshed
  too, and cursor-shape-only updates no longer reset the idle clock that gates
  the refresh.
- **The link estimator could be fooled in both directions.** A burst left open
  across an idle gap completed with a near-zero rate and walked a gigabit LAN
  down to 256 colours; a kernel receive backlog (the normal case over an SSH
  tunnel) read as multiple gigabits and pinned full quality on a 5 Mbit link.
  Bursts must now span real wall time, stale bursts are abandoned at the
  threshold-crossing delivery too, and implausible samples are rejected.
- **Auto quality now behaves like a controller instead of a coin flip near a
  boundary.** Tier thresholds gained directional hysteresis, a genuinely slow
  fresh sample downgrades within seconds instead of waiting out a ten-second
  window maximum, the ladder no longer switches H.264 on and off (which
  restarted the codec and forced a keyframe every crossing), returning to Auto
  after a manual preset detour resyncs the tuner instead of doing nothing, the
  "client is slow" relief no longer fires on slow *links* (it read network
  wait as decode time and lowered compression exactly where compression was
  needed most), and the per-second stats divide by real elapsed time.
- **Black and White was the most expensive preset on the wire.** It negotiated
  full 32-bit colour with JPEG off and greyed the image client-side, costing
  more bandwidth than Medium while promising the opposite. It now negotiates
  the same 256-colour indexed format as Low.
- **Stuck keys and buttons, four separate ways.** Global capture forgot which
  key-downs it had swallowed, so releasing the modifier before the key left
  the key held on the remote; a key-up targeting a just-opened dialog was
  ignored; releasing the left button during a middle-drag pan was never sent;
  and a release cancelled after the coalesced pointer move was sent out of
  order. All four now release correctly.
- **Cursor fidelity.** Cursors on the 256-colour presets rendered as grey
  noise (the colour map was never applied), alpha cursors kept their
  premultiplied fringe, an alpha cursor delivered through a non-Raw encoding
  was channel-scrambled, and a hostile hotspot could push the cursor overlay
  off-target. All fixed, with the conversion now shared with the framebuffer
  path.
- **Robustness against misbehaving servers.** An unknown negative encoding now
  fails cleanly as unsupported instead of silently desynchronising the stream;
  an endless stream of empty rects under the unknown-length sentinel is
  bounded instead of growing memory without limit; and a full-screen Raw
  rectangle from a 5K/6K display (macOS Screen Sharing sends these) no longer
  trips a cap sized for 4K.
- **Renderer correctness and cost.** H.264 frames could land out of order with
  other rects (the one path that escaped the ordered apply chain); JPEG rects
  were colour-managed differently from RGBA rects and could tint; library live
  previews did a full-resolution GPU readback twice a second (now downscaled
  on the GPU, roughly a hundredth of the traffic at 4K); and the CopyRect
  scratch texture never shrank after a 4K session.
- **"Natural scrolling" in Preferences now does something.** It was stored and
  never read. It now flips wheel direction, page-mode scrolls (Firefox) are no
  longer dead, one trackpad flick can no longer fire hundreds of wheel events,
  a plain middle-click always reaches the remote instead of depending on zoom
  level, and the toolbar's Ctrl+Alt+Del and friends carry scancodes so they
  work on scancode-only hosts.

## [0.4.0] - 2026-08-02

### Added

- **"Always request fresh frames" in the session toolbar's Quality menu.** The
  manual override for a server whose damage tracking cannot be trusted: while
  it is on, the client re-fetches the whole screen every second instead of
  relying on the server to report what changed, so a picture can never stay
  stale no matter what the server forgot to send. It costs real bandwidth,
  which is why it is a switch rather than the default.
- **LAN / WAN override in the session toolbar.** The Quality menu now leads
  with a Network section: Auto (detect from the link), LAN (full quality, no
  adaptation), and WAN (save bandwidth). LAN pins full quality and disables
  the adaptive tuner entirely.

### Fixed

- **The quality settings were inverted: "High" produced the worst picture.**
  The JPEG-quality and compression pseudo-encodings are ascending on the wire
  (`QualityLevel0 = -32` … `QualityLevel9 = -23`), but both were computed
  descending, so asking for level 9 transmitted the encoding meaning level 0.
  Choosing High, or LAN, requested the most heavily compressed image the
  server could produce, and choosing Low requested a good one. Everything
  built on top inherited the inversion, including the Auto ladder, which is
  why quality appeared to *fall* as conditions improved. The formulas are now
  pinned to the literal wire constants by a test, because the old tests
  compared the buggy helper against itself and were blind to it by
  construction.
- **Fence replies tore the session down.** `ServerFence` is message type 248
  (249 is an unrelated registry entry), but the client dispatched on 249, so
  a real fence reply fell through to "unknown server message type" and killed
  the connection. Reachable on any server implementing the Fence extension,
  which the client always advertises. Round-trip time also read as 0 for the
  life of every session because of it.
- **The Low preset painted grey noise.** It asks the server for a 256-colour
  indexed format, and `SetColourMapEntries` was parsed and then discarded, so
  the decoders fell back to their grayscale identity path and drew palette
  *indices* as grey levels. The map is now handed to the decoder, which is
  what makes the automatic low-bandwidth tier usable at all.
- **Keyboard was mismapped: backspace typed "u", among others.** The client
  sent X11 keycodes (evdev + 8) where the QEMU Extended Key Event carries XT
  (PC set 1) scancodes. The two numberings differ by 8, so Backspace (X11 22 =
  0x16) arrived as the U key, and the whole main block was shifted the same
  way. The table is now real XT scancodes, including the `0xE0`-prefixed
  extended keys (arrows, Home/End, right Ctrl/Alt, Delete), which would
  otherwise hit their numpad twins.
- **Pixelated, ghosted picture on Raspberry Pi (wayvnc) sessions.** Window
  animations left the screen posterised and smeared with stale content that
  only healed under the mouse. Three causes, all fixed:
  - wayvnc loses track of damaged regions when the client is busy rendering
    during an animation storm, and never re-sends them. The client now
    requests one full repaint whenever a burst of activity settles, so the
    picture always converges to the truth within about a second of things
    going quiet, whatever the server lost.
  - The same damage loss happens around a mid-session quality change; every
    encoding switch is now followed by a full repaint request too.
  - Auto quality no longer reduces colour depth (that now belongs only to the
    explicit Low and Black & White presets), its floor rose from JPEG q2 to
    q3, and link speed is measured from stall-anchored bursts with a windowed
    maximum instead of an average of time-spent-waiting, so a slow server's
    encoder is no longer mistaken for a slow network. A Raspberry Pi on
    gigabit ethernet used to read as ~1.5 Mbit/s and got 64 colours; it now
    reads as a fast LAN and gets full quality.

- **Copying on this computer and pasting into the remote did nothing.** The
  local clipboard was only ever sent by the toolbar's "Send clipboard to
  remote" button, so pasting into the remote pasted whatever that machine
  already had. Preferences ▸ Clipboard offered "Sync clipboard automatically"
  and "Push clipboard when the window gains focus", both on by default, and
  both were wired to nothing. They now work: the local clipboard is pushed
  when a session connects and whenever you switch back to it, which is exactly
  when it can have changed, since while the session has the keyboard every
  Ctrl/Cmd+C goes to the remote. Text that just arrived *from* the remote is
  not echoed back, and an unchanged clipboard sends nothing.
- **Clipboard text never reached servers that ask before accepting it.** With
  the Extended Clipboard extension negotiated, the client pushed an unsolicited
  `provide`, which a server that advertised it wants no unsolicited data drops;
  it then asks with a `request`, which the client ignored. The client now
  announces with a `notify` and answers a `request` with the text, so both
  kinds of server receive it.

## [0.3.0] - 2026-08-02

### Added

- **SSH tunnelling for the VNC connection.** A host profile can now run its
  whole session through an SSH login (Edit Host ▸ Advanced ▸ "Tunnel over
  SSH"): the app connects to the SSH gateway, asks *it* to reach the VNC
  endpoint, and carries the session over that encrypted channel. This is what
  makes the recommended hardened setup usable, a VNC server bound to the
  remote machine's own loopback, reachable only through SSH, and it encrypts
  and authenticates the connection even when the VNC server itself offers
  nothing.
  - The gateway defaults to the VNC address and the user to your local
    username, so the common case is a single checkbox. Authentication is the
    Files panel's: a saved passphrase/password from the keychain, your
    ssh-agent, or a private key file.
  - No local forwarded port is ever opened; the channel itself is the
    session's byte stream, so no other local process can race onto the
    tunnel. Auto-reconnect re-dials through the tunnel, re-verifying the
    gateway against its pin.
  - The gateway's host key is trust-on-first-use with the same pin store the
    Files panel uses: trusting a machine once covers both. First contact
    shows a fingerprint prompt before anything connects; a *changed* key is a
    hard stop with no way to click through, exactly as everywhere else.
  - The host editor grew an SSH password / key-passphrase field alongside the
    tunnel settings, stored in the system keychain and shared with the Files
    panel.
- **`connect_session` now returns a tagged outcome** (`started` /
  `ssh-host-key-prompt` / `ssh-host-key-changed`) instead of a bare session
  id, and takes `acceptSshHostKey`; see `IPC_CONTRACT.md`. For profiles
  without a tunnel the behaviour is unchanged.

### Fixed

- Saving a password no longer erases the other credentials stored for the
  same host: `save_password` merges per field, so a host can hold a VNC
  password and an SSH passphrase (Files panel, and now the tunnel) without
  one save wiping the other.

## [0.2.0] - 2026-08-01

### Added

- **Tabbed view.** Connected computers can be shown as tabs across the top of
  the library window and switched between like browser tabs, instead of each
  one opening a window of its own. Turn it on in Preferences ▸ Connections,
  "Show sessions as tabs in one window"; it is off by default, so nothing
  changes unless you ask for it.
  - The library is the first tab and cannot be closed. Every session tab
    carries a status dot, the name the server reports for that desktop, and a
    close button; middle-click closes one too.
  - `Ctrl+Tab` and `Ctrl+Shift+Tab` move between tabs, `Cmd/Ctrl+1…9` jump
    straight to one (1 being the library), `Cmd/Ctrl+Shift+W` closes the tab in
    front and `Cmd/Ctrl+Shift+L` returns to the library. The first two and the
    last two are real menu items under Window, which is what makes them work
    while shortcut pass-through is sending everything else to the remote
    machine. The palette (`Cmd/Ctrl+K`) also lists every open session.
  - Only the tab you are looking at draws, holds the keyboard, or answers
    dropped files. The others stay connected and keep their picture up to date,
    so switching back shows the desktop as it is now, not as it was.
  - The preference decides where the *next* session goes. Sessions already
    running stay where they are, in a window or in a tab, because a live
    picture cannot be moved between the two without reconnecting. Connecting to
    a machine that is already open still finds it either way and brings it
    forward rather than starting a second session.
  - Closing the library window with tabs open shuts those sessions down
    cleanly, but skips the parting thumbnail refresh; closing a tab does not.
- **A windows/tabs switch in the library toolbar**, beside the grid and list
  buttons. It is the same preference as Preferences ▸ Connections and the two
  always agree; it is simply within reach of the moment it matters, which is
  the moment before connecting.
- **The session toolbar can be put away by hand.** A collapse button sits next
  to the pin, and `Cmd/Ctrl+Shift+M` now toggles rather than only recalling, so
  the chord that brings the toolbar back also sends it away. Previously it
  could only be waited out, and a pinned toolbar never hid at all.
- **The session toolbar can be dropped anywhere in the window**, not only along
  one of the four edges. Let go within 40px of an edge and it still docks
  flush, which keeps the tidy docked look and keeps the edge meaningful for
  which way menus open and the collapse chevron points. Its position is
  remembered, as before, and shared by every toolbar mounted in tabbed view.
  The collapsed chevron is a drag handle too, so the toolbar can be moved
  without opening it first.

### Fixed

- A key held down while switching away from a session stayed down on that
  remote desktop. Detaching the input handler unhooked its listeners without
  releasing anything, so the keyup went elsewhere and every later keystroke in
  that session arrived with the modifier still applied. Held mouse buttons had
  the same problem. Releasing is now part of detaching, which also covers the
  gesture most likely to cause it, a modifier held down while pressing the key
  that switches tabs.
- Keyboard capture (shortcut pass-through) is now released and re-armed based
  on which window actually asked for it, rather than on the window's name. The
  old rule read the session id back out of a `session-<id>` window label, which
  meant nothing owned capture in a window hosting several sessions, and focusing
  any window that was not a session window force-released the grab.

- SSH host-key pins are keyed on one canonical spelling of the host, so `::1`,
  `[::1]`, `studio.local` and the mDNS-qualified `studio.local.` are one
  machine rather than up to four. Previously each spelling earned its own
  trust prompt and its own pin. Both sides are normalized at lookup time
  rather than only on write, so pins already on disk keep matching and no
  migration is needed. A store that already holds duplicates is folded on
  load, keeping the most recently seen pin: without that, forgetting a key
  would leave a shadow pin behind that answers the next connection, and a
  disagreeing fingerprint there is a hard stop with no way through it.

- The session toolbar could be dragged almost entirely out of the window, drag
  handle and all, leaving no way to get it back. The clamp bounded the anchor
  point to 5–95% of the window, but the anchor was the toolbar's *centre* and
  the box hung off it, so on a 1400px window a 614px toolbar reached
  `left: -237px`. Placement is now computed as a clamped top-left corner, which
  is the thing that actually has to stay on screen. A position already stored
  off-screen is re-clamped when it loads, so a toolbar previously lost that way
  comes back rather than staying lost.
- Moving the pointer over the collapsed toolbar chevron reopened the toolbar,
  so it could not be moved past or picked up without it springing open. It now
  opens on a click, and lights up on hover instead.

## [0.1.2] - 2026-07-31

### Added

- **QuickConnect address bar**, always visible under the library toolbar. Type
  an address, press Enter, and you are connected without saving anything first.
  The feature existed before as a dialog behind `Cmd/Ctrl+T` with no visible
  entry point anywhere in the window, so in practice it could not be found.
  - Suggestions as you type, drawn from saved hosts, machines found by
    discovery, and the addresses you last quick-connected to. The last of those
    are kept in the settings blob rather than the store's `history` table,
    because that table is keyed by host id and a quick connect has no host.
  - Typing an address that a saved host already covers connects through that
    host, so its quality, view-only setting and stored password still apply.
  - `Cmd/Ctrl+T` and File -> Connect to… now focus the bar.
- **"Remember this password" now works on a quick connect.** Credentials are
  keyed by host id, so a session with no host profile had nowhere to put one:
  the tick was silently discarded and the password was asked for again on the
  next connection. Ticking it now adopts the endpoint as a saved host, stores
  the password against it, and the new tile appears in the Library while the
  session is still open. A quick connect that saves nothing still leaves no
  trace, and a repeat connect to the same endpoint reuses the host it already
  made rather than adding a second tile.

### Fixed

- An IPv6 address given as a bare literal could not be connected to. `resolve`
  joined the host and port as `{host}:{port}`, so `::1` became `::1:5900`,
  which is not a parseable address. Bare literals are now bracketed before the
  lookup.
- The same fault in the SFTP sidecar: the connection label, the SSH session
  label, and three user-visible error messages (`Connect`, `HostKeyUnknown`,
  `HostKeyChanged`) all joined host and port the same way. Its mirror image
  was there too: `russh::client::connect` and `TcpStream::connect` take
  `(host, port)` as a tuple, which accepts neither a bracketed literal nor a
  DNS name spelled that way, so a host saved as `[::1]` would connect over VNC
  while its Files panel reported the machine unreachable. Brackets are now
  added where a string is built and removed where a resolver is called.
- Matching a typed address against the saved hosts now normalizes case and a
  trailing dot on both sides, so `Studio.local`, `studio.local` and the
  mDNS-qualified `studio.local.` are one machine rather than three. There is
  one definition of that rule (`vnc_store::normalize_address`) instead of the
  session layer and the store each having their own.
- The native `Cmd/Ctrl+T` and `Cmd/Ctrl+N` menu accelerators did nothing. Both
  emitted `menu://action` to the focused window and no window listened for
  them. They are now routed to the library window and handled there, so they
  also work while a session window is in front.
- Address parsing was duplicated between the host dialog and quick connect, and
  both copies mangled IPv6: `[::1]:5901` parsed to a host of `[` or `[::1]`
  depending on the copy. There is now one parser (`ui/src/lib/address.ts`),
  which also understands `host::5901`, `vnc://` links, and rejects out-of-range
  ports instead of passing them to an IPC call that only takes a `u16`.
- The host dialog reported "address is required" for everything. It now shows
  the specific reason the address cannot be used.

## [0.1.1] - 2026-07-31

### Fixed

- Text copied on the remote never reached the local clipboard. Two independent
  faults, both on that path:
  - The Extended Clipboard handshake was half implemented. The client
    advertised the pseudo-encoding but never answered the server's capabilities
    message with its own, and never answered a `notify` (which carries no data)
    with a `request`, so servers using the modern flow had no way to hand the
    text over. A capabilities announcement also sets the notify bit, so it was
    additionally being read as an offer of data.
  - The delivery into the OS clipboard went through `navigator.clipboard`.
    WebKit only honours it while a user gesture is live, and remote clipboard
    text arrives from the socket, so the write was rejected and the rejection
    swallowed. Both directions now go through the shell
    (`set_local_clipboard` / `read_local_clipboard`).

## [0.1.0] - 2026-07-30

Everything below shipped in the `v0.1.0` build. The entries were still filed
under "Unreleased" when that tag was cut; they are grouped here rather than
moved into `0.1.1`, which contains only the clipboard fix above.

### Added

- `#![forbid(unsafe_code)]` on `vnc-core`, `vnc-transport`, and `vnc-store`,
  making the existing absence of `unsafe` compiler enforced rather than a review
  convention. `vnc-discovery` and `vnc-files` already declared it.
- In-app **About and Help** dialog with version, author, license, keyboard
  shortcut reference, and troubleshooting notes. Reachable from the command
  palette, the Help menu, and the macOS application menu.
- macOS code signing and notarization tooling under `scripts/`: self-signed
  identity setup for local development, a linker shim that keeps the code
  identity stable across rebuilds, and a packaging script that signs, notarizes,
  and staples both the `.app` and the `.dmg`.
- `docs/MACOS_SIGNING.md` explaining why an ad-hoc signed build loses keychain
  and TCC grants on every rebuild, and how a stable signing identity fixes it.
- Project documentation for public release: `LICENSE-MIT`, `LICENSE-APACHE`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and this changelog.

### Fixed

- Text copied on the remote never reached the local clipboard. Two independent
  faults, both on that path:
  - The Extended Clipboard handshake was half implemented. The client
    advertised the pseudo-encoding but never answered the server's capabilities
    message with its own, and never answered a `notify` (which carries no data)
    with a `request`, so servers using the modern flow had no way to hand the
    text over. A capabilities announcement also sets the notify bit, so it was
    additionally being read as an offer of data.
  - The delivery into the OS clipboard went through `navigator.clipboard`.
    WebKit only honours it while a user gesture is live, and remote clipboard
    text arrives from the socket, so the write was rejected and the rejection
    swallowed. Both directions now go through the shell
    (`set_local_clipboard` / `read_local_clipboard`).
- Native menu items were inert. `menu.rs` emitted a `menu://action` event for
  every custom item, but nothing in the frontend listened for it, so
  **Settings** and **Help** did nothing when selected. The frontend now routes
  those events.
- Notarization stapled the ticket to the disk image only. An app dragged out of
  the DMG carried no ticket of its own, so its first launch on a machine without
  network access would fail Gatekeeper. The `.app` is now notarized and stapled
  before the DMG is assembled, giving both layers a ticket.

### Changed

- Dependency refresh. Rust: `russh` 0.49 to 0.62 (see Security), `rusqlite`
  0.32 to 0.40, `keyring` 3 to 4, `netdev` 0.31 to 0.45, `mdns-sd` 0.11 to
  0.20, `directories` 5 to 6, `zune-jpeg` 0.4 to 0.5, `fast_image_resize` 5 to
  6, `webpki-roots` 0.26 to 1.0. Frontend: React 18 to 19, Vite 6 to 8,
  TypeScript 5 to 7, `@vitejs/plugin-react` 4 to 6.
- CI and the documented prerequisite move to Node 22, which Vite 8 requires
  (`^20.19.0 || >=22.12.0`).
- `rand` stays at 0.8 on purpose. rand 0.9+ implements the rand_core 0.9/0.10
  traits while `rsa` 0.9 requires rand_core 0.6, and the RA2 handshake passes
  an RNG straight into `RsaPrivateKey::new`. Moving forward needs `rsa` 0.10,
  which is still a release candidate. Recorded in `.cargo/audit.toml`.
- The macOS About panel is populated with name, version, author, copyright,
  license, and project URL. It previously used `AboutMetadata::default()` and
  showed only the bundle name.
- `.gitignore` now covers `*.key`, `*.cer`, `*.p8`, `*.pfx`,
  `*.certSigningRequest`, `*.mobileprovision`, and editor directories. It
  previously covered only `*.pem` and `*.p12`.

### Security

- **Upgraded `russh` 0.49 to 0.62**, which fixes RUSTSEC-2026-0154 (unbounded
  32-bit allocation) and RUSTSEC-2026-0153 (unchecked `CryptoVec` allocation),
  both reachable from a hostile SSH peer during file transfer. Patched upstream
  in 0.60.3. The ignore entries for these were removed rather than retained, so
  a regression fails the build.
- Migrated `vnc-files` to the russh 0.62 API: `Handler` now uses
  return-position `impl Future` instead of `#[async_trait]`, authentication
  returns `AuthResult` (which distinguishes full success from partial success)
  rather than a bare bool, `PrivateKeyWithHashAlg::new` is infallible, and the
  agent hands back `AgentIdentity` values that may wrap a certificate.
- `rsa` RUSTSEC-2023-0071 (Marvin) remains accepted and documented. There is
  still no fixed release; the only newer publication is a release candidate
  carrying the same advisory. It is now present twice, directly for RA2 and
  transitively through `ssh-key`.
- Test fixtures no longer embed a real machine name captured from a developer's
  network. The mDNS packet fixture in `crates/vnc-discovery/src/dnsmsg.rs` was
  rewritten with a same-length placeholder label so all wire length fields stay
  valid and the packet remains byte exact.
- Personal signing identifiers and an Apple ID address were removed from
  `docs/MACOS_SIGNING.md`, which now reads as generic setup instructions.

### Initial implementation

Core capability at this point:

- Pure Rust RFB implementation covering protocol versions 3.3 through 3.8.
- Encodings: Raw, CopyRect, RRE, Hextile, Zlib, ZRLE, Tight, and H.264.
- Pseudo-encodings including Cursor, Cursor With Alpha, Desktop Size, Extended
  Desktop Size, Desktop Name, Extended Clipboard, Fence, Continuous Updates,
  LastRect, Extended Mouse Buttons, and the QEMU key, LED, and pointer
  extensions.
- Authentication: None, VncAuth, VeNCrypt, RealVNC RSA-AES (RA2), Apple
  Diffie-Hellman, MS-Logon, and Tight security negotiation.
- TLS through rustls with trust-on-first-use certificate pinning.
- Host library backed by SQLite, with groups, tags, thumbnails, and history.
- Credential storage in the OS keychain, with an encrypted-file fallback using
  XChaCha20-Poly1305 under an Argon2id derived key.
- LAN discovery over mDNS plus a rate-limited subnet scan with RFB banner
  fingerprinting, and hostname resolution over mDNS, LLMNR, NetBIOS, and MS-RPC.
- Wake-on-LAN.
- SFTP file transfer with a dual-pane browser and drag and drop.
- Adaptive quality presets, remote desktop resize, and automatic reconnect with
  backoff and jitter.

[Unreleased]: https://github.com/psmux/DeskVNC/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/psmux/DeskVNC/compare/v0.1.2...v0.2.0
[0.1.0]: https://github.com/psmux/DeskVNC/releases/tag/v0.1.0
