# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version stays below 1.0, minor releases may contain breaking changes
to stored data and to the IPC contract between the Rust core and the frontend.

## [Unreleased]

## [0.17.2] - 2026-08-26

Patch: one frontend fix. Nothing stored changes and no command or event
gains a field.

### Fixed

- **Clicking a tab occasionally showed a Paste menu.** The click was
  never the cause: a secondary click anywhere in the window produced it,
  and on macOS both Ctrl+click and a two-finger trackpad tap count as
  one, so it was easy to do by accident.

  What made it a *paste* menu was where the focus was. Both kinds of
  session keep a focused, editable element to own keyboard input: a VNC
  or RDP session has the transparent composition overlay that dictation
  and IME need in the accessibility tree, and an SSH session has the
  terminal's own hidden input. A webview picks its context menu from the
  **focused** element rather than the clicked one, so with either of
  those focused the editing menu appeared over the tab strip, the
  toolbar, anywhere at all. It needed a session to be open, which is also
  the only time there are tabs to click, which is why it seemed
  intermittent.

  The native menu is now suppressed everywhere except a genuine text
  field, where Cut, Copy and Paste are the point. The session canvas
  still owns the right click it forwards to the remote desktop.


## [0.17.1] - 2026-08-26

Patch: behaviour only. Nothing stored changes shape and no command or
event gains a field.

### Fixed

- **Detaching from tmux or psmux hung up the connection.** `Ctrl-B D`
  ended the whole session instead of returning to the remote prompt.

  The attach command was run as the SSH command itself, which ties the
  connection's life to the multiplexer: the moment it exits, the channel
  closes and the connection goes with it. That is what
  `ssh -t host tmux attach` does, and it is not what anyone wants from a
  terminal. A login shell now starts and the attach is typed into it, so
  detaching behaves like `ssh host` followed by `tmux attach`: back at
  the remote prompt, still connected, free to reattach or do something
  else.

  The previous release only changed the wording of the message. The
  session still ended, which is not a fix.

- **A saved SSH password was ignored unless the profile also said to use
  one.** A host with a password in the keychain still failed with "the
  ssh agent holds no identities", because authentication was an
  exclusive choice and the default was the agent.

  Every real SSH client treats authentication as a preference order, and
  this one now does too: the configured method is tried first, then
  whatever else there is material for. Saving a password is enough to
  make it work, whatever the setting says. A method with nothing behind
  it is skipped rather than attempted and refused, which would burn a
  try against servers that count them.

- **A profile's startup command never ran.** It was stored and read and
  then never reached the far side. It now runs inside the multiplexer,
  so it is as persistent as the rest of the session, and is covered by
  tests.


## [0.17.0] - 2026-08-26

Minor rather than patch under the sub-1.0 rule in this file's own header:
the `ssh_settings` blob gains two more fields and there is a new command.

### Added

- **Connect straight into WSL.** A Windows host can be set to enter a WSL
  distribution instead of its native shell, and attach to tmux **inside**
  the distribution.

  That last word is the whole point. The multiplexer a WSL user cares
  about lives in the distribution, not on the Windows side, so the probe
  runs in there too. A probe that asked Windows whether it had tmux would
  be answering for the wrong machine, and would answer "no" on a box
  whose WSL has had tmux for years.

  The distribution can be detected rather than typed: where a host has
  saved credentials, the editor asks it which ones it has and offers
  them. Where it cannot ask, for a host with no WSL or no saved
  credential, a name can be typed instead, and a blank one means the
  default distribution. None of that is treated as an error, because
  none of it is one.

- **An SSH host tile shows its terminal.** It fell back to the
  hashed-colour placeholder before, because a terminal has no framebuffer
  to snapshot. The visible buffer is now drawn to an image and stored the
  same way a desktop's thumbnail is, so an SSH host looks alive in the
  Library like every other host. The store's existing downscale is reused
  rather than a second one invented.


## [0.16.1] - 2026-08-26

Patch rather than minor: nothing stored changes shape and no command or
event gains a field. The one contract addition is a new value in the
`symbol` vocabulary, which the contract already specifies is to be
ignored when unrecognised, so it cannot break a webview that predates it.

### Fixed

- **A terminal used only the top-left corner of its window.** The remote
  stayed at the size the profile was saved with, usually 80 by 24, so a
  full-screen program drew into a small box and left the rest of the
  window empty.

  The terminal measures itself the moment it appears and sends its size
  immediately, but the session is still connecting then: a dial, a key
  exchange, authentication, the multiplexer probe and a pty request all
  have to finish first. That first message arrived before there was
  anything to receive it and was dropped, and nothing sent another. The
  size is now sent again once the session connects, which also covers a
  reconnect, where the far side is a new pty that has never been told
  anything.

- **Detaching from tmux or psmux looked like a failure.** `Ctrl-B D`
  reported "the remote shell exited", because detaching makes the attach
  command exit cleanly and at that level a detach and typing `exit` are
  the same event.

  They mean opposite things to the person watching, and the multiplexer
  is what tells them apart: with one attached, a clean exit means the
  session is still running on the remote. It now says so. It deliberately
  does not reconnect on its own, because reattaching someone who has just
  asked to detach would make detaching impossible.


## [0.16.0] - 2026-08-26

Minor rather than patch under the sub-1.0 rule in this file's own header:
the `ssh_settings` blob gains two fields. The release exists for the fix
below, which made SSH host profiles unusable in 0.15.0.

### Fixed

- **An SSH profile ignored its username and password.** Adding a host with
  an account and a password, then connecting, failed with "no ssh agent is
  available: the ssh agent holds no identities" whatever had been typed.

  The shell loaded the saved credential correctly and then the conversion
  into the session's own options threw it away, so every SSH connection was
  attempted as agent authentication with an empty user name. The comment on
  that function asserted the shell had already turned the credential into an
  `SshAuth`; nothing did, and the claim is what made the gap look deliberate.
  The credential is now read where the comment said it already was, and four
  tests pin it, one of them named for this failure.

- **An SSH profile had no way to say how to authenticate.** There was no
  setting for it at all, so agent was not merely the default, it was the only
  possibility. Profiles now choose between the agent, a password from the
  keychain, and a key file, and the host editor asks first, above the
  multiplexer, because it decides whether the connection works at all.

- **Quick Connect could not open an SSH session.** An ad-hoc target has no
  profile, so it has no stored account and no secret, and without a way to
  ask, the only authentication that could ever succeed was an agent. A
  refused authentication now asks, reusing the credential dialog the other
  protocols already use, and retries with the answer. Only an authentication
  refusal asks: a refused dial or a changed host key are not things a
  password fixes, and a dialog for either would be one that cannot help.

  An empty user name now resolves to the local account rather than being
  sent as empty, which a server rejects outright.


## [0.15.0] - 2026-08-25

Minor rather than patch under the sub-1.0 rule in this file's own header:
the host store gains an `ssh_settings` column and two credential fields,
and the IPC contract gains SSH commands, events and a binary message
type.

### Added

- **SSH is a third protocol**, alongside VNC and Remote Desktop. A host
  profile can speak it, so an SSH machine gets a tile in the Library, an
  `ssh://` address in Quick Connect, its own session window or tab, and the
  same connection history and reconnect behaviour as any other session. It
  goes through the same `connect_session` and the same session registry, so
  it inherits all of that rather than growing a parallel copy of it.

  Per-host settings cover which multiplexer to attach to and under what
  session name, a startup command to run instead of the login shell, and the
  terminal's font size and scrollback.

- **psmux and tmux are both first class, on Linux and on Windows.** The
  default is to detect rather than assume: the app asks the far side what it
  actually has, in one round trip, and takes the best of psmux, tmux, zellij
  or screen. psmux ranks ahead of tmux, and because it speaks tmux's command
  language the two share one implementation rather than two that could drift.

  A Windows machine running OpenSSH Server is a first-class target here, not
  an afterthought. Its default shell may be `cmd.exe` or PowerShell, where a
  POSIX probe does not fail loudly, it fails *silently*: the shell errors, the
  answer is unrecognisable, and the session quietly opens a plain shell on
  exactly the machine the user most wanted persistence on. So the question is
  asked in a second dialect when the first goes unanswered, and "nothing is
  installed" is kept distinct from "I did not understand the reply".

  A remote with none of them still gets a working terminal. It is told once,
  quietly, that this session will not survive a disconnect.

- **A remote shell**, as its own module (`ssh-core`) over the SSH connection
  the Files panel and the tunnel already use. It is built around the four
  things that make running `ssh` in a window irritating:

  - **It reconnects by itself.** On the same backoff ladder as a VNC session
    (250 ms doubling to a 15 second cap, with jitter), so this is one set of
    numbers to reason about rather than two. "Reconnect now" skips the wait
    and resets the counter, for when you know the network is back.

  - **It notices a hang instead of sitting in one.** A link whose peer went
    away without closing the socket looks identical to an idle one, and TCP
    will happily wait minutes before admitting it. Keepalive probes every five
    seconds, three misses, so a dead link is called in about fifteen seconds
    and reconnected through.

  - **Your work is still there afterwards.** Reconnecting on its own gets you
    a fresh empty shell, which just makes the loss quicker to find: the remote
    PTY died with the link and took everything under it. So the session
    attaches to a multiplexer instead (`tmux` by default, `screen`, `zellij`
    or a command of your own), whose session belongs to the remote machine and
    outlives any one connection. Where the multiplexer is not installed it
    opens a plain shell and says so, rather than refusing to connect.

  - **A session cut mid-`tmux` no longer wrecks the terminal.** Programs like
    `tmux`, `vim` and `htop` switch the terminal into mouse reporting and
    bracketed paste and are expected to switch it back on exit. A severed link
    never gives them the chance, which is why moving the mouse then prints
    escape garbage at the prompt and pasting arrives wrapped in control codes.
    The session now tracks which of those modes the remote turned on and sends
    exactly what undoes them whenever the link goes away.

  Host keys are trust-on-first-use against the **same** pin store as the Files
  panel and the tunnel, so trusting a machine once covers all three; a changed
  key is the same hard stop it is everywhere else.

### Changed

- **The SSH connection code moved into its own crate**, `ssh-transport`
  (dialling, host-key pinning, authentication, tunnelling, the reachability
  probe). It was inside `vnc-files`, which would have meant a terminal
  depending on a file-transfer crate to open a socket. Nothing on the wire
  changed and no behaviour changed: `vnc-files` re-exports every name it used
  to export, and the file-transfer IPC shape is identical, which is what the
  `#[serde(flatten)]` on `FileTransferConfig` is there to preserve.

## [0.14.0] - 2026-08-25

Minor rather than patch: the stored per-host Remote Desktop settings gain a
field and lose one, and the `connect_session` IPC call takes two more
arguments.

### Added

- **A resolution setting for Remote Desktop connections**, in the connection
  dialog, the View menu and Preferences. One control with three choices: match
  this window when connecting, match it and keep matching, or a fixed size from
  1280 by 720 up to 3840 by 2160, or one you type. They are one setting rather
  than a size plus a "follow the window" switch because they are not
  independent: a fixed size that also tracked the window would stop being fixed
  as soon as the window moved.

  The default is to match the window when connecting and then leave the desktop
  alone, which is what Windows' own client does. A desktop that resizes every
  time you drag a window edge rearranges that machine's icons each time.

### Fixed

- **Every Remote Desktop session connected at 1024 by 768**, whatever the
  window size. The size was a constant with a comment saying the real one
  arrived from the shell "once the window exists"; that hand off was never
  built, so nothing ever wrote it. The shell now measures the window and the
  session asks for a desktop that fits it.

- **A 4K desktop could not be reached.** The connection request cannot carry a
  height above 2048, so a 3840 by 2160 desktop was silently cut to 2048. It now
  connects at the size the request can carry and asks for the rest over the
  Display Update channel, which has room for it.

- **Preferences' Remote Desktop defaults did nothing.** Every one of them had a
  switch, a row in the store and no consumer, so turning one on changed nothing
  and the next host still arrived with the built-in defaults. Sound, clipboard,
  multiple monitors and the new resolution setting all apply to new hosts now.

- **The floating toolbar refused to resize an RDP desktop**, saying the Display
  Update channel was not supported yet. It has been for several releases, and
  the View menu never refused the same thing, so the two disagreed.

- **A resize asked for before the Display Update channel opened was lost.**
  Harmless while dragging a window, since another follows, and wrong for a size
  that is only ever asked for once.

### Changed

- The per-host "Match the remote resolution to this window" checkbox and the
  matching preference are replaced by the resolution setting. Existing profiles
  keep their behaviour: a host with the box ticked becomes "match this window,
  and keep matching".

- `.rdp` import understands `desktopwidth`, `desktopheight` and `dynamic
  resolution` together, the way mstsc treats them. The first two were parsed,
  range checked and then discarded because no field held them.

## [0.13.4] - 2026-08-25

### Fixed

- **RDP colours, properly this time.** 0.13.2 fixed the width of the planar
  colour loss reconstruction and 0.13.3 shipped with the amount still wrong,
  which left hard edged patches of roughly the complementary hue across the
  most saturated parts of the picture: teal blotches on a red face, a teal band
  along the sand.

  The shift is one less than the colour loss level, and the non lifting form of
  the transform goes with it. The lifting form carries two halvings of its own
  and needs the full level; pairing it with the eight bit reconstruction
  introduced in 0.13.2 meant every chroma sample in the top half of its range
  overflowed and wrapped, flipping its sign.

  The check that passed 0.13.3 could not see this. A wrap stays inside 0 to
  255, so nothing clamped: it reported zero clamped tiles while 15.72% of its
  chroma was sign flipped. The check that does see it is that a correct scale
  never discards a set bit. Measured live: 2,474,934 of 15,745,024 chroma bytes
  lost a bit before, 0 of 15,728,640 after. There is now a test for that
  invariant that needs no server.

  Verified on the desktop icons rather than the wallpaper, because their
  colours are known: Chrome's blue centre and red arc, blue Edge, blue Recycle
  Bin arrows, a red Core Temp bulb, a blue ASUS gear, orange OpenVPN, a yellow
  folder. Every one of them was wrong before, in ways the photograph hid.
  Cross checked against FreeRDP, which agrees.

- **NSCodec's colour transform had the same two faults**, plus the sign of Co,
  which it defines the opposite way round from the planar codec. Its encoder
  here is rewritten as the inverse of the corrected decoder, rounding to
  nearest rather than truncating. Still unverified against a real NSCodec
  server: this crate's encoder is the only thing it has been checked against,
  which is precisely the weakness that hid both planar faults.

## [0.13.3] - 2026-08-25

### Fixed

- **A pointer press could be dropped after a reconnect.** The shell decides
  whether a pointer event is safe to shed under backpressure by comparing it
  to the last button mask it saw, and that cache survived a reconnect the
  backend's input state did not. A real press whose mask matched the stale
  value was classified as stale motion and dropped if the queue was full. It
  is now forgotten on any state change. Same family as the stuck button fixed
  in 0.13.2.

- **RDP reported no frame rate and no rectangles.** The stats overlay showed 0
  for both, and a throughput figure that was neither a rate nor in the right
  unit: the byte delta since the last tick went into a field that means bits
  per second, so it read eight times low against a VNC session and drifted
  with any late tick. Frames are now counted where every graphics path
  converges, so the legacy bitmap updates, the surface bits and the graphics
  pipeline are all covered, and rates divide by the time actually elapsed.
  Decode time is still reported as 0 rather than guessed at.

- **CI was red on `main`.** Rust 1.98 became stable and its clippy carries two
  lints the previous toolchain did not, so the test gate had been failing on
  every platform since v0.13.1. Both are cleared, and the gate was rerun
  against 1.98 itself rather than a newer local toolchain that does not raise
  them.

## [0.13.2] - 2026-08-25

### Fixed

- **RDP colours were wrong.** Large areas of the remote desktop came out in
  flat, blown out primaries over a picture that was otherwise sharp and
  correctly placed, and changing the colour depth made no difference. A
  Windows 11 host sends every 32 bpp tile with a colour loss level of 3, which
  leaves five meaningful bits in each stored chroma byte; the reconstruction
  has to happen in eight bits so the rest falls off the top, and this did it
  in sixteen and kept it. A stored `0x12` means -112 and was read as +144, so
  every strongly coloured pixel left the 0 to 255 range and clamped.

  Converting a real pixel to YCoCg and back cannot leave that range, so a
  decode that clamps has misread the stream. Against a real host, 1125 of 1921
  tiles clamped before this and none after. The client's own encoder made the
  same assumption, so the round trip test agreed with the fault; the new test
  uses the bytes the host actually sent.

- **A cancelled pointer left a button held down.** On both VNC and RDP the
  right button would stop working, then start arriving long after the gesture,
  and then ordinary left clicks would open context menus. All three are one
  stuck bit: `pointercancel` and `lostpointercapture` report no button, so the
  release path ignored them and the bit survived for the rest of the session.
  A left press then travelled as left and right together.

  Button state now follows what the browser reports as actually held, on every
  event, so a mask that drifts is corrected on the next one. A cancelled pan
  had the same hole and stopped pointer input entirely. On the RDP side,
  releasing everything now releases held buttons as well as keys, and turning
  view only on no longer remembers a mask it never sent.


## [0.13.1] - 2026-08-24

### Fixed

- **RDP showed no picture.** The first bitmap update of every session was
  rejected as malformed and ended the connection. The fast path body carries a
  two octet type field that this client skipped, so the count of rectangles was
  read as the first rectangle's left edge and the rectangle came out inverted.
  A Windows 11 host sends 162 tiles in that first update; none of them arrived.
  Verified against a real host: 155 frames and 42 cursor updates in twenty
  seconds, where 0.13.0 managed none.

  The test server had the same gap, which is why two thousand passing tests
  agreed with the fault. It now sends what a real server sends, and the twelve
  octets a Windows host actually put on the wire are a test vector.

## [0.13.0] - 2026-08-24

### Added

- **DeskVNCViewer speaks RDP.** Add a host, choose Windows Remote Desktop, and
  the port and the fields change to suit it. Quick connect takes `rdp://host`.
  Saved hosts connect, ask about the certificate the first time, ask for a
  password if none is saved, and show a desktop you can type into and click on.
  The clipboard works both ways, the remote desktop follows the window when you
  resize it, and a dropped connection retries on the same ladder VNC has always
  used.
- The whole RDP stack is written in this repository. No third party RDP,
  CredSSP, NTLM or Kerberos library is used anywhere, and a test refuses one
  from the lockfile up. Cryptography is the exact opposite: every cipher, hash,
  MAC and key derivation is a call into a vetted library, and three tests fail
  if a source file starts to look like a hand written primitive.
- Graphics arrive through the modern graphics channel: RemoteFX, ClearCodec,
  NSCodec, progressive RemoteFX, the planar and interleaved codecs, and the
  RDP 8.0 bulk decompressor. There is no `unsafe` in any of it, and every
  decoder beats the performance budget written for it.
- Network Level Authentication with NTLMv2, checked against the published test
  vectors at every intermediate value. Kerberos is implemented too, for domains
  whose policy refuses NTLM, though see the limitations below.
- Network discovery finds RDP hosts as well as VNC ones, and reads the name off
  the certificate on the connection it already opened rather than opening a
  second one. It can be turned off, and when it is off it opens nothing.
- `.rdp` files can be imported.
- A message for a case domain users actually hit: a host whose policy refuses
  NTLM now names the two Group Policy settings to change, in the words an
  administrator sees, and does not ask for the password again. Asking again
  would have spent three attempts against a lockout counter for a password that
  was never wrong.
- `docs/RDP_SPEC_NOTES.md`, which records every place the code had to choose a
  reading that only a specification vector can settle, so nobody has to
  rediscover them from a module comment.

### Changed

- **The host database gains a schema version, and the interface contract gains
  fields.** Existing profiles migrate and keep working exactly as they did, and
  a profile written by a newer build is refused with a message saying so rather
  than misread. This is what makes the release a minor one rather than a patch.
- Internals were split so two protocols can share them rather than growing a
  second copy: the session contract, pixel conversion, the reconnect ladder,
  the credential and certificate prompts, the renderer, the frame channel and
  the SSH tunnel are now common to both. The VNC side behaves as it did, and
  its tests pass without an assertion being edited.

### Fixed

- **Four faults that only a real server could find.** The first connection to a
  real Windows host found all of them in an hour. The domain parameters in the
  MCS connect were tagged as an application type rather than a plain sequence,
  which the host rejected by name. The length the host gives for its own
  greeting understates it by the two blocks it appends afterwards, and trusting
  that number cut the greeting short. A server lists its codecs with no
  identifiers assigned, which was read as four codecs colliding. And the
  priority marking on the host's first real message was compared against the
  one value this client happens to send. Every one of them passed every test in
  the suite, because the test server was written from the same misreadings.
- **A right click could do nothing, and then take effect much later.** Input
  packets were sent as independent IPC requests, and nothing made the shell
  handle two of them in the order they were issued. A press and its release
  milliseconds apart, which is what a trackpad tap and a synthesised context
  click both are, could therefore land reversed, leaving the remote holding a
  button the user had already let go of: the click appeared to do nothing, and
  only came out later when some unrelated pointer event happened to carry a
  mask without that bit. Input is now queued so no packet can overtake
  another, and a synthesised right click travels as a single packet the way a
  wheel click already did.

### Security

- Every decoder is fed bytes controlled by a remote peer, so every one has a
  test asserting that a truncated input returns an error rather than panicking,
  for every possible prefix. The codec decoders also have fuzz targets driven
  from raw bytes.
- RDP certificates are pinned under their own scheme rather than sharing the
  VNC one. A host can serve both protocols with unrelated certificates, and a
  shared row would have let one vouch for the other.
- Nothing is sent to a server whose certificate you have not approved. The
  prompt holds the connection open until you answer, and dismissing it ends the
  attempt before the first credential is built.
- A password that came from the keychain rather than from you is tried once and
  not replayed, because replaying a saved credential is how a domain account
  gets locked out.
- Locking the credential store now wipes every decrypted secret it was holding.
  It previously wiped only the key and let the decrypted entries drop, which
  left every password it had opened sitting in freed memory.

### Known limitations

RDP is new in this release and these are the edges of it.

- **It has been connected to one real machine.** A Windows 11 host, on
  2026-08-24, reaching the desktop through NLA and receiving the picture. That
  work found five faults in an afternoon that two thousand passing tests never
  could, because the mock server is built from the same reading of the
  specification as the client and agrees with every misreading. Expect more of
  them on hosts that differ: older Windows, a domain, a gateway, xrdp. `docs/RDP_SPEC_NOTES.md` names the
  two places where being wrong shows up as subtly wrong pixels rather than an
  error, and neither is settled.
- **H.264 is not used.** The client advertises graphics capability versions 8
  and 8.1, which contain no H.264, so a server will not send it. Everything
  else in the graphics channel is used.
- **Kerberos is not reachable from a running session.** The implementation is
  complete and tested against the RFC vectors, but the session does not yet
  perform the name lookup that finds a domain controller, and it is behind a
  build feature. A Kerberos only domain still fails today.
- **Audio is decoded and not played.** Where playback should happen is not
  decided yet.
- TLS 1.0 and 1.1, for Windows 7 and Server 2008 R2 hosts, is built but the
  handshake is not implemented, and the feature is off.
- Not planned: RemoteApp, printer and smart card redirection, drive
  redirection, audio input, and the RD Gateway.

## [0.12.0] - 2026-08-23

### Added

- **Hosts can be selected in bulk and dropped onto a group or a tag.** Click a
  tile, Cmd/Ctrl-click to add one, Shift-click for a run of them, or sweep a
  marquee across empty space the way you would over files. Cmd/Ctrl+A selects
  everything on screen, Escape clears it. Dragging the selection onto a group
  in the sidebar moves the whole lot; dropping it on a tag adds that tag and
  leaves the tags those hosts already carried alone; dropping it on All Hosts
  takes them out of their group. The same two moves are in a bar above the
  grid and in the right-click menu, for anyone who would rather not drag, and
  every one of them can be undone from the toast it raises. The gesture is
  built on pointer events rather than HTML5 drag and drop, which the file-drop
  handler the session window needs would have blocked on Windows.
- Three new IPC commands behind it, `set_hosts_group`, `add_tag_to_hosts` and
  `remove_tag_from_hosts`, each writing the whole selection in one
  transaction.

### Fixed

- **New groups and new tags are created again.** The Library sent only the
  name it had just asked for, but the shell deserializes a complete record, so
  every creation was rejected before it reached the database. The failure was
  then swallowed into a console warning: the dialog closed, the sidebar did
  not change, and nothing said why. The payload is now complete, and a
  creation that does fail says so in a toast.

## [0.11.0] - 2026-08-23

### Added

- **The floating toolbar can be switched off, and the app menu carries
  everything it did.** Preferences ▸ Session has a "Hide the floating
  toolbar" switch for anyone who would rather have nothing at all on top of
  the remote desktop. The View and Session menus grew to cover the whole bar
  first: scaling and zoom, the monitor list, pointer options, quality and
  gray levels, view only, shortcut pass-through and the send-to-remote
  chords, clipboard, file transfer, screenshot, refresh, and a Connection
  Info dialog with the latency and throughput figures the status button used
  to show. The menu is live rather than decorative, it shows which scaling
  mode, quality preset and monitor are actually in force, follows whichever
  session is in front, and greys the session half out when nothing is
  connected. The zoom items deliberately carry no keyboard shortcuts:
  a menu accelerator is claimed by the OS before the webview sees it, so
  Cmd/Ctrl+= and Cmd/Ctrl+- would have been stolen from every remote
  application for the life of the app.
- **Preferences ▸ Session sets the defaults for every toolbar option.**
  Scaling, quality, gray levels, view only, always-request-fresh-frames,
  shortcut pass-through, zoom lock and edge panning all have a global default
  now, which is where a computer starts before anything has been adjusted on
  it. "My pointer" joined "Show the remote pointer" under Input.

### Fixed

- **The chosen monitor is remembered, and no longer thrown away by a
  reconnect.** Picking a monitor is now kept against that computer, through a
  disconnect, a reconnect, and closing the app. It survived none of those
  before, and the reconnect case was not really about persistence: the
  selection was cleared the instant its id was missing from the list of
  monitors, and a reconnect arrives with an empty list before the server
  describes itself again, so the choice was dropped in the gap and never came
  back. The selection is now derived from a remembered intent rather than
  stored as an applied id, so a list that momentarily matches nothing shows
  the whole desktop and the monitor returns with the layout. Matching is by
  identity where there is one (a server's own screen id, or the detected
  left/right pair, which is followed even when the seam moves by a pixel
  between runs) and by rectangle otherwise, so a manual cut is never carried
  onto a desktop of another size where its id would mean a different piece of
  the screen.
- **"Always request fresh frames" never did anything.** `set_always_refresh`
  was wired up as a command and called by the toolbar, but was missing from
  the permission manifest and from both capability files, so every call was
  refused with "Command not found" and the switch moved without changing the
  session. It is allowed from the library and session windows now.
- **Menu items could act twice on one click.** The `menu://action` listeners
  resolved a turn after the effect that registered them, so a cleanup that had
  already run left the unsubscribe function to be assigned after the fact and
  the listener stayed registered for good; every re-run added another. It went
  unnoticed while the menu held only one-way actions, and would have made
  every new toggle a no-op, applied once by each listener and landing back
  where it started.
- **Everything else the toolbar changes is remembered too**, per computer:
  scaling mode, zoom, quality preset, gray levels, view only,
  always-request-fresh-frames and shortcut pass-through. Pass-through is
  re-armed quietly on reconnect, without raising the Accessibility explainer
  on its own. Ending a session no longer counts as switching pass-through
  off, which is what used to erase that setting on every disconnect.

## [0.10.0] - 2026-08-17

### Added

- **The seam between two monitors is now detected from the picture.** When
  the server describes no layout, the desktop is sampled at full resolution
  shortly after the connection settles and the one column where two side by
  side monitors visibly disagree (different wallpapers, a taskbar stopping
  dead, a letterbox band) is searched for, but only at positions where a
  monitor boundary could plausibly sit: the midpoint, or a common panel
  width from either edge. A find appears in the Displays menu as "Display 1
  / Display 2 (detected)" above the manual cuts; a miss (mirrored
  wallpapers, a window straddling the seam) keeps the manual cuts, and a
  "Detect displays again" entry re-runs the search once the seam is
  uncovered. Detection re-runs on every desktop resize and never crosses a
  server-described layout.

## [0.9.1] - 2026-08-17

### Fixed

- **Monitor selection did nothing against the servers that need it most.**
  The TightVNC family serves a multi-head desktop as one wide framebuffer and
  never says where the seams are, so 0.9.0's Displays menu could only shrug
  at exactly the "two monitors squeezed into one view" complaint it was built
  for. When the server describes no layout, the menu now offers manual cuts
  of the desktop instead: equal halves, one common monitor width (2560, 1920
  or 1440) on either side for unequal pairs, and thirds when the desktop is
  wide enough, labelled as the guesses they are. Selecting one crops the
  view exactly as a server-described monitor would.

## [0.9.0] - 2026-08-17

### Added

- **Pick a single monitor of a multi-head desktop.** The toolbar's Displays
  menu is now real: it lists every monitor the server advertises through
  ExtendedDesktopSize, in left to right order with resolutions, and selecting
  one shows just that monitor. Every scaling mode, edge panning, the drag
  pan and pointer mapping work against the selection, and the pointer cannot
  leave the selected monitor. Thumbnails, live previews and screenshots still
  capture the whole desktop. Servers that never describe their monitors keep
  the whole desktop view, and the menu says so.
- **A diagnostics toolkit for "the picture is slow"** (`docs/DIAGNOSTICS.md`).
  The interesting failures are attribution problems: the network, the server's
  encoder, our protocol behaviour, our decoder and the webview all look the
  same from inside the app. So there is now a set of small probes that stand
  outside it and measure one thing each (`tools/limbs`), plus a headless
  client (the `stall_probe` example) that runs the real vnc-core stack with no
  UI and reports the update gap distribution.
- **Connection stats say where the latency figure came from** (a fence, an
  idle probe, or the passive update pipeline readout) **and how hard the
  server is working for us** (the fraction of time spent inside framebuffer
  updates), because the sources are not comparable and a reader that treats
  them as one number draws the wrong conclusion.

### Fixed

- **The automatic quality tuner could saturate the link and never notice.**
  Compression relief on the High tier could drive Tight compression to 0,
  which does not mean "a bit less zlib", it means no zlib at all: measured
  against TightVNC on a 2880x1800 desktop, a steady 9.9 MB/s of raw
  sub-encodings on an 82 Mbit/s link. It was also self-sustaining, because
  uncompressed rects take longer to read off the wire, which kept the relief
  that caused them engaged. The ladder never asks for less than compression
  level 1 now.
- **A fast link in front of a slow server pinned quality at High while
  interactivity collapsed.** The tier choice had no term for what the chosen
  tier costs the server. Measured at 2880x1800: High bought about twice
  Medium's bandwidth and cost about twenty times its response time, 430 ms
  against 19 ms. The ladder is now capped while the server's measured
  response stays over budget, with a two minute penalty so the cap cannot
  limit cycle through the improvement its own remedy produces.
- **Latency now reads on servers without the Fence extension even when the
  screen never goes quiet.** The idle probe only samples a still screen, so a
  busy desktop could go minutes without a reading. A passive readout now
  times request to next header during busy streaks, takes the median so one
  full screen repaint cannot set the figure, and expires stale samples so an
  idle stretch cannot leave a ten minute old number standing.
- **"Always refresh" could be parked for the rest of the session by one lost
  answer.** A refresh is now recognised by damage coverage rather than exact
  size, abandoned after ten seconds, and asked less often of a server that
  answers slowly.

## [0.8.2] - 2026-08-07

### Fixed

- **The latency reading was consistently too low, never too high** ([#1]). The
  probe for servers without the Fence extension was completed by whichever
  framebuffer update arrived first, and an unrelated update is always *earlier*
  than the probe's own answer, which is why the error only ever ran one way: a
  276 ms link read as 200 ms, and a loopback connection read tens of
  milliseconds. A one-pixel probe is answered by a one-pixel update, so an
  update carrying real damage now spoils the probe instead of completing it,
  and the next quiet moment tries again. Note the figure is a round trip
  through the server's update loop, not a network ping: it includes however
  long the server takes to notice and answer, which is why even a loopback
  connection does not read as zero.
- **The connection detail panel still showed "0 ms" before anything had been
  measured** ([#1]). The toolbar was fixed in 0.8.0; the panel behind it was
  not. It now reads "-" as well.
- **Fullscreen was bound to Ctrl+F on Windows and Linux** ([#1]). The
  accelerator was written as `CmdOrCtrl+Ctrl+F`, which collapses to a plain
  Ctrl+F on those platforms, quietly taking Find away from every remote
  application. It is now F11 there, the convention on both, and stays
  Cmd+Ctrl+F on macOS.
- **Help ▸ About from a session window opened the dialog on the library
  window** ([#1]), behind the session being looked at. The shell that renders
  it is only mounted in the library window; a session window now has its own.

### Removed

- **Space-drag panning, which never worked** ([#1]). Nothing ever told the
  input handler the space bar was down, so holding it simply typed a space on
  the remote desktop. Wiring it up would have been the wrong fix: space is an
  ordinary key that belongs to the remote, and holding it to pan would stop it
  typing. Edge scrolling covers what it was meant for, and Alt+middle-drag
  still pans deliberately.

[#1]: https://github.com/psmux/DeskVNC/issues/1


## [0.8.1] - 2026-08-07

### Fixed

- **The latency reading jumped between about 1 ms and 180 ms on the same
  link** ([#1]). The round-trip probe introduced in 0.8.0 for servers without
  the Fence extension is closed by the next framebuffer update, and on a busy
  screen that update is somebody else's: one already in flight ends the timer
  almost immediately, while the probe's own answer queued behind a full
  repaint reads as hundreds of milliseconds. It now waits for a quiet moment
  before probing, when the parked incremental request means the only update
  that can arrive is the answer to the probe, and the figure is smoothed so a
  single scheduling hiccup does not throw it. An unanswered probe is
  abandoned after five seconds rather than freezing the reading.
- **Fullscreen kept the menu bar on Windows and Linux** ([#1]), so the remote
  desktop never actually filled the screen. There the menu belongs to the
  window, and it is now hidden while fullscreen and restored on the way out.
  macOS puts the menu in the system bar, which it hides for fullscreen
  windows itself. The toolbar's fullscreen button and its shortcut both still
  work with the menu gone; Escape is deliberately left alone, since it has to
  reach the remote desktop.

[#1]: https://github.com/psmux/DeskVNC/issues/1


## [0.8.0] - 2026-08-07

### Added

- **The view scrolls itself when you push against an edge** ([#1]). At 1:1 on
  a desktop larger than the window, everything past the edge was simply
  unreachable: panning existed, but only as a space-drag nobody could be
  expected to discover. Moving the pointer into the edge of the view now
  scrolls toward it, faster the closer you get, the way RealVNC does. It is
  inert whenever the desktop already fits, and it only scrolls in a direction
  that has something left to show. The remote pointer keeps up with the
  moving view rather than lagging behind it. "Pan by moving to edges" in the
  toolbar's Scaling menu turns it off, next to the pinch-zoom lock;
  space-drag panning works either way.

### Fixed

- **The Session and Connection menus did nothing at all** ([#1]). Every
  custom menu item is emitted to the frontend to be routed, and the library
  window and app shell each handled their own, but nothing ever listened for
  the session's. So Show/Hide Toolbar, Actual Size, Fit to Window, the
  Quality items, View Only, Refresh Screen, Send Ctrl+Alt+Del, Release All
  Keys, Reconnect and Disconnect were all dead from the menu bar, while the
  same actions worked from the session toolbar. Only the view in front acts,
  so the item does what you would expect with several tabs open.
- **The toolbar hid itself while the pointer was resting on it.** Auto-hide
  is driven by pointer movement, so a stationary pointer over the toolbar
  produced no events and it collapsed at exactly the moment it was being
  used. Hovering it now holds it open, and the countdown restarts when the
  pointer leaves.
- **The toolbar twitched sideways once a second.** The latency readout is
  re-measured every second and sized itself to its contents, so the whole bar
  shifted as the figure moved between "-", "9ms" and "290ms". The field now
  has a fixed width.
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
  point to 5 to 95% of the window, but the anchor was the toolbar's *centre* and
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

[Unreleased]: https://github.com/psmux/DeskVNC/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/psmux/DeskVNC/compare/v0.13.4...v0.14.0
[0.13.4]: https://github.com/psmux/DeskVNC/compare/v0.13.3...v0.13.4
[0.13.3]: https://github.com/psmux/DeskVNC/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/psmux/DeskVNC/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/psmux/DeskVNC/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/psmux/DeskVNC/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/psmux/DeskVNC/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/psmux/DeskVNC/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/psmux/DeskVNC/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/psmux/DeskVNC/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/psmux/DeskVNC/compare/v0.8.2...v0.9.0
[0.2.0]: https://github.com/psmux/DeskVNC/compare/v0.1.2...v0.2.0
[0.1.0]: https://github.com/psmux/DeskVNC/releases/tag/v0.1.0
