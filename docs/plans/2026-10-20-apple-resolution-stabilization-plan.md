# Apple resolution instability: evidence and exact repair plan

Date: 2026-10-20. Audit target: `6933f0d`.

Status: the client-side defects below are fixed on
`feature/apple-screen-sharing-driver`, and the eight probes that reproduced
them now pass. Nothing has been verified against a live Mac yet, and no PR has
been pushed.

## What this round changed

Fixed, with tests:

| Finding | State | Where |
|---|---|---|
| R1 one-pixel answer treated as a shrink | fixed: a shrink is a loss of points, not of pixels | `desktop_shrank`, `answer_is_notable` |
| R2 restoration was a bare write | fixed: a restore is a full round with one attempt, reported only after the layout confirms it | `start_round`, `ResizeRound::restoring` |
| R2 queued round kept a stale rollback target | fixed: the next round snapshots the geometry this one confirmed | `finish_round` |
| R3 any layout/picture counted as completion | fixed in part: the round requires a picture assembled after its re-offer, and recovery cannot re-offer during a round | `round.needs_picture`, revive guard |
| R4 renderer dropped a new layout and stretched into the old one | fixed: the layout is held and committed with the picture that answers it; a differently shaped picture is surfaced, not stretched | `WebGLRenderer.pendingLayout` |
| R5 a reduced stream overwrote the remembered panel | fixed: equal points with fewer pixels no longer replaces the entry | `writeAppleGeometry` |
| R6 wire request could differ from the reported intent | fixed: the descriptor carries the request's pixels exactly, no ratio round trip | `DisplayRequest`, `display_config` |

Not done in this round, and still required before normal use:

- Step 1's startup descriptor change. The first `0x1d` still asks for the
  remembered geometry, because that is the message that attaches the session
  to the console display. A person who changed the Mac's resolution since the
  last session will still have it put back. Deciding between a non-dynamic
  descriptor and a dynamic one that echoes the current mode needs a live test.
- Step 2's full separation of observation and preference (one versioned cache,
  connection epochs, per-display keys).
- Step 3's rejection of a request that cannot keep the desktop (for example a
  4:3 picture on a 16:10 desktop). It is now sent exactly and reported, not
  silently rewritten.
- Step 7's presentation acknowledgement back to the driver. Completion still
  rests on an assembled access unit, not on the renderer confirming what it
  presented.
- Step 8's transaction logging, Step 9's fake-session transaction test, and
  Step 10's live matrix.

This round changed production code, tests, and these documents. It did not
install a binary, restart the application, change application storage, or
connect to a Mac.

## 1. What needs to hold

A stream-quality choice must not silently change the Mac's logical desktop or
rearrange its windows. Changing local Fit/zoom must not send a display-mode
request. An explicit experimental remote-mode change may change geometry, but
must complete as one serialized, acknowledged transaction or report failure.
Neither a layout acknowledgement nor receipt of any H.264 access unit proves
that the requested picture has been decoded and presented.

The visible symptom has two distinct forms:

- Smaller **desktop points** make remote UI elements larger relative to the
  screen. This is a remote mode change, not just local zoom.
- A stale local framebuffer/view transform or a stretched mismatched picture
  can change the viewer's scale without establishing a new remote mode.

Both are possible in the current code. A low-resolution picture upscaled into
a large texture does not restore the Mac's point geometry or add sharpness.

## 2. Findings and evidence

### R1. A one-pixel difference triggers a full rollback (reproduced, P0)

`quality.rs:resolution_for` rounds Low's height from 1169 up to 1170.
`session.rs:answered_smaller` then treats **any** smaller backing dimension as
failure, without checking whether the desktop points changed.

Actual local log, UTC, `logs/deskvnc.log`:

```
09:56:18.226  request pixels=(1800,1170), points=(1800,1169)
09:56:21.440  layout bw=1800 bh=1169 lw=1800 lh=1169
09:56:21.632  resize round complete
09:56:21.632  answered smaller; desktop restored before=(1800,1169)/(1800,1169)
09:56:23.382  no picture; media session re-offered
```

This is not evidence of a logical shrink: points are unchanged. It is evidence
of an unnecessary second display request. The server's exact cropping/rounding
rule is not established by the log; do not invent one to explain it.

The converse also fails: changing points from 1800x1169 to 900x584 with backing
unchanged at 3600x2338 passes the current pixel-only check.

### R2. Rollback is fire-and-forget (confirmed in code, P0)

`finish_round` clears `in_flight`. The `RoundEnd::Done` branch then writes a
new `0x1d` for `round.before`, but does not start another round. Its subsequent
`0x451` is therefore outside the branch that sends `0x1c` and waits for video.
The code immediately logs "desktop restored" and tells the user it was put
back, before even a layout acknowledgement.

The protocol notes describe `0x1d -> 0x451 -> 0x1c -> replacement video` for a
media-mode resize. A rollback is another resize and cannot omit its latter
steps. A later generic recovery re-offer can accidentally make it work, which
fits "small, then bigger again, or not"; that causal explanation still needs
a controlled session trace.

Other rollback defects:

- `finish_round` does not update `before` when it starts a queued round.
- Timeout clears the round and drops intent without confirmed restoration.
- An external/user display change cannot be distinguished from our request's
  reply. A blind restore risks undoing somebody else's change.

### R3. Completion is not tied to the replacement picture (confirmed, P0)

Any next `0x451` while `awaiting_layout` is accepted as the reply. There is no
request reason, causal layout boundary, or selected-display identity.

The video task labels **any** assembled unit with the current generation.
An old active SSRC can still produce units after a re-offer. No decoded or
presented width/height/epoch is returned to `ResizeRound`. If backing pixels
do not change, `needs_picture = false` skips the picture wait even when the
logical desktop or encoder changes.

Generic recovery also sends `0x1c` and increments the same generation while a
resize is running. The log includes a recovery re-offer between a resize's
layout and completion. Two controllers are restarting one encoder.

### R4. The renderer loses new layouts and stretches into old geometry (reproduced, P0)

`WebGLRenderer.setRemoteSize` returns immediately for an active Apple decoder.
It saves no pending layout. The output callback later compares the decoded
size to `fbWidth/fbHeight`, labels that old texture size as the "known layout",
and stretches any difference greater than 32 pixels into it.

Reproduction: old 3600x2338 -> new layout 2700x1754 -> decoded 2700x1754 still
leaves the framebuffer at 3600x2338. An unrelated 1600x1200 picture is also
accepted and stretched across that Retina surface. Preserving an old picture
during a transition is sensible; discarding the target layout is not.

`Session.tsx` separately updates `remoteSize`, so the UI and renderer can report
different sizes. Input mapping uses the renderer's geometry; validate it too.

### R5. Initial geometry is a feedback loop, not physical-panel detection (reproduced/code, P1)

The startup path is:

```
per-profile cached layout -> first encrypted dynamic 0x1d (if cache accepted)
ServerInit -> provisional local size and Native button
first 0x451 -> baseline/native pixel and point geometry
Connected -> UI restores saved quality -> SetQuality -> another dynamic 0x1d
subsequent layouts -> write the same cache -> next connection's first 0x1d
```

The first layout is observed **after** a cached display configuration may
already have been sent. Naming it "the Mac's own geometry" does not make it an
independent physical capability measurement.

`writeAppleGeometry` preserves the largest point area, but overwrites pixels
when point area is equal. A reduced 1800x1169 stream can therefore replace
3600x2338 in the cache used on the next connection. LAN and VPN saved profiles
also have different keys even if they address the same Mac.

The `>=1280x800` heuristic cannot distinguish physical panels, virtual screens,
valid small displays, or a client-requested mode. `nativeSizeRef` latches the
first provisional size and has no baseline provenance. Reading physical modes
over the separate SSH path is a different measurement; do not silently enable
that or change a panel to diagnose a stream.

### R6. Display intent and actual serialized request can differ (reproduced, P1)

`request_for` averages two axis ratios, clamps to 1..3, and rounds to two
decimal places. `display_config` then rebuilds dimensions from the scalar.
A manual 1600x1200 request with 1800x1169 points is silently serialized as
1800x1170. Telemetry still says 1600x1200.

The new alternate modes also offer smaller logical desktops. There is no
capture showing that macOS must receive precisely this heterogeneous table or
that it selects its first/preferred entry on all session paths.

### R7. Earlier protocol conclusions were overstated (correction)

The earlier review `../reviews/2026-10-20-apple-resolution.md` says a small cap
made it impossible to grow. However, the pre-`4a897d8` serializer already used
`max(requested pixels, prior cap)` in each axis. The requested first mode was
not excluded by that advertised bound. The host may have another internal
limit, but increasing our cap is not proof of removing that limit.

The reference RFC documents bounds/index validation and a host-dependent
fallback. It does not establish that repeated point sizes cause fallback, that
3840x2160 is a universal cap, or that a `0x1d` geometry chooses the console
login session. Its media resize example is HEVC; our path is AVC. Those are
hypotheses requiring controlled evidence, not completed fixes.

Likewise, mismatched decoded and layout dimensions do not prove the AVC
encoder always follows points. A stale encoder after an incomplete resize or
rollback can produce the same observations. Do not redefine High to enlarge
the user's logical desktop based on those observations.

## 3. Repeatable evidence without touching a Mac

Commands from the repository root:

```sh
python3 docs/reviews/apple-resolution-review-probes/run_rust.py
ui/node_modules/.bin/vitest run \
  --config docs/reviews/apple-resolution-review-probes/vitest.config.mts
```

At this HEAD: **4 Rust failures, 1 Rust pass, 3 UI failures**, all on unchanged
production helpers. The pass establishes that the descriptor bounds its first
mode. The failures reproduce R1, stale queued rollback, R4, cache poisoning,
and requested-vs-serialized dimension mismatch.

Normal suites still pass: **103 apple-core tests, 480 UI tests**, TypeScript
check clean. This demonstrates missing coverage, not a validated resize path.
See the probes' README for limitations. Historical log entries do not carry
build/connection/transaction IDs consistently, so they cannot establish which
build or route caused a fallback.

## 4. Repair options

1. **Contain first, then repair transactions (recommended).** Stop automatic
   Apple display mutations and gate experimental remote-mode changes. Repair
   the lifecycle and presentation contract before restoring quality presets.
2. **Patch only the descriptor/cap again.** Small change, but cannot fix false
   rollback, stale presentation, or interleaved re-offers. Not sufficient.
3. **Keep fixed geometry and defer dynamic resizing.** Safest initial PR scope;
   quality would need a separately verified encoder-only control. This matches
   the original AppleRD note, which deferred dynamic resizing.

## 5. Exact implementation steps, in order

Each step is a small reviewable commit with tests. Do not install or reconnect
until the offline gates pass and the user approves a live test window.

### Step 1: contain surprising changes

Files: `session.rs`, `Session.tsx`, `SessionToolbar.tsx`, `MacDisplayControls.tsx`.

- For Apple, stop automatically converting restored quality preferences into
  dynamic `0x1d` requests on connect/reconnect.
- Separate local Fit/actual/custom zoom from explicit remote display changes.
- Gate dynamic mode controls as experimental and state their possible desktop
  effects. Do not promise preservation from a request alone.
- Do not blindly replay inferred panel geometry from localStorage at startup.
  Validate a no-change/static preface for the console attach path before
  replacing the current preface; omitting a required protocol message is not
  an assumed safe fix.
- Gate both UI and driver paths so CLI/agent requests cannot bypass containment.

Acceptance: a normal connect/reconnect plus local Fit/zoom produces no implicit
steady-state display-mode changes. VNC/RDP/SSH behaviour remains unchanged.

### Step 2: separate the five geometries and their provenance

Files: `options.rs`, `apple_media.rs`, `session.rs`, `appleGeometry.ts`,
`useSession.ts`, `Session.tsx`.

Represent separately: ServerInit/provisional size, requested display points and
backing, accepted `0x451`, media-answer canvas, decoded/presented surface.
Keep a last-known-good presentation distinct from last requested values.

- Record connection epoch, source, selected display, and observation time.
- Treat physical panel capabilities as unknown unless independently read with
  permission. Never infer them from largest area or the first arbitrary layout.
- Cache user preferences separately from observations. Old geometry entries
  must not be applied as native capabilities. Use a versioned cache migration
  through the application API, not direct SQLite edits.
- Reset per-connection native/observed state on reconnect. Do not latch
  ServerInit as a permanent Native target.

Acceptance: reconnect after Low cannot silently redefine native High; absent
capability data stays unknown instead of guessed from a smaller stream.

### Step 3: make wire intent exact and traceable

Files: `session.rs`, `quality.rs`, protocol fixtures/tests.

- Store explicit pixel and point pairs. Do not average axes or silently clamp
  an intent into another mode. Reject incompatible requests with a reason.
- Validate message length, indices, every mode, and bounds independently of
  the Mac. Report the actual selected wire entry, not only the UI's intent.
- Keep the selected target's point geometry exact for a quality-only request.
- Capture-backed validation must decide which descriptors, bounds, alternate
  modes and refresh flags work. Do not generate a new magic table to hide a
  lifecycle bug. Record AVC-specific evidence and avoid copying AGPL code.

Acceptance: logged/requested/serialized target agrees byte-for-byte, or the
request is rejected before transmission. A changed backing cap is not treated
as a discovered host capability.

### Step 4: one coordinator for resize and media recovery

Files: extract a small coordinator from `session.rs`; integrate `video.rs`.

Use explicit states:

```
Idle -> AwaitLayout -> AwaitMediaAnswer/Replacement -> AwaitPresented -> Idle
                          | failure
                          v
                    RestoreAwaitLayout -> RestoreAwaitMedia ->
                    RestoreAwaitPresented -> Idle or Failed
```

- One pending user intent (latest wins), one active transaction, one encoder
  re-offer controller. Recovery cannot issue an independent `0x1c` mid-round.
- Snapshot last confirmed geometry for each new transaction, including queued
  rounds. Snapshot is not the stale first round's `before`.
- Associate layout events with the serialized request boundary as far as the
  protocol permits. If ambiguous, remain pending/report ambiguity rather than
  treating any session-transition layout as success. Local transaction IDs
  alone do not create an on-wire acknowledgement.
- A new local generation is not proof of a new encoder. Require a configured
  independent replacement picture with verified dimensions and epoch; do not
  count units from the old active SSRC as completion.
- Handle unsolicited layout changes explicitly, including changes initiated
  by a person or another viewer, without blind automatic restoration.

Acceptance: delayed layouts, old-stream pictures and repeated user selections
cannot falsely complete or overlap a round.

### Step 5: define success by intent, not a pixel-only less-than test

Files: coordinator, `quality.rs`, geometry validation tests.

- Quality-only success requires unchanged desktop points. Smaller backing
  alone is not a smaller logical desktop.
- Record backing/visible/coded differences separately. A 1170 -> 1169 layout
  difference with unchanged points is not by itself grounds to restore.
- Validate AVC crop/alignment from stream metadata; do not apply an arbitrary
  32-pixel tolerance to every mismatch.
- A logical-only change must be noticed even if backing is unchanged.
- An explicit requested smaller desktop is not a failed quality change.

Acceptance: Low 1800x1170 -> layout 1800x1169 / 1800x1169 points does not bounce
back; a genuine unintended point-size change is handled as failure.

### Step 6: make restoration a complete, bounded transaction

Files: coordinator and the rollback/timeout branches in `session.rs`.

- Run restoration through the same layout, re-offer, replacement and
  presentation handshake, not a bare write after clearing `in_flight`.
- Allow at most one automatic restoration attempt per failed transaction.
- Update state and the user's notice only after verified restoration. Before
  that say "restoration requested". On timeout say current state is unverified.
- Preserve queued intent until the transaction reaches a terminal state, and
  give external changes precedence rather than overwriting them.

Acceptance: after a rejected High request, either previous geometry and live
video are verified, or a clear failure is shown. No resize loop and no false
"desktop restored" notice.

### Step 7: commit presentation atomically

Files: `WebGLRenderer.ts`, `Session.tsx`, binary/event/IPC framing as needed.

- Keep `pendingLayout` separate from the texture holding the last good picture.
- Carry stream/transaction identity to the renderer; discard retired output.
- On compatible replacement output, allocate/upload a replacement texture and
  commit texture dimensions, view transform, cursor and input geometry together.
- Return a small generation-and-dimensions presentation acknowledgement for
  transitions only, not an expensive acknowledgement for every frame.
- Surface an incompatible aspect/size as mismatch and request coordinated
  recovery. Do not close the last good frame and stretch arbitrary 4:3 output
  into a Retina surface, or call upscaled Low output native High.
- Test pointer mapping against remote points and the accepted pixel geometry;
  do not blindly send a stale renderer's coordinates to the Mac.

Acceptance: both downsize and upscale transitions commit once, old frames do
not change geometry, mismatched frames cannot silently redefine it, and the
cursor still hits all four corners at different local device-pixel ratios.

### Step 8: diagnostics that can settle the protocol questions

Files: session/media events, diagnostics hook/component/report and logging.

Record: build hash/dirty flag, connection and transaction IDs, action reason
(startup/quality/manual/restore/recovery), before/requested/serialized/accepted
pixel and point pairs, media answer, SSRC/epoch, SPS/visible/coded dimensions,
presented geometry, and restoration result. No passwords, keys, clipboard
contents or raw authentication records.

Keep sampling at session scope even with Connection Info closed. Currently the
hook is inside that conditional dialog, which explains reports beginning only
when it opens. Snapshot report counters and findings at the same time.

Label `prefer-hardware` as a configured preference, not proven actual decoder
selection. Current input timing is input-to-next-assembled-unit, not correlated
input-to-presented-effect; do not use it to certify the session healthy.

Acceptance: opening the dialog at 600s includes pre-dialog transitions and
identifies exactly which build and round produced a fallback.

### Step 9: fake-session tests before another live install

Add tests for: odd-size acknowledgement; logical-only shrink; queued snapshots;
exact wire intent; delayed and unsolicited layout; same-size layout with a new
encoder; old SSRC continuing after re-offer; recovery racing a round; rollback
success/failure/timeout; close/reconnect mid-round; pending renderer layout;
retired output; aspect mismatch; cache migration and one Mac under two profiles.
Assert emitted `0x1d`/`0x1c` sequence and presentation acknowledgements, not only
pure helper return values. Keep unrelated protocols' regression tests.

Run baseline suites and migrate the seven RED audit cases into production
coverage. Existing tests that bless old-framebuffer stretching or pixel-only
rollback must be replaced with the user-visible invariants above.

### Step 10: authorized live matrix and PR gate

Only with renewed permission, record the Mac's initial point geometry and run:

1. Fresh profile and reconnect with normal fixed geometry; include a previous
   small-stream session. Compare startup, layout and presented dimensions.
2. Low -> Medium -> High -> Low at least five cycles, first slowly, then with
   rapid selections. Observe the Mac's point geometry/window arrangement.
3. Same user/session over LAN and VPN; one viewer at a time. Include pause,
   sustained motion, 10 minutes idle and 30 minutes of active use per route.
4. Authorized induced delay/loss and a rejected request. Verify bounded
   restoration, no re-offer storm and a responsive last valid view.
5. Reconnect and close mid-transition. Verify final desktop state explicitly.

Pass criteria: no unrequested logical mode change, no small/large oscillation,
no stale stream counted as completion, correct input geometry, truthful
failure notices, and measured replacement presentation. Do not claim High
works merely because `0x451` echoed a large backing size.

Hold the PR as experimental/not ready for normal use until these gates pass.
Do not open or push a PR without the user's separate approval.

## Sources

- Current production files at `6933f0d`, cited by function above.
- Local historical application log, inspected read-only, UTC excerpts above.
- `iShareScreen/docs/apple_vnc_rfc.md`, sections 6.5, 7.1-7.5, 8.4, 10.9.
  Reverse-engineered evidence with acknowledged revision gaps, not an Apple
  guarantee for this AVC server path.
- Scoped Joplin AppleRD `approach.md`, pulled before use. Its original scope
  explicitly deferred dynamic resizing and separated physical display controls.
