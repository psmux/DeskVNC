# Apple Screen Sharing review: disconnects, black screens, quality changes

Date: 2026-10-19. Reviewed working tree based on `7e6dd7f`, including the uncommitted Apple driver and frontend changes.

## Scope and confidence

This is a review, not a fix release. No Mac connection, input, resolution, application process, or installed binary was changed. Human takeover remains respected. Only this report and an isolated, intentionally failing regression harness were added.

Reviewed: authentication, encrypted control framing, media offers, SRTP, RTP/H.264 assembly, resize sequencing, WebCodecs/WebGL presentation, quality UI, input commands, and SSH physical-display control. The installed and bundled AppImages have matching SHA-256 `6496ea8d9a60da88a4f980e6f68a767ad5bc0577e4d23d031398b60bb3c1001c`; matching artifacts does not verify live behavior.

Evidence labels:
- **Reproduced:** exercised locally against unchanged source with synthetic packets or a mocked WebCodecs API.
- **Confirmed in code:** a directly observable implementation/state-machine defect; its frequency on this Mac is not measured.
- **Needs live verification:** server behavior, negotiated capabilities, actual panel effects, or hardware output cannot be established statically.

Existing tests pass: **19 Apple-core tests and 58 selected renderer/input tests**. Additional review probes fail **7 Rust cases and 4 renderer cases**, demonstrating missing coverage rather than an existing-suite regression. Details and commands are below.

The protocol document is a useful reference, not a universal capture oracle. In particular, its dynamic-media examples are HEVC-oriented, its `0x451` live-geometry leader and provider-blob/Appendix C descriptions have acknowledged offset discrepancies, and multiple-rekey/answer schemas retain revision gaps. Do not blindly apply those descriptions to AVC without vectors. The attempted bounded Joplin pull did not produce a usable result; this report does not claim to incorporate newly synchronized notes.

## Observed symptom: scrolling artifacts (added after the first review pass)

Reported on the live Mac connection: **visible artifacts appear on both High and Low quality during horizontal or vertical page scrolling**. Many artifacts accumulate, they are hard to clear, and **reconnecting often fixes it**.

That fingerprint is diagnostic. A quality-independent, motion-triggered, self-sustaining corruption that a fresh session clears is not a quantization or resolution problem. It is a broken H.264 reference chain with no repair path.

Three mechanisms in this code produce exactly that, and they compound:

1. **Motion is the trigger, because motion is when the reference chain is exercised.** Scrolling produces many inter-coded pictures, a higher bitrate, and therefore the most packet loss and reordering. A static screen hides the same defects.
2. **Nothing repairs the chain.** There is no reorder buffer, no gap detection, no NACK, no independent-picture request, and no decoder feedback to the driver (P0-3, P0-5). A picture lost once stays wrong until the next IDR, and the encoder's IDR interval is not under our control. That is the "hard to get rid of them" part.
3. **An intra picture during motion wipes the decoder's references.** See P0-7. The picture after an unnecessary decoder reset references pictures the new decoder never had, so corruption persists, and a reconnect, which starts a clean IDR, appears to "fix" it.

The reference implementation documents the same class of failure in this exact area, and it is the strongest available corroboration:

The reference implementation documents the same class of failure in this exact area, and it is the strongest available corroboration. In its own words, paraphrased: Apple's four-tile AVC stream uses cross-tile references, so decoding the interleaved sub-streams in one shared decoder resolves those references to the wrong tile's pictures. No decode error is raised, the corrupted frame is published anyway, and drift (it calls them "fleas") accumulates under motion. Asking for one self-contained picture per frame removes the cross-tile dimension.

Source: `iShareScreen/src/isharescreen/proxy/protocol/offers.py`, function `tiles_per_frame`. That project is AGPL-3.0-or-later; the protocol facts are used here, and none of its code is copied into this repository.

Two consequences for this driver:

- Our offer already requests `tilesPerFrame = 1` (media blob field 6 = 1), the same single-self-contained-picture workaround the reference uses for AVC. Keep that, and **verify the server honors it** by counting distinct video SSRCs. That count is not currently logged.
- If more than one SSRC is ever seen, the streams must never be merged into one decoder. The reference shows the result is silent corruption with no decode error, which is precisely the artifact symptom.

The reference's recovery design is also the model to follow: per-SSRC sequence tracking, NACK on detected gaps, a targeted per-tile Full Intra Request, a stalled-tile FIR backstop, and LTRP-aware fast recovery.

## Executive diagnosis

The symptoms are consistent with several interacting defects, not simply an overly aggressive quality setting:

1. **Quality switching is an unfinished encoder-restart transaction.** A layout event clears the resize lock, clears the visible framebuffer, and permits another restart before new video has decoded.
2. **RTP streams are mixed by arrival order.** Any SSRC change resets one shared assembler, even before authentication. Old/new-stream overlap can prevent complete pictures indefinitely.
3. **Packet loss becomes decoder corruption.** Sequence numbers never reach the assembler; incomplete fragments and malformed aggregation can be published as key pictures. There is no media repair/recovery feedback loop.
4. **A decoded intra picture destroys the reference chain.** Any access unit containing an intra slice is treated as a key picture and used as a decoder reset, so the decoder's reference pictures are discarded mid-stream. Under motion this happens often, and the corruption persists until the next IDR.
5. **Decoder failure can become permanent.** A failure latch survives resize/reconnect within the same renderer, while asynchronous hardware errors bypass the advertised software fallback.
6. **“Quality” actually changes display configuration.** The descriptor is explicitly virtual, uses flat 1× modes, and does not implement a verified physical-panel-preserving stream-quality control.

Normal softness from reducing resolution and enlarging H.264 4:2:0 is expected. Persistent blocks, gray/smeared areas, frozen references, "fleas" drifting over the picture, and a screen that never returns are not an acceptable consequence of Low quality. Current code provides multiple mechanisms for those defects without any evidence that the Mac's compression quantizer is the primary cause. The reported scrolling artifacts are a worked example: they are a broken reference chain, not "Low quality looks soft".

## Pieces worth preserving

- The steady-state ciphertext buffer uses cancellation-safe `read_buf`; mouse activity no longer discards a partially read control record. Keep the interrupted-read regression.
- Initial 4096-bit RSA-SRP sign-in and initial record decryption were previously verified live. The remaining server-proof/rekey issues do not invalidate those specific observations.
- SRTP correctly verifies the truncated 80-bit authentication tag before decrypting; do not regress to full-length SHA-1 comparison.
- avcC plus length-prefixed chunks, host GStreamer discovery, and linear NV12 resolved specific previously observed WebKit/AppImage problems. Hardware decode was previously evidenced with `vah264dec`; this review does not reverify the current running pipeline.
- Latest-decoded-frame presentation closes superseded frames, and generic pruning preserves H.264 dependency barriers. Keep those properties when bounding backlog.
- SSH uses the existing trusted host-key verifier and credentials; retain those trust boundaries and refusal to undo outside mode changes.

| Symptom | Most likely mechanism | Findings |
|---|---|---|
| Artifacts during scrolling, on every preset, cleared by a reconnect | Intra picture misclassified as a key picture, used as a decoder reset, wiping the reference chain; loss and reordering with no repair path | P0-7, P0-8, P0-3, P0-2, P0-9 |
| Black screen after a quality change | Resize transaction completes before new video decodes; framebuffer cleared early; decoder failure latched | P0-1, P0-4, P0-2 |
| Intermittent disconnects | Rekey resets the record sequence counters; unparsed control messages; worker death is silent | P1-11, P1-10, P1-14 |
| Mac resolution changes unexpectedly | The resize path is a virtual-display configuration with flat 1× modes, not a panel-preserving quality control | P0-6, P1-7, P1-18 |

## Latest corrective pass: quality switches still appear ineffective

The earlier **Fixed/Done table below is historical and overstates completion**;
it is not a live verification record. No Mac control or reconnect was performed
in this pass; human takeover remains in force.

Locally reproduced and corrected:

- A cached decoded size overrode later framebuffer sizes, including non-Apple
  sessions. A new decoder whose rectangle already matched its output skipped
  resizing the old texture. Continuous output now sizes the texture directly;
  layout announcements keep the old picture/decoder until replacement output.
- Late output/errors from a retired decoder could affect its replacement in the
  same slot. Callbacks now check context identity as well as generation.
- Merely seeing two SSRCs permanently blocked further stream adoption. Candidates
  also lost their configuration burst because they were ignored before assembly.
  Per-SSRC assembly now keeps candidates; configured key pictures may replace the
  active stream after re-offer or a stall, and retired streams cannot take it back.
  Unknown SSRCs authenticate before allocation; the bounded cache no longer clears
  active replay state. Its 32-stream limit remains a per-connection limitation.
- Queued requests lost logical-point dimensions. Both coordinate spaces now travel
  with each request, and quality requests explicitly use baseline desktop points.
  A baseline layout is processed before starting a deferred quality request.
- Removed the speculative pixel/point swap and automatic retry introduced in
  `7631a81`. A size ratio is not evidence of reversed wire fields. Neither Dock
  position nor screenshots prove physical-panel changes or their cause.
- Control reports now distinguish requested pixels, layout pixels/desktop points,
  media-answer canvas and actual frontend-decoded dimensions. Reports refresh once
  per second, independent of picture-count modulo. Backend pictures are labelled
  **assembled**, not decoded; decoder delay is submission-to-output only.

Auto/High intentionally share one resolution target; Low/B&W share another, with
B&W additionally using local grayscale. Balanced still requests 1.5 pixels/point;
**no evidence here establishes whether macOS accepts that density**. Earlier
claims that macOS can only supply 1×/2× were not established.

Validation: **88 apple-core tests, 453 UI tests (28 files), TypeScript, 37 Rust
review probes and 6 renderer review probes pass**. Regression tests first failed
for texture sizing, retired callbacks, SSRC replacement/replay-state allocation
and misleading panel labels. These use synthetic packets/mocked WebCodecs, not
real hardware decoding. Two review-probe fixtures needed the previously added
submission-timing map; their assertions were unchanged.

Still unverified/incomplete: negotiated stream identity/geometry correlation,
renderer acknowledgement and rollback, complete same-SSRC restart handling,
physical desktop/panel preservation, genuine RTT correlation, loss/backpressure
recovery and post-change hardware performance. Assembly progress is not proof of
successful decoding/presentation at the requested size. Do not infer successful
SRP server-side test impossibility from the earlier incorrect server equations.

## Historical implementation status (not live verification)

The findings below are the original implementation status. Read the corrective
pass above before relying on any **Fixed/Done** label.

| Finding | State |
|---|---|
| P0-1 resize transaction | **Fixed.** A round ends on a picture at the new size, not on an acknowledgement; the newest request wins; a round that is never answered times out and says so. |
| P0-2 SSRC adoption | **Fixed.** Packets are authenticated before they can change anything; each SSRC keeps its own state; a second stream is reported, not merged. |
| P0-3 H.264 assembly | **Fixed.** Sequence numbers reach the assembler, packets are put back in order, a hole invalidates its picture instead of corrupting it, and the wait for a hole is bounded. |
| P0-4 decoder recovery | **Fixed.** A failure belongs to the stream, not to the pane; the hardware refusal is reported and retried; a first frame is counted when pixels reach the screen. |
| P0-5/P0-8 media recovery | **Fixed.** The feedback key is kept, and the session asks for the missing packets and for a fresh picture, in the three forms Apple's server answers. |
| P0-6 virtual display | **Corrected, still to be seen.** The display type is required for a dynamic descriptor and is what the native viewer sends; the comment no longer calls it a private display. A quality change now keeps the desktop at the size the person arranged it at. Whether the physical panel itself is untouched still needs a live check. |
| P0-7 intra picture | **Fixed.** Only an IDR resets the decoder; an intra picture is fed to the existing one. |
| P0-9 two streams | **Fixed.** The negotiated tile count is reported and the streams are never merged. |
| P1-7 logical and backing sizes | **Fixed.** The mode table keeps the desktop in points and changes only the pixels. |
| P1-8 classification | **Fixed.** The whole picture is classified, and "key" and "reset" are different things. |
| P1-9 SRTP replay | **Fixed.** A replay window, a monotonic state, and rollover counters that the tag settles. |
| P1-10 control parsing | **Fixed.** The rectangles are walked, and the layout and the rekey are found wherever they are. |
| P1-11 rekey counters | **Fixed.** A rekey changes the key and the IV; the counters belong to the session. |
| P1-12 offer flags | **No change needed.** The code was already right, and the note in the protocol document is a trap. |
| P1-13 offer and answer | **Done.** The answer is read: a binary property list with the media description in it, and the description says the canvas the encoder settled on and how many tiles it is using. An answer with an empty canvas means the Mac's encoder is still warming up, and the offer is asked again. |
| P1-14 supervisor | **Fixed.** A dropped connection comes back, "reconnect now" works, and a dead video receiver ends the session instead of hiding it. |
| P1-15 display controls | **Fixed.** The work is off the input path, listing modes no longer resizes the picture, and an orderly disconnect restores the panel. |
| P1-16 authentication | **Partly.** The server's proof is now checked, the sign-in has a deadline, and the group is checked. The proof's exact shape is still unconfirmed against a live Mac, so a mismatch is reported rather than fatal. |
| P1-17 input contracts | **Fixed.** Held keys and buttons are released, view-only sends nothing, and the agent's intents are refused with a reason. |
| P1-18 sizes and baselines | **Done.** The bounds are one rule for every entry point, and the baseline is the Mac's own geometry from its first layout rather than the canvas the caller asked for. The presets are measured against it, in **pixels per point** rather than in absolute pixels: a retina Mac draws two pixels for every point, so "balanced" is one and a half and "low" is one. An absolute box put a retina Mac below one pixel per point, which is blurrier than the plain screen the person was used to. |
| P2-19 measurement | **Done.** The stream's health is counted, logged, and on the screen: the canvas the Mac is sending, the pictures decoded, the packets lost, the recoveries, the decoder's queue and how far behind it is. |
| P2-20 UDP buffers | **Done.** The sockets are bound before the offer goes out, they ask for a four megabyte receive buffer and say what they got, only the Mac's own packets are read, the pictures go through a queue so the receiver never stops reading the socket, and the ports are options with a clear error when they are taken. |
| P2-21 decoder backlog | **Partly.** The decoder's queue and the delay from the wire to the picture are measured and shown. The NV12 upload is still a copy rather than a zero-copy path, which WebKit does not offer. |
| P2-22 the interface | **Done.** The Mac's quality menu says what it does, the stream size buttons keep the shape of the screen, and the media numbers are in the Mac panel. |
| P2-23 regression coverage | **Partly.** The protocol, the renderer and the session rules have tests, and a whole media stream is driven through the real SRTP protection and the real assembler. A fake *server* is still missing: the sign-in needs a server side of the SRP exchange, and the two sides' key derivations do not agree in an independent implementation of the textbook formulas, so a fake server cannot be written from the specification alone. The live Mac's server does agree with our client, which is the only reason the sign-in works. |

**Two things are worth knowing about the sign-in.** The server accepted our
client proof, and that proof contains the session key, so the Mac's key and
ours are the same. The Mac's proof is therefore checked against ours, and a
mismatch is reported rather than fatal until a live session has confirmed
the framing. Separately, an independent implementation of the textbook
server formula does not produce the same key as our client, so the two
sides' derivations do not agree in the abstract: the live Mac is the
authority here, and a fake server cannot be written from the specification
alone.

**The mouse offset in a scaled window is explained.** The pointer mapping
is the exact inverse of the drawing: a new test puts points on the screen,
maps them to a framebuffer pixel and asks where that pixel is drawn, and
the two answers agree to within the rounding, in every scaling mode and
with the view panned.

The offset the user saw is the margin of an aspect-preserving view. A
3600x2338 desktop shown in a 16:9 window leaves a margin on each side,
and a pointer in that margin is outside the remote screen, so it is held
at the edge of the picture. The remote cursor is then drawn at that edge,
which is a little way inside the window, and the two cursors do not agree:
about a hundred pixels in a 1600 pixel window, which is the "about fifty
pixels near the right edge" that was reported.

It is not a mapping mistake, and it cannot be fixed by moving the pointer
mapping: the remote screen has no such margin, so a pointer there has
nowhere to be. The honest fixes are to say that the pointer is off the
picture, or to shrink the margin. That is a decision about the interface,
and it is still open.

## Priorities

Here **P0** means fix before further unattended resize experiments, **P1** means required for a dependable driver, and **P2** means measurement, completeness, or performance work. This is project triage, not a CVSS security classification.

### P0-1: Finish the resize transaction through actual decoded output

**Confirmed in code.** `crates/apple-core/src/session.rs:255-260,378-390,436-470`; `ui/src/screens/Session.tsx:426-428`.

- `resize_in_flight` becomes false on the first recognized `0x451`, immediately before/around writing the media re-offer. The next queued `0x1d` is sent immediately afterward. There is no answer/configuration/key-picture/decoded-output gate.
- There is no resize deadline, rollback, rejected-request state, or correlation with a particular request. Unrelated/duplicate layout events can advance the transaction.
- A specific latest-intent bug: from native, request Low and then High before Low's layout arrives. High equals the *old current dimensions*, so the outer `target != current` check discards it. Low can then apply even though High is the latest selection.
- Physical-mode requests and stream resizes use separate, overlapping sequencing.

**Fix:** one coordinator with requested, pending, and effective states and a media generation. Model at least `requested, then layout accepted, then media offered and answered, then an authenticated new configuration, then an independent picture, then decoded and presented, then committed`. Queue the latest desired target even when it equals the pre-transition geometry. Add bounded timeouts and explicit rollback/recovery to a last verified setting. Wire a renderer acknowledgement back to the coordinator; UDP access-unit emission alone is insufficient. Do not invent an on-wire request ID if the server has none, use a local generation and validated transition expectations.

**Acceptance:** rapid Low, Medium, High and native, Low, High-before-layout both end at the final request with decoded output; stale layouts cannot complete a newer transaction; lost replies time out visibly and recover.

### P0-2: Authenticate before SSRC adoption; never mix streams in one assembler

**Confirmed in code.** `session.rs:269-325`.

`video_ssrc` is replaced and the single depacketizer reset before `unprotect()`. One delayed old-stream packet resets the new stream; the next new packet resets it again. Simultaneous quality variants have the same problem, even with a one-picture offer. Invalid unauthenticated packets can also alter selection and populate the 32-entry context map. Once full, a legitimate unseen SSRC is refused indefinitely; old contexts are never retired.

**Fix:** validate/authenticate a candidate without committing active state; retain per-SSRC sequence, assembly, and crypto state; select a negotiated display/tier/generation, not the most recently arriving packet. Promote only a usable configuration/independent-picture stream, retire old generations after a bounded overlap, and bound authenticated candidate storage with eviction. Restrict expected peer/source where possible, without replacing SRTP authentication with an address check.

**Acceptance:** interleaved old/new SSRCs do not reset each other; random invalid packets cannot change active state or exhaust stream slots; more than 32 legitimate successive resizes remain usable.

### P0-3: Make H.264 assembly loss-, order-, and corruption-aware

**Reproduced.** `crates/apple-core/src/h264.rs:24-80,112-157`; `session.rs:325`.

- RTP sequence numbers are discarded before assembly. A missing middle FU packet produces a truncated NAL that is still emitted as a key picture.
- A missing FU end leaves `fu_open` true across a timestamp change. A later complete, single-packet IDR is then suppressed instead of recovering.
- A STAP-A containing one complete NAL followed by a truncated NAL publishes the partial aggregation instead of rejecting the access unit.
- There is no reorder window, duplicate suppression, assembly deadline, byte limit, or bounded number of pending fragments/NALs. A damaged stream can grow assembly memory or corrupt reference state.

**Fix:** track extended RTP sequence numbers per authenticated SSRC; reorder within a bounded latency window; discard incomplete access units atomically on a known gap/deadline; clear all FU state on timestamp/configuration/generation changes. Parse aggregation/configuration atomically with strict lengths. Bound frame bytes, fragments, and lifetime. Surface loss events into media recovery rather than feeding known-incomplete reference pictures to WebCodecs.

**Acceptance:** all four H.264 transport probes pass; reorder, duplicate, wrap, lost start/middle/end/marker, malformed lengths, missing configuration, and bounded-memory cases are covered.

### P0-4: Preserve the last good picture and make decoder failure recoverable

**Reproduced in part; remaining behavior confirmed in code.** `ui/src/render/WebGLRenderer.ts:601,711-744,1038-1062,1150-1224,1273`; `Session.tsx:426-428,578-595`.

`setRemoteSize()` reallocates/clears textures, clears `sawFrame`, and closes decoders before replacement video is known to work. A dropped configuration or failed restart therefore immediately exposes a blank screen. `h264Failed` causes every later decode call to return, and is never cleared by a resize; the renderer also survives session reconnects in the same pane. The software fallback handles synchronous `configure()` exceptions only. A normal asynchronous WebCodecs error just closes the context.

**Fix:** keep the last verified image while a new-generation decoder/surface is priming, with an explicit pending/stalled overlay. Atomically commit geometry and presentation when a valid replacement output arrives. Implement bounded decoder recreation on fresh configuration/key pictures; do not retain an unrecoverable latch across media/session generations. Handle asynchronous configuration failures explicitly. If software fallback is permitted, report it; if hardware-only is required, fail visibly rather than silently violating that requirement. Guard callbacks by decoder identity and media generation, not only context ID.

**Acceptance:** missing configuration, unsupported hardware configuration, decoder error, and repeated resizes cannot permanently blank a previously usable pane; recovery preserves hardware-path reporting.

### P0-5: Add a real media recovery loop

**Confirmed in code; exact server-compatible feedback needs verification.** `session.rs:266-297,368-377`; `h264.rs`.

The UDP task emits one-byte hole-punch packets, drains/discards control datagrams, and does not implement RTCP receiver reports, loss feedback, NACK, or PLI/FIR recovery. `Refresh` sends an RFB framebuffer request, not a verified H.264 key-picture request. There is no feedback from decoder failure/stall to the driver. A lost configuration or damaged reference chain can therefore remain broken indefinitely while TCP stays connected.

**Fix:** implement the documented RTP/RTCP demultiplexing and the server-compatible, authenticated feedback path, with rate limits. Request independent-picture recovery after unrecoverable loss; recover configuration explicitly; escalate from repair to a controlled media restart only after deadlines. Do not treat another one-byte keepalive or `0x03` request as demonstrated encoder recovery.

**Acceptance:** deterministic packet-loss injection recovers without a manual quality toggle; dropping the first configuration/key picture of a resize produces bounded recovery, not permanent black.

### P0-6: Stop presenting a virtual-display operation as safe stream-only quality

**Confirmed descriptor/design conflict; actual current panel/curtain state needs live verification.** `session.rs:571-620`; `docs/plans/2026-10-19-apple-server-controls-design.md`.

`display_config()` explicitly writes `display_type = 4` (virtual). This is not evidence that only encoder resolution changes while the physical console remains untouched. Earlier statements that this path was a verified physical-display-preserving quality control were unsupported. A layout acknowledgement does not establish panel restoration, absence of curtaining, or the user's original physical mode.

**Fix:** capability-gate this experimental path and accurately label it. Verify physical/virtual/console behavior with explicit permission. If a panel-preserving encoder-scale/bitrate/FPS control cannot be established, say unsupported; do not silently substitute a private/curtained virtual display. Keep physical-panel changes separately authorized with independent restore state.

**Acceptance:** before/after mode, logical geometry, physical visibility, selected display, and restoration are independently verified, not inferred from `0x451`.

### P0-7: An intra picture must not wipe the decoder's reference pictures

**Reproduced.** `crates/apple-core/src/h264.rs:160-198`; `session.rs:337`; `ui/src/render/WebGLRenderer.ts:1057-1062`.

`is_keyframe()` returns true for **any** non-IDR slice whose type is I (2 or 7). `Depacketizer::push` then marks the whole access unit as a key picture, the driver sets `reset: au.keyframe`, and the renderer reacts by closing the decoder and building a new one:

```text
if (r.h264Reset || !ctx) { if (ctx) this.closeH264(id); ctx = this.createH264(r, id, r.payload) }
```

A new decoder starts with an empty reference picture buffer. The next inter-coded picture references pictures that no longer exist, so the picture is wrong, and it stays wrong until an IDR arrives. WebCodecs reports no error, so nothing surfaces the fault. This is the "artifacts during scrolling, hard to clear, reconnect fixes it" fingerprint: motion is when the encoder emits intra-coded pictures, and the corruption outlives them.

Marking the chunk as a key chunk is legitimate: an intra picture is independently decodable. **Resetting the decoder is not.** The reference protocol states that only an IDR is a DPB reset ("treat any IDR as a DPB reset for all tiles"), so an intra refresh picture must be fed to the existing decoder.

**Fix:** distinguish three things on the wire: IDR (DPB reset), intra/non-IDR starting picture (independently decodable, decoder keeps its references), and ordinary delta. Feed an intra picture to the existing decoder as a key chunk without recreating the context. Recreate the decoder only for a genuine configuration change, a new media generation, or controlled recovery. Do not classify a mixed I/P access unit as independently decodable (see P1-8).

**Acceptance:** an intra refresh picture does not recreate the decoder; the following delta pictures decode against the preserved references; artifacts do not appear after scrolling stops.

### P0-8: Scrolling must not be able to break the picture, and loss must be repairable

**Confirmed in code; symptom reported live.** `session.rs:266-297,325-337`; `h264.rs`.

During scrolling the encoder emits many inter-coded pictures at a higher bitrate. This driver then loses or reorders packets, keeps the corrupted reference chain, and never asks for a new picture. Concretely missing today:

- RTP sequence numbers are discarded before assembly (P0-3), so a reordering or a loss is invisible.
- No NACK, no receiver report, no independent-picture request, no FIR (P0-5).
- No decoder feedback at all: the driver's `Refresh` command sends an RFB framebuffer request, which is not a video recovery request.

**Fix:** implement the documented RTCP/RTP feedback path with per-SSRC sequence tracking, a reorder window, NACK for detected gaps, and a request for an independent picture after unrecoverable loss, all rate-limited and authenticated. Detect decoder-side trouble (missing references, decode errors) and escalate to a controlled media restart after a deadline. Reuse the reference's proven design as the behavioural model: per-tile gap detection, targeted intra requests, and a stalled-stream backstop.

**Acceptance:** a scripted scroll with injected loss produces no lasting artifacts; recovery is automatic and bounded; a deliberately dropped key picture self-heals without a reconnect.

### P0-9: Never merge two video SSRCs into one decoder

**Confirmed in code; corroborating evidence in the reference.** `session.rs:269-325`; reference `offers.py` (`tiles_per_frame`).

The reference states that Apple's stream uses cross-tile references, and that decoding interleaved H.264 sub-streams in one shared decoder "resolves the cross-tile references to the wrong tile's pictures: no decode error, so the corrupted frame is published and drift/ghosting ('fleas') accumulates under motion". Our driver currently resets its single assembler whenever the SSRC changes, which is the other half of the same hazard: it can only ever display one tile, and it destroys the other tile's assembly state each time it switches.

Our offer already requests `tilesPerFrame = 1` (media blob field 6), the same single-self-contained-picture workaround the reference uses for AVC. That is the right choice and should be kept.

**Fix:** log and count distinct video SSRCs to prove the server honored the request. Keep per-SSRC assembly, crypto, and sequence state, and never feed two SSRCs into one decoder. If a second SSRC appears, isolate it and report the negotiated tile count instead of switching streams. Do not attempt multi-tile decoding without the shared-DPB design the reference requires; a partial implementation produces silent corruption, which is worse than a visible failure.

**Acceptance:** the negotiated tile count is reported; a second SSRC never corrupts the active picture; the artifact symptom cannot reappear through tile mixing.

### P1-7: Preserve logical points, backing pixels, and HiDPI ratio separately

**Confirmed in code.** `session.rs:449-452,609-619,651-674`; `ui/src/components/MacDisplayControls.tsx:43-45`.

The mode table writes equal pixel and scaled dimensions (flat 1×), and the receiver discards the parsed scaled dimensions. “Native” stores initial framebuffer pixels, not a complete display mode. This can explain a seemingly paradoxical higher Mac workspace at a lower video resolution: for example, a 2× 3600×2338 backing screen corresponds to 1800×1169 logical points, whereas a flat 2217×1440 mode is a *larger logical workspace* despite fewer encoded pixels. This example is not a new measurement of the Mac's current mode.

**Fix:** carry display ID/origin, logical bounds, backing bounds, scale, and mode identity through negotiation, UI, and input. Restore the original mode/ratio rather than merely its pixel dimensions. Verify pointer wire coordinates for this Apple input path at center and edges; do not apply an arbitrary 50-pixel compensation that breaks fullscreen.

### P1-8: Do not equate one I slice with a key picture or every key picture with decoder reset

**Reproduced classification defect; the reset consequence is now P0-7.** `h264.rs:64,160-198`; `session.rs:337`; `WebGLRenderer.ts:1057-1062`.

`any(is_keyframe)` labels a whole access unit independently decodable when only one non-IDR slice is intra; a mixed I/P picture is therefore mislabeled, and the mislabel is then used as a decoder reset. This is the classification half of P0-7.

**Fix:** classify the complete access unit, not any single slice. Distinguish IDR, intra-only, and mixed pictures; validate independence of the whole picture. Separate the `keyframe` flag (chunk type) from the `reset` flag (DPB reset), and carry them as different fields. Preserve the documented Apple non-IDR starting-picture behavior using a captured, decodable vector rather than a two-byte slice heuristic alone.

### P1-9: Implement SRTP anti-replay and correct rollover/reordering state

**Reproduced.** `crates/apple-core/src/srtp.rs:41-87`.

Authenticated duplicates are accepted, `last_seq` can move backward, an unseen late packet from the prior rollover cycle is rejected, and an old authenticated replay can rewind state so the next legitimate rollover fails authentication. Duplicates can also corrupt FU assembly. RTP version/padding validation is incomplete.

**Fix:** follow RFC 3711 packet-index estimation and an authenticated per-SSRC replay window; advance the high-water mark monotonically only after authentication. Allow valid unseen packets within the previous-cycle reorder window. Validate RTP header/version/extensions/padding without passing padding into H.264. Keep state tied to the correct key epoch.

### P1-10: Parse the control protocol as framed messages and rectangle sequences

**Confirmed in code.** `session.rs:436-470,651-674,731-785`; `Live::read_body()`.

The record transport is buffered correctly, but upper-level handling assumes a record body contains a recognizable message at its start and only examines a first rectangle. `find_display_layout()` immediately returns `None` when that rectangle is not `0x451`; `find_rekey()` has a comparable limited shape. Large higher-level server messages can span records. Advertised fallback framebuffer formats and much metadata are not implemented/parsed.

**Fix:** bounded higher-level reassembly plus a real rectangle/message parser; validate declared sizes and supported versions, skip known payload shapes safely, and process every relevant rectangle in order. Do not advertise codecs that cannot be consumed or explicitly rejected safely. Preserve unknown-extension tolerance without guessing payload boundaries. Build actual `0x451` vectors for this server version; the reference's appendix/provider offsets are not a reason to overwrite working live-geometry offsets blindly.

**Acceptance:** cursor/layout/rekey rectangles in different orders, split/coalesced TCP delivery, multi-record payloads, malformed sizes, and unknown metadata are covered.

### P1-11: Rekey must not silently reset record sequence counters

**Confirmed implementation/reference mismatch; second-rekey host behavior needs capture verification.** `session.rs:440-442`; `crates/apple-core/src/record.rs:33-40`; reference §6.4.4.

A steady-state rekey constructs a new `RecordLayer`, resetting both counters to zero. The reference describes session-monotonic counters. If the peer retains its counters, the next record fails integrity and disconnects. The broad native capture did not exercise a second rekey, so this is a credible latent disconnect mechanism, not proof that it caused a particular observed disconnect.

**Fix:** explicit key/IV rotation preserving verified counter semantics, generation validation, and independent direction state. Add synthetic multi-rekey vectors and a controlled-host capture before claiming this fixed.

### P1-12: Media-offer flags: no change needed, and the note in the reference document is a trap

**Resolved by evidence: the byte order in the code is right.** `crates/apple-core/src/offer.rs`; reference §10.3; `iShareScreen/src/isharescreen/proxy/protocol/negotiation.py`.

This finding originally said the flags word had to be little-endian, because the reference document describes it as host-endian and shows `07 00 00 00`. That is the trap. The reference implementation says so in as many words, and records the experiment:

The reference notes, paraphrased: the field is big-endian, and switching it to little-endian on the strength of a host-side read of the framebuffer configuration is a trap. The observed behaviour is that the big-endian value `00 00 00 07` makes the host honour `do_not_send_cursor`, while the little-endian `07 00 00 00` leaves the flag clear and the host bakes the cursor into the video, which brings the double-cursor regression back. The runtime behaviour is what counts.

Source: `iShareScreen/src/isharescreen/proxy/protocol/negotiation.py`. That project is AGPL-3.0-or-later; the protocol facts are used here, and none of its code is copied into this repository.

The code already writes big-endian `00 00 00 07`, which is the same value the reference sends on the standard path (`config_flags = 3` plus the cursor bit). **Nothing is changed.** A comment now says so at the line itself, so the next reader does not "fix" it.

What is still worth doing: parse enough of the `0x1c` answer to know that the offer was accepted, and report the effective media state (cadence, tile count) rather than assuming it.

### P1-13: Model offer/answer and key epochs across encoder restarts

**Confirmed missing state; some server details remain unknown.** `session.rs:227-240,413,459`; `offer.rs`.

The same serialized offer/IDs/keys are reused without parsing the media answer or synchronizing the UDP worker. Existing SSRC crypto state survives independently of resize state, and every outgoing picture is assigned the most recently stored geometry rather than its own stream generation. An old picture can consequently acquire new dimensions. Reusing SRTP keys is not itself a proven protocol violation (the reference explicitly permits it), but reset sequence spaces must never reuse a key/SSRC/packet-index nonce.

**Fix:** represent negotiated offers, answers, stream identities, and key/media epochs explicitly. Coordinate old/new overlap and retire it safely. If rotating keys, authenticate into the intended candidate epoch before promotion. Tag IPC frames with epoch/geometry and fence stale frames at the renderer. Handle unsolicited geometry transitions and rejected/degenerate answers explicitly.

### P1-14: Reconnect and media-task failure need a session supervisor

**Confirmed in code.** `crates/apple-core/src/lib.rs:61-63`; `session.rs:21-65,272-352,358-435`.

The Apple driver launches one `run()` and has no reconnect supervisor. `ReconnectNow` falls through the ignored-command wildcard. The UDP task can terminate silently while the TCP loop continues to report connected. There is no media-health deadline or task-result propagation. Thus a toolbar recovery action can do nothing, and “connected” can mean no usable video.

**Fix:** supervise control and media together, implement reconnect/disconnect commands and cancellation across phases, join/observe worker results, and distinguish authenticated, negotiating, displaying, stalled, reconnecting, and disconnected states. Reset renderer/media generation on genuine session restart. Preserve the separate original physical-mode restore obligation across reconnects.

### P1-15: Move SSH display operations out of the input loop; make restoration orderly

**Confirmed in code; no successful Mac mode apply/restore was verified.** `session.rs:393-417`; `crates/apple-core/src/macos.rs:12-41,60-132`; `mac_display.swift`.

- SSH connect and commands are awaited inside the control/input select branch. A Set may run two 30-second Swift invocations after a 15-second SSH connection, blocking input/control processing and timely cancellation.
- Even **List** overwrites stream dimensions and emits `DesktopResize`, despite being read-only and not re-offering media. Opening mode enumeration can therefore reset the renderer independently of actual stream state.
- `restore_on_disconnect()` is never called; restoration relies on an unawaited Drop-spawned task, unreliable on application/runtime shutdown.
- Rust records an expected mode ID but asks Swift to choose again by width/height; duplicate modes/ties/external changes can invalidate rollback identity. Restore checks command success, not final original-mode identity before clearing restore state.

**Fix:** cancellable worker operations feeding the common transition coordinator; List must not mutate video geometry. Select/apply an exact display+mode ID and verify it. Await conditional restoration on ordinary disconnect within a bounded shutdown path; retain recovery state on failure. Keep the existing refusal to undo outside changes, and make inability to guarantee restoration on crash/app exit explicit. Consider an independently authorized server-side watchdog only if stronger restoration guarantees are required.

### P1-16: Finish authentication verification and handshake bounds

**Confirmed in code.** `session.rs:169-170`; `crates/apple-core/src/auth.rs:108-110,226,253`; handshake read helpers.

The server proof is read and discarded; `m2_matches()` is unused. Received group/generator values are parsed but not validated against the supported constant group. The 15-second timeout bounds TCP connect, not every authentication/prelude read or total handshake; cancellation is also incomplete during these awaits.

**Fix:** implement/verify the precise server-proof framing and mutual SRP proof against controlled vectors; do not merely switch on an unverified prefix comparison. Validate group, generator, lengths, iteration limits, public values, and RSA envelope bounds. Use phase/overall deadlines and cancellation. Reduce credential/key lifetime and use zeroizing containers where practical. Preserve the existing credential store and SSH host-key trust, and never work around failures by logging secrets or trusting unknown keys.

### P1-17: Honor input-release and view-only contracts

**Confirmed ignored commands.** `session.rs:358-435`; shared `ClientCommand` integration.

`ReleaseAllKeys`, `SetViewOnly`, and related expected commands fall through the wildcard. A lease loss, focus loss, or view-only transition cannot rely on this driver to release remotely held modifiers/buttons. Frontend filtering alone is not a backend safety contract. No systematic pressed-key/button state is retained for cleanup.

**Fix:** track keys/buttons; implement release-all, startup/runtime view-only, disconnect cleanup, and takeover-safe neutralization. Audit every shared command: support it, explicitly refuse it nonfatally, or remove the corresponding UI capability. The wildcard also ignores native `Agent` intents instead of settling/refusing them; preserve the control plane's exactly-one-result contract. Prefer exhaustive matching so new variants cannot silently disappear. Add takeover/focus-loss tests without bypassing the human's lease.

### P1-18: Unify valid sizes and honest native restoration

**Confirmed in code.** `session.rs:255,418-433,571-620`; `quality.rs`; `MacDisplayControls.tsx:43-45`; `Session.tsx:383-384`.

The manual path rejects heights over 2160, so Native cannot request 3600×2338, while High/Auto bypass that bound. Presets produce odd widths (2217 and 1663 on the reported baseline); acceptance and H.264/NV12 crop alignment were not verified. The descriptor advertises multiple synthesized modes without validating each against bounds. Native is merely startup geometry, and the frontend native ref is not reset per true session baseline. Manual 16:9 buttons also conflict with aspect-preserving presets.

**Fix:** one capability-driven size/mode validator for all entry points, with pixel/texture budgets, verified codec alignment, and negotiated caps. Preserve aspect within rounding tolerance; do not upscale a genuine baseline. Retain original logical/backing/mode identity independently of current or already-altered geometry. Expose requested/effective sizes and host clamping. Do not silently force 16:9 or claim an arbitrary pixel request restored the physical mode.

### P2-19: Replace optimistic health flags with end-to-end measurements

**First-frame defect reproduced; remaining missing instrumentation confirmed in code.** `WebGLRenderer.ts:952-958,1170-1198,1533-1542`; `session.rs:329-331`; `useSession.ts`.

`applyFrameOrdered()` marks `sawFrame` and fires `onFirstFrame` after compressed input is submitted, even if no decoded output has arrived. The first-five/early-key-picture log limiter is not a continuing frame-flow counter. Layout/write success is not video success, and backend stats are not emitted for the Apple path.

**Fix:** separate counters/timestamps for received, authenticated, reordered/lost, assembled, decoder-submitted, decoded, uploaded, and presented frames; selected SSRC/epoch, decode queue, bitrate, cadence, effective geometry, recovery events, and actual decoder implementation. Base displaying/resize success on a new presented output. Provide bounded transition traces without keys, passwords, or plaintext desktop content.

### P2-20: Improve UDP buffering, endpoint correctness, and backpressure

**Confirmed omissions; impact needs measurement.** `session.rs:266-353,523-550`.

UDP ports are fixed IPv4 5900/5901 regardless of configured control port; sends are ignored; sockets accept any source; receive-buffer sizing/overflow diagnostics are absent. The receiver awaits UI event delivery, potentially letting OS UDP queues overflow during stalls/key-picture bursts. Multiple Apple sessions cannot bind the same fixed local ports. Initial binding follows the first offer rather than ensuring receive readiness first.

**Fix:** explicitly negotiate/document endpoint constraints, bind before offering where compatible, resolve/check peers, report send/receive failures, size/measure socket buffers, and decouple bounded packet ingestion from frontend delivery. Support shared demultiplexing or clearly expose a one-Apple-session limitation. Do not silently switch to ephemeral ports: prior live tests established the server did not send there on this setup.

### P2-21: Bound WebCodecs work without breaking H.264 references

**Confirmed omissions; throughput comparison needs measurement.** `WebGLRenderer.ts:1038-1120,1170-1190,1533-1542`; `src-tauri/src/main.rs`.

Latest-frame presentation bounds decoded pictures awaiting paint, but does not bound `VideoDecoder.decodeQueueSize` or encoded IPC pressure. The generic pruning helpers correctly preserve H.264 dependencies; dropping arbitrary deltas to reduce lag would introduce corruption. Resetting decoders on each key picture adds avoidable hardware initialization cost. NV12 mapping and WebGL uploads remain copies, not native zero-copy presentation.

**Fix:** measure decoder backlog and stage latency. If saturated, reduce supported server cadence/bitrate, or perform a controlled drop-to-independent-picture recovery, not blind reference-frame dropping. Reuse healthy decoders. Validate hardware support and effective implementation per reconfiguration. Keep the linear-NV12 workaround overridable and test packaging against supported plugin/driver combinations; host-plugin discovery can expose ABI/version issues. Native iShareScreen performance parity remains unproven.

### P2-22: Make Apple quality/control UI match implemented capabilities

**Confirmed in code.** `quality.rs`; `ui/src/components/SessionToolbar.tsx:925-1005`; `useSession.ts:857-885`; `Session.tsx:1075-1077,1689-1690`.

Auto maps to startup native; no Apple adaptation loop exists. Black & White maps to Low resolution without grayscale. Always request fresh frames is exposed but its command is ignored. FPS/bitrate controls are not implemented. Selection is saved immediately through fire-and-forget commands, without requested/applied/failed distinction; remembered quality is resent whenever connected, potentially restarting an encoder immediately after reconnect. A bad preset can therefore recur and still look successfully selected.

**Fix:** protocol-specific capabilities and labels; hide unsupported controls or explain refusal. Distinguish resolution, encoder policy, local scaling, and physical mode. Confirm effective settings before persisting a successful default; show pending/failure/clamping states and cancel obsolete commands. Gate initial quality application on a ready media generation rather than TCP-connected alone.

### P2-23: Add regression coverage and simplify the state model before more patches

The current 19 Apple tests and renderer coverage do not model a complete resize/video lifecycle. Encoding a happy-path message length or receiving a layout is not a successful-stream test.

**Fix:** migrate the review probes into the production test suites with their fixes; factor protocol parsing, stream selection, and resize coordination into testable components. Add a deterministic fake server/packet source with loss, reorder, stale streams, delayed answers, and decoder callbacks. Replace ad hoc atomics/booleans with explicit state/events. Audit existing comments and success messages that currently promise behavior not demonstrated by output. Keep this native implementation license-compatible; use protocol facts, not copied AGPL reference implementation code.

## Recommended implementation order

1. **Observability and guardrails:** add media generations/counters, truthful pending/failure state, and gate the unverified virtual-display control. Do not clear the last good image while experimenting. Log the negotiated tile count, intra-picture frequency, and decoder recreation events: the scrolling-artifact chain is invisible without them.
2. **Packet correctness:** P0-2/3 and P1-8/9, with all seven Rust probes passing; add configuration/loss recovery feedback (P0-8).
3. **Reference-chain correctness:** P0-7 first (an intra picture must not recreate the decoder), then P0-4 and P0-9, with all four renderer probes passing. This is the shortest path to the reported scrolling artifacts disappearing.
4. **One restart coordinator:** complete P0-1/P1-13/14, including latest-intent, deadlines, worker failure, rollback, and physical-operation serialization.
5. **Protocol/geometry correctness:** flags, parser, rekey, mutual authentication, logical/backing geometry, unified bounds, and verified baseline restoration.
6. **Physical controller and input safety:** nonblocking exact-mode apply/restore and release-all/view-only handling.
7. **Only then tune quality/performance:** supported server-side FPS/bitrate/encoder scale, measured hardware decode, and adaptive policy. Lower resolution alone is not a complete quality/performance implementation.

## Release verification matrix

No renewed remote authorization was requested or assumed for this review. Run live steps only after explicit permission, with the real console/panel observed independently.

- **Rapid transitions:** at least 50 mixed Low/Medium/High changes, including final-native requests before the first acknowledgement and deliberate delays at each transaction phase. Verify final decoded/presented geometry, not writes/layout alone.
- **Scrolling artifacts (the reported symptom):** on a static page, a fast horizontal scroll, and a fast vertical scroll, at each preset, compare frames against a reference capture of the same motion. Count corrupted regions per second, and confirm the picture returns to correct without a reconnect. Repeat with injected loss at the observed bitrate. An artifact counter (regions differing from the reference beyond a threshold) is needed; "looks wrong to a human" is not a regression test.
- **Reference chain integrity:** log intra/non-IDR picture frequency during motion, decoder recreation events, and the negotiated tile count. An unexpected decoder recreation during scrolling is a defect even when the picture still looks acceptable.
- **Loss/reordering:** drop FU start/middle/end, marker, parameter-set burst, first key picture; reorder around RTP wrap; duplicate and replay packets; interleave old/new SSRCs; inject invalid SSRC headers. Bound memory and recovery time.
- **Decoder failures:** asynchronous hardware configure failure, unsupported new SPS, closed/error decoder, delayed outputs from retired epochs, queue saturation. No permanent latch, stale image commit, or false first-frame success.
- **Control failures:** multi-rectangle layout/rekey, split higher-level payloads, second rekey, missing answer/layout, EOF, stalled TCP, cancellation during auth/SSH. Explicit error/recovery state; no fake reconnect.
- **Display safety:** compare original/effective display ID, physical mode, point size, backing size, HiDPI ratio, and curtain state. Enumerating modes must not resize video. Test approved apply/restore and ordinary disconnect restore; refuse to undo an outside change.
- **Input:** center/four corners/right edge in fit, 1:1, zoom/pan, fullscreen, and every supported resize/HiDPI state; release held keys/buttons on focus/view-only/takeover/disconnect.
- **Performance:** record bitrate, loss, decoded and presented FPS, decode queue, CPU/GPU use, and input-to-visible-response latency for each stable preset on the same scene. Compare to native baseline at the same resolution and cadence. A `vah264dec` log proves decoder selection, not zero-copy or latency parity.
- **Packaging:** verify installed AppImage hash/build identity, required GStreamer plugins, actual hardware decoder after each reconfiguration, and clean launch from the desktop menu.

## Reproductions added

Folder: `docs/reviews/apple-protocol-review-probes/`. These load the current source directly. They intentionally assert the *desired corrected behavior*, so they are expected to fail until the defects are fixed. The Rust harness also runs four existing imported module tests, which pass. Neither harness connects to a Mac.

```sh
# From DeskVNC; standalone fixture workspace, not part of normal CI.
cargo test --offline --manifest-path docs/reviews/apple-protocol-review-probes/Cargo.toml
./ui/node_modules/.bin/vitest run --config docs/reviews/apple-protocol-review-probes/vitest.config.mts
```

Seven failing Rust probes:
1. unfinished FU must not block the next complete IDR;
2. malformed STAP must not publish a partial key picture;
3. mixed I/P slices must not be labeled an independent key picture;
4. a known missing RTP fragment must not be delivered as a complete access unit (exercises the driver's sequence-discarding handoff);
5. authenticated SRTP replay must be rejected;
6. an unseen late packet across rollover must authenticate;
7. an old authenticated replay must not poison the rollover high-water mark.

Three failing mocked renderer probes:
1. recoverable failure must not remain latched across resize;
2. asynchronous hardware configuration failure must reach a recovery/fallback path;
3. compressed submission without output must not count as the first presented frame;
4. a non-IDR intra picture must not destroy the decoder's reference pictures (the scrolling-artifact mechanism).

These establish implementation defects, not the measured frequency or sole cause of any particular live disconnect. No fix, native restoration, or successful Low/Medium video output is claimed by this review.
