# Apple protocol: long-session reliability and performance task list

Date: 2026-10-20. Reviewed source: `abfaecbc5f0ced4b8673b97fe3b97d5a40b0c627` (`feature/apple-screen-sharing-driver`).

Requested outcome: faster, reliable Apple Screen Sharing sessions that remain usable for hours, especially when mouse input still works but video freezes.

This is a code review and implementation backlog. No production implementation was changed for this review. The **32 task groups and 261 checklist items** below are open, including tasks whose underlying behavior has been reproduced. Local tests use synthetic packets or mocked decoding; they do not establish the cause of a specific live freeze or prove hardware performance.

## 1. Main conclusion

The highest-value work is recovery correctness and visibility into the complete video path. There are concrete ways for the backend to keep accepting input and assembling video while the renderer stops displaying it. There are also long-session stream-state limits, packet-ordering defects, and reconnect control-flow errors. Lowering resolution alone will not repair these states.

The current implementation already contains substantial improvements. Preserve cancellation-safe encrypted reads, authenticated per-SSRC state, bounded RTP reordering, packet-loss feedback, the separate picture publisher, latest-decoded-picture presentation, retired-decoder callback guards, and the recent resize fixes. Earlier reports contain historical findings and superseded explanations; this document assesses the current source.

### Why working mouse movement does not establish video health

```text
Keyboard / pointer -> command queue -> encrypted TCP control -> Mac input

Mac encoder -> UDP -> SRTP authentication -> per-SSRC RTP reorder
  -> H.264 access-unit assembly -> picture buffer -> session event queue
  -> Tauri binary channel -> frontend queue -> WebCodecs
  -> decoded VideoFrame -> WebGL texture upload -> animation-frame draw
```

Input and video follow different paths. The Apple offer also requests a separately drawn cursor (`offer.rs:36–46`), and the viewer draws its own pointer. Seeing a cursor move is weaker evidence than seeing remote application content respond. A new assembled access unit proves neither decoding nor presentation.

### First implementation sequence

| Order | Task IDs | Result |
|---|---|---|
| 1 | OBS-01, REN-01, REN-02 | Identify the stalled stage; recover decoder failures without a permanent latch |
| 2 | RTP-01, BUF-01, EPOCH-01, STREAM-01 | Keep reference chains, packet indexes, and stream replacement correct over time |
| 3 | LIFE-01, LIFE-02, REC-01, REC-02 | Tear down every failed attempt and actually escalate/reconnect with backoff |
| 4 | RTP-02, RTP-03, MEM-01, RTCP-01 | Close loss/reordering and memory-bound gaps |
| 5 | SIZE-01, SIZE-02, CTRL-01, AUTH-01 | Complete transitions and make control/handshake behavior dependable |
| 6 | PERF-01 through PERF-04, QA-01 through QA-03 | Tune measured bottlenecks and qualify real long-running builds |

P0 means a correctness issue capable of stranding/corrupting video or defeating recovery. P1 means a reliability or resource issue to finish before long-session qualification. P2 means measured optimization or broader compatibility work. Priorities describe the backlog, not a measured incidence rate.

## 2. Evidence and verification performed

| Check | Result in this review | What it establishes |
|---|---|---|
| `cargo test --offline -p apple-core` | 107 discovered; **103 passed; 4 failed at local socket bind with `EPERM`** | Pure tests passed. Socket-dependent tests could not execute in this environment; these four failures are not evidence of production regressions |
| `cd ui && npm test -- --reporter=dot` | **482 passed, 30 files** | Existing UI regression suite passes with mocked platform APIs |
| `cd ui && npm run typecheck` | Passed | Current TypeScript types check |
| `python3 docs/reviews/apple-resolution-review-probes/run_rust.py` | **5 passed** | Recent pure resize/serialization regressions remain fixed |
| `ui/node_modules/.bin/vitest run --config docs/reviews/apple-resolution-review-probes/vitest.config.mts` | **3 passed** | Recent renderer-layout/cache regressions remain fixed |

The four socket-blocked Rust tests were `a_lost_picture_is_asked_for_again`, `a_request_is_not_sent_twice_in_a_row`, `interrupted_record_read_keeps_partial_ciphertext`, and `releasing_everything_held_says_so_on_the_wire`. Run these in the normal CI/host environment before treating the complete Rust suite as green.

Additional isolated review probes and their exact results are recorded in section 10. A passing existing suite does not cover every recovery state below.

Historical local application log evidence: `/home/eugenep/.local/share/com.deskvncviewer.desktop/logs/deskvnc.log`, lines 9561–9572, contains repeated `re-offering the media session` messages on 2026-10-20 at 12:24:40–12:24:56 UTC, with `silent_ms` rising from 123159 to 138659. This establishes an earlier episode of repeated unsuccessful recovery for over two minutes. The log has insufficient build/attempt/renderer correlation to attribute it to this exact source revision or to identify the stalled stage. The sibling workspace's `logs/` folder contains older iShareScreen runs and must not be treated as evidence of current DeskVNC behavior.

Evidence labels used below:

- **Code:** directly visible current behavior or missing contract.
- **Probe:** demonstrated using the current implementation and synthetic inputs/mocks.
- **Measure:** plausible optimization or platform behavior that needs a controlled measurement.

## 3. P0: eliminate freeze states and failed recovery

### OBS-01 — Add progress and health across the entire video path

**Priority:** P0. **Evidence:** Code. **Effort:** medium/large. **Dependencies:** shared contract for REN-01, REC-01, SIZE-01, and performance work.

**Code:** `crates/apple-core/src/session.rs:1527–1568,2002–2046,2057–2069`; `crates/remote-core/src/apple_media.rs:7–52`; `src-tauri/src/framing.rs:215–231`; `ui/src/render/WebGLRenderer.ts:1090–1106,1468–1488,1594–1597,1684,1977–1981`; `ui/src/lib/diagnostics.ts:246–263`.

The backend's health and resize completion use assembled-picture progress. There is no renderer-to-driver acknowledgement identifying a decoded/uploaded/presented picture. Current `input_latency_ms` ends when an arbitrary following access unit is assembled; it is not input-to-visible-response latency. `MediaState::is_streaming()` stays true after any historical picture, even if video is now stalled. Decoder acceleration reporting derives from the requested preference rather than confirmed implementation.

Implementation tasks:

- [ ] Carry a connection-attempt ID, media epoch, selected SSRC, access-unit ID, and transition ID through the backend, binary framing, renderer, and acknowledgement path. Keep the framing versioned and update `FRAME_FORMAT.md`/`IPC_CONTRACT.md` with compatibility behavior.
- [ ] Record monotonic progress times and counters for received, authenticated, reordered, discarded, assembled, published, IPC accepted, decoder submitted, decoded, uploaded, and drawn pictures. Keep epoch-local and session-cumulative counters distinct.
- [ ] Acknowledge successful texture upload and a subsequent draw separately. A JavaScript callback is an application-level presentation proxy; do not claim physical monitor scanout timing.
- [ ] Report queue depth, bytes, oldest-item age, decoder pending submissions, last decoded/drawn age, failure reason, recovery stage, and recovery attempt count.
- [ ] Represent healthy static desktop, waiting for configuration, waiting for independent picture, decoder backlog, decoder error, presentation error, media silence, and reconnecting explicitly.
- [ ] Rename existing input timing to input-to-next-assembled-picture estimate. For controlled benchmarks, correlate input to an observable remote content change and a drawn frame; unrelated video must not count as the response.
- [ ] Make the diagnostics panel display missing/unknown measurements honestly; label backend FPS as assembled FPS and expose decoded/drawn FPS separately.
- [ ] Keep a bounded metadata-only event ring for the time around a freeze. Include source revision, app artifact identity, OS/webview/codec implementation, chosen geometry, and per-stage ages. Exclude passwords, media keys, clipboard, and desktop image contents.

Acceptance and validation:

- [ ] Stop output at each pipeline stage independently; one diagnostic snapshot identifies the first stalled stage without relying on cursor activity.
- [ ] An assembler producing 60 access units/s with zero decoder outputs reports a decoder stall rather than healthy video.
- [ ] A decoded/uploaded picture that never reaches the draw loop does not complete a resize or clear a presentation-stall condition.
- [ ] Stats remain monotonic and understandable across SSRC replacement/reconnect; old epoch acknowledgements cannot make a new epoch healthy.

### REN-01 — Recover decoder failures without an accumulating permanent latch

**Priority:** P0. **Evidence:** Code/Probe. **Effort:** medium. **Dependencies:** OBS-01 for precise progress; add immediate error feedback before the full metrics work is complete.

**Code:** `ui/src/render/WebGLRenderer.ts:861–888,1280–1285,1607–1613,1632–1649`; renderer lifetime in `ui/src/screens/Session.tsx:453–603`.

`h264Failures` increases on errors but healthy output does not reset it. Three errors spread across a long healthy session can set `h264Failed`, after which every compressed picture returns early. A same-size `setRemoteSize()` returns before resetting that state, and the renderer survives reconnects within the mounted screen. The asynchronous error path closes the decoder but does not request a fresh picture, so a damage-driven stream may never provide the next independently decodable frame on its own.

Implementation tasks:

- [ ] Replace lifetime cumulative failure counting with a bounded recovery policy: consecutive failures or a time window, cleared after sustained successful output/presentation.
- [ ] Add an explicit begin/end connection-attempt lifecycle to the renderer. Reset transient failure/behind/configuration state by epoch even when dimensions are unchanged; invalidate pending work from the previous attempt. Retain true platform capability absence until the environment/capability actually changes.
- [ ] Have decoder configuration errors, asynchronous decode errors, synchronous `decode()` errors, and output timeouts emit typed, rate-limited recovery feedback to the backend.
- [ ] Ask for a new independent picture when references have been lost. Escalate through REC-01 when it never arrives.
- [ ] Preserve a bounded hardware-to-software fallback. Distinguish unsupported codec/platform from a corrupt stream and from a temporary hardware failure; avoid endlessly alternating decoder preferences.
- [ ] Keep the last good image with an accurate recovery status until replacement output is ready.
- [ ] Make notices accurate for Apple: changing the quality preset does not select a non-H.264 encoding in this driver, and an upload failure currently does not actually negotiate another encoding.

Acceptance and validation:

- [ ] Error, 10,000 healthy outputs, error, 10,000 healthy outputs, error does not permanently disable video.
- [ ] A same-resolution reconnect following a recoverable failure produces and draws a new picture; no component remount is required.
- [ ] A decoder error followed by no spontaneous key picture produces a bounded fresh-picture request and then bounded escalation.
- [ ] Late errors/output from a retired decoder cannot reset a healthy replacement or acknowledge a new epoch.

### REN-02 — Reconfigure WebCodecs after backlog reset

**Priority:** P0. **Evidence:** Code/Probe. **Effort:** small/medium. **Dependencies:** REN-01 recovery policy.

**Code:** `WebGLRenderer.ts:1300–1341,1362–1375`. `dropBehind()` calls `VideoDecoder.reset()` and leaves the context in the map; the next independent picture can reach `decode()` without `configure()`.

WebCodecs reset clears configuration and sets the decoder to `unconfigured`; decoding requires a configured decoder. See the [WebCodecs decoder algorithms](https://www.w3.org/TR/webcodecs/#videodecoder-interface). The Apple path marks ordinary IDRs with `reset=true`, which recreates the context and can mask this bug. The concrete uncovered case is an independent non-IDR picture with `key=true, reset=false` after the backlog reset, or another context that does not carry a reset flag.

- [ ] Either close/remove the context and rebuild it with cached/current parameter sets on the next valid independent picture, or retain validated configuration and explicitly reconfigure after reset.
- [ ] Track decoder configuration state explicitly; never treat `unconfigured` as ready.
- [ ] Settle waiters, clear timing metadata, close obsolete pending frames, and fence old callbacks on every reset/reconfigure path.
- [ ] Use the most recent parameter sets for the epoch; do not configure a replacement with an earlier resolution's SPS/PPS.

Acceptance and validation:

- [ ] Use a realistic fake decoder whose `reset()` sets `state="unconfigured"` and whose `decode()` throws unless configured. Drive backlog -> reset -> independent non-IDR -> delta and verify output recovers.
- [ ] Repeat with IDR, no key picture, async configure refusal, and context retirement during recovery.
- [ ] No silent `decode()` catch can leave the backend believing a complete video pipeline is healthy.

### RTP-01 — Discard the entire damaged access unit after a sequence gap

**Priority:** P0. **Evidence:** Code/Probe. **Effort:** medium. **Dependencies:** none.

**Code:** `crates/apple-core/src/h264.rs:140–176`, `report_gap`, `assemble`, `discard_picture`.

The gap path clears current assembly, then permits a later slice with the same RTP timestamp to start a new assembly. A surviving marker-terminated slice can therefore be emitted as if it were a complete picture, including as a key picture. Clearing buffers alone does not remember that the timestamp is damaged. A decoder can silently conceal missing slices rather than report an error.

- [ ] Track invalid/damaged access-unit identity per stream and discard the remainder of that timestamp after loss, malformed aggregation, unfinished FU, and overflow.
- [ ] Require a defensible new picture boundary before resuming assembly. When the first missing packet's timestamp is unknown, apply a documented conservative policy rather than assuming the surviving tail is complete.
- [ ] Keep transport completeness separate from intra-slice classification. An intra slice is not evidence that all slices of the picture arrived.
- [ ] Trigger bounded repair feedback and remain in reference-chain recovery until a verified acceptable starting picture arrives.
- [ ] Ensure a retransmission within the repair window can complete the original picture; packets arriving after abandonment must not resurrect it.

Acceptance and validation:

- [ ] Lose the first, middle, last, and marker packet of a multi-slice picture; no damaged timestamp is published.
- [ ] A marker-terminated IDR slice following a gap within that timestamp is not labeled a complete independent picture.
- [ ] A subsequent complete independent picture restores output without reconnect; test FU and single-NAL combinations and malformed STAP tails.

### BUF-01 — Remove obsolete deltas before resuming from an independent picture

**Priority:** P0. **Evidence:** Code/Probe. **Effort:** small. **Dependencies:** none.

**Code:** `crates/apple-core/src/pictures.rs:72–116`. In the broken-chain branch, `pop()` removes the selected independent picture from the middle with `queue.remove(at)` but leaves every older delta ahead of it in the queue. It then sets `broken=false`. Subsequent pops can emit those older deltas after the recovery picture.

- [ ] Discard the complete prefix before the selected recovery picture, accounting for every discarded unit/byte; then emit that picture followed only by its valid successors.
- [ ] Define whether to select the first or newest usable independent picture based on latency and retained dependencies. Never mix predecessor deltas into its successor chain.
- [ ] Preserve epoch/SSRC/configuration identity with buffered units so a replacement stream cannot inherit an old stream's queue.
- [ ] Mark a decoder reset when required by a new epoch/configuration; do not blindly reset on every non-IDR intra picture.

Acceptance and validation:

- [ ] With a forced overflow leaving `[old delta A, old delta B, key K, new delta C]`, output is `[K,C]`, with A/B discarded and correctly counted.
- [ ] Exercise multiple keys, a key that itself overflows, no key, a new stream during overflow, and a slow publisher.
- [ ] After recovery, emitted access-unit IDs stay in order and all retained deltas belong to the recovered chain.

### EPOCH-01 — Preserve valid SRTP packet indexes through a local re-offer

**Priority:** P0. **Evidence:** Code/Probe. **Effort:** large. **Dependencies:** shared identity/epoch contract established in OBS-01; design together with STREAM-01.

**Code:** `session.rs:1473–1515`; `video.rs:40–50`; `srtp.rs:113–126,165–168,221–253`.

Every local generation change resets all stream replay/high-water state while reusing the media keys. That reset happens after the current packet has already been pushed/flushed. A continuing same-SSRC encoder at rollover counter 2 or higher can no longer authenticate after the reset: an empty context tries counters near zero, not the established counter. A local request is also insufficient evidence that old authenticated packets belong to a new cryptographic epoch; clearing replay state can admit old packets again. At 1,000 packets/s two 16-bit wraps take about 131 seconds; this is an illustration of packet-index timing, not a prediction of a 131-second freeze.

- [ ] Separate local offer generation, authenticated sender identity, packet-index continuity, decoder configuration epoch, and display transaction identity.
- [ ] Keep the active stream's valid SRTP context unless an authenticated, protocol-supported transition establishes replacement state.
- [ ] Support both continuing-numbering and genuinely restarted-numbering senders with a bounded candidate mechanism, or negotiate fresh keys/identity if the verified Apple exchange supports it.
- [ ] Preserve replay rejection for the old epoch during overlap. Do not solve recovery by globally accepting old sequence numbers or widening ROC guesses indefinitely.
- [ ] Apply the epoch transition before processing packets for that epoch, with a clear policy for already assembled/queued old units.
- [ ] Document the same-key/same-SSRC/index-reuse limitation if the host really does reset numbering; confirm the behavior with captures before declaring it safe.

Acceptance and validation:

- [ ] Reach ROC 0, 1, 2, and 3; re-offer with the sender continuing its sequence; video remains authenticatable.
- [ ] Repeat with a same-SSRC numbering restart, a new SSRC, delayed old packets, a replayed old key picture, and reordered rollover packets.
- [ ] Re-offer during configuration/FU assembly; neither a partial old unit nor a replay can acknowledge the new generation.

### STREAM-01 — Replace lifetime SSRC exhaustion with bounded stream lifecycle management

**Priority:** P0. **Evidence:** Code/Probe. **Effort:** medium/large. **Dependencies:** shared identity/epoch contract established in OBS-01; design together with EPOCH-01.

**Code:** `crates/apple-core/src/video.rs:8,46–50,77–106,123–146,160–174`.

`MAX_STREAMS=32` bounds the map, but entries are never evicted. Once 32 authenticated SSRCs have appeared, a valid 33rd replacement is ignored for the remainder of that connection. Retired flags are permanent, including across `new_epoch()`, so a server that later reuses a retired SSRC cannot be adopted. This is a limit on lifetime stream identities rather than concurrent memory use.

- [ ] Track active, candidate, and retired stream roles with timestamps, generation, authentication state, and explicit expiry/eviction rules.
- [ ] Bound concurrent candidate assembly and retired replay records independently. Preserve active replay state under untrusted traffic and do not re-admit retired traffic simply because it was evicted.
- [ ] Define how a legitimately reused SSRC is distinguished from a delayed retired stream; tie re-adoption to validated epoch/configuration state.
- [ ] Surface capacity pressure and rejected replacement streams as actionable health events, not a one-time warning followed by a frozen picture.
- [ ] Reclaim retired depacketizer payload/configuration memory when safe; retain only the replay/identity metadata needed for the overlap policy.

Acceptance and validation:

- [ ] Perform at least 1,000 simulated encoder replacements with bounded memory and successful adoption beyond stream 32.
- [ ] Reuse an earlier SSRC after a validated transition and recover; delayed packets from its old incarnation cannot take the display back.
- [ ] Forged SSRC floods allocate no authenticated stream entries and cannot erase active replay protection.

### LIFE-01 — Make every connection exit run bounded cleanup

**Priority:** P0. **Evidence:** Code. **Effort:** medium/large. **Dependencies:** LIFE-02.

**Code:** worker creation `session.rs:1113–1128,1219–1239,1249–1663`; early-return examples `1678,1696,1881,1970,2081`; cleanup `2204–2216`; `Live::send_body:2241–2246`.

Many `?` exits bypass key release, awaited display-worker completion, and explicit video/publisher aborts. Dropping Tokio join handles detaches their tasks. Dropping `video_request_tx` can eventually end the video worker, so an unconditional permanent UDP leak is not established. The confirmed problem is missing deterministic teardown, possible retry-versus-port-release races, blocked publishers, and restoration that can continue without its owner awaiting the result.

- [ ] Give each connection attempt an owned worker group and child cancellation token. Route every loop outcome/error through one async cleanup path before returning to the supervisor.
- [ ] Stop publication/input, cancel workers, settle pending operations, perform best-effort key/button release on a usable control channel, close sockets, and join all workers under explicit deadlines.
- [ ] Abort and join remaining workers after timeout; dropping a timed-out join handle must not leave an unowned worker running.
- [ ] Preserve the original failure reason while reporting cleanup/restore failures separately.
- [ ] Ensure the event sink closing ends the attempt rather than leaving producer tasks without a consumer.
- [ ] Confirm UDP ports and the prior attempt's publisher are gone before starting another attempt.

Acceptance and validation:

- [ ] Inject read EOF, record integrity error, write failure, cancellation, worker panic, closed event sink, and event-channel saturation after each worker spawn point.
- [ ] Every case ends with no retained attempt tasks/sockets/timers, no pending operation left unsettled, and no old frame arriving after the next attempt begins.
- [ ] Disconnect during held input and an in-flight display operation completes within the declared cleanup deadline; restoration failure is visible and never reported as success.

### LIFE-02 — Treat worker death as a retryable attempt failure

**Priority:** P0. **Evidence:** Code. **Effort:** small/medium. **Dependencies:** LIFE-01.

**Code:** `session.rs:2094–2099,2215–2216,744–755`; publisher task `1219–1239`.

When `video_task.is_finished()` becomes true, the loop logs that it will restart and then breaks. `connect()` returns `Ok(())`; with the explicit-reconnect flag unset, `run()` interprets that as a requested stop and exits. The publisher's termination is not supervised at all.

- [ ] Replace ambiguous `Ok(())` plus a side-channel boolean with explicit outcomes: user disconnect, cancellation, requested reconnect, and attempt failure.
- [ ] Select/join the video, publisher, and display worker results directly; classify EOF, panic, and internal error rather than polling only `is_finished()`.
- [ ] Propagate unexpected media-worker termination to the supervisor after LIFE-01 cleanup, with a stable reason code.
- [ ] Maintain exactly one terminal settlement per pending command/transition during restart.

Acceptance and validation:

- [ ] Finish or panic each worker while the control socket stays alive; the session visibly recovers or reports a classified terminal failure.
- [ ] A user disconnect never reconnects; a transient worker failure does reconnect when policy allows it.

### REC-01 — Add bounded recovery escalation driven by displayed progress

**Priority:** P0. **Evidence:** Code and historical log corroboration. **Effort:** large. **Dependencies:** OBS-01, LIFE-01/02, EPOCH-01.

**Code:** `session.rs:1332–1429,1538–1567,2048–2091`; renderer error path `WebGLRenderer.ts:1632–1649`.

The current backend can re-offer media every five seconds indefinitely without escalating to a full attempt restart. It clears picture debt on assembly even if the frontend never displays that picture. Conversely, a static desktop may legitimately send no video. Recovery must distinguish a quiet desktop from a failed stage rather than treating every silence as a failure.

- [ ] Centralize recovery in an explicit state machine with one owner for loss repair, fresh-picture requests, decoder recreation, media re-offer, and full reconnect.
- [ ] Use stage-specific evidence: network/assembly stall, decoder stall with continued assembly, upload/draw stall, and normal idle. Use a sparse verified health probe only where an idle state otherwise cannot be distinguished safely.
- [ ] Set per-stage deadlines and maximum attempts. A proposed starting policy is one local decoder recovery, up to two fresh-picture rounds, one media re-offer, then a full connection retry; tune against the fake server and real captures.
- [ ] Reset escalation only on valid progress from the expected epoch/stage, ultimately a replacement drawn picture. A write succeeding, an unrelated layout, or an old picture is insufficient.
- [ ] Serialize recovery with display/quality transactions; cancel or time out obsolete transitions before starting a competing encoder restart.
- [ ] Rate-limit user notices and requests and expose the active recovery stage. Preserve the last good image and release/settle input state appropriately on a real reconnect.

Acceptance and validation:

- [ ] Backend assembly with no renderer output triggers decoder recovery; continued failure escalates without waiting for a UDP-silence detector.
- [ ] A media server that ignores feedback and re-offers reaches full reconnect within a declared finite recovery budget.
- [ ] Ten minutes of a valid unchanged desktop does not produce repeated encoder restarts.
- [ ] A changed/animated scene cannot remain labeled healthy while no new picture is drawn for the configured failure budget.

### REC-02 — Fix reconnect backoff, policy, and credential retention

**Priority:** P0/P1. **Evidence:** Code. **Effort:** medium. **Dependencies:** LIFE-01/02.

**Code:** `session.rs:679–709,744–782,786–819,840–851`; existing shared supervisor in `crates/remote-core/src/reconnect.rs`.

The retry loop resets `attempt=0` after every wait, so repeated failures keep using 500 ms rather than growing backoff. It converts all errors to strings and retries authentication/protocol errors like transport failures, without applying the shared reconnect policy. Credentials entered after the initial prompt update the local username/password but not the tuple copied back on the next retry. Runtime settings are also reconstructed rather than consistently retained.

- [ ] Implement the shared `ConnectOnce`/`RetryClassify` supervisor contract, or document and test an equivalent Apple-specific implementation.
- [ ] Use bounded exponential backoff with jitter, maximum attempts/elapsed budget, and reset only after stable uptime or explicit reconnect.
- [ ] Classify wrong password, unsupported protocol, identity/integrity failure, port conflict, transport timeout, and media-worker failure separately. Stop for required user action; honor reconnect disabled/max-attempt settings.
- [ ] Update the authoritative credentials when a prompt is answered; retain them across permitted retries without logging them.
- [ ] Retain intended view-only, quality, always-refresh, and other supported runtime settings across reconnect. Absorb settings received during backoff instead of discarding them.
- [ ] Keep disconnect/cancel/reconnect-now responsive during connect, authentication, backoff, and cleanup. Emit coherent states rather than treating a transient disconnect as an ended session.

Acceptance and validation:

- [ ] Simulate ten transient failures; verify the configured delay ladder, jitter bounds, attempts, and stable-uptime reset.
- [ ] Start with missing credentials, submit them once, force a disconnect, and verify the next attempt uses the submitted credentials.
- [ ] Wrong password prompts/stops according to policy and never enters a 500 ms endless loop. A user disconnect never reconnects.
- [ ] A view-only session remains view-only after recovery, including before the first post-reconnect input command.

## 4. P1: packet recovery, resource bounds, and control reliability

### RTP-02 — Make reorder expiry correct across sequence wrap and configuration packets

**Evidence:** Code/Probe. **Effort:** medium. **Dependencies:** RTP-01.

**Code:** `h264.rs:131–138,147–176,246–282`. The reorder map is keyed by raw `u16`; expiry chooses its numerically smallest key, which is not necessarily nearest to `expected` around 65535 -> 0. The far-gap branch counts `ahead - 1` even though `expected` already names the next missing packet. Configuration payloads beginning `0x92` return before ordinary sequence accounting, leaving a sequence number unexplained when those packets share the RTP sequence space.

- [ ] Select expired buffered packets by modular forward distance from `expected`, or use validated extended sequence indexes. Keep all comparisons within an explicit half-sequence-space bound.
- [ ] Account for every authenticated RTP sequence, including configuration/control payloads on that stream; dispatch payload semantics after ordering. Verify the configuration sequence-space assumption against captured traffic.
- [ ] Correct missing-count and NACK ranges at immediate-gap and timeout-gap boundaries.
- [ ] Define a single restart/discontinuity policy for large forward/backward jumps instead of inferring every large gap is harmless.
- [ ] Count duplicate, reordered, too-late, lost, abandoned, configuration, and discontinuity events separately; do not label duplicates as network loss.

Acceptance and validation:

- [ ] Cover expected 65534 with buffered 65535, 0, and 1, and expiry on both sides of rollover. The nearest forward packet is processed first.
- [ ] Cover exactly 0, 1, lookahead-limit, loss-limit, half-space, and restart-sized gaps, including duplicate/stale buffered packets.
- [ ] Insert an authenticated configuration packet between consecutive media packets; it causes no false missing-sequence request or unnecessary reorder wait.

### RTP-03 — Make repair timing and feedback useful rather than merely present

**Evidence:** Code; host behavior needs measurement. **Effort:** medium/large. **Dependencies:** RTP-01/02, REC-01.

**Code:** `h264.rs:152–155,198–243,263–310`; `session.rs:1605–1640`; `rtcp.rs` NACK/FIR builders. The driver sends NACKs after abandoning the hole and advancing `expected`; the original missing sequence then takes the too-late path and cannot repair that abandoned AU. `session.rs:1617` also copies the remembered loss history on each gap, re-requesting obsolete losses. Whether macOS responds usefully remains unmeasured.

- [ ] Define a bounded repair window: detect the hole, request retransmission while the unit is still repairable, hold within a latency budget, then abandon the entire damaged unit and request an independent picture if necessary.
- [ ] Avoid asking for retransmissions that are guaranteed to be discarded as late; if the Mac does not retransmit usefully, prefer supported independent-picture recovery and report the limitation.
- [ ] Keep only outstanding repairable holes in the NACK set, with per-sequence retry/expiry state. Size replay and reorder windows consistently with supported packet rate and repair delay; the existing 64-position replay window may be shorter than the desired repair interval.
- [ ] Use measured reorder/RTT evidence to choose wait budgets; retain strict maximum delay/bytes/packet limits for a pathological peer.
- [ ] Record requested/retransmitted/usefully repaired/too-late counts and independent-picture request-to-output latency.
- [ ] Coalesce and rate-limit loss feedback; apply a recovery budget shared with decoder/resize recovery to avoid key-picture amplification.

Acceptance and validation:

- [ ] A missing packet arriving inside the configured repair window completes the original AU; the same packet arriving after abandonment is ignored and cannot restore a damaged timestamp.
- [ ] Compare immediate abandonment against bounded NACK repair under defined latency/loss profiles. Use presented latency and corruption rate, not request count, to choose policy.

### RTCP-01 — Track FIR request identity and verify feedback interoperability

**Evidence:** Code/spec; macOS impact unmeasured. **Effort:** medium. **Dependencies:** REC-01.

**Code:** `session.rs:144–182` always supplies FIR sequence `0` at line 167; `rtcp.rs` builds feedback and empty receiver reports; incoming feedback is only consumed at `session.rs:1457–1470`.

New FIR commands need distinct per-target request sequence values; retransmission of the same command keeps its value. See [RFC 5104 section 4.3.1](https://www.rfc-editor.org/rfc/rfc5104.html#section-4.3.1). PLI and legacy requests are also sent, so a constant FIR sequence does not prove that all recovery requests are ignored by this Mac.

- [ ] Maintain a wrapping FIR command sequence per request-source SSRC and target SSRC pair; distinguish a new recovery command from repeating the same command.
- [ ] Capture which of FIR, PLI, legacy request, and NACK the supported macOS versions honor; retain compatibility based on observed behavior rather than speculative packet variants.
- [ ] Parse authenticated sender/receiver report information where supported and useful; validate source/length/index/replay before trusting feedback state.
- [ ] Populate receiver loss/jitter/highest-sequence report blocks where the verified protocol expects them. Do not label an empty report as useful network-quality feedback.
- [ ] Keep RTT unknown until SR/RR timestamps or another correlated exchange support it; RTCP arrival timing alone is not RTT.
- [ ] Bound feedback rates and log failures/response outcomes without media key material.

Acceptance and validation:

- [ ] Packet vectors show distinct sequence numbers for new FIR commands, unchanged numbers for repetitions, correct wrap, and the proper media SSRC.
- [ ] A controlled server deduplicating FIR sequence values still accepts successive new recovery commands.
- [ ] A real-host trace ties a supported feedback command to fresh independent output; merely sending it is not recorded as successful recovery.

### MEM-01 — Enforce byte, age, and ownership bounds at every queue

**Evidence:** Code/Probe. **Effort:** medium/large. **Dependencies:** BUF-01, OBS-01.

**Code:** fragment accumulation `h264.rs:436–459` versus AU cap `356–360`; picture-count bound `pictures.rs:29–47`; unbounded request channel `session.rs:1215`; timestamp insertion/deletion `WebGLRenderer.ts:1323–1326,1483–1485`; configure failure cleanup `1461–1614`.

The FU accumulator can grow before the complete-NAL/AU cap is checked. Eight queued pictures are a count bound, not a byte/latency bound; eight 8 MiB completed-NAL payloads alone represent 64 MiB, excluding unfinished fragments, Annex-B/configuration overhead, container storage, and in-flight/IPC copies. This is an illustrative payload calculation, not an enforced total ceiling. The renderer stores one timing entry per submitted chunk and deletes only exact output matches. A decoder consuming input without output can retain 10,000 timing entries after 10,000 submissions. A newly constructed decoder whose configure attempts both throw is returned without being closed or entered into the map that owns cleanup.

- [ ] Enforce maximum bytes and age while appending FU fragments, not only after completion. Abort/mark the timestamp damaged immediately on violation.
- [ ] Set independent limits for per-SSRC assembly, all candidate streams combined, picture count/bytes/oldest age, IPC in-flight bytes, pending decoder work, unmatched timing entries, and retained frames.
- [ ] Bound timing metadata by count and age; reclaim unmatched older timestamps when later output and the supported ordering guarantee make them obsolete. Count evicted/unknown latency samples.
- [ ] Add an Apple continuous-decoder no-output deadline even if `decodeQueueSize` remains zero. A queue of zero does not prove output is progressing.
- [ ] Replace refresh/toggle command accumulation with bounded coalescing state/notification. Keep requests idempotent where possible.
- [ ] Close every partially constructed/refused decoder and every obsolete `VideoFrame`, waiter, timer, canvas, and GPU resource on all exits.
- [ ] Use `u64` or explicitly defined wrapping for lifetime telemetry counters; preserve protocol-defined wire widths. Include counter wrap/reset behavior in diagnostics tests.

Acceptance and validation:

- [ ] An endless FU without its end packet cannot exceed the declared memory/age limit; the next complete independent picture can recover.
- [ ] A decoder accepting 100,000 chunks with zero outputs and zero reported queue size has bounded timing metadata and triggers recovery.
- [ ] Constructor throw, both-configure-throw, delayed error, retirement during configure, queue saturation, and cancellation leave live-resource counts at baseline.
- [ ] A stalled consumer never makes total retained bytes or oldest picture age exceed the declared budgets without an explicit recovery transition.

### CTRL-01 — Parse bounded control messages independently of encryption records

**Evidence:** Code; actual host framing variations need vectors. **Effort:** large. **Dependencies:** LIFE-01, OBS-01.

**Code:** `Live::read_body:2249–2269`; rectangle walking `session.rs:2530–2571`; layout extraction `2581–2603`; `answer.rs:42–52`; `plist.rs:42–67,79–98`.

The code treats a decrypted record body as a complete control-message container. The rectangle walker recognizes rekey/layout encodings, stops at an unknown encoding, and tolerates truncated declared layout payloads. The answer parser scans for a `bplist` marker, hands the remainder of the record to a parser that expects a trailer at the end, and inflates compressed data without an output cap. Valid messages split/combined differently or a known rectangle following another encoding may be missed. These are observable parser limitations; their frequency in Apple's actual stream is unverified.

- [ ] Establish complete message framing from verified protocol captures and implement a bounded incremental parser independent of TCP and encrypted-record boundaries.
- [ ] Return typed incomplete/malformed/unsupported results with consumed lengths; do not silently accept truncated critical geometry or skip all later supported rectangles without a diagnostic.
- [ ] Parse plist/media payloads from their declared containers rather than a raw marker search plus the rest of a record.
- [ ] Bound compressed and decompressed bytes, object count, recursion, aggregate decoded-value allocation, protobuf lengths, dimensions, tile count, and total pending message bytes.
- [ ] Use checked arithmetic for offsets/lengths and range-check before allocation. Keep the existing recursion bound and add cycle/shared-object allocation tests.
- [ ] Process valid rekeys/layouts in order, including multiple relevant rectangles. Preserve monotonically advancing record sequence counters through rekey.
- [ ] For unsupported encodings, skip only when a verified length contract allows it; otherwise fail the attempt with a precise reason rather than guessing boundaries.

Acceptance and validation:

- [ ] Feed every supported message split at every TCP/record boundary and coalesced with other messages; output is identical where the verified wire grammar permits those shapes.
- [ ] Cover a rekey/layout after another supported rectangle, repeated rekeys, truncated lengths, zero/huge lengths, malformed plist offsets, decompression bombs, cyclic references, and impossible dimensions.
- [ ] Arbitrary malformed authenticated control data produces a bounded error, not an allocation explosion, panic, missed critical transition, or false success.

### IO-01 — Bound handshake/control I/O and first-picture readiness

**Evidence:** Code. **Effort:** medium. **Dependencies:** LIFE-01, REC-02.

**Code:** `session.rs:871–1004,1024–1038,1066,1246,2241–2246,2621–2634,2683–2709`.

Some handshake reads have 20-second timeouts, but the cleartext rekey loop and its `read_exact()` calls have no overall bound. Writes also lack deadlines/cancellation. Once a branch awaits a write, the outer `select!` cancellation branch cannot run. `Connected` is emitted before media output, while the initial picture debt is zero; no incoming initial media plus no user input can leave a connected black pane without starting the normal debt-based recovery.

- [ ] Apply one overall establishment deadline and shorter phase deadlines covering DNS, TCP, RSA/SRP computation, all writes/reads, cleartext rekey, media answer, first decoded output, and first drawn picture.
- [ ] Make long I/O/event/display-queue awaits cancellation-aware, including those inside selected command branches.
- [ ] Treat timeout/cancellation after a partial encrypted write as a fatal attempt failure. Sealing advances cipher state; do not reseal/retry the command on the same connection after an uncertain write.
- [ ] Mark transport-connected and media-ready separately; start a bounded initial-media deadline when the offer is sent.
- [ ] Permit a documented bounded encoder warmup period and empty-answer retries, then escalate/report the actual stalled phase.

Acceptance and validation:

- [ ] A peer that never speaks, trickles bytes, withholds initial rekey, stops reading writes, or accepts the offer but sends no media cannot hold establishment/cancellation indefinitely.
- [ ] Disconnect during every phase settles within the published cancellation budget; no task continues using the next attempt's UI state.

### DISPLAY-01 — Serialize physical-display requests and handle reply closure

**Evidence:** Code. **Effort:** medium/large. **Dependencies:** LIFE-01, SIZE-01.

**Code:** `session.rs:1087–1132,1788–1807,1848–1857`; `crates/apple-core/src/macos.rs` restore/apply ownership.

Each new display command overwrites the sole reply receiver. When the worker replies to a now-dropped earlier receiver, it breaks and starts restoration; later requests are left without a worker. A closed reply receiver reaches `display.expect("a display reply")` and can panic. Filling the four-entry worker queue also makes the main control loop await slow display work, despite the worker being intended to preserve input responsiveness.

- [ ] Assign IDs and retain one result receiver per outstanding request, or serialize/coalesce requests with an explicit busy response. A stale UI interest must not terminate the worker.
- [ ] Replace `expect` on channel closure with a typed worker/result failure; settle every request exactly once.
- [ ] Keep queue admission nonblocking for input/control I/O; bound action count and total outstanding operation age.
- [ ] Coordinate physical changes, in-band quality changes, recovery, and restoration under one transition owner.
- [ ] Cancel obsolete queued actions on reconnect and await bounded restoration with clear ownership. Retain the existing refusal to undo an outside display change.
- [ ] Verify exact mode identity after apply/restore and report unconfirmed restoration accurately; do not infer it solely from a helper command exit.

Acceptance and validation:

- [ ] Issue List/List/Set/Restore while the first action is delayed. No worker termination, panic, lost settlement, or blocked input occurs.
- [ ] Force reply closure, helper timeout, worker panic, disconnect, and immediate reconnect; a retired worker cannot restore over a new attempt's confirmed choice.

### NET-01 — Make endpoints, address selection, and path changes consistent

**Evidence:** Code; platform/host support needs live qualification. **Effort:** medium. **Dependencies:** LIFE-01, REC-01.

**Code:** configured initial binding `session.rs:2273–2289`; hardcoded steady-state destinations `1077–1078`; peer resolution `230–260,1240`; IPv4 bind `2303`; repeated punches `1298–1303`.

- [ ] Separate local bind ports and server destination ports in options and transport state. Use the verified negotiated/fixed endpoint contract consistently; current initial and steady-state behavior differ for custom ports.
- [ ] Resolve/store a concrete endpoint associated with the connected control peer, with explicit policy for multihoming/NAT. Avoid repeated hostname resolution on frequent `send_to()` calls.
- [ ] Surface unsupported address families/endpoints early; implement and qualify dual-stack behavior if Apple media supports it.
- [ ] Define the single/multiple Apple-session policy. Binding the same wildcard local ports prevents simultaneous sessions even to different Macs; show a precise resource-conflict error until safe demultiplexing/alternate endpoints are implemented.
- [ ] Measure effective OS receive buffers and socket overflow counters. The current code already requests 4 MiB and logs the actual size; increasing buffers again without observing drops is not a fix.
- [ ] Make NAT keepalive interval configurable/measured. The current 200 ms punches on two sockets cost about ten datagrams per second per session, plus reports; preserve connectivity while reducing avoidable wakeups where measurements justify it.
- [ ] Handle suspend/resume, Wi-Fi change, VPN route/DNS change, and stale NAT mappings through the recovery coordinator. Refresh/reconnect when the existing media path cannot be repaired.

Acceptance and validation:

- [ ] Cover custom-port options, IPv4/IPv6, multiple DNS answers, two simultaneous Apple sessions, wrong-source datagrams, and route changes. Unsupported cases fail with a clear explanation.
- [ ] Do not silently switch to ephemeral media ports: older observations indicate the Mac used fixed destinations on this setup; verify any alternate-port scheme on the wire.

### AUTH-01 — Finish mutual-proof validation and isolate expensive authentication work

**Evidence:** Code. **Effort:** medium/large. **Dependencies:** typed errors in REC-02, bounded startup in IO-01.

**Code:** proof handling `session.rs:934–965`; `auth.rs:53–83,121–123,231–280`. Missing/mismatching server proofs warn and continue. The parser bounds iterations, but accepts modulus/generator bytes without comparing them with the fixed group actually used by the client. Expensive PBKDF2/modular exponentiation executes synchronously in the async connection task.

- [ ] Confirm the exact proof framing with controlled server/client vectors and supported macOS captures; enforce matching mutual proof once framing is established. A notice is not successful mutual authentication.
- [ ] Validate supported modulus/generator, public-value range, salt/options lengths, and supported iteration bounds against the actual computation.
- [ ] Use appropriate constant-time verification/zeroizing ownership for secret material and avoid unnecessary long-lived credential/key copies.
- [ ] Run bounded CPU-heavy authentication work on an appropriate blocking/CPU worker so simultaneous reconnects cannot stall the async runtime. Bound concurrency and remember that cancelling a blocking task does not automatically stop its computation.
- [ ] Classify proof/group/credential errors as requiring intervention rather than repeatedly reconnecting to the same invalid exchange.

Acceptance and validation:

- [ ] Correct/missing/malformed/wrong proofs and unsupported groups produce the intended secure outcome with deterministic vectors.
- [ ] Parallel connection attempts at the maximum supported iteration count do not starve an existing session's input/media loop.

### PAD-01 — Read RTP padding from decrypted plaintext

**Priority:** P1. **Evidence:** Code/Probe; occurrence on the real host unknown. **Effort:** small. **Dependencies:** none.

**Code:** `srtp.rs:154–161,165–184`. The receiver reads the RTP padding count from encrypted bytes before authentication/decryption and then decrypts only the truncated region. A correctly protected padded packet fails the review roundtrip. RTP payload padding is inside the encrypted region; see [RFC 3711 section 3.1](https://www.rfc-editor.org/rfc/rfc3711.html#section-3.1).

- [ ] Authenticate the packet, decrypt the complete encrypted payload including padding, then validate/remove the plaintext padding.
- [ ] Define replay/index-state treatment for authenticated malformed payloads without letting malformed traffic rewind the accepted high-water state.
- [ ] Replace misleading padding coverage with actual encrypted sender/receiver vectors plus an independent known-answer vector.
- [ ] Cover padding 1/2/maximum, zero/oversized padding, header extensions/CSRCs, tampering, rollover, and empty payload edge cases.

Acceptance: valid padded SRTP yields the exact original media payload; malformed padding is rejected predictably without changing unrelated stream state.

### WATCH-01 — Track the first outstanding response without inventing desktop damage

**Priority:** P1. **Evidence:** Code. **Effort:** medium. **Dependencies:** OBS-01, REC-01.

**Code:** `session.rs:1363–1385,1538–1557,1577–1580,1680–1705,2057–2069`.

Every pointer/key event overwrites the outstanding picture timestamp. Continuous input can therefore postpone the UDP debt-age recovery path, which requires that timestamp to be at least two seconds old. The separate TCP re-offer path uses time since the last assembled picture and can instead trigger shortly after a single non-damaging pointer move following a long legitimate idle. A separately drawn cursor does not require the desktop image to change. These inconsistent debt rules also make the latency estimate misleading.

- [ ] Store first outstanding screen-affecting request separately from latest input time and last response; do not move the first deadline forward on every event in a burst.
- [ ] Classify pure pointer overlay motion, button/key actions, explicit refresh, resize, and recovery asks. Do not assert that every key or pointer event necessarily changes image content.
- [ ] Use a protocol-supported expected-response/health policy for ambiguous idle cases and stage progress for known pending media work.
- [ ] Clear response debt only using the agreed epoch/stage acknowledgement, with a bounded estimate when exact content correlation is unavailable.
- [ ] Read the live picture-buffer chain state or notify when the consumer repairs it. The receiver's local `chain_broken` snapshot must not keep requesting recovery after the consumer is already healthy.
- [ ] Count one stall incident separately from repeated requests within that incident; expose both successful and ineffective recovery rounds.

Acceptance and validation:

- [ ] Ten seconds of continuous mouse/key input cannot continually postpone recovery of a known stalled decoder/stream.
- [ ] Ten minutes of an unchanged screen followed by pointer-only motion does not immediately provoke an encoder restart.
- [ ] Key repeat, view-only remote animation, a valid static desktop, missing output, and a repaired buffer each reach the intended state without conflicting watchdogs.

## 5. Complete quality, geometry, and presentation transitions

### SIZE-01 — Complete a transition only when its replacement picture is drawn

**Priority:** P1. **Evidence:** Code. **Effort:** large. **Dependencies:** OBS-01, REC-01, EPOCH-01; extends the existing resolution stabilization plan.

**Code:** `session.rs:1961–1984,2101–2199`; `video.rs:123–157`; `WebGLRenderer.ts:860–875,1503–1576`; current [resolution stabilization plan](2026-10-20-apple-resolution-stabilization-plan.md).

The recent code correctly keeps a pending layout and requires assembly after re-offer, but current generation tagging is still local intent rather than authenticated replacement-picture identity. Any assembled old-stream unit can be stamped with the current generation. The renderer's pending layout has no matching backend transition/epoch acknowledgement. A resize can appear complete without the requested picture being decoded/drawn.

- [ ] Make request -> layout -> media answer/configuration -> selected replacement stream -> decode -> upload/draw one cancellable, serialized transaction with deadlines.
- [ ] Carry and validate transaction/epoch/configuration/geometry identity through buffered AUs, IPC, decoder callbacks, and completion acknowledgement.
- [ ] Preserve latest-intent-wins behavior and update rollback snapshots from confirmed current state. Keep the existing one-attempt restoration policy and one-pixel point-preserving tolerance.
- [ ] Distinguish requested, server acknowledged, effective decoded, and drawn geometry; report clamping/refusal rather than pretending exact application.
- [ ] Confirm restore via the same complete transaction; retain the last good image until a valid replacement is ready.
- [ ] Define timeout/cancel/unknown-state outcomes and behavior if a user/server changes the display during the transaction. Never blindly undo an external change.

Acceptance and validation:

- [ ] Fifty rapid High/Low/High requests, delayed layout/answer/output, same-size encoder restart, old SSRC overlap, and reconnect mid-round all end at the final intended effective setting or a clear failure.
- [ ] Old buffered units and delayed callbacks cannot complete a new transition. A layout-only or assembly-only answer cannot report presentation success.
- [ ] A refused change restores once and reports the confirmed result; it cannot oscillate between recovery and rollback.

### SIZE-02 — Separate remembered observation, user preference, and physical capabilities

**Priority:** P1. **Evidence:** Code; startup host effects need controlled verification. **Effort:** medium/large. **Dependencies:** SIZE-01.

**Code:** `session.rs:28–49,1006–1038,1940–1952`; `ui/src/hooks/useSession.ts:528–541,643`; `ui/src/lib/appleGeometry.ts`; `quality.rs`.

The initial display descriptor can replay remembered geometry before observing the current Mac desktop. That observation may already reflect a previous client request. The recent equal-point/lower-pixel cache fix is present and should remain; it does not establish current physical panel capabilities or cross-profile identity.

- [ ] Carry forward the remaining startup-descriptor and cache work in the existing resolution plan; do not treat its fixed historical defects as still broken.
- [ ] Define startup behavior from a controlled capture: whether a non-dynamic descriptor or an echo of independently observed current geometry can attach correctly without replaying a stale mode.
- [ ] Version caches and attach provenance, observation time, display identity, connection epoch, and host identity. Keep user preference separate from observed/effective geometry.
- [ ] Use one capability/texture/pixel-budget validator across presets, manual size, native, and recovery. Reject incompatible aspect/point requests explicitly rather than relying on server fallback.
- [ ] Do not label the first post-configuration layout as an independently measured physical native mode. Preserve logical points, backing pixels, encoded pixels, and physical mode identity separately.
- [ ] Persist effective successful settings after confirmation; show pending/failed/clamped state and do not restart the encoder immediately on every reconnect solely because a preference was re-emitted.
- [ ] Make Auto and quality labels reflect the policy actually implemented. Local grayscale already exists for Apple B&W; avoid adding duplicate work to implement it again.

Acceptance and validation:

- [ ] Changing the Mac's mode between connections does not silently replay a stale preference as detected hardware capability.
- [ ] LAN/VPN profiles and multiple displays cannot overwrite each other's native observation accidentally.
- [ ] Fit/zoom/window resize has the documented local behavior and does not send an unintended remote mode change.

### GPU-01 — Recover presentation/context loss and reuse scaling resources

**Priority:** P1/P2. **Evidence:** Code; performance magnitude needs measurement. **Effort:** medium/large. **Dependencies:** OBS-01, REN-01.

**Code:** `WebGLRenderer.ts:1568–1576,1657–1715,1970–1985`. Canvas fallback allocates a new full-size `OffscreenCanvas` and context on every frame. A fallback error sets the global failure latch. There is no explicit `webglcontextlost`/`webglcontextrestored` recovery contract.

- [ ] Handle context loss/restoration: stop invalid GL work, recreate GPU resources, fence retired frames, request/accept a current picture as required, and acknowledge resumed draw.
- [ ] Count and time direct video upload, cropping, stretched/canvas fallback, allocation, upload failure, and draw duration.
- [ ] Reuse canvas/context storage per compatible geometry and release it on retirement. Prefer source-sized video-texture upload plus shader scaling if measurements show it removes CPU canvas copies safely.
- [ ] Keep input mapping tied to the confirmed desktop/point geometry when rendering a lower-resolution video texture.
- [ ] Check texture limits, framebuffer completeness, and GPU memory budgets. Report errors with bounded sampling rather than expensive per-frame diagnostic calls.
- [ ] Route upload failures to the common recovery policy with an honest capability message; Apple has no implemented automatic alternate-image encoding fallback here.

Acceptance and validation:

- [ ] Force GL context loss/restore and both upload paths; current video returns without reopening the pane and all frames/resources are closed exactly once.
- [ ] Native picture, reduced picture scaled to native layout, cropped padding, and forced canvas fallback each have measured p95 upload/draw cost and stable allocation/resource counts.

## 6. P2: improve speed and efficiency with measurements

### PERF-01 — Benchmark the same scene at the same effective settings

**Evidence:** Measure. **Effort:** medium. **Dependencies:** OBS-01 and correctness fixes.

- [ ] Build reproducible workloads: static text, typing, small window drag, rapid horizontal/vertical scrolling, full-screen animation, and large key-picture bursts. Identify exact encoded/drawn sizes and cadence.
- [ ] Compare current build versus each candidate change and, where available, a native client at equivalent output size/cadence. Separate startup/recovery costs from steady-state cost.
- [ ] Record received bitrate/packet rate, socket loss, AU loss, decode/drawn FPS, queue bytes/age, CPU/GPU utilization, RSS, allocations, decoder creation count, and p50/p95/p99/max stage latency.
- [ ] Measure actual remote-input response with a changing visual marker and drawn-frame acknowledgement. A local cursor is not the benchmark response.
- [ ] Record decoder preference and verified implementation separately. `prefer-hardware` is a hint, not proof of hardware use; see [WebCodecs acceleration preferences](https://www.w3.org/TR/webcodecs/#hardware-acceleration).
- [ ] Keep raw metadata results, run duration, workload version, machine/environment identity, source revision, and artifact hash. Set acceptance budgets from these baselines before declaring percentage improvements.

Acceptance: every claimed speed/CPU/memory improvement has an equivalent-workload comparison, sample counts, tail latency, and no new corruption/recovery regression.

### PERF-02 — Reuse a healthy decoder across same-configuration IDRs

**Evidence:** Code; performance benefit requires measurement. **Effort:** medium. **Dependencies:** EPOCH-01, REN-01/02.

**Code:** `h264.rs:370–371`; `session.rs:646–653`; `WebGLRenderer.ts:1300–1306`. Every IDR currently propagates `reset=true`, closing/recreating a decoder even when codec configuration is unchanged. The existing non-IDR fix is present; preserve its reference-chain semantics.

- [ ] Separate independent picture/IDR from decoder recreation. Rebuild for actual epoch/configuration changes or failed decoder state, rather than every healthy IDR.
- [ ] Fingerprint SPS/PPS/codec/coded geometry and verify compatible reuse. An unchanged displayed size does not prove unchanged codec configuration.
- [ ] Measure configure-to-first-output delay, discarded pending output, CPU/GPU spikes, and decoder creation count at observed IDR rates.
- [ ] Test periodic same-config IDRs, changed SPS/PPS with same size, changed dimensions, legitimate reference reset, and delayed old callbacks.

Acceptance: same-config IDRs decode correctly without pipeline recreation; changed configurations remain correct and measured recovery/startup latency improves or stays within budget.

### PERF-03 — Reduce hot-path allocations and downstream backlog

**Evidence:** Code optimization candidates; dominant costs unmeasured. **Effort:** medium/large. **Dependencies:** MEM-01, OBS-01.

**Code:** `srtp.rs:182,221–246,487–488`; `h264.rs:198–230,331,372–382`; `video.rs:160–174`; `src-tauri/src/framing.rs:178–231`; `src-tauri/src/commands/session.rs:814–848`; `WebGLRenderer.ts:1333–1335`.

- [ ] Profile allocation/copy volume per packet and per AU before selecting changes. Candidate costs include ROC-vector allocation, decrypted payload allocation, reordered-payload copies, Annex-B packing, frame IPC copy, and length-prefix conversion.
- [ ] Use a stack-sized ROC candidate set and ensure the preferred estimate is actually first; reuse keyed cipher/HMAC setup only with benchmarks and independent correctness vectors.
- [ ] Consider owned/reused packet buffers and pre-sized AU output without borrowing memory past its lifetime or retaining large buffers indefinitely.
- [ ] Avoid sorting/allocating all SSRC IDs on every 20 ms flush; schedule only streams with pending timeout work while preserving candidate fairness.
- [ ] Measure event-channel dwell and Tauri send-to-JS receive time. Bound in-flight compressed bytes upstream of JS; renderer queue bounds cannot control messages already waiting in the bridge.
- [ ] Preserve H.264 dependencies when dropping backlog. Apply one explicit discontinuity and resume from an acceptable independent picture rather than arbitrarily pruning delta messages.
- [ ] Measure synchronous `agent.feed()` before `channel.send()` and keep secondary mirror/perception work bounded off the video critical path where warranted.
- [ ] Treat persistent binary-channel failure as a failed consumer, not an endless per-frame warning loop. Coordinate reattachment or end the unconsumed attempt.
- [ ] Avoid reinstating the previous per-frame credit/repaint feedback loop; sampled progress and byte budgets must not create request storms.

Acceptance: profiles show reduced CPU/allocation/bridge dwell under the same workloads while replay protection, AU completeness, ordering, buffer ownership, and latency bounds remain correct.

### PERF-04 — Define adaptive and background-session policy

**Evidence:** Code/Measure. **Effort:** medium/large. **Dependencies:** OBS-01, SIZE-01, REC-01.

**Code:** fixed offer `offer.rs:24–75`; preset mapping `quality.rs`; background draw control `Session.tsx:634–647`; continuous upload `WebGLRenderer.ts:1974–1977`.

- [ ] Verify supported server controls for cadence/bitrate/encoder policy on each tested macOS version before exposing them. Document unsupported controls; do not infer them from standard VNC knobs.
- [ ] If supported, adapt encoder load using measured bandwidth/loss/queue/presentation pressure with hysteresis, minimum dwell time, and a user override.
- [ ] Keep resolution/desktop points separate from bitrate/cadence policy. Do not repeatedly change a person's logical desktop as a congestion response.
- [ ] For hidden tabs/minimized windows/lock/suspend, define whether to keep, reduce, or pause media while retaining control safely. Current hidden views can stop drawing while continuing decode/IPC; latest-frame retention bounds one stage but still spends decoder work.
- [ ] On resume, distinguish intentionally suspended drawing from a frozen renderer; verify fresh epoch/transport/decoder progress and refresh only when needed.
- [ ] Measure background CPU/GPU/power/traffic and first-current-picture latency on return; exercise repeated hide/show and device sleep/wake.

Acceptance: supported background/adaptive policy reduces measured work without unbounded catch-up, repeated display-mode changes, false recovery storms, or stale output on return.

## 7. Test infrastructure and long-session qualification

### QA-01 — Build a deterministic fake-server and renderer lifecycle suite

**Priority:** P1, started alongside the P0 fixes. **Effort:** large. **Dependencies:** testable transport/epoch/recovery components.

- [ ] Extract state transitions from the 3,696-line session module into small testable components with explicit inputs/outcomes: attempt supervision, media identity/selection, progress/recovery, and display transactions.
- [ ] Add a fake Apple control peer and authenticated packet source with injectable clock, socket reads/writes, event sink, and renderer acknowledgements. Use no saved credentials or real Mac.
- [ ] Control split/combined records, rekeys, layouts/answers, old/new SSRC overlap, continuing/reset numbering, SPS/PPS/configuration changes, and packet order/loss/replay.
- [ ] Model real WebCodecs states and asynchronous callbacks, including consumed input without output, queue saturation, delayed output/error after retirement, and failed configure.
- [ ] Assert observable invariants: one active owner per attempt, bounded memory/time, valid dependency order, monotonic identity, one settlement per request, and no false media-ready/transition-success state.
- [ ] Turn the characterization probes into corrected-behavior regressions in production test modules as each bug is fixed. Do not remove a failing characterization assertion merely to restore a green review harness without replacing its coverage.
- [ ] Cover all worker exits, event-sink closure, partial encrypted writes, retry policy, credentials supplied by prompt, and same-size reconnect.
- [ ] Use injected time for deadlines/backoff/reordering where possible; avoid flaky wall-clock sleeps in the eventual CI tests.
- [ ] Add property/fuzz coverage for RTP sequence wrap/order, control lengths, plist/protobuf parsing, and access-unit damage. Store no private desktop captures or keys in fixtures.

Acceptance: each corrected P0 issue has a regression that first fails against the reviewed revision and passes with the fix; complete loss/recovery/resize/reconnect scenarios run without a live Mac.

### QA-02 — Run fault injection and soak tests on an isolated session

**Priority:** P1 release gate. **Effort:** medium/large. **Dependencies:** fixes and OBS-01 instrumentation.

Run active experiments on a test account/session or isolated Mac suitable for display/network changes. Keep the user's current interactive session out of fault injection. Every run records source/build hash, platform/webview/plugin/driver versions, negotiated settings, workload, timing, and packet-index range.

| Scenario | Minimum workload/faults | Required result/evidence |
|---|---|---|
| Initial readiness | Missing rekey/answer/media, delayed first picture, empty answer, no user input | Bounded waiting, clear failed stage, cancellation works, no permanent connected black pane |
| Renderer-only freeze | Keep UDP/AU flow healthy; suppress outputs, fail decoder, fail upload/draw | First stalled stage identified; bounded local recovery/escalation; input remains responsive |
| UDP-only failure | Black-hole media/feedback while TCP input works; restore path | Bounded retry/re-offer/full reconnect; no infinite five-second re-offer loop |
| Packet correctness | Drop first/middle/last/marker/FU/config packets; reorder/duplicate/replay | No damaged complete/key AU, useful bounded repairs, fresh output restores reference chain |
| RTP wrap/restart | At least three sequence wraps; re-offer at ROC 0/1/2/3; same/new/reused SSRC | Continuations authenticate; genuine restarts recover; delayed old traffic cannot commit new state |
| Stream churn | 1,000 synthetic replacements; at least 100 supported live quality/recovery cycles | No stream-32 exhaustion; bounded active/candidate/retired memory |
| Recovery overlap | Resize during loss, decoder failure during resize, reconnect during restore | One coordinator wins; final intended setting or explicit failure; no oscillation |
| Backpressure | Stall event sink, JS delivery, decoder, and draw separately; large key bursts | Declared count/bytes/age bounds hold; dependency-safe dropping; no repair amplification |
| Control lifecycle | EOF/half-open write, integrity failure, worker panic, closed IPC consumer | One classified outcome; joined teardown; retry policy honored; no old attempt work persists |
| Idle and return | 30–60 minutes static desktop, then visible remote content change | No idle request/re-offer storm; new content appears within the declared return budget |
| Background/resume | Repeated tab hide/show, minimized window, GPU context reclamation, local suspend 5/30 min | Bounded resources; no timer-induced false recovery; fresh output on return |
| Remote sleep/session | Remote lock/unlock, display sleep/wake, supported user-session switch | Correct session/geometry/epoch, actionable status, no unintended display reconfiguration |
| Network change | LAN/VPN, DNS/multihoming change, NAT expiration, Wi-Fi interruption | Path failure classified and recovered; endpoint policy consistent |
| Physical display | Delayed List/Set/Restore, external mode change, helper failure, disconnect | No worker panic or blocked input; exact apply/restore verification; no undo of outside changes |
| Reconnect churn | 100 controlled connects/disconnects and failures at different phases | Task/socket/decoder/FD counts return to baseline; prompted credentials/settings retained |

Suggested progression:

1. [ ] Run deterministic fault cases and 10-minute integration smoke tests before a long soak.
2. [ ] Run **2 hours active** with scrolling/typing/window motion and regular key-picture bursts.
3. [ ] Run **8 hours mixed active/idle** with background/resume and a controlled network interruption each hour.
4. [ ] Run **24 hours mixed** after shorter runs pass; include multiple RTP rollovers and at least one same-SSRC continuing re-offer after ROC 2.
5. [ ] Run an optional **72-hour stress** and the supported multi-session matrix before broad release if deployment usage warrants it.
6. [ ] Compare the first and last steady-state windows; retain distributions and worst incidents, not just averages and final RSS.

Capture at 1-second intervals plus event-triggered snapshots: last stage ages; packets/bytes/auth rejects/loss/reorder; queue count/bytes/oldest age; assembled/submitted/decoded/uploaded/drawn counts; decode preference/implementation; recovery stages/requests/successes; RSS/FD/task/socket/decoder/GPU counts; CPU/GPU; selected geometry and IDs. Keep high-cardinality details in bounded traces rather than unbounded labels/logs.

### QA-03 — Qualify the installed artifact and regression gates

**Priority:** P1/P2. **Effort:** medium. **Dependencies:** QA-01/02.

**Code:** `.github/workflows/ci.yml:63–85,138–159`; Linux codec setup `src-tauri/src/main.rs:1–36`. Apple-core tests/lints are already included in CI; do not add a duplicate task claiming they are missing.

- [ ] Run the complete 107-test Apple suite on a host/CI where loopback sockets are permitted, plus relevant shared-supervisor/framing/renderer tests and typecheck.
- [ ] Migrate the durable regression cases into normal CI so an isolated review-harness green state cannot be mistaken for release qualification.
- [ ] Verify the actual installed binary/source revision and artifact hash before interpreting live diagnostics. A rebuilt source tree is not evidence that the running AppImage contains the fixes.
- [ ] Test packaged Linux/AppImage host GStreamer discovery, the existing overridable linear-NV12 workaround, codec plugin ABI/driver compatibility, and launch from the desktop environment.
- [ ] Verify actual decoder selection after startup, reconfiguration, fallback, reconnect, and resume. Repeat on supported macOS/Windows webviews if those Apple-client platforms are shipped.
- [ ] Record unsupported combinations explicitly; show an actionable media capability error rather than a permanently blank video surface.
- [ ] Create a small release evidence bundle: exact commands/results, workload/run metadata, distributions, resource-count trend, freeze incident traces, and known limits.

Acceptance: the artifact intended for the user passes the declared platform/session matrix, and its build identity matches the evidence. Source tests alone do not qualify packaging or real hardware decoding.

## 8. Proposed acceptance budgets and measurement definitions

These are initial engineering targets for test design, **not measured current performance or a product SLA**. Establish a baseline and revise with evidence for supported hardware/networks.

| Metric | Initial acceptance target | Definition/caveat |
|---|---|---|
| Expected-output stall diagnosis | Within 2–3 seconds | Applicable when media work/response is genuinely pending; ordinary static desktop is exempt |
| Unsuccessful recovery escalation | Full reconnect decision within 15 seconds of a classified stall | Calibrate encoder warmup/round budgets; no indefinite media re-offers |
| Permanent freezes | Zero in the supported 24-hour matrix | Report every unresolved incident and last successful pipeline stage |
| Retained metadata | Always bounded by declared count/byte/age budgets | Include timestamps, retired streams, requests, traces, waiters, and IPC backlog |
| Resource churn | No growing live task/socket/decoder/FD trend over 100 cycles | Allow runtime allocator/cache warmup; verify live ownership, not just RSS |
| Memory soak | Stable plateau after warmup, with a documented maximum workload budget | Compare first/last windows and repeat cycles; do not impose an arbitrary universal RSS threshold |
| Input control | No regression in p95 remote action latency during ordinary video recovery | Measure the remote effect separately from local pointer motion |
| Latency/FPS | No worsening p95/p99 latency or drawn FPS at matched workload/settings | Set numeric baseline-specific budgets after PERF-01; report maxima/outliers |
| Idle recovery work | No repeated FIR/re-offer cycle for a healthy static desktop | Sparse verified health probes, if required, have a documented low overhead |
| Transition completion | Exact requested result, explicitly reported clamp/refusal, or bounded failure | Requires current drawn output; layout/write/assembly alone do not satisfy it |
| Teardown/cancellation | Every phase has a declared finite deadline | Separate short transport/media stop from the bounded physical-restore budget |

Definitions to keep consistent:

- **Assembled FPS:** complete backend access units per interval, not rendered frames.
- **Decoded FPS:** WebCodecs output callbacks per interval for the current epoch.
- **Drawn FPS:** new current picture incorporated in a draw; application proxy for presentation.
- **Decode latency:** submission-to-output for matched timestamps; report unmatched/expired samples.
- **Input response latency:** controlled input dispatch-to-first drawn correlated remote content response, with the dispatch boundary and content correlation documented; current arbitrary next-AU estimate gets a different label.
- **Recovery success:** replacement output reaches the expected healthy stage/epoch; request transmission is a separate counter.
- **Network loss:** sequence holes after the supported repair policy; separate authentication rejects, replay, late packets, damaged AUs, local queue drops, and decoder drops.

## 9. Suggested implementation batches and ownership

Keep batches reviewable. Do not combine all transport, renderer, display, and optimization changes into one patch.

| Batch | Main owner | Scope | Exit condition |
|---|---|---|---|
| A | Shared media/renderer | OBS-01 contract, REN-01/02, continuous no-output watchdog | Renderer errors and same-size reconnect cannot strand video; stage diagnosis exists |
| B | Apple transport | RTP-01, BUF-01, RTP-02, PAD-01, fragment/queue bounds | All reproduced packet/buffer defects have corrected-behavior regressions |
| C | Apple transport + shared media | EPOCH-01/STREAM-01 identity contract | ROC2+ continuation, genuine restart, delayed/replayed old media and 1,000 stream transitions pass |
| D | Session lifecycle | LIFE-01/02, REC-02, IO-01, display ownership | Every failure tears down/joined workers; policy/credentials/cancellation work |
| E | Recovery + UI | REC-01, WATCH-01, SIZE-01, DISPLAY-01 | One bounded recovery/transition coordinator uses drawn progress |
| F | Protocol/control | CTRL-01, RTCP-01, RTP-03, AUTH-01, NET-01 | Verified control/feedback grammar, safe bounded parsing, useful repairs and endpoints |
| G | Renderer/performance | GPU-01, PERF-01/02/03/04 | Matched-workload evidence of lower resource use/latency without correctness loss |
| H | QA/release | QA-01/02/03, remaining SIZE-02 verification | Installed artifact passes deterministic cases and declared 24-hour/platform matrix |

QA-01 regressions and OBS-01 instrumentation accompany the relevant earlier batch rather than waiting for H. SIZE-02's stale-startup-geometry behavior should be resolved before routinely exercising reconnect/quality loops on a real console display.

## 10. Durable offline characterization probes

Review-only harness: [apple-long-session-review-probes](../reviews/apple-long-session-review-probes/README.md). It imports production modules without modifying them and uses synthetic packets/mocked WebCodecs. It requires no Mac, network connection, desktop interaction, or downloaded dependencies when existing caches are present.

**Important:** these are characterization assertions of the current defects. A passing probe means the unwanted behavior was observed, **not** that the bug is fixed. Corrected-behavior tests belong in production suites with the fix; update/retire the matching characterization only after that coverage exists.

Commands from the DeskVNC root:

```sh
cargo test --offline --manifest-path docs/reviews/apple-long-session-review-probes/Cargo.toml --lib
ui/node_modules/.bin/vitest run --config docs/reviews/apple-long-session-review-probes/vitest.config.mts
```

Current results: **59 Rust tests passed** (48 imported module tests plus 11 new characterization probes); **5 new renderer characterization probes passed**. The renderer specialist also ran 42 existing renderer tests successfully; those are a subset of the full 482-test UI result above and must not be added to it as independent coverage.

| Probe | Observed behavior | Task |
|---|---|---|
| Stream 33 | Authenticated replacement ignored permanently at capacity | STREAM-01 |
| Reused retired SSRC | Remains ineligible after a new local epoch | STREAM-01/EPOCH-01 |
| Broken queue prefix | Recovery key picture followed by older delta | BUF-01 |
| Damaged multi-slice timestamp | Surviving IDR tail published as complete key picture | RTP-01 |
| Far sequence gap | One missing packet omitted from loss/NACK range | RTP-02 |
| Configuration sequence | Received config packet reported lost | RTP-02 |
| Wraparound reorder | Received pre-wrap packet skipped/later marked late | RTP-02 |
| Unfinished FU | Accumulation beyond nominal 8 MiB completed-NAL cap | MEM-01 |
| Encrypted RTP padding | Correctly protected padded payload not recovered correctly | PAD-01 |
| Continuing ROC 2 after reset | Next authentic packet rejected | EPOCH-01 |
| Old authenticated replay after reset | Previously rejected replay accepted again | EPOCH-01 |
| Non-IDR recovery after decoder reset | Reaches `decode()` without reconfigure and is discarded | REN-02 |
| Three separated renderer errors | Global failure latch persists through same-size resize/reconnect signal | REN-01 |
| Async decoder error | No independent-picture recovery callback | REN-01/REC-01 |
| Consumed input, zero output | 10,000 unmatched submission timestamps retained | MEM-01/OBS-01 |
| Both configure preferences throw | Created decoder never closed | MEM-01 |

Limits: media payloads are intentionally minimal and do not validate pixel accuracy; some SRTP probes isolate authentication/index state rather than a decodable video picture. The renderer harness calls the real methods with fake platform objects and is not a real hardware decoder. Current configuration-sequence probe tests the implementation's treatment of a configuration-shaped packet; captured valid configurations must also be covered in the corrected production test. Neither harness establishes real macOS feedback efficacy, wire epoch identity, screen-session selection, physical-mode preservation, actual decoder implementation, or measured long-run performance.

## 11. Existing work and source map

- [Existing stream review](../reviews/2026-10-19-apple-stream-review.md): historical findings plus later corrective-pass caveats. Do not read its old Fixed/Done table as current live verification.
- [Resolution stabilization plan](2026-10-20-apple-resolution-stabilization-plan.md): preserves the recent point-aware rollback, queued rollback snapshot, exact request serialization, pending-layout commit, and cache fixes; carries remaining startup/epoch/presentation work.
- [Apple driver](../../crates/apple-core/src/session.rs): handshake, control loop, workers, recovery, resize and teardown.
- [Stream selection](../../crates/apple-core/src/video.rs), [SRTP](../../crates/apple-core/src/srtp.rs), [H.264 assembly](../../crates/apple-core/src/h264.rs), [picture queue](../../crates/apple-core/src/pictures.rs), [RTCP](../../crates/apple-core/src/rtcp.rs): packet and reference-chain correctness.
- [Renderer](../../ui/src/render/WebGLRenderer.ts), [session hook](../../ui/src/hooks/useSession.ts), [session view](../../ui/src/screens/Session.tsx): decode, presentation, reconnect lifetime and UI state.
- [Shell event bridge](../../src-tauri/src/commands/session.rs), [binary framing](../../src-tauri/src/framing.rs), [frame contract](../../src-tauri/FRAME_FORMAT.md): media IPC and queue ownership.
- [Shared reconnect supervisor](../../crates/remote-core/src/reconnect.rs), [media state](../../crates/remote-core/src/apple_media.rs): contracts to reuse/extend rather than duplicate.
- [Local protocol research](../../../iShareScreen/docs/apple_vnc_rfc.md): useful reverse-engineering context with revision/codec-specific uncertainty. Use protocol facts and independent vectors; do not copy incompatible-license reference implementation code into this repository.

All task checkboxes remain open. Completing this review does not claim a freeze fix, a successful live quality transition, or native-client performance parity.
