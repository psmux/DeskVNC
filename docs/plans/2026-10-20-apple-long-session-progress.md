# Apple long-session reliability: progress against the task list

Companion to [the task list](2026-10-20-apple-long-session-reliability-tasklist.md).
That document has 32 task groups and 261 items; this one records which of them
this pass changed, with the commit and the production test that now guards it.

Nothing here was verified against a Mac, and no long session was run. A fixed
item below means its reproduced defect has a corrected-behaviour regression in
the production suite, not that the pipeline has been qualified.

## Fixed, with regressions

| Task | Change | Commit | Test |
|---|---|---|---|
| BUF-01 | A recovered chain discards the stale prefix and keeps only the picture's successors | `3d8a7cd` | `recovery_discards_the_deltas_queued_before_the_independent_picture` |
| PAD-01 | RTP padding is counted after decryption, so protected padding round-trips and malformed counts do not rewind the index | `3c6bd28` | `padding_is_removed_from_the_payload`, `malformed_padding_is_rejected_without_rewinding_the_stream` |
| RTP-01 | A picture that lost a packet refuses its surviving tail until a different picture arrives | `4f71327` | `the_surviving_tail_of_a_damaged_picture_is_not_published` |
| MEM-01 (fragment) | The access-unit cap applies while a fragment grows, not after it completes | `e6fb951` | `an_unfinished_fragment_cannot_grow_past_the_access_unit_cap` |
| RTP-02 | Configuration packets are ordered in the media sequence space; a far gap counts every missing packet; expiry picks the nearest packet across the 65535 to 0 wrap | `0ee9bf9` | `a_configuration_packet_does_not_leave_a_hole_in_the_sequence`, `every_packet_of_a_far_gap_is_asked_for`, `expiry_takes_the_next_packet_across_the_sequence_wrap` |
| REN-02 | A decoder reset by a backlog drop is rebuilt and reconfigured instead of being handed a picture it cannot decode | `40a59c6` | `reconfigures a decoder that a backlog reset left unconfigured` |
| REN-01 (policy) | Failures are consecutive; healthy output clears them; a new attempt resets transient state; a decoder error asks for one fresh picture at the shared rate limit | `1bf645a` | `does not latch a failure that healthy output has recovered from`, `clears transient decoder state when a new attempt begins`, `asks for a fresh picture when a decoder fails` |
| MEM-01 (renderer) | Unmatched timing samples are bounded by count and age; a decoder whose configuration was refused is closed | `abfce90` | `bounds the timestamps of pictures that never come back`, `closes a decoder whose configuration was refused` |
| STREAM-01 | The stream table evicts the longest-silent inactive entry instead of refusing every SSRC after thirty two; a replaced SSRC is eligible again only under a newer generation, with its replay window kept | `dcf7351` | `an_encoder_replacement_beyond_the_stream_limit_is_adopted`, `a_replaced_stream_can_be_adopted_again_after_a_new_stream_is_asked_for` |
| RTCP-01 (sequence) | Every new FIR command gets the next number for its sender and target pair; the session seeds it randomly | `b4d5779` | `a_new_fir_command_carries_a_new_sequence_number` |
| DISPLAY-01 (safety) | A second display request waits its turn instead of replacing the reply receiver; a closed reply is a typed failure, not a panic | `3ccf608` | none offline: the control loop needs the fake server |
| REC-02 (backoff) | The wait doubles per consecutive failure up to eight seconds and restarts only after a minute of uptime | `49c4021` | `repeated_failures_back_off_and_a_stable_session_starts_over` |
| LIFE-02 (outcome) | A dead video or publisher worker ends the attempt with an error instead of looking like a user stop | `f471112` | none offline: the control loop needs the fake server |

## Started, not finished

- **REN-01.** The latch and the attempt boundary are fixed. Typed, rate-limited
  error classes (configuration, decode, output timeout) and the hardware to
  software policy still need the shared recovery contract from OBS-01.
- **MEM-01.** The fragment cap, the timing bound and the leaked decoder are
  fixed. Per-queue byte and age budgets for pictures and IPC, and coalescing
  the command channel, are not.
- **RTCP-01.** Sequence identity is fixed. Which feedback form this macOS
  honours, receiver report contents, and RTT remain unmeasured.
- **REC-02.** Backoff and the stable-uptime reset are fixed. Credential
  retention across retries, failure classification, and reusing the shared
  supervisor contract are not.
- **LIFE-02.** The outcome is now distinguishable. Typed failure reasons and
  joining the workers (LIFE-01) are not.
- **DISPLAY-01.** Serialization and the panic are fixed. Per-request identity,
  non-blocking admission, and applying or restoring exact modes are not.

## Not started, and what each needs

| Tasks | Why they are blocked |
|---|---|
| OBS-01, SIZE-01, EPOCH-01 | One contract change: an attempt, epoch and transaction identity carried through the driver, binary framing, renderer and acknowledgement path. Doing one of them alone would add a second, conflicting identity. |
| REC-01, WATCH-01 | Needs stage-level progress (OBS-01) to distinguish idle, decoder stall and presentation stall, plus one recovery owner shared with resize and recovery. |
| LIFE-01 | An owned worker group with cancellation and bounded joins; it touches every exit of the session loop. |
| RTP-03 | A repair window in front of RTP-01's abandonment policy, with measured reorder and RTT evidence. |
| CTRL-01, IO-01, AUTH-01 | Bounded incremental framing, establishment deadlines, and mutual-proof enforcement need captured wire grammar and vectors before the parsers change. |
| NET-01 | Endpoint policy and dual stack need live qualification; the fixed 5900/5901 bind is already reported as a conflict. |
| GPU-01, PERF-01..04 | Performance work needs the measurement harness from PERF-01 first. |
| QA-01..03 | A deterministic fake server, then 2/8/24 hour soaks on an isolated Mac, then installed-artifact qualification. |
| SIZE-02 | The startup descriptor question is recorded in the resolution plan; it needs a controlled capture. |

## State of the evidence

- 123 `apple-core` tests and 488 UI tests pass, with `cargo fmt --check`,
  clippy `-D warnings` and `tsc`.
- The eight resolution probes still pass.
- The characterization probes in
  `../reviews/apple-long-session-review-probes` were written against `abfaecb`
  and assert the defects as they were then. Some of them now fail because the
  defects are fixed; that is the harness doing its job as a historical
  characterization, and the corrected behaviour lives in the production tests
  listed above. Do not read a green probe as a fix, or a red one as a
  regression.
- No Mac was contacted, no session was resumed, and the installed AppImage was
  not changed by this pass.
