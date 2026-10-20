# Apple long-session review characterization probes

Reviewed source: `abfaecbc5f0ced4b8673b97fe3b97d5a40b0c627`, 2026-10-20.

Companion to the [detailed reliability/performance task list](../../plans/2026-10-20-apple-long-session-reliability-tasklist.md).

These tests deliberately assert observed current defects. **Passing confirms unwanted behavior; it does not establish a fix.** When fixing an issue, add a corrected-behavior regression in the production test suite, then update or retire its characterization here with an explanation. The existing imported tests still assert their ordinary intended behavior.

The Rust harness includes unchanged production H.264, SRTP, picture-buffer, RTCP and stream-selection modules by relative paths. It is an isolated Cargo workspace, outside the normal CI test suite. The renderer harness imports the real renderer with synthetic platform objects. No credentials, saved hosts, desktop screenshots, live sockets, or Mac connections are used. Existing cached dependencies are sufficient for the commands below.

Run from the DeskVNC root:

```sh
cargo test --offline --manifest-path docs/reviews/apple-long-session-review-probes/Cargo.toml --lib
ui/node_modules/.bin/vitest run --config docs/reviews/apple-long-session-review-probes/vitest.config.mts
```

At the reviewed revision: **59 Rust tests passed** (48 imported existing module tests, 11 fresh characterizations) and **5 renderer characterizations passed**.

**After the first round of fixes** (see
[the progress document](../../plans/2026-10-20-apple-long-session-progress.md)),
eight Rust characterizations are marked `#[ignore]` because the behaviour they
assert no longer exists. Their corrected-behaviour regressions are in the
production suite, named in that document. The ignored tests are kept as the
record of what `abfaecb` did; a green run here no longer means "the defects are
present", and a red one would mean a fix regressed.

Rust cases cover permanent stream-33 rejection, retired-SSRC reuse, stale deltas after recovery keyframes, partial IDR publication after loss, an off-by-one missing count, configuration sequence accounting, numeric order across RTP wrap, unbounded unfinished FU accumulation, encrypted RTP padding, ROC-2 continuation after reset, and replay readmission after reset.

Renderer cases cover unconfigured decode after backlog reset with a non-IDR independent picture, accumulating errors plus a same-size reset signal retaining the failure latch, missing recovery callback after async decoder error, unbounded unmatched timestamp metadata, and unclosed decoder ownership after failed configuration.

The tests are narrow reproductions, not a protocol/codec conformance or end-to-end hardware test. Minimal NAL/configuration-shaped payloads isolate control flow; the ROC tests isolate authenticated packet indexes rather than decoded pixels. The configuration sequence case must be complemented with valid captured configurations when fixed. Three reorder cases use short sleeps because the current source owns its clock; production regression coverage should inject time where possible.

See task-list section 10 for the case-to-task mapping and its broader verification limitations. Neither a green harness nor passing application unit tests establish long-session readiness.
