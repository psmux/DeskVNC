# Performance

How DeskVNCViewer's pixel hot path is measured, what it currently costs, and how
it compares with the budgets in **PRD/13 §3.6**.

> Every number here is reproducible with the commands in [§2](#2-how-to-reproduce).
> Nothing in this document is estimated.

---

## 1. What is measured, and why

The central engineering problem (PRD/01 §3) is that a 1080p RGBA frame is 8.3 MB
and Tauri's binary IPC is slow on WebView2, so the client is built around dirty
rects: decode in Rust, ship only the damaged rectangles. That makes the *decode*
step the thing that has to be fast, because it sits between the socket and the
renderer on every single frame.

So the benchmark suite covers exactly the code on that path:

| Group | What it covers |
|---|---|
| `decode/*` | Every rect decoder, driven through the real public `decode_rect` dispatcher, at 1080p and 4K |
| `convert/*` | `convert_to_rgba` for the canonical format and for the awkward ones (16bpp, 8bpp indexed, non-canonical shifts/maxes). This group lives in `crates/remote-pixel/benches/convert.rs`; every other group is in `crates/vnc-core/benches/decode.rs` |
| `framebuffer/*` | `Framebuffer::apply` for RGBA rects and for overlapping CopyRect |
| `thumbnail/*` | The pure-Rust box downscale for host tiles (PRD/03 §3) |
| `damage/*` | The `Rect::union` coalescing the run loop does per `FramebufferUpdate` |
| `before_after/*` | Each optimised routine against a verbatim copy of its pre-optimisation self, in the same process |

Throughput is reported with criterion's `Throughput::Elements(pixels)`, so
criterion's `Melem/s` reads directly as **MPixels/s** and 1080p and 4K numbers
are directly comparable.

### 1.1 Test content

Decoders are only as fast as the content lets them be, so the wire data is built
from a synthetic desktop rather than noise or a flat fill:

- `synth_desktop`, flat "window" panes, a wallpaper gradient, and text-like
  high-frequency detail. This is the mix that decides whether a real server picks
  solid / palette / RLE / raw tiles.
- `synth_flat`, large solid regions with long horizontal runs, i.e. the content
  a server actually selects RLE and solid subencodings for.

Each benchmark builds genuinely valid wire data with a small encoder for that
format (a real Hextile tile analyser, a real Tight gradient forward filter, real
ZRLE tile packing), **outside the timed loop**. The timed region contains only
the decoder.

### 1.2 Honest caveats

- **The decoders are `async`.** The benchmarks drive them with a one-poll
  executor over an in-memory slice, so no runtime or I/O cost is included. This
  measures decode work, not socket throughput, which is the intent.
- Persistent zlib streams are per-connection state. Benchmarks that need a
  fresh stream construct a new `DecoderState` in criterion's untimed `setup`;
  Tight benchmarks instead set the stream-reset bits in the control byte, which
  is what a real server does.
- These runs were taken on a **shared, actively loaded developer machine**
  (several concurrent build jobs, load average 2-9). Single runs showed swings
  of 2-3x on identical code. Every number in §3 and §4 is therefore the
  **minimum of the lower confidence bound across 3 full repetitions**, which is
  the estimator least contaminated by interference. Treat them as "this hardware
  can do at least this", not as a tight distribution.
- Every routine here allocates its output buffer (a decoded rect really is a
  fresh `Vec`), so a few megabytes of `malloc` + first-touch page faults are
  inside the timed region. That is realistic, it is what the decoder does per
  rect, but it means these benchmarks are partly measuring the allocator, and
  it is a second source of run-to-run variance.
- **Compression ratio is content-dependent.** The synthetic desktop has large
  flat regions, so zlib-family payloads inflate faster here than a photo-heavy
  real desktop would. Read `decode/zlib`, `decode/tight_*` and `decode/zrle_*`
  as an optimistic bound on inflate-limited encodings.

---

## 2. How to reproduce

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cd /path/to/vncviewer

# Full suite (HTML reports land in target/criterion/)
cargo bench -p vnc-core --bench decode

# One group
cargo bench -p vnc-core --bench decode -- 'convert'
cargo bench -p vnc-core --bench decode -- 'before_after'

# Idle RSS + idle CPU with a live session against the mock RFB server
cargo run --release -p vnc-core --example idle_session -- 15

# Client-added input latency through the real session task
cargo run --release -p vnc-core --example input_latency
```

**Measurement machine:** Apple M4 (4 P + 6 E cores), 24 GB, macOS 26.5.2,
rustc 1.97.1, `--release` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 1`).

---

## 3. Results

### 3.1 Decoders

| Encoding | 1080p ms | 1080p MPix/s | 4K ms | 4K MPix/s |
|---|---:|---:|---:|---:|
| Raw (0) | 1.19 | 1745 | 5.01 | 1655 |
| CopyRect (1) | 0.009 µs | n/a | 0.009 µs | n/a |
| Hextile (5) | 1.35 | 1536 | 5.13 | 1617 |
| zlib (6) | 3.27 | 633 | 14.30 | 580 |
| Tight, Fill | 0.21 | 9790 | 0.92 | 9041 |
| Tight, palette (256 colours) | 1.41 | 1474 | 6.12 | 1354 |
| Tight, gradient filter | 7.56 | 274 | 30.36 | 273 |
| Tight, compressed copy | 3.94 | 526 | 16.40 | 506 |
| ZRLE, solid tiles | 0.30 | 6921 | 1.70 | 4875 |
| ZRLE, packed palette (4 colours) | 1.43 | 1446 | 6.23 | 1332 |
| ZRLE, plain RLE | 0.31 | 6762 | 1.67 | 4969 |
| ZRLE, palette RLE | 0.29 | 7061 | 1.67 | 4958 |

Notes:

- **CopyRect** only parses a 4-byte source position; the actual pixel movement
  is `Framebuffer::apply` (see §3.3), so its "throughput" is meaningless and is
  reported as raw time.
- **Tight/gradient** is the slowest decoder by a wide margin, because the
  gradient predictor is serially dependent along a scanline (each pixel needs
  its left neighbour's *reconstructed* value) and therefore cannot be
  vectorised at all.
- **zlib (6)** and **Tight/compressed-copy** are dominated by inflate, not by
  pixel work, see §4.3.

### 3.2 Pixel conversion

| Pixel conversion | 1080p ms | 1080p MPix/s | 4K ms | 4K MPix/s |
|---|---:|---:|---:|---:|
| 32bpp BGRA (canonical fast path) | 0.33 | 6332 | 1.38 | 6014 |
| 16bpp RGB565 | 1.36 | 1520 | 5.35 | 1551 |
| 8bpp indexed + colour map | 0.43 | 4801 | 2.25 | 3693 |
| 32bpp BE, 10-bit channels (generic) | 1.40 | 1482 | 6.43 | 1289 |

The canonical BGRA path is a pure byte swizzle and runs at roughly memory
bandwidth. The other three are now within 3-4x of it, which is about what a
shift-and-mask (or one table lookup) per channel costs; before §5.1 they were
2.5-4.4x slower again than they are here.

### 3.3 Framebuffer, thumbnails, damage

| Framebuffer / misc | 1080p ms | 1080p MPix/s | 4K ms | 4K MPix/s |
|---|---:|---:|---:|---:|
| `Framebuffer::apply`, full RGBA rect | 0.25 | 8215 | 1.19 | 6967 |
| `Framebuffer::apply`, overlapping CopyRect | 0.22 | 9477 | 1.50 | 5538 |
| Thumbnail downscale 1080p -> 480px | 2.61 | 795 |, |, |
| Damage union, 4096 rects | 5.11 µs | 802 Mrect/s |, |, |

---

## 4. Budgets (PRD/13 §3.6)

### 4.1 Verdicts

| Metric | Budget | Measured | Verdict |
|---|---|---|---|
| Decode + apply, 1080p full-frame update | < 12 ms | 7.8 ms worst case (Tight/gradient); every other encoding is under 4.2 ms | **PASS** |
| Client-added input latency | < 16 ms | 50 µs median, 357 µs worst of 200 (vnc-core portion) | **PASS** |
| Idle CPU (connected, static desktop) | < 2 % | 0.00-0.07 % of one core | **PASS** |
| Idle RAM (one session) | < 250 MB | 26 MiB (vnc-core), ~127 MiB whole app | **PASS** |
| Cold start → library visible | < 800 ms | 284 ms median of 4 runs | **PASS** |

**All five budgets pass.** Details for the last three are in §6.

### 4.2 Decode + apply, per encoding

The budget is a *full-frame* 1080p update, so this is one 1920x1080 rect decoded
and applied. `Framebuffer::apply` for a full RGBA rect is the "apply" half.

| Encoding | decode ms | + apply ms | total ms | headroom vs 12 ms |
|---|---:|---:|---:|---:|
| Raw (0) | 1.19 | 0.25 | **1.44** | 8.3x |
| Hextile (5) | 1.35 | 0.25 | **1.60** | 7.5x |
| zlib (6) | 3.27 | 0.25 | **3.53** | 3.4x |
| Tight, Fill | 0.21 | 0.25 | **0.46** | 25.8x |
| Tight, palette (256 colours) | 1.41 | 0.25 | **1.66** | 7.2x |
| Tight, gradient filter | 7.56 | 0.25 | **7.81** | 1.5x |
| Tight, compressed copy | 3.94 | 0.25 | **4.19** | 2.9x |
| ZRLE, solid tiles | 0.30 | 0.25 | **0.55** | 21.7x |
| ZRLE, packed palette (4 colours) | 1.43 | 0.25 | **1.69** | 7.1x |
| ZRLE, plain RLE | 0.31 | 0.25 | **0.56** | 21.5x |
| ZRLE, palette RLE | 0.29 | 0.25 | **0.55** | 22.0x |

### 4.3 Where the remaining time goes, and the one thing left on the table

The three slowest 1080p decoders, Tight/compressed-copy, zlib and
Tight/gradient, all spend the majority of their time inside **zlib inflate**,
not in pixel code. `decode/zlib` inflates 8.3 MB of wire pixels and then runs
the canonical BGRA swizzle: the swizzle is 0.33 ms of a
3.27 ms total, so ~90 % of that decoder is inflate.

**PRD/01 §4 specifies `flate2` with the `zlib-rs` backend. The build was
using the default `miniz_oxide` backend.** This has since been **fixed** in the
workspace manifest:

```toml
flate2 = { version = "1", default-features = false, features = ["zlib-rs"] }
```

Confirmed active with `cargo tree -p vnc-core -e features` (`flate2 feature
"zlib-rs"` → `zlib-rs v0.6.6`, `any_zlib` enabled); `miniz_oxide` remains in
`Cargo.lock` only as an unused optional entry.

### Measured effect of the backend swap

Re-run on an **idle** machine (the §3 baselines were taken under concurrent
build load, so these are compared against the documented baseline values, not
against criterion's `change:` line, which was contaminated by that load):

| Benchmark | miniz_oxide | zlib-rs | speed-up |
|---|---:|---:|---:|
| `decode/zlib` 1080p | 3.27 ms | **2.01 ms** | **1.63x** |
| `decode/tight_copy` 1080p | 3.94 ms | **2.76 ms** | **1.43x** |
| `decode/tight_copy` 4K | 16.40 ms | **12.22 ms** | **1.34x** |
| `decode/tight_gradient` 1080p | 7.56 ms | 7.33 ms | 1.03x |

**Correction to the analysis above:** the claim that all three of the slowest
decoders are inflate-dominated holds for `zlib` and `tight_copy`, but **not**
for `tight_gradient`, swapping the inflate implementation moved it only 3 %,
which shows its cost is the gradient filter itself, not decompression. That is
consistent with §5: the gradient kernel is what responded to optimisation
(8.07 → 6.21 ms), and it remains the worst-case encoding at 7.33 ms against the
12 ms budget (1.6x headroom).


---

## 5. Optimisations

Everything below keeps the public API unchanged, introduces no `unsafe`, and
leaves all vnc-core tests green. Each entry says what the win came from.

Before/after was measured **in the same process** by keeping a verbatim copy of
each routine's pre-optimisation implementation in the benchmark
(`benches/decode.rs`, module `legacy`), so the two are timed on the same machine
under the same conditions. The gradient pair asserts the two kernels produce
byte-identical output on a full 1080p frame before timing them.

| Optimisation | before | after | speed-up |
|---|---:|---:|---:|
| `convert_to_rgba`, canonical BGRA | 0.46 ms | 0.43 ms | **1.05x** |
| `convert_to_rgba`, 16bpp RGB565 | 3.81 ms | 1.50 ms | **2.54x** |
| `convert_to_rgba`, 8bpp indexed | 2.26 ms | 0.51 ms | **4.39x** |
| `convert_to_rgba`, 10-bit channels | 5.45 ms | 1.56 ms | **3.49x** |
| Tight gradient filter | 8.07 ms | 6.21 ms | **1.30x** |
| CopyRect, overlapping | 0.64 ms | 0.23 ms | **2.76x** |

Decoder-level effects of the same changes, at 1080p:

| Benchmark | before | after | speed-up |
|---|---:|---:|---:|
| Tight, gradient filter (decode) | 16.34 ms | 7.56 ms | **2.16x** |
| Tight, compressed copy (decode) | 6.90 ms | 3.94 ms | **1.75x** |
| ZRLE, solid tiles (decode, 4K) | 14.99 ms | 1.70 ms | **8.81x** |
| ZRLE, packed palette (decode, 4K) | 20.09 ms | 6.23 ms | **3.22x** |
| ZRLE, palette RLE (decode, 4K) | 8.25 ms | 1.67 ms | **4.93x** |
| Raw, 8bpp indexed conversion (1080p) | 9.61 ms | 0.43 ms | **22.25x** |

(The decoder-level "before" column is the archived pre-optimisation run. It was
taken under heavier machine load than the "after" column, so read these six as
directional, the same-process pairs above are the reliable ones. The ZRLE rows
are the only evidence available for §5.5, which has no same-process pair because
the tile loop is private.)

### 5.1 `pixel/convert.rs`, `convert_to_rgba{,_mapped}`

The old code had one fast path (canonical 32bpp BGRA) and, for everything else,
a fully scalar per-pixel loop that re-derived every invariant on every pixel:
it re-tested `true_colour`, re-read the shifts and maxes, assembled the wire
pixel byte-by-byte through a loop over `bytes.iter()`, and, worst, performed
**three integer divisions per pixel** inside `scale_channel`.

It is now a set of specialisations chosen once per call:

| Condition | Path |
|---|---|
| 32bpp LE BGRA | `chunks_exact(4)` byte swizzle |
| `!true_colour` | one 256-entry RGBA table built from the colour map, then a single lookup per pixel |
| all channel maxes == 255 | shift + mask only, `scale_channel(c, 255) == c`, so the division disappears entirely |
| maxes < 1024 | three stack lookup tables built once per call, replacing 3 divisions/pixel with 3 loads |
| anything else | the original scalar fallback |

Endian assembly is specialised on `(bytes_per_pixel, big_endian)` *outside* the
loop, so each variant compiles to a straight `chunks_exact` walk with no
per-pixel branching and no bounds checks.

This is the change that matters most in practice: the **Low quality preset
negotiates `Palette256`** (8bpp indexed), so the indexed path is a shipping
code path, not a curiosity, and it was the slowest one.

The LUT is skipped below 512 pixels, where zeroing the tables would cost more
than the divisions saved (Hextile calls this function once per 16x16 raw tile).

A new test, `fast_paths_match_scalar_reference`, asserts every path is
byte-identical to `pixel_to_rgba` across nine awkward pixel formats at sizes
either side of the LUT threshold.

### 5.2 `encodings/tight.rs`, gradient filter

`undo_gradient` handled compact and non-compact TPIXELs in one loop. For the
compact case (32bpp/depth24, i.e. almost every server) the per-channel
`rem_euclid(max + 1)` and `scale_channel(v, max)` both went through values LLVM
could only sometimes constant-fold, and every pixel re-indexed two `Vec<[i32;3]>`
row buffers with bounds checks.

Split into `undo_gradient_compact` and `undo_gradient_generic`. The compact
kernel knows `max == 255`, so `rem_euclid(256)` becomes `u8::wrapping_add` and
the output scaling vanishes. The previous row is carried in one reused
`Vec<[u8; 3]>` updated in place instead of two swapped buffers, and the row walk
is three zipped `chunks_exact` iterators, so there are no bounds checks left.

The benchmark asserts the two kernels produce byte-identical output on a full
1080p frame before timing them, and `gradient_filter_round_trips` covers it as a
unit test.

### 5.3 `encodings/tight.rs`, `FILTER_COPY`

The copy filter called `tpixel_to_rgba` per pixel, which re-evaluated
`pf.is_compact_3byte()` (five field comparisons) on every pixel. Hoisted: the
compact case is now a `chunks_exact(3)` → `chunks_exact_mut(4)` widening copy,
and the non-compact case delegates to `convert_to_rgba_mapped`, which is exactly
equivalent and already specialised.

### 5.4 `pixel/framebuffer.rs`, `copy_rect`

CopyRect allocated a `w * h * 4` temporary, copied the source region into it,
then copied it back out, two full passes over the region plus a heap
allocation, on what is usually a near-full-screen scroll.

`slice::copy_within` is a `memmove`, so overlap *within* a row pair is already
safe; only the row visiting order matters. Copying rows bottom-up when the
destination is below the source (and top-down otherwise) is overlap-correct with
no temporary at all. `copy_rect_overlapping_rows_both_directions` covers both
directions.

### 5.5 `encodings/zrle.rs`, per-tile allocations

`decode_tile` allocated a fresh tile buffer (16 KB), a palette `Vec` and a wire
payload `Vec` **per tile**. A 1080p ZRLE rect is 510 tiles and a 4K rect is
2040, so a single full-frame update was doing thousands of allocate/free pairs.

All three now live in a per-rect `TileScratch`. The tile buffer only ever grows
and is never re-zeroed between tiles (every subencoding writes all of it before
it is read), and `read_exact_into` fills a caller-owned buffer instead of
returning a fresh `Vec`. The packed-palette inner loop also copies the palette
into a fixed 16-entry array so the index bound check folds away after the
explicit range test.

`multi_tile_mixed_subencodings` decodes a 130x70 rect spanning six tiles of
three different sizes, cycling raw / solid / packed-palette / palette-RLE, and
compares the whole buffer, a stale byte anywhere in the reused scratch shows up
as a wrong pixel.

### 5.6 `pixel/framebuffer.rs`, `opaque_black`

`vec![0; n*4]` followed by a loop writing every fourth byte became
`[0, 0, 0, 255].repeat(n)`, which fills by doubling `memcpy`. This is off the
per-frame path (it runs on `Framebuffer::new`/`resize` only) so no speed-up is
claimed for it; it is simply less code.

### 5.7 Tried and reverted: `pixel/thumbnail.rs`

The box downscale looked like an easy win, two `u64` divisions per *output*
pixel that never change between rows, and four bounds-checked indexes per
*source* pixel. Hoisting the column boxes into a precomputed table and replacing
the inner loop with a `chunks_exact(4)` walk over `u32` accumulators (segmented
so they cannot overflow) was implemented, tested and benchmarked.

It measured **1.05x**. The box for a 1080p -> 480px downscale is only 4x4
pixels, so the hoisted divisions were already amortised over 16 source reads,
and the loop was memory-bound rather than bounds-check-bound. A 5% gain did not
justify a segmented accumulator loop on a routine that (see below) the shipping
app does not even call, so **the change was reverted** and `thumbnail.rs` is
byte-for-byte its original self.

Worth recording for whoever looks next: the shipping thumbnail path does not go
through this function at all. The session renderer posts raw RGBA to
`capture_thumbnail`, and `vnc_store::save_thumbnail` does the downscale with
SIMD `fast_image_resize` (PRD/01 §4). `vnc_core::pixel::downscale_rgba` is only
reachable via `Framebuffer::thumbnail_rgba`, which nothing in the app
constructs. If it ever becomes hot, port it to `fast_image_resize` rather than
hand-tuning the box filter.


---

## 6. Memory, input latency and startup

### 6.0 Client-added input latency

`crates/vnc-core/examples/input_latency.rs` measures the part of the input path
this crate owns: from handing a `ClientCommand::Pointer` to the `SessionHandle`
until the encoded PointerEvent has been read off the socket by the server. That
covers the command channel, the run loop's `select` arm, message encoding and
the socket write. It excludes the OS event tap, the webview and the Tauri IPC
hop, which live in `vnc-input-capture`, `ui/` and `src-tauri/`.

```
client-added input latency over 200 samples
  min        37.3 µs
  median     49.7 µs
  p95        90.0 µs
  p99       191.0 µs
  max       356.7 µs
```

Against a 16 ms budget that is **~320x of headroom at the median and 45x at the
worst sample**, and the number is an over-estimate because detection polls the
mock's recorded-message log (an O(n) scan) inside the timed window. vnc-core is
not where input latency will be lost; the remaining ~15.6 ms of budget belongs
to the capture and IPC layers.

### 6.1 Idle session (vnc-core only)

`crates/vnc-core/examples/idle_session.rs` drives a real `Session` against the
integration-test mock RFB server over a real loopback socket: full handshake,
one 1080p full-frame paint, then 400 further small rects cycling Raw / zlib /
ZRLE / Tight / Hextile so every decoder and all six persistent zlib streams are
genuinely allocated, then a quiet idle window.

```
baseline RSS (process started, no session):      2.1 MiB
after connect + 1080p full frame:               26.1 MiB
after 400 further updates:                      26.3 MiB
after 15s idle:                                 26.3 MiB
idle CPU:                                        0.07 % of one core (0.01s over 15.3s)
growth during idle:                             +0.0 MiB
```

Zero growth across 400 updates is the answer to "do decoder scratch buffers grow
monotonically": they do not.

- `TileScratch` (ZRLE) is **per rect**, it is dropped with the rect, so it
  cannot accumulate across a session. Hoisting it into `DecoderState` would save
  three allocations per rect versus thousands per rect before this change; that
  is not worth threading `DecoderState` through the decoder signatures.
- The six persistent `flate2::Decompress` streams are fixed-size (32 KB window
  each) and are the only genuinely long-lived decoder state.
- `ZlibStream::decompress` sizes its output from a server-derived hint that is
  clamped by `MAX_INFLATED_LEN`, and the buffer is per call.

### 6.2 Does the framebuffer double-buffer?

No. `pixel::Framebuffer` is **not instantiated anywhere in the shipping path**, the run loop decodes rects and hands them straight to the Tauri shell, which
frames them as binary and pushes them to the WebGL2 renderer (PRD/01 §3.2). The
only full-resolution image lives in the webview's GL texture. `Framebuffer` is a
library facility for the native thumbnail path (PRD/03 §3) and for the
integration tests.

So there is no Rust-side double buffer to remove. Adding one would cost
8.3 MB per 1080p session (33 MB at 4K) for no benefit unless thumbnails become a
per-session background job.

### 6.3 Whole application

Measured on the release binary with the library screen open and no session:

```
target/release/deskvncviewer, library visible, no session:  101 MiB RSS
```

That is the Tauri shell plus WKWebView. Adding the 26 MiB measured for a live
1080p session gives roughly **127 MiB for one idle session**, against a 250 MB
budget.

### 6.4 Cold start

Timed from `execve` to the first `discover_start` reaching the backend, which
the Library screen issues on mount, i.e. the library is rendered and running.
Four consecutive runs, each process killed after measuring:

| run | first backend log | library visible |
|---|---:|---:|
| 1 | 96 ms | 270 ms |
| 2 | 120 ms | 288 ms |
| 3 | 109 ms | 280 ms |
| 4 | 136 ms | 315 ms |

**Median 284 ms** against an 800 ms budget. These are warm starts (the binary
and its frameworks are in the page cache); a genuinely cold first-boot start
will be slower, so the margin is smaller than 2.8x in the worst case.

### 6.5 One memory risk worth flagging (not in my scope to fix)

`session/run_loop.rs::handle_framebuffer_update` accumulates **every** decoded
rect of one `FramebufferUpdate` into a `Vec<DecodedRect>` before emitting a
single coalesced event. That batching is required by PRD/01 §3.2 (present once
per update, never per rect), and it is why a full-frame update transiently holds
one framebuffer's worth of RGBA (8.3 MB at 1080p, 33 MB at 4K).

The rect *count* is a `u16` and each rect is bounds-checked against the
framebuffer, but there is no cap on the **total** decoded bytes accumulated for
one update. A hostile server can legally send 65535 rects that each cover the
whole screen, which is ~544 GB of `RectPayload::Rgba`, an out-of-memory kill
rather than a protocol error.

Suggested fix (owner: `session/`): track the accumulated payload bytes and, past
a threshold of a few framebuffers' worth, either emit the batch early or fail
the connection with a protocol error. It costs one counter in the existing loop.


---

## 7. What was deliberately *not* optimised

- **`unsafe`.** Not used anywhere, by design. A malicious server is the threat
  model for every one of these decoders, so all the speed-ups here come from
  giving LLVM the shape it needs (`chunks_exact` walks, hoisted invariants,
  provably in-range table indices) rather than from removing checks.
- **SIMD intrinsics.** The remaining hot loops are already memory-bound or
  auto-vectorised; hand-written NEON/AVX would add per-architecture code paths
  and a second correctness surface for single-digit gains.
- **`decode_jpeg_to_rgba`.** In the shipping path JPEG rects are handed to the
  webview as `RectPayload::Jpeg` and decoded on the GPU
  (`createImageBitmap`), so the Rust software decoder only runs for thumbnails.
  Optimising `zune-jpeg`'s output normalisation would not move any budget.
- **The per-rect output `Vec`.** Every decoder allocates its `RectPayload::Rgba`
  buffer, and at 1080p that is an 8.3 MB allocation whose first touch is a
  string of page faults. Pooling it would be a real win, but `RectPayload` is
  the integration contract with the Tauri shell (`types.rs` is explicitly "treat
  changes here as API changes"), so removing the allocation means changing the
  public API, which this task forbids. The *inner* allocations, which were free
  to fix, are gone (§5.5).
- **`RectPayload::Rgba` copies into the framing buffer.** That lives in
  `src-tauri/src/framing.rs`, which is owned by another agent.
- **The `RRE`/`CoRRE` decoders.** Effectively dead on modern servers; they are
  correct and bounded, and no server that matters negotiates them.
- **`Rect::union` damage coalescing.** Already ~800 M rects/s over 4096 rects
  (5.1 µs for a pathological 4096-rect update), against a 12 ms budget. Nothing
  to win.
- **`pixel/thumbnail.rs`.** Optimised, measured at 1.05x, and reverted, see
  §5.7.
