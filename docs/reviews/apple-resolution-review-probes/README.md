# Apple resolution audit probes

Audit target: `6933f0d`, 2026-10-20.

These probes assert the behaviour the audit asked for, against the real
production helpers. They were written RED against `6933f0d` (4 of 5 Rust and
all 3 UI probes failed) and are GREEN after the fixes in
`../../plans/2026-10-20-apple-resolution-stabilization-plan.md`. They stay
outside the normal suite on purpose: they are the audit's acceptance record,
and the same requirements also live in the crates' and the UI's own tests.
They do not connect to a Mac, send input, change a display, modify application
storage, restart an app, or install a binary.

Run from the DeskVNC repository root:

```sh
python3 docs/reviews/apple-resolution-review-probes/run_rust.py
ui/node_modules/.bin/vitest run \
  --config docs/reviews/apple-resolution-review-probes/vitest.config.mts
```

The Rust script extracts the actual pure resize/descriptor helpers from
`crates/apple-core/src/session.rs`, compiles them in a temporary directory,
and removes the temporary binary afterwards. It needs the installed `rustc`,
not another Cargo dependency tree. The tests do not reimplement those helpers.
If the helpers are renamed or moved, update the extraction boundaries before
interpreting a compilation failure as a regression.

The UI harness imports the real renderer and geometry-cache module, with a
fake VideoDecoder and GL allocation functions. It does not run a GUI or prove
actual decoded content.

## Results

At `6933f0d`: **4 Rust failing, 1 passing; 3 UI failing**. After the fixes:
**5 Rust passing, 3 UI passing**.

The failures reproduced, and now guard against:

- 1800x1170 requested and 1800x1169 acknowledged, with unchanged desktop
  points, triggering a rollback.
- A logical desktop shrink hidden by a pixel-only comparison.
- A queued round reusing the first round's rollback snapshot instead of the
  geometry the session really has.
- A 1600x1200 intent serialized as an 1800x1170 mode, so the reported request
  and the wire disagreed.
- A confirmed 2700x1754 layout leaving the renderer at 3600x2338.
- An unrelated 1600x1200 picture being stretched across a Retina desktop
  instead of being surfaced as a mismatch.
- A reduced-stream layout with unchanged points overwriting the cached native
  pixels.

The passing Rust probe is the one that establishes the descriptor already
advertised a bound covering its first mode, which is why the earlier
"the cap prevented growth" explanation was withdrawn.

These are narrow regression reproductions, not a full protocol test. In
particular, they do not validate which `0x451` acknowledges which request, and
they cannot show why a particular macOS host chose a fallback. The remaining
work is listed in the plan: startup descriptor behaviour, presentation
acknowledgement, transaction logging, a fake-session transaction test, and an
authorized live matrix.

The normal suites pass at both targets (103 apple-core and 480 UI tests at the
audit target; 107 and 482 after the fixes). Their earlier success did not cover
any of the eight cases above.
