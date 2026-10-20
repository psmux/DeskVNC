# Apple protocol review probes (temporary harness)

These probes were written during the read-only review of the Apple driver
(`../2026-10-19-apple-stream-review.md`). They load the production modules
directly and assert the **desired corrected behaviour**, so they are expected
to be RED until the corresponding finding is fixed.

They are a review aid, not a CI suite. As each finding is fixed, the equivalent
test is migrated into the production crate's own test module
(`crates/apple-core/src/h264.rs`, `crates/apple-core/src/srtp.rs`,
`ui/src/render/WebGLRenderer.apple.test.ts`) and this folder is retired.

Run:

```sh
cargo test --manifest-path Cargo.toml
../ui/node_modules/.bin/vitest run --config vitest.config.mts
```

Neither harness connects to a Mac, opens a socket, or touches the desktop.
