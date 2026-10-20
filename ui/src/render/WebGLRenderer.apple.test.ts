import { afterEach, expect, it, vi } from "vitest";
import { WebGLRenderer } from "./WebGLRenderer";
import { RectFormat } from "./frameProtocol";

afterEach(() => vi.unstubAllGlobals());

it("keeps only the latest decoded continuous picture until the next paint", () => {
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
  });
  const upload = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null,
    fbWidth: 3600, fbHeight: 2338,
    uploadVideoFrame: upload,
  });
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  const first = { displayWidth: 3600, displayHeight: 2338, close: vi.fn() };
  const newest = { displayWidth: 3600, displayHeight: 2338, close: vi.fn() };
  output(first);
  output(newest);
  expect(first.close).toHaveBeenCalledOnce();
  expect(newest.close).not.toHaveBeenCalled();
  expect(renderer.latestVideo.frame).toBe(newest);
  expect(upload).not.toHaveBeenCalled();
});

it("feeds continuous AVC without waiting for output and converts Annex-B lengths", async () => {
  vi.stubGlobal("VideoDecoder", class {});
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const decode = vi.fn();
  const wait = vi.fn(() => { throw new Error("continuous video must not wait"); });
  // No GL is used by chunk submission; output/upload is separately driven
  // by WebCodecs. A decoder retaining its first picture must not block the
  // second submission (GStreamer's normal one-frame delay).
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false,
    continuousH264: true,
    h264: new Map([[0, { avc: true, timestamp: 0, submitted: new Map(), decoder: { state: "configured", decode } }]]),
    awaitH264Frame: wait,
  });
  const rect = {
    h264Key: true,
    payload: new Uint8Array([0, 0, 0, 1, 0x65, 0xaa, 0, 0, 1, 0x61, 0xbb]),
  };
  await renderer.decodeH264(rect);
  await renderer.decodeH264({ ...rect, h264Key: false });
  expect(wait).not.toHaveBeenCalled();
  expect(decode).toHaveBeenCalledTimes(2);
  expect(Array.from(decode.mock.calls[0][0].data)).toEqual([
    0, 0, 0, 2, 0x65, 0xaa, 0, 0, 0, 2, 0x61, 0xbb,
  ]);
});

/** A renderer with texture allocation but no real browser/GPU. */
function sizedDecoderHarness(extra: Record<string, unknown> = {}) {
  return decoderHarness({
    fbWidth: 3600, fbHeight: 2338, sawFrame: true,
    mediaPictureWidth: 3600, mediaPictureHeight: 2338,
    mediaDecoded: 0, mediaMismatches: 0, mediaLatencyDropped: 0,
    pendingLayout: null, layoutMismatchRun: 0,
    frameTex: {}, scratchTex: {},
    gl: {
      bindTexture: vi.fn(), texImage2D: vi.fn(), texSubImage2D: vi.fn(),
      TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4,
    },
    clearViewRect: vi.fn(), markDirty: vi.fn(),
    ...extra,
  });
}

it("does not let a previous H.264 rectangle override a normal framebuffer resize", () => {
  const renderer = sizedDecoderHarness({
    continuousH264: false, mediaPictureWidth: 320, mediaPictureHeight: 240,
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.getRemoteSize()).toEqual({ width: 1920, height: 1080 });
});

it("scales a picture that disagrees with the confirmed layout instead of resizing it", () => {
  // The Mac's encoder does not always follow the layout it reports: a stream
  // asked for 3600x2338 arrived at 1800x1168. Adopting that changed the
  // desktop's size mid session, which reads as the view zooming.
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  const ctx = renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  for (const [w, h] of [[1800, 1168], [2700, 1754]]) {
    output({ displayWidth: w, displayHeight: h, timestamp: 1, close: vi.fn() });
    const pending = renderer.latestVideo!;
    renderer.latestVideo = null;
    expect(pending.ctx.stretch).toBe(true);
    expect(pending.ctx.w).toBe(3600);
    expect(pending.ctx.h).toBe(2338);
    expect(renderer.getRemoteSize()).toEqual({ width: 3600, height: 2338 });
  }
  // A picture that matches the layout is uploaded at its own size.
  output({ displayWidth: 3600, displayHeight: 2338, timestamp: 2, close: vi.fn() });
  const pending = renderer.latestVideo!;
  expect(pending.ctx.stretch).toBe(false);
  expect(renderer.getRemoteSize()).toEqual({ width: 3600, height: 2338 });
  expect(renderer.h264.get(0)).toBe(ctx);
});

it("accepts the stream's own desktop after it keeps disagreeing with the layout", () => {
  // A permanently disagreeing stream is the real content; refusing it for
  // ever would leave the pane frozen on a picture from an older geometry.
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  for (let i = 0; i < 19; i++) {
    output({ displayWidth: 1600, displayHeight: 1200, timestamp: i, close: vi.fn() });
  }
  expect(renderer.getRemoteSize()).toEqual({ width: 3600, height: 2338 });
  output({ displayWidth: 1600, displayHeight: 1200, timestamp: 99, close: vi.fn() });
  expect(renderer.getRemoteSize()).toEqual({ width: 1600, height: 1200 });
  expect(renderer.latestVideo?.ctx.stretch).toBe(false);
});

it("does not latch a failure that healthy output has recovered from", () => {
  // Three errors spread across a long healthy session used to add up until
  // video was disabled for the rest of the renderer's life.
  let callbacks: { error: (e: Error) => void; output: (f: unknown) => void } | null = null;
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(c: { error: (e: Error) => void; output: (f: unknown) => void }) { callbacks = c; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  for (let round = 0; round < 3; round++) {
    renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
    callbacks!.error(new Error("decoder hiccup"));
    expect(renderer.h264Failures).toBe(1);
    // A fresh decoder produces a picture, which is what recovery looks like.
    renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
    callbacks!.output({ displayWidth: 3600, displayHeight: 2338, timestamp: 1, close: vi.fn() });
    expect(renderer.h264Failures).toBe(0);
  }
  expect(renderer.h264Failed).toBe(false);
});

it("clears transient decoder state when a new attempt begins", () => {
  // A reconnect can arrive at the same size, so the renderer must be told
  // about the new attempt explicitly or a failed decoder stays latched.
  const renderer = sizedDecoderHarness({
    h264Failed: true, h264Failures: 3, h264Behind: true, closeAllH264: vi.fn(),
  });
  renderer.beginConnectionAttempt();
  expect(renderer.h264Failed).toBe(false);
  expect(renderer.h264Failures).toBe(0);
  expect(renderer.h264Behind).toBe(false);
  // A platform with no decoder at all does not become able because of a
  // reconnect, so that fact is kept.
  const unsupported = sizedDecoderHarness({
    h264Failed: true, h264Unsupported: true, closeAllH264: vi.fn(),
  });
  unsupported.beginConnectionAttempt();
  expect(unsupported.h264Failed).toBe(true);
});

it("asks for a fresh picture when a decoder fails", () => {
  let error: (e: Error) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { error: typeof error }) { error = callbacks.error; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const behind = vi.fn();
  const renderer = sizedDecoderHarness({ onDecoderBehind: behind, behindAskedAt: 0 });
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  error(new Error("decode failed"));
  expect(behind).toHaveBeenCalledOnce();
  // A burst of errors must not become a burst of requests.
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  error(new Error("decode failed again"));
  expect(behind).toHaveBeenCalledOnce();
});

it("bounds the timestamps of pictures that never come back", async () => {
  // A decoder that consumes input and never produces output used to keep one
  // timing entry per submitted chunk, so a stall grew the map forever.
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    decodeQueueSize = 0;
    configure() {}
    decode() {}
    close() { this.state = "closed"; }
  });
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const renderer = sizedDecoderHarness();
  await renderer.decodeH264({
    h264Context: 0, h264Key: true, h264Reset: true,
    payload: new Uint8Array([0, 0, 0, 1, 0x65, 0xaa]),
  });
  for (let i = 0; i < 500; i++) {
    await renderer.decodeH264({
      h264Context: 0, h264Key: false,
      payload: new Uint8Array([0, 0, 0, 1, 0x61, 0xbb]),
    });
  }
  const ctx = renderer.h264.get(0)!;
  expect(ctx.submitted.size).toBeLessThanOrEqual(128);
  expect(renderer.mediaLatencyDropped).toBeGreaterThan(0);
});

it("closes a decoder whose configuration was refused", () => {
  let closed = 0;
  vi.stubGlobal("VideoDecoder", class {
    state = "unconfigured";
    configure() { throw new Error("no codec"); }
    close() { closed += 1; this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  const ctx = renderer.createH264(
    { x: 0, y: 0, w: 3600, h: 2338 }, 0,
    new Uint8Array([0, 0, 0, 1, 0x67, 0x64, 0, 0x1f, 0, 0, 0, 1, 0x68, 0xee]),
  );
  expect(ctx).toBeNull();
  expect(closed).toBe(1);
});

it("reconfigures a decoder that a backlog reset left unconfigured", () => {
  // WebCodecs reset() clears the configuration. An independent non-IDR
  // picture then reached decode() without configure(), was refused, and the
  // context was closed: the picture was lost even though it could start a
  // decoder.
  let decoders = 0;
  let configureCalls = 0;
  let decodeCalls = 0;
  let decodeThrows = 0;
  vi.stubGlobal("VideoDecoder", class {
    state = "unconfigured";
    decodeQueueSize = 0;
    configured = false;
    constructor(_callbacks: unknown) { decoders += 1; }
    configure() { this.configured = true; this.state = "configured"; configureCalls += 1; }
    reset() { this.configured = false; this.state = "unconfigured"; }
    decode() {
      decodeCalls += 1;
      if (!this.configured) { decodeThrows += 1; throw new Error("unconfigured"); }
    }
    close() { this.state = "closed"; }
  });
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const renderer = sizedDecoderHarness();
  const key = new Uint8Array([0, 0, 0, 1, 0x65, 0xaa]);
  const delta = new Uint8Array([0, 0, 0, 1, 0x61, 0xbb]);
  return (async () => {
    await renderer.decodeH264({ h264Context: 0, h264Key: true, h264Reset: true, payload: key });
    expect(decoders).toBe(1);
    // Fill the decoder queue so the next picture drops the backlog and
    // resets the decoder.
    const ctx = renderer.h264.get(0)!;
    ctx.decoder.decodeQueueSize = 4;
    await renderer.decodeH264({ h264Context: 0, h264Key: false, payload: delta });
    expect(ctx.decoder.state).toBe("unconfigured");
    expect(decodeThrows).toBe(0);
    // An independent non-IDR picture arrives as the recovery picture.
    await renderer.decodeH264({ h264Context: 0, h264Key: true, h264Reset: false, payload: key });
    expect(decoders).toBe(2);
    expect(configureCalls).toBe(2);
    expect(decodeThrows).toBe(0);
    expect(decodeCalls).toBe(2);
    expect(renderer.h264.get(0)).toBeDefined();
  })();
});

it("lets the first picture define the size when no layout is known yet", () => {
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness({ fbWidth: 0, fbHeight: 0 });
  renderer.createH264({ x: 0, y: 0, w: 0, h: 0 }, 0, new Uint8Array());
  const frame = { displayWidth: 1800, displayHeight: 1168, timestamp: 1, close: vi.fn() };
  output(frame);
  expect(renderer.latestVideo?.ctx.stretch).toBe(false);
  expect(renderer.getRemoteSize()).toEqual({ width: 1800, height: 1168 });
});

it("commits a layout the Mac confirmed together with the picture that answers it", () => {
  // The layout is authoritative. Dropping it left the renderer at the old
  // size for ever; applying it before the replacement picture blanked the
  // pane. Both change at once, when the replacement arrives.
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  const ctx = renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  renderer.setRemoteSize(2700, 1754);
  // Nothing changes until there is something to put in the new geometry.
  expect(renderer.getRemoteSize()).toEqual({ width: 3600, height: 2338 });
  expect(renderer.gl.texImage2D).not.toHaveBeenCalled();
  output({ displayWidth: 2700, displayHeight: 1754, close: vi.fn() });
  expect(renderer.getRemoteSize()).toEqual({ width: 2700, height: 1754 });
  expect(renderer.latestVideo?.ctx.stretch).toBe(false);
  expect(renderer.h264.get(0)).toBe(ctx);
});

it("keeps the picture on screen when the Mac sends a different desktop", () => {
  // 1600x1200 for a 3600x2338 desktop is not a quality tier of this desktop:
  // it is a different screen (a server fallback). Stretching 4:3 across a
  // Retina desktop shows something that is not the Mac's screen, so the last
  // good picture stays and recovery is asked for.
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const behind = vi.fn();
  const renderer = sizedDecoderHarness({ onDecoderBehind: behind });
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  const good = { displayWidth: 3600, displayHeight: 2338, timestamp: 1, close: vi.fn() };
  output(good);
  const fallback = { displayWidth: 1600, displayHeight: 1200, timestamp: 2, close: vi.fn() };
  output(fallback);
  expect(renderer.latestVideo?.frame).toBe(good);
  expect(fallback.close).toHaveBeenCalledOnce();
  expect(renderer.mediaMismatches).toBe(1);
  expect(renderer.getRemoteSize()).toEqual({ width: 3600, height: 2338 });
  expect(renderer.notice).toHaveBeenCalled();
  expect(behind).toHaveBeenCalledOnce();
});

it("ignores output and errors from a retired decoder sharing the replacement's slot", () => {
  const callbacks: { output: (f: unknown) => void; error: (e: Error) => void }[] = [];
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(c: typeof callbacks[number]) { callbacks.push(c); }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  renderer.closeH264(0);
  const replacement = renderer.createH264({ x: 0, y: 0, w: 2700, h: 1754 }, 0, new Uint8Array());
  const stale = { displayWidth: 1800, displayHeight: 1170, close: vi.fn() };
  callbacks[0].output(stale);
  expect(stale.close).toHaveBeenCalledOnce();
  expect(renderer.latestVideo).toBeNull();
  expect(renderer.mediaPictureWidth).toBe(3600);
  callbacks[0].error(new Error("late old decoder error"));
  expect(renderer.h264.get(0)).toBe(replacement);
  expect(renderer.h264Failures).toBe(0);
});

/** A renderer with just enough state for the decoder paths. */
function decoderHarness(extra: Record<string, unknown> = {}) {
  return Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null, notices: new Set(),
    h264Failed: false, h264Unsupported: false, h264Failures: 0,
    h264Acceleration: "prefer-hardware",
    notice: vi.fn(),
    ...extra,
  });
}

it("does not rebuild the decoder for a key picture that is not a reset", async () => {
  // The driver marks only an IDR as a reset. An intra picture is a key
  // chunk, so it can start a decoder, but rebuilding the decoder would
  // throw away the reference pictures the next delta picture needs, and the
  // corruption that follows outlives the picture that caused it.
  vi.stubGlobal("VideoDecoder", class { state = "configured"; configure() {} close() {} });
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const existing = {
    avc: true, timestamp: 0, generation: 1, waiters: new Map(), submitted: new Map(),
    decoder: { state: "configured", decode: vi.fn() },
  };
  const closeH264 = vi.fn();
  const createH264 = vi.fn();
  const renderer = decoderHarness({
    sawFrame: true, gl: {}, h264: new Map([[0, existing]]), closeH264, createH264,
  });
  await renderer.decodeH264({
    h264Key: true,
    h264Reset: false,
    payload: new Uint8Array([0, 0, 0, 1, 0x61, 0xaa]),
  });
  expect(closeH264).not.toHaveBeenCalled();
  expect(createH264).not.toHaveBeenCalled();
  expect(existing.decoder.decode).toHaveBeenCalledOnce();
});

it("reports what the decoder is doing", () => {
  // The queue is how much the decoder has been given and has not finished,
  // and the delay is how old the picture on screen is. The acceleration is
  // reported from what the webview accepted, never inferred from the delay.
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map([[0, { decoder: { decodeQueueSize: 3 } }]]),
    mediaSubmitted: 10,
    mediaDecoded: 8,
    mediaLatencyMs: 42.4,
    hardwareDecoding: true,
    h264Behind: false,
    fbWidth: 3600,
    fbHeight: 2338,
    mediaPictureWidth: 3600,
    mediaPictureHeight: 2338,
    mediaMismatches: 0,
    mediaLatencyDropped: 0,
  });
  expect(renderer.getMediaStats()).toEqual({
    queued: 3,
    submitted: 10,
    decoded: 8,
    latencyMs: 42,
    pictureWidth: 3600,
    pictureHeight: 2338,
    frameWidth: 3600,
    frameHeight: 2338,
    mismatches: 0,
    latencySamplesDropped: 0,
    acceleration: "hardware",
    behind: false,
  });
});

it("does not latch a decoder failure across a resize", () => {
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    fbWidth: 3600, fbHeight: 2338, generation: 1, sawFrame: true,
    h264Failed: true, h264Unsupported: false, h264Failures: 3,
    frameTex: {}, scratchTex: {},
    gl: { bindTexture: vi.fn(), texImage2D: vi.fn(), TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4 },
    clearViewRect: vi.fn(), closeAllH264: vi.fn(), markDirty: vi.fn(),
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.h264Failed).toBe(false);
  expect(renderer.h264Failures).toBe(0);
});

it("keeps the fact that this webview has no H.264 decoder across a resize", () => {
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    fbWidth: 3600, fbHeight: 2338, generation: 1, sawFrame: true,
    h264Failed: true, h264Unsupported: true, h264Failures: 3,
    frameTex: {}, scratchTex: {},
    gl: { bindTexture: vi.fn(), texImage2D: vi.fn(), TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4 },
    clearViewRect: vi.fn(), closeAllH264: vi.fn(), markDirty: vi.fn(),
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.h264Failed).toBe(true);
});

it("reports an asynchronous decoder failure and keeps the stream recoverable", () => {
  let error: (e: Error) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { error: typeof error }) { error = callbacks.error; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = decoderHarness();
  renderer.createH264({ x: 0, y: 0, w: 1920, h: 1080 }, 0, new Uint8Array());
  error(new Error("No hardware decoder for this reconfigured stream"));
  // The failure is reported rather than swallowed, the hardware path is
  // given up on, and one failure is a hiccup rather than a dead end: the
  // next independent picture builds a fresh decoder.
  expect(renderer.notice).toHaveBeenCalled();
  expect(renderer.h264Acceleration).toBe("prefer-software");
  expect(renderer.h264Failed).toBe(false);
  expect(renderer.h264Failures).toBe(1);
});

it("gives up on a stream whose decoder keeps failing", () => {
  let error: (e: Error) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { error: typeof error }) { error = callbacks.error; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = decoderHarness();
  for (let i = 0; i < 3; i++) {
    renderer.createH264({ x: 0, y: 0, w: 1920, h: 1080 }, 0, new Uint8Array());
    error(new Error("decoder died"));
  }
  expect(renderer.h264Failed).toBe(true);
});

it("does not count an accepted compressed chunk as a presented frame", async () => {
  vi.stubGlobal("VideoDecoder", class { state = "configured"; configure() {} close() {} });
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const firstFrame = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false, continuousH264: true, sawFrame: false, disposed: false,
    generation: 1, latestVideo: null, gl: {}, notices: new Set(),
    h264: new Map([[0, { avc: false, timestamp: 0, generation: 1, submitted: new Map(), decoder: { state: "configured", decode: vi.fn() } }]]),
    onFirstFrame: firstFrame, markDirty: vi.fn(),
  });
  await renderer.applyFrameOrdered(
    [{ format: RectFormat.H264, h264Key: true, payload: new Uint8Array([0, 0, 0, 1, 0x65, 0xaa]) }],
    [null],
    1,
  );
  expect(firstFrame).not.toHaveBeenCalled();
  expect(renderer.sawFrame).toBe(false);
});

it("counts a painted rectangle as the first frame", async () => {
  const firstFrame = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false, continuousH264: true, sawFrame: false, disposed: false,
    generation: 1, latestVideo: null, notices: new Set(),
    gl: { bindTexture: vi.fn(), texSubImage2D: vi.fn(), TEXTURE_2D: 1, RGBA: 3, UNSIGNED_BYTE: 4 },
    frameTex: {},
    onFirstFrame: firstFrame, markDirty: vi.fn(),
  });
  await renderer.applyFrameOrdered(
    [{ format: RectFormat.Rgba, x: 0, y: 0, w: 2, h: 2, payload: new Uint8Array(16) }],
    [null],
    1,
  );
  expect(firstFrame).toHaveBeenCalledOnce();
  expect(renderer.sawFrame).toBe(true);
});
