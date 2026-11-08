import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebGLRenderer } from "./WebGLRenderer";
import { RectFormat, type FrameMessage, type WireRect } from "./frameProtocol";

// The renderer's H.264 path against a decoder that behaves like the one a
// webview really has: WebView2's gives each picture back before the next
// chunk is needed, WebKitGTK's (vah264dec, nvh264dec) only after two or
// three more chunks have gone in. GL is a stub that records what was
// uploaded, in order.

const W = 64;
const H = 48;

/** What reached the frame texture, in order: "v<n>" for picture n, "rgba". */
let uploads: string[] = [];
/** Pictures a decoder holds back before giving the oldest one out. */
let holdBack = 0;
/** The decoder fails on Annex B, as WebKitGTK's does, and takes only length prefixed chunks. */
let rejectAnnexB = false;

class FakePicture {
  displayWidth = W;
  displayHeight = H;
  codedWidth = W;
  codedHeight = H;
  constructor(readonly timestamp: number) {}
  close(): void {}
}

class FakeChunk {
  readonly timestamp: number;
  readonly type: string;
  readonly data: Uint8Array;
  constructor(init: { timestamp: number; type: string; data: Uint8Array }) {
    this.timestamp = init.timestamp;
    this.type = init.type;
    this.data = init.data;
  }
}

/** Whether `data` is one or more NAL units each after a four byte length. */
function lengthPrefixed(data: Uint8Array): boolean {
  let at = 0;
  while (at + 4 <= data.length) at += 4 + new DataView(data.buffer, data.byteOffset + at).getUint32(0);
  return at === data.length && data.length > 0;
}

class FakeDecoder {
  state = "unconfigured";
  private held: number[] = [];
  private avcc = false;
  constructor(private readonly init: { output: (p: FakePicture) => void; error: (e: unknown) => void }) {}
  configure(config: { description?: Uint8Array }): void {
    this.state = "configured";
    this.avcc = config.description !== undefined;
  }
  decode(chunk: FakeChunk): void {
    if (rejectAnnexB && (!this.avcc || !lengthPrefixed(chunk.data))) {
      setTimeout(() => {
        this.state = "closed";
        this.init.error(new DOMException("Decode error", "EncodingError"));
      }, 1);
      return;
    }
    this.held.push(chunk.timestamp);
    while (this.held.length > holdBack) {
      const ts = this.held.shift()!;
      // Pictures come back on a later task, as from a real decoder.
      setTimeout(() => {
        if (this.state !== "closed") this.init.output(new FakePicture(ts));
      }, 2);
    }
  }
  close(): void {
    this.state = "closed";
  }
}

function fakeGl(): WebGL2RenderingContext {
  const fns: Record<string, unknown> = {
    getShaderParameter: () => true,
    getProgramParameter: () => true,
    texSubImage2D: (...args: unknown[]) => {
      const source = args[args.length - 1];
      uploads.push(source instanceof FakePicture ? `v${source.timestamp / 1000}` : "rgba");
    },
  };
  return new Proxy({} as WebGL2RenderingContext, {
    get: (_t, prop: string) => {
      if (prop in fns) return fns[prop];
      if (/^[A-Z0-9_]+$/.test(prop)) return 1;
      return () => ({});
    },
  });
}

function canvas(): HTMLCanvasElement {
  const c = document.createElement("canvas");
  c.getContext = (() => fakeGl()) as unknown as HTMLCanvasElement["getContext"];
  return c;
}

function message(rects: Partial<WireRect>[]): FrameMessage {
  return {
    rects: rects.map((r) => ({ x: 0, y: 0, w: W, h: H, srcX: 0, srcY: 0, format: RectFormat.H264, payload: new Uint8Array(8), ...r })),
    damageX: 0,
    damageY: 0,
    damageW: W,
    damageH: H,
  } as unknown as FrameMessage;
}

// Annex B, as a Boundary computer sends it: parameter sets and an IDR slice
// in a keyframe, one non-IDR slice in each picture after it.
const KEY = new Uint8Array([0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f, 0xda, 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, 0, 0, 1, 0x65, 0x88, 0x84, 0x21]);
const DELTA = new Uint8Array([0, 0, 0, 1, 0x41, 0x9a, 0x21, 0x6c]);
let chunks = 0;
function video(): FrameMessage {
  chunks++;
  const key = chunks === 1;
  return message([{ format: RectFormat.H264, h264Context: 0, h264Key: key, h264Reset: key, payload: key ? KEY : DELTA }]);
}
function tile(x: number, y: number, w: number, h: number): FrameMessage {
  return message([{ format: RectFormat.Rgba, x, y, w, h, payload: new Uint8Array(w * h * 4) }]);
}

beforeEach(() => {
  vi.useFakeTimers();
  uploads = [];
  chunks = 0;
  rejectAnnexB = false;
  vi.stubGlobal("VideoDecoder", FakeDecoder);
  vi.stubGlobal("EncodedVideoChunk", FakeChunk);
  vi.stubGlobal("VideoFrame", FakePicture);
  // A display refreshing at 60 Hz, on the fake clock.
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => setTimeout(() => cb(0), 16));
  vi.stubGlobal("cancelAnimationFrame", (id: number) => clearTimeout(id));
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function renderer(): WebGLRenderer {
  const r = new WebGLRenderer(canvas());
  r.setRemoteSize(W, H);
  r.setCanvasSize(W, H);
  r.start();
  return r;
}

describe("H.264 from a decoder that holds pictures back (WebKitGTK)", () => {
  it("shows the video, a few pictures behind, instead of timing out on every chunk", async () => {
    holdBack = 3;
    const r = renderer();
    // Thirty pictures a second for one second, as a Boundary computer sends
    // while its screen moves.
    for (let i = 0; i < 30; i++) {
      r.applyFrame(video());
      await vi.advanceTimersByTimeAsync(33);
    }
    // Learning the lag costs one wait per held picture, once, and the
    // pictures that queued up meanwhile go by faster than frames are drawn.
    // Then the newest picture but the three still inside is on screen.
    await vi.advanceTimersByTimeAsync(1000);
    const shown = uploads.filter((u) => u.startsWith("v"));
    expect(shown.at(-1)).toBe("v27");
    expect(shown).toEqual([...shown].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1))));
    // And the window keeps up from then on: a second of video, no waiting.
    uploads = [];
    for (let i = 0; i < 30; i++) {
      r.applyFrame(video());
      await vi.advanceTimersByTimeAsync(33);
    }
    expect(uploads).toHaveLength(30);
    expect(uploads.at(-1)).toBe("v57");
    expect(r.getQueueStats().depth).toBe(0);
    r.dispose();
  });

  it("never paints a late picture over a tile that came after it", async () => {
    holdBack = 3;
    const r = renderer();
    for (let i = 0; i < 10; i++) {
      r.applyFrame(video());
      await vi.advanceTimersByTimeAsync(33);
    }
    await vi.advanceTimersByTimeAsync(1600);
    // Video stops; the computer sends sharp tiles over part of the screen.
    // Pictures 8 to 10 are still inside the decoder, and must stay there.
    r.applyFrame(tile(0, 0, 16, 16));
    await vi.advanceTimersByTimeAsync(10);
    r.applyFrame(video());
    await vi.advanceTimersByTimeAsync(50);
    const after = uploads.slice(uploads.lastIndexOf("rgba") + 1);
    expect(after).toEqual([]);
    r.dispose();
  });

  it("asks a Boundary computer for the screen once when the last pictures stay inside the decoder", async () => {
    holdBack = 3;
    const r = renderer();
    const asked = vi.fn();
    r.onVideoBehind = asked;
    for (let i = 0; i < 10; i++) {
      r.applyFrame(video());
      await vi.advanceTimersByTimeAsync(33);
    }
    await vi.advanceTimersByTimeAsync(2000);
    expect(asked).toHaveBeenCalledTimes(1);
    // The answer covers the whole screen, which settles the debt.
    r.applyFrame(tile(0, 0, W, H));
    await vi.advanceTimersByTimeAsync(1000);
    expect(asked).toHaveBeenCalledTimes(1);
    r.dispose();
  });
});

describe("H.264 from a decoder that gives each picture back at once (WebView2)", () => {
  it("puts each picture on screen before the next rect, with no waiting and no extra refresh", async () => {
    holdBack = 0;
    const r = renderer();
    const asked = vi.fn();
    r.onVideoBehind = asked;
    r.applyFrame(video());
    r.applyFrame(tile(0, 0, 16, 16));
    r.applyFrame(video());
    await vi.advanceTimersByTimeAsync(20);
    expect(uploads).toEqual(["v1", "rgba", "v2"]);
    await vi.advanceTimersByTimeAsync(1000);
    expect(asked).not.toHaveBeenCalled();
    r.dispose();
  });
});

describe("H.264 into a decoder that turns Annex B down (WebKitGTK)", () => {
  it("starts again from the same keyframe, length prefixed, and the video plays", async () => {
    holdBack = 2;
    rejectAnnexB = true;
    const r = renderer();
    for (let i = 0; i < 30; i++) {
      r.applyFrame(video());
      await vi.advanceTimersByTimeAsync(33);
    }
    await vi.advanceTimersByTimeAsync(1500);
    // The newest picture but the two the decoder still holds is on screen,
    // and the window has kept up with the stream.
    const shown = uploads.filter((u) => u.startsWith("v"));
    expect(shown.at(-1)).toBe("v28");
    expect(r.getQueueStats().depth).toBe(0);
    r.dispose();
  });
});

describe("H.264 from a decoder that runs ahead of the display", () => {
  it("uploads only the newest picture for each frame drawn", async () => {
    holdBack = 0;
    const r = renderer();
    // A burst of pictures, all back before the next frame is drawn.
    for (let i = 0; i < 10; i++) r.applyFrame(video());
    await vi.advanceTimersByTimeAsync(40);
    expect(uploads.at(-1)).toBe("v10");
    expect(uploads.length).toBeLessThan(10);
    r.dispose();
  });
});
