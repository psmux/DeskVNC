import { describe, expect, it } from "vitest";
import { MSG_CURSOR, MSG_FRAMEBUFFER, messageType, parseCursorMessage, parseFrameMessage } from "../render/frameProtocol";
import { buildCursorMessage, buildFrameMessage } from "../dev/frames";

describe("frame parser", () => {
  it("reads RGBA, JPEG and CopyRect rects in order", () => {
    const rgba = new Uint8Array(2 * 2 * 4).fill(7);
    const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xd9]);
    const copy = new Uint8Array([10, 0, 20, 0]);
    const buf = buildFrameMessage([
      { x: 1, y: 2, w: 2, h: 2, format: 0, payload: rgba },
      { x: 100, y: 50, w: 30, h: 40, format: 1, payload: jpeg },
      { x: 5, y: 6, w: 8, h: 9, format: 2, payload: copy },
    ]);
    expect(messageType(buf)).toBe(MSG_FRAMEBUFFER);
    const m = parseFrameMessage(buf)!;
    expect(m.damageX).toBe(1);
    expect(m.damageY).toBe(2);
    expect(m.damageW).toBe(129);
    expect(m.damageH).toBe(88);
    expect(m.rects.map((r) => r.format)).toEqual([0, 1, 2]);
    expect(Array.from(m.rects[0].payload)).toEqual(Array.from(rgba));
    expect(Array.from(m.rects[1].payload)).toEqual(Array.from(jpeg));
    expect(m.rects[2].srcX).toBe(10);
    expect(m.rects[2].srcY).toBe(20);
    expect(m.rects[2].payload.length).toBe(0);
  });

  it("splits the H.264 header from the Annex B data", () => {
    const payload = new Uint8Array(12 + 3);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, 1, true); // ResetContext
    dv.setUint32(4, 9, true); // context 9
    dv.setUint32(8, 3, true); // rebuild + IDR
    payload.set([0, 0, 1], 12);
    const m = parseFrameMessage(buildFrameMessage([{ x: 0, y: 0, w: 64, h: 64, format: 3, payload }]))!;
    const r = m.rects[0];
    expect(r.h264Flags).toBe(1);
    expect(r.h264Context).toBe(9);
    expect(r.h264Reset).toBe(true);
    expect(r.h264Key).toBe(true);
    expect(Array.from(r.payload)).toEqual([0, 0, 1]);
  });

  it("keeps the rects before a truncated one", () => {
    const full = buildFrameMessage([
      { x: 0, y: 0, w: 1, h: 1, format: 0, payload: new Uint8Array(4) },
      { x: 0, y: 0, w: 1, h: 1, format: 0, payload: new Uint8Array(4) },
    ]);
    const cut = full.slice(0, full.byteLength - 2);
    const warn = console.warn;
    console.warn = () => {};
    try {
      expect(parseFrameMessage(cut)!.rects).toHaveLength(1);
    } finally {
      console.warn = warn;
    }
  });

  it("reads a cursor shape, and ignores other message types", () => {
    const px = new Uint8Array(3 * 2 * 4).fill(200);
    const buf = buildCursorMessage(3, 2, 1, 0, px);
    expect(messageType(buf)).toBe(MSG_CURSOR);
    const c = parseCursorMessage(buf)!;
    expect([c.width, c.height, c.hotspotX, c.hotspotY]).toEqual([3, 2, 1, 0]);
    expect(c.pixels.length).toBe(24);
    expect(parseFrameMessage(buf)).toBeNull();
    expect(parseFrameMessage(new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).buffer)).toBeNull();
  });
});
