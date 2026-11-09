/**
 * The mock and the demo computer must speak the exact frame layout of
 * src-tauri/FRAME_FORMAT.md, or every demo pixel lands in the wrong place.
 * Round trip through the session's own parser to prove it.
 */
import { describe, expect, it } from "vitest";
import { parseFrameMessage } from "../session/render/frameProtocol";
import { encodeRgbaFrame } from "./mock";

describe("encodeRgbaFrame", () => {
  it("round trips through the session's frame parser byte for byte", () => {
    const w = 5;
    const h = 3;
    const rgba = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < rgba.length; i++) rgba[i] = (i * 7 + 3) & 0xff;
    const buf = encodeRgbaFrame(rgba, w, h);

    // 12 byte message header, 14 byte rect header, then exactly the pixels.
    expect(buf.byteLength).toBe(12 + 14 + w * h * 4);

    const msg = parseFrameMessage(buf);
    expect(msg).not.toBeNull();
    expect(msg).toMatchObject({ damageX: 0, damageY: 0, damageW: w, damageH: h });
    expect(msg!.rects).toHaveLength(1);
    const rect = msg!.rects[0];
    expect(rect).toMatchObject({ x: 0, y: 0, w, h, format: 0 });
    expect(Array.from(rect.payload)).toEqual(Array.from(rgba));
  });
});
