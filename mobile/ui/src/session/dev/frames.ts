/**
 * Builds channel messages in the src-tauri/FRAME_FORMAT.md layout, for the
 * dev page's pretend computer and for the tests.
 */

export interface OutRect {
  x: number;
  y: number;
  w: number;
  h: number;
  format: 0 | 1 | 2 | 3;
  payload: Uint8Array;
}

export function buildFrameMessage(rects: OutRect[]): ArrayBuffer {
  let size = 12;
  for (const r of rects) size += 14 + r.payload.length;
  const buf = new ArrayBuffer(size);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  let minX = Infinity;
  let minY = Infinity;
  let maxX = 0;
  let maxY = 0;
  for (const r of rects) {
    minX = Math.min(minX, r.x);
    minY = Math.min(minY, r.y);
    maxX = Math.max(maxX, r.x + r.w);
    maxY = Math.max(maxY, r.y + r.h);
  }
  dv.setUint8(0, 1);
  dv.setUint8(1, 0);
  dv.setUint16(2, rects.length, true);
  if (rects.length) {
    dv.setUint16(4, minX, true);
    dv.setUint16(6, minY, true);
    dv.setUint16(8, maxX - minX, true);
    dv.setUint16(10, maxY - minY, true);
  }
  let off = 12;
  for (const r of rects) {
    dv.setUint16(off, r.x, true);
    dv.setUint16(off + 2, r.y, true);
    dv.setUint16(off + 4, r.w, true);
    dv.setUint16(off + 6, r.h, true);
    dv.setUint8(off + 8, r.format);
    dv.setUint8(off + 9, 0);
    dv.setUint32(off + 10, r.payload.length, true);
    u8.set(r.payload, off + 14);
    off += 14 + r.payload.length;
  }
  return buf;
}

export function buildCursorMessage(w: number, h: number, hx: number, hy: number, rgba: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(10 + rgba.length);
  const dv = new DataView(buf);
  dv.setUint8(0, 2);
  dv.setUint16(2, w, true);
  dv.setUint16(4, h, true);
  dv.setUint16(6, hx, true);
  dv.setUint16(8, hy, true);
  new Uint8Array(buf).set(rgba, 10);
  return buf;
}

/** A classic arrow pointer, white with a black edge, as RGBA. */
export function arrowCursor(): { w: number; h: number; rgba: Uint8Array } {
  const rows = [
    "X...........",
    "XX..........",
    "XOX.........",
    "XOOX........",
    "XOOOX.......",
    "XOOOOX......",
    "XOOOOOX.....",
    "XOOOOOOX....",
    "XOOOOOOOX...",
    "XOOOOOOOOX..",
    "XOOOOOOOOOX.",
    "XOOOOOOXXXXX",
    "XOOOXOOX....",
    "XOOXXOOX....",
    "XOX..XOOX...",
    "XX...XOOX...",
    "X.....XOOX..",
    "......XOOX..",
    ".......XX...",
  ];
  const w = 12;
  const h = rows.length;
  const rgba = new Uint8Array(w * h * 4);
  rows.forEach((row, y) => {
    for (let x = 0; x < w; x++) {
      const c = row[x];
      const i = (y * w + x) * 4;
      if (c === "X") rgba.set([0, 0, 0, 255], i);
      else if (c === "O") rgba.set([255, 255, 255, 255], i);
    }
  });
  return { w, h, rgba };
}
