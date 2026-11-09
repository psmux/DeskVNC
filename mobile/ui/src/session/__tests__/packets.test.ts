import { describe, expect, it } from "vitest";
import { BUTTON, InputSender, encodeKey, encodePointer, encodeReleaseAll } from "../input/packets";

describe("input packets", () => {
  it("encodes a pointer event as 7 little endian bytes", () => {
    expect(Array.from(encodePointer(0x1234, 0x0201, BUTTON.left | BUTTON.right))).toEqual([0, 0x34, 0x12, 0x01, 0x02, 5, 0]);
  });

  it("clamps pointer coordinates into u16", () => {
    const b = encodePointer(-5, 70000, 0);
    const dv = new DataView(b.buffer);
    expect(dv.getUint16(1, true)).toBe(0);
    expect(dv.getUint16(3, true)).toBe(0xffff);
  });

  it("encodes a key event as 10 bytes", () => {
    expect(Array.from(encodeKey(true, 0xff0d, 0x1c))).toEqual([1, 1, 0x0d, 0xff, 0, 0, 0x1c, 0, 0, 0]);
    expect(Array.from(encodeKey(false, 0x01000000 + 0x263a, 0))).toEqual([1, 0, 0x3a, 0x26, 0, 1, 0, 0, 0, 0]);
  });

  it("encodes release all as one byte", () => {
    expect(Array.from(encodeReleaseAll())).toEqual([2]);
  });
});

describe("InputSender", () => {
  const bench = () => {
    const sent: { seq: number; body: number[] }[] = [];
    let pending: (() => void) | null = null;
    const s = new InputSender({
      send: (seq, body) => sent.push({ seq, body: Array.from(body) }),
      schedule: (cb) => {
        pending = cb;
      },
    });
    const frame = () => {
      const p = pending;
      pending = null;
      p?.();
    };
    return { s, sent, frame };
  };

  it("keeps only the newest pointer move per frame", () => {
    const { s, sent, frame } = bench();
    s.pointer(1, 1, 0);
    s.pointer(2, 2, 0);
    s.pointer(3, 3, 0);
    frame();
    expect(sent).toHaveLength(1);
    expect(sent[0].seq).toBe(1);
    expect(sent[0].body).toEqual(Array.from(encodePointer(3, 3, 0)));
  });

  it("never drops a button change, and numbers bodies from 1", () => {
    const { s, sent, frame } = bench();
    s.pointer(5, 5, 0);
    s.pointer(5, 5, BUTTON.left);
    s.pointer(6, 6, BUTTON.left);
    s.pointer(7, 7, BUTTON.left);
    s.pointer(7, 7, 0);
    frame();
    const expected = [
      ...encodePointer(5, 5, 0),
      ...encodePointer(5, 5, BUTTON.left),
      ...encodePointer(7, 7, BUTTON.left),
      ...encodePointer(7, 7, 0),
    ];
    expect(sent[0].body).toEqual(expected);
    s.pointer(8, 8, 0);
    frame();
    expect(sent.map((x) => x.seq)).toEqual([1, 2]);
  });

  it("keeps keys in order between moves", () => {
    const { s, sent, frame } = bench();
    s.pointer(1, 1, 0);
    s.key(true, 0x61, 0x1e);
    s.pointer(2, 2, 0);
    s.pointer(3, 3, 0);
    frame();
    expect(sent[0].body).toEqual([...encodePointer(1, 1, 0), ...encodeKey(true, 0x61, 0x1e), ...encodePointer(3, 3, 0)]);
  });

  it("sends release all at once, after anything queued", () => {
    const { s, sent } = bench();
    s.key(true, 0xffe3, 0x1d);
    s.releaseAll();
    expect(sent).toHaveLength(1);
    expect(sent[0].body).toEqual([...encodeKey(true, 0xffe3, 0x1d), 2]);
  });
});
