/** A slow link must get the newest pointer position, not a backlog. */
import { describe, expect, it } from "vitest";
import { InputSender, encodePointer, BUTTON } from "../input/packets";
import { KeyboardField, SENTINEL } from "../input/keys";

function slowRig() {
  const bodies: Uint8Array[] = [];
  const settle: (() => void)[] = [];
  const s = new InputSender({
    send: (_seq, body) => {
      bodies.push(body);
      return new Promise<void>((r) => settle.push(r));
    },
    schedule: (cb) => cb(),
  });
  const done = async (): Promise<void> => {
    settle.shift()?.();
    await Promise.resolve();
    await Promise.resolve();
  };
  return { s, bodies, done };
}

describe("input back pressure", () => {
  it("merges moves made while a body is in flight into the newest one", async () => {
    const { s, bodies, done } = slowRig();
    s.pointer(1, 1, 0);
    for (let x = 2; x <= 50; x++) s.pointer(x, x, 0);
    expect(bodies.length).toBe(1);
    await done();
    expect(bodies.length).toBe(2);
    expect(Array.from(bodies[1])).toEqual(Array.from(encodePointer(50, 50, 0)));
  });

  it("keeps button changes and their order while waiting", async () => {
    const { s, bodies, done } = slowRig();
    s.pointer(1, 1, 0);
    s.pointer(2, 2, BUTTON.left);
    s.pointer(3, 3, BUTTON.left);
    s.pointer(4, 4, 0);
    await done();
    expect(Array.from(bodies[1])).toEqual([
      ...encodePointer(2, 2, BUTTON.left),
      ...encodePointer(3, 3, BUTTON.left),
      ...encodePointer(4, 4, 0),
    ]);
  });

  it("flush(true) sends at once so typed text cannot overtake queued keys", () => {
    const { s, bodies } = slowRig();
    s.pointer(1, 1, 0);
    s.key(true, 0xff08, 0);
    expect(bodies.length).toBe(1);
    s.flush(true);
    expect(bodies.length).toBe(2);
  });
});

describe("field after Enter", () => {
  it("a suggestion for the word before Enter does not backspace into it", () => {
    const f = new KeyboardField();
    f.compositionStart();
    const typed = f.input(SENTINEL + "teh", true);
    const enter = f.keyDown({ key: "Enter", keyCode: 229, isComposing: true }, SENTINEL + "teh") ?? [];
    expect([...typed, ...enter]).toEqual([{ type: "text", text: "teh" }, { type: "enter" }]);
    f.clearedAfterEnter();
    // The field was put back to the sentinel; the late commit sees only that.
    expect(f.compositionEnd(SENTINEL)).toEqual([]);
    expect(f.input(SENTINEL + "x", false)).toEqual([{ type: "text", text: "x" }]);
  });
});
