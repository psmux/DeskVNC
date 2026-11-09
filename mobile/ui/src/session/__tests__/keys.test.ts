import { describe, expect, it } from "vitest";
import { SENTINEL, TextDiffer, afterKey, charIds, heldModifiers, namedKeyIds, nextModState } from "../input/keys";

describe("keysyms", () => {
  it("maps key bar keys to keysym and XT scancode", () => {
    expect(namedKeyIds("Escape")).toEqual({ keysym: 0xff1b, keycode: 0x01 });
    expect(namedKeyIds("Tab")).toEqual({ keysym: 0xff09, keycode: 0x0f });
    expect(namedKeyIds("ArrowLeft")).toEqual({ keysym: 0xff51, keycode: 0xcb });
    expect(namedKeyIds("Home")).toEqual({ keysym: 0xff50, keycode: 0xc7 });
    expect(namedKeyIds("PageDown")).toEqual({ keysym: 0xff56, keycode: 0xd1 });
    expect(namedKeyIds("F5")).toEqual({ keysym: 0xffc2, keycode: 0x3f });
    expect(namedKeyIds("F12")).toEqual({ keysym: 0xffc9, keycode: 0x58 });
    expect(namedKeyIds("Delete")).toEqual({ keysym: 0xffff, keycode: 0xd3 });
    expect(namedKeyIds("Backspace")).toEqual({ keysym: 0xff08, keycode: 0x0e });
  });

  it("maps typed characters, lower casing letters under a modifier", () => {
    expect(charIds("c", true)).toEqual({ keysym: 0x63, keycode: 0x2e });
    expect(charIds("C", true)).toEqual({ keysym: 0x63, keycode: 0x2e });
    expect(charIds("C", false)).toEqual({ keysym: 0x43, keycode: 0x2e });
    expect(charIds("7", false)).toEqual({ keysym: 0x37, keycode: 0x08 });
    expect(charIds("é", false)).toEqual({ keysym: 0xe9, keycode: 0 });
    expect(charIds("€", false)).toEqual({ keysym: 0x010020ac, keycode: 0 });
  });
});

describe("sticky modifiers", () => {
  it("taps once for the next key and double taps to lock", () => {
    expect(nextModState("off", false)).toBe("once");
    expect(nextModState("once", false)).toBe("off");
    expect(nextModState("once", true)).toBe("locked");
    expect(nextModState("locked", false)).toBe("off");
    const after = afterKey({ ctrl: "once", alt: "locked", meta: "off", shift: "off" });
    expect(after).toEqual({ ctrl: "off", alt: "locked", meta: "off", shift: "off" });
    expect(heldModifiers(after)).toEqual(["alt"]);
  });
});

describe("TextDiffer", () => {
  it("sends typed letters as text", () => {
    const d = new TextDiffer();
    expect(d.onValue(SENTINEL + "h", false)).toEqual([{ type: "text", text: "h" }]);
    expect(d.onValue(SENTINEL + "hi", false)).toEqual([{ type: "text", text: "i" }]);
  });

  it("turns a backspace on an empty field into one backspace", () => {
    const d = new TextDiffer();
    expect(d.onValue("", false)).toEqual([{ type: "backspace", count: 1 }]);
  });

  it("handles autocorrect replacing a word", () => {
    const d = new TextDiffer();
    d.onValue(SENTINEL + "teh", false);
    expect(d.onValue(SENTINEL + "the ", false)).toEqual([
      { type: "backspace", count: 2 },
      { type: "text", text: "he " },
    ]);
  });

  it("waits for an IME composition to finish", () => {
    const d = new TextDiffer();
    expect(d.onValue(SENTINEL + "に", true)).toEqual([]);
    expect(d.onValue(SENTINEL + "にほ", true)).toEqual([]);
    expect(d.onCompositionEnd(SENTINEL + "日本")).toEqual([{ type: "text", text: "日本" }]);
  });

  it("sends Latin composition (Android keyboards) letter by letter", () => {
    const d = new TextDiffer();
    expect(d.onValue(SENTINEL + "c", true)).toEqual([{ type: "text", text: "c" }]);
    expect(d.onValue(SENTINEL + "ca", true)).toEqual([{ type: "text", text: "a" }]);
    expect(d.onCompositionEnd(SENTINEL + "ca")).toEqual([]);
  });

  it("counts emoji as one character", () => {
    const d = new TextDiffer();
    d.onValue(SENTINEL + "a😀", false);
    expect(d.onValue(SENTINEL + "a", false)).toEqual([{ type: "backspace", count: 1 }]);
  });
});
