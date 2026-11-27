import { describe, expect, it } from "vitest";
import { DOUBLE_TAP_MS, GestureRecognizer, LONG_PRESS_MS, type GestureAction, type Pt, type TouchInput, type TouchMode } from "../input/gestures";

/** Drives a recognizer with a script of touches, ticking the clock as it goes. */
function rig(mode: TouchMode) {
  // The recognizer used to take a context saying whether the whole desktop
  // was showing, which is when a double tap zoomed instead of clicking. The
  // second argument tells an old build "yes, it is", so the double click
  // tests below fail there for the reason issue #91 reports. The current
  // constructor ignores it.
  const Recognizer = GestureRecognizer as unknown as new (m: TouchMode, ctx: unknown) => GestureRecognizer;
  const r = new Recognizer(mode, { canDoubleTapZoom: () => true });
  let t = 1000;
  const out: GestureAction[] = [];
  const touches = new Map<number, Pt>();
  const ev = (type: TouchInput["type"]) => out.push(...r.feed({ type, t, touches: [...touches.values()] }));
  const api = {
    out,
    down(id: number, x: number, y: number) {
      touches.set(id, { id, x, y });
      ev("start");
      return api;
    },
    move(id: number, x: number, y: number) {
      touches.set(id, { id, x, y });
      ev("move");
      return api;
    },
    up(id: number) {
      touches.delete(id);
      ev("end");
      return api;
    },
    wait(ms: number) {
      const end = t + ms;
      while (t < end) {
        t = Math.min(end, t + 20);
        out.push(...r.tick(t));
      }
      return api;
    },
    types: () => out.map((a) => a.type),
  };
  return api;
}

describe("trackpad", () => {
  it("drag moves the pointer by relative steps", () => {
    const g = rig("trackpad").down(1, 100, 100).move(1, 104, 100).move(1, 130, 110).move(1, 140, 115).up(1);
    const moves = g.out.filter((a) => a.type === "move") as { dx: number; dy: number }[];
    expect(moves.reduce((s, m) => s + m.dx, 0)).toBe(40);
    expect(moves.reduce((s, m) => s + m.dy, 0)).toBe(15);
    expect(g.types()).not.toContain("click");
  });

  it("tap clicks after the double tap wait", () => {
    const g = rig("trackpad").down(1, 50, 50).wait(80).up(1);
    expect(g.out).toEqual([]);
    g.wait(DOUBLE_TAP_MS + 20);
    expect(g.out).toEqual([{ type: "click", button: "left" }]);
  });

  it("two quick taps double click at the pointer, with the whole desktop showing (#91)", () => {
    const g = rig("trackpad").down(1, 50, 50).wait(60).up(1).wait(80).down(1, 52, 51).wait(60).up(1).wait(400);
    expect(g.out).toEqual([
      { type: "click", button: "left" },
      { type: "click", button: "left" },
    ]);
  });

  it("tap then drag holds the button for the drag", () => {
    const g = rig("trackpad").down(1, 50, 50).wait(60).up(1).wait(80).down(1, 50, 50).move(1, 80, 60).move(1, 120, 70).up(1).wait(400);
    expect(g.types()).toEqual(["down", "move", "move", "up"]);
  });

  it("two finger tap is a right click", () => {
    const g = rig("trackpad").down(1, 100, 100).down(2, 140, 100).wait(80).up(1).up(2);
    expect(g.out).toEqual([{ type: "click", button: "right" }]);
  });

  it("two finger drag scrolls", () => {
    const g = rig("trackpad").down(1, 100, 300).down(2, 150, 300);
    for (let i = 1; i <= 6; i++) g.move(1, 100, 300 - i * 10).move(2, 150, 300 - i * 10);
    g.up(1).up(2);
    const scrolls = g.out.filter((a) => a.type === "scroll") as { dy: number }[];
    expect(scrolls.length).toBeGreaterThan(0);
    expect(scrolls.every((s) => s.dy < 0)).toBe(true);
    expect(g.types()).not.toContain("zoom");
    expect(g.types()).not.toContain("click");
  });

  it("three finger tap opens the keyboard", () => {
    const g = rig("trackpad").down(1, 100, 100).down(2, 140, 100).down(3, 180, 100).wait(60).up(1).up(2).up(3);
    expect(g.out).toEqual([{ type: "keyboard" }]);
  });
});

describe("direct touch", () => {
  it("tap clicks where the finger is when zoomed in", () => {
    const g = rig("direct").down(1, 210, 330).wait(60).up(1);
    expect(g.out).toEqual([{ type: "click", button: "left", x: 210, y: 330 }]);
  });

  it("long press fills the ring and right clicks", () => {
    const g = rig("direct").down(1, 90, 90).wait(LONG_PRESS_MS + 40);
    expect(g.types()).toEqual(["ring", "ring", "click"]);
    expect(g.out[2]).toEqual({ type: "click", button: "right", x: 90, y: 90 });
    g.up(1);
    expect(g.out).toHaveLength(3);
  });

  it("moving cancels the long press ring and drags instead", () => {
    const g = rig("direct").down(1, 90, 90).wait(200).move(1, 140, 90).up(1);
    expect(g.types()).toEqual(["ring", "ring", "point", "down", "point", "up"]);
    expect(g.out[1]).toMatchObject({ type: "ring", state: "cancel" });
  });

  it("double tap double clicks on the first tap's spot and never zooms (#91)", () => {
    const g = rig("direct").down(1, 120, 200).wait(50).up(1);
    // The first click goes at once; the desktop does not wait for us.
    expect(g.out).toEqual([{ type: "click", button: "left", x: 120, y: 200 }]);
    g.wait(90).down(1, 127, 205).wait(50).up(1).wait(400);
    expect(g.out).toEqual([
      { type: "click", button: "left", x: 120, y: 200 },
      { type: "click", button: "left", x: 120, y: 200 },
    ]);
  });

  it("a third quick tap stays on the same spot, for a triple click", () => {
    const g = rig("direct").down(1, 120, 200).wait(40).up(1).wait(80).down(1, 124, 198).wait(40).up(1).wait(80).down(1, 117, 203).wait(40).up(1);
    expect(g.out).toEqual([
      { type: "click", button: "left", x: 120, y: 200 },
      { type: "click", button: "left", x: 120, y: 200 },
      { type: "click", button: "left", x: 120, y: 200 },
    ]);
  });

  it("two taps far apart are two clicks, each where it landed", () => {
    const g = rig("direct").down(1, 40, 40).wait(40).up(1).wait(80).down(1, 300, 400).wait(40).up(1);
    expect(g.out).toEqual([
      { type: "click", button: "left", x: 40, y: 40 },
      { type: "click", button: "left", x: 300, y: 400 },
    ]);
  });

  it("a slow second tap is a fresh click where it landed", () => {
    const g = rig("direct").down(1, 120, 200).wait(40).up(1).wait(900).down(1, 130, 206).wait(40).up(1);
    expect(g.out).toEqual([
      { type: "click", button: "left", x: 120, y: 200 },
      { type: "click", button: "left", x: 130, y: 206 },
    ]);
  });

  it("a drag between two taps does not join them into a double click", () => {
    const g = rig("direct").down(1, 120, 200).wait(40).up(1).down(1, 120, 200).move(1, 180, 200).up(1).down(1, 182, 203).wait(40).up(1);
    expect(g.out.filter((a) => a.type === "click")).toEqual([
      { type: "click", button: "left", x: 120, y: 200 },
      { type: "click", button: "left", x: 182, y: 203 },
    ]);
  });

  it("the second tap of a double tap does not start a long press ring", () => {
    const g = rig("direct").down(1, 90, 90).wait(40).up(1).wait(60).down(1, 92, 91).wait(250).up(1);
    expect(g.types()).toEqual(["click", "click"]);
  });
});

describe("pinch", () => {
  it("spreading fingers zooms, sliding pans, a flick glides", () => {
    const g = rig("direct").down(1, 100, 300).down(2, 200, 300);
    for (let i = 1; i <= 8; i++) {
      g.wait(16);
      g.move(1, 100 - i * 10, 300 + i * 4).move(2, 200 + i * 10, 300 + i * 4);
    }
    g.up(1).up(2);
    const zooms = g.out.filter((a) => a.type === "zoom") as { factor: number }[];
    expect(zooms.length).toBeGreaterThan(0);
    expect(zooms.reduce((p, z) => p * z.factor, 1)).toBeGreaterThan(1.5);
    expect(g.types()).toContain("pan");
    const end = g.out.find((a) => a.type === "panEnd") as { vy: number };
    expect(end.vy).toBeGreaterThan(0);
    expect(g.types()).not.toContain("scroll");
  });

  it("a second finger cancels a direct drag cleanly", () => {
    const g = rig("direct").down(1, 100, 100).move(1, 130, 100).down(2, 200, 100);
    expect(g.types()).toEqual(["point", "down", "point", "up"]);
  });
});
