import { describe, expect, it } from "vitest";
import {
  DEFAULT_KEY_BUTTON_POS,
  DRAG_SLOP,
  DragTracker,
  KEY_BUTTON_MARGIN,
  KEY_BUTTON_SIZE,
  KEY_BUTTON_TOP,
  clampKeyButton,
  keyButtonTap,
  placeKeyButton,
  sanitizeKeyButtonPos,
  snapKeyButton,
  verticalRange,
  type KeyButtonArea,
} from "../input/keyButton";

const PHONE: KeyButtonArea = { w: 412, h: 915, bottomInset: 0 };
const UNFOLDED: KeyButtonArea = { w: 900, h: 1000, bottomInset: 0 };

describe("keyboard button: tap or drag", () => {
  it("a press that stays put is a tap", () => {
    const d = new DragTracker();
    d.down(100, 100);
    expect(d.move(103, 104)).toBe(false);
    expect(d.up()).toBe("tap");
  });

  it("moving past the slop makes it a drag, and it stays one", () => {
    const d = new DragTracker();
    d.down(100, 100);
    expect(d.move(100 + DRAG_SLOP + 1, 100)).toBe(true);
    // Back where it started: still a drag, so no keyboard toggle.
    expect(d.move(100, 100)).toBe(true);
    expect(d.up()).toBe("drag");
  });

  it("a move or up without a press does nothing", () => {
    const d = new DragTracker();
    expect(d.move(50, 50)).toBe(false);
    expect(d.up()).toBeNull();
  });

  it("cancel forgets the press", () => {
    const d = new DragTracker();
    d.down(0, 0);
    d.move(40, 0);
    d.cancel();
    expect(d.up()).toBeNull();
    d.down(0, 0);
    expect(d.up()).toBe("tap");
  });
});

describe("keyboard button: placement", () => {
  it("starts at the bottom right, inside the margins", () => {
    const p = placeKeyButton(DEFAULT_KEY_BUTTON_POS, PHONE);
    expect(p.x).toBe(PHONE.w - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
    expect(p.y).toBe(PHONE.h - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
  });

  it("keeps the top band clear for the toolbar", () => {
    expect(placeKeyButton({ edge: "left", y: 0 }, PHONE)).toEqual({ x: KEY_BUTTON_MARGIN, y: KEY_BUTTON_TOP });
  });

  it("sits above an overlaid keyboard and the key bar", () => {
    const kb = { ...PHONE, bottomInset: 300 + 100 };
    const p = placeKeyButton(DEFAULT_KEY_BUTTON_POS, kb);
    expect(p.y + KEY_BUTTON_SIZE).toBeLessThanOrEqual(PHONE.h - 400);
    expect(p.y).toBe(PHONE.h - 400 - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
  });

  it("stays on screen when the free area is shorter than the top band", () => {
    const tiny: KeyButtonArea = { w: 800, h: 150, bottomInset: 60 };
    const r = verticalRange(tiny);
    expect(r.min).toBeLessThanOrEqual(r.max);
    const p = placeKeyButton({ edge: "right", y: 0.5 }, tiny);
    expect(p.y).toBeGreaterThanOrEqual(0);
    expect(p.y + KEY_BUTTON_SIZE).toBeLessThanOrEqual(tiny.h - tiny.bottomInset);
  });

  it("leaves the quality badge's corner when the area is cramped", () => {
    // A phone held sideways with the keyboard and the key bar up: about 150
    // CSS pixels of page, 100 of them the key bar.
    const sideways: KeyButtonArea = { w: 915, h: 150, bottomInset: 100 };
    const p = placeKeyButton({ edge: "left", y: 0.5 }, sideways);
    expect(p.x).toBe(sideways.w - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
    // With room again it goes back to the edge it was left on.
    expect(placeKeyButton({ edge: "left", y: 0.5 }, PHONE).x).toBe(KEY_BUTTON_MARGIN);
  });

  it("clamps a dragged corner inside the area", () => {
    expect(clampKeyButton(-50, -50, PHONE)).toEqual({ x: KEY_BUTTON_MARGIN, y: KEY_BUTTON_TOP });
    expect(clampKeyButton(9999, 9999, PHONE)).toEqual({
      x: PHONE.w - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN,
      y: PHONE.h - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN,
    });
  });
});

describe("keyboard button: snapping and what is stored", () => {
  it("snaps to the nearer side edge", () => {
    expect(snapKeyButton(50, 400, PHONE).edge).toBe("left");
    expect(snapKeyButton(300, 400, PHONE).edge).toBe("right");
    // The centre decides: a corner just left of middle whose centre is right of it.
    expect(snapKeyButton(PHONE.w / 2 - 10, 400, PHONE).edge).toBe("right");
  });

  it("stores the height as a fraction of the free height", () => {
    const r = verticalRange(PHONE);
    const mid = r.min + (r.max - r.min) / 2;
    expect(snapKeyButton(300, mid, PHONE).y).toBeCloseTo(0.5, 2);
    expect(snapKeyButton(300, r.min, PHONE).y).toBe(0);
    expect(snapKeyButton(300, r.max, PHONE).y).toBe(1);
  });

  it("round trips a drop point through the stored position", () => {
    const pos = snapKeyButton(20, 500, PHONE);
    const back = placeKeyButton(pos, PHONE);
    expect(back.x).toBe(KEY_BUTTON_MARGIN);
    expect(Math.abs(back.y - 500)).toBeLessThanOrEqual(1);
  });

  it("keeps the same relative place after unfolding or turning", () => {
    const pos = snapKeyButton(300, verticalRange(PHONE).min + 0.25 * (verticalRange(PHONE).max - verticalRange(PHONE).min), PHONE);
    const open = placeKeyButton(pos, UNFOLDED);
    const r = verticalRange(UNFOLDED);
    expect(open.x).toBe(UNFOLDED.w - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
    expect((open.y - r.min) / (r.max - r.min)).toBeCloseTo(0.25, 2);
    const landscape: KeyButtonArea = { w: 915, h: 412, bottomInset: 0 };
    const l = placeKeyButton(pos, landscape);
    expect(l.y).toBeGreaterThanOrEqual(verticalRange(landscape).min);
    expect(l.y).toBeLessThanOrEqual(verticalRange(landscape).max);
  });

  it("falls back to the default for broken stored values", () => {
    expect(sanitizeKeyButtonPos(undefined)).toEqual(DEFAULT_KEY_BUTTON_POS);
    expect(sanitizeKeyButtonPos("x")).toEqual(DEFAULT_KEY_BUTTON_POS);
    expect(sanitizeKeyButtonPos({ edge: "top", y: Number.NaN })).toEqual(DEFAULT_KEY_BUTTON_POS);
    expect(sanitizeKeyButtonPos({ edge: "left", y: 7 })).toEqual({ edge: "left", y: 1 });
    expect(sanitizeKeyButtonPos({ edge: "left", y: -1 })).toEqual({ edge: "left", y: 0 });
  });
});

describe("keyboard button: what a tap does", () => {
  it("shows the keyboard when the field is not focused", () => {
    expect(keyButtonTap(false, false)).toBe("show");
  });
  it("hides it when it is up", () => {
    expect(keyButtonTap(true, true)).toBe("hide");
  });
  it("brings it back when Android hid it but the field kept focus", () => {
    expect(keyButtonTap(true, false)).toBe("reshow");
  });
});
