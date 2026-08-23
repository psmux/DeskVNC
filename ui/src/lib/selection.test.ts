import { describe, expect, it } from "vitest";
import {
  dragPayload,
  idsBetween,
  idsInRect,
  marqueeSelection,
  pressSelection,
  pruneSelection,
  rectFromPoints,
  rectsIntersect,
  type Rect,
  type SelectionState,
} from "./selection";

const ORDER = ["a", "b", "c", "d", "e"];

function state(ids: string[], anchor: string | null = null): SelectionState {
  return { ids: new Set(ids), anchor };
}

const NONE = { toggle: false, range: false };
const TOGGLE = { toggle: true, range: false };
const RANGE = { toggle: false, range: true };

describe("pressSelection", () => {
  it("a plain press replaces the selection", () => {
    const r = pressSelection(state(["a", "b"]), ORDER, "d", NONE);
    expect([...r.ids]).toEqual(["d"]);
    expect(r.anchor).toBe("d");
    expect(r.collapseOnRelease).toBe(false);
  });

  it("keeps a multi-selection intact when the press lands inside it, so the drag can carry it", () => {
    const r = pressSelection(state(["a", "b", "c"], "a"), ORDER, "b", NONE);
    expect([...r.ids].sort()).toEqual(["a", "b", "c"]);
    expect(r.collapseOnRelease).toBe(true);
  });

  it("collapses nothing when the press lands on the only selected tile", () => {
    const r = pressSelection(state(["b"], "b"), ORDER, "b", NONE);
    expect([...r.ids]).toEqual(["b"]);
    expect(r.collapseOnRelease).toBe(false);
  });

  it("toggle adds and removes one", () => {
    const added = pressSelection(state(["a"], "a"), ORDER, "c", TOGGLE);
    expect([...added.ids].sort()).toEqual(["a", "c"]);
    const removed = pressSelection(added, ORDER, "a", TOGGLE);
    expect([...removed.ids]).toEqual(["c"]);
  });

  it("shift extends from the anchor, in either direction", () => {
    const down = pressSelection(state(["b"], "b"), ORDER, "d", RANGE);
    expect([...down.ids]).toEqual(["b", "c", "d"]);
    const up = pressSelection(state(["d"], "d"), ORDER, "b", RANGE);
    expect([...up.ids]).toEqual(["b", "c", "d"]);
  });

  it("keeps the anchor still, so a second shift-click re-measures rather than creeping", () => {
    const first = pressSelection(state(["b"], "b"), ORDER, "d", RANGE);
    const second = pressSelection(first, ORDER, "c", RANGE);
    expect([...second.ids]).toEqual(["b", "c"]);
    expect(second.anchor).toBe("b");
  });

  it("falls back to a plain press when the anchor has been filtered off screen", () => {
    const r = pressSelection(state(["z"], "z"), ORDER, "c", RANGE);
    expect([...r.ids]).toEqual(["c"]);
    expect(r.anchor).toBe("c");
  });
});

describe("idsBetween", () => {
  it("is inclusive at both ends", () => {
    expect(idsBetween(ORDER, "b", "d")).toEqual(["b", "c", "d"]);
  });

  it("is empty when an end is missing", () => {
    expect(idsBetween(ORDER, "b", "zz")).toEqual([]);
  });
});

describe("marquee geometry", () => {
  const tile = (left: number, top: number): Rect => ({
    left,
    top,
    right: left + 100,
    bottom: top + 60,
  });

  it("normalizes a rectangle dragged up and to the left", () => {
    expect(rectFromPoints(120, 90, 20, 10)).toEqual({ left: 20, top: 10, right: 120, bottom: 90 });
  });

  it("counts an overlap but not a touching edge", () => {
    expect(rectsIntersect(tile(0, 0), rectFromPoints(50, 30, 200, 200))).toBe(true);
    expect(rectsIntersect(tile(0, 0), rectFromPoints(100, 0, 200, 60))).toBe(false);
  });

  it("collects every tile the band crosses", () => {
    const rects = [
      { id: "a", rect: tile(0, 0) },
      { id: "b", rect: tile(120, 0) },
      { id: "c", rect: tile(0, 80) },
    ];
    expect(idsInRect(rects, rectFromPoints(10, 10, 130, 20))).toEqual(["a", "b"]);
  });

  it("adds to the set the drag started from only when asked", () => {
    expect([...marqueeSelection(new Set(["z"]), ["a"], true)].sort()).toEqual(["a", "z"]);
    expect([...marqueeSelection(new Set(["z"]), ["a"], false)]).toEqual(["a"]);
  });
});

describe("pruneSelection", () => {
  it("forgets hosts that are no longer listed", () => {
    expect([...pruneSelection(new Set(["a", "gone"]), ORDER)]).toEqual(["a"]);
  });
});

describe("dragPayload", () => {
  it("carries the whole selection when the pressed tile belongs to it", () => {
    expect(dragPayload(new Set(["a", "b"]), "b").sort()).toEqual(["a", "b"]);
  });

  it("carries just the pressed tile otherwise", () => {
    expect(dragPayload(new Set(["a", "b"]), "c")).toEqual(["c"]);
  });
});
