import { describe, expect, it } from "vitest";
import {
  DETECTED_LEFT_ID,
  DETECTED_RIGHT_ID,
  buildDisplayOptions,
  matchDisplay,
  orderDisplays,
  toChoice,
} from "./displays";
import type { DisplayOption, RemoteScreen } from "./types";

const screen = (id: number, x: number, width: number, height = 1080): RemoteScreen => ({
  id,
  x,
  y: 0,
  width,
  height,
});

describe("buildDisplayOptions", () => {
  it("uses the server's layout when it describes two or more monitors", () => {
    const layout = [screen(7, 1920, 1920), screen(3, 0, 1920)];
    expect(buildDisplayOptions(layout, { w: 3840, h: 1080 }, 1600)).toBe(layout);
  });

  it("offers nothing before the first frame has said how big the desktop is", () => {
    expect(buildDisplayOptions([], null, null)).toEqual([]);
  });

  it("puts a detected pair above the manual cuts and drops the cut it duplicates", () => {
    const opts = buildDisplayOptions([], { w: 3840, h: 1080 }, 1920);
    expect(opts[0].id).toBe(DETECTED_LEFT_ID);
    expect(opts[1].id).toBe(DETECTED_RIGHT_ID);
    // 3840 halves at exactly 1920, which is where the seam was found, so the
    // "Left half" cut would be the same rectangle offered twice.
    const leftHalves = opts.filter((o) => o.x === 0 && o.width === 1920);
    expect(leftHalves).toHaveLength(1);
  });

  it("keeps the manual cuts when detection found nothing", () => {
    const opts = buildDisplayOptions([], { w: 3840, h: 1080 }, null);
    expect(opts.every((o) => o.id !== DETECTED_LEFT_ID)).toBe(true);
    expect(opts.some((o) => o.x === 0 && o.width === 1920)).toBe(true);
  });

  it("ignores a seam that does not fall inside the desktop", () => {
    expect(buildDisplayOptions([], { w: 3840, h: 1080 }, 3840)).not.toContainEqual(
      expect.objectContaining({ id: DETECTED_LEFT_ID }),
    );
  });
});

describe("matchDisplay", () => {
  const layout: DisplayOption[] = [screen(3, 0, 1920), screen(7, 1920, 2560)];

  it("has nothing to match when the whole desktop is showing", () => {
    expect(matchDisplay(null, layout)).toBeNull();
  });

  it("finds the monitor whose rectangle is unchanged", () => {
    const want = toChoice(layout[1]);
    expect(matchDisplay(want, layout)?.id).toBe(7);
  });

  it("survives a reconnect that arrives with no layout yet, then finds it again", () => {
    const want = toChoice(layout[1]);
    // The screen list is empty between the reconnect and the server describing
    // itself again. Nothing matches, so the whole desktop shows...
    expect(matchDisplay(want, [])).toBeNull();
    // ...and the moment the layout is back, so is the monitor. This is the
    // reported bug: the old code cleared the choice during the gap.
    expect(matchDisplay(want, layout)?.id).toBe(7);
  });

  it("follows a server-described monitor that moved, by its id", () => {
    const want = toChoice(layout[1]);
    const rearranged: DisplayOption[] = [screen(7, 0, 2560), screen(3, 2560, 1920)];
    expect(matchDisplay(want, rearranged)?.id).toBe(7);
  });

  it("follows the detected pair when the seam shifts between runs", () => {
    const want = { id: DETECTED_LEFT_ID, x: 0, y: 0, width: 1920, height: 1080 };
    const moved = buildDisplayOptions([], { w: 3840, h: 1080 }, 1918);
    expect(matchDisplay(want, moved)?.width).toBe(1918);
  });

  it("falls back to the equivalent manual cut when detection comes back empty", () => {
    const want = { id: DETECTED_LEFT_ID, x: 0, y: 0, width: 1920, height: 1080 };
    const noSeam = buildDisplayOptions([], { w: 3840, h: 1080 }, null);
    expect(noSeam.some((o) => o.id === DETECTED_LEFT_ID)).toBe(false);
    expect(matchDisplay(want, noSeam)?.width).toBe(1920);
  });

  it("will not carry a manual cut onto a desktop where its rectangle is gone", () => {
    // -1 is "the left half", which on a 3840 desktop meant 1920 pixels and on
    // a 1600 one means 800. Matching it by id would silently show a different
    // part of the screen than the one that was picked, so it does not.
    const want = { id: -1, x: 0, y: 0, width: 1920, height: 1080 };
    const smaller = buildDisplayOptions([], { w: 1600, h: 1080 }, null);
    expect(smaller.some((o) => o.id === -1)).toBe(true);
    expect(matchDisplay(want, smaller)).toBeNull();
  });

  it("keeps a manual cut when the desktop comes back the same", () => {
    const opts = buildDisplayOptions([], { w: 3840, h: 1080 }, null);
    const want = toChoice(opts.find((o) => o.x === 0 && o.width === 1920));
    expect(matchDisplay(want, buildDisplayOptions([], { w: 3840, h: 1080 }, null))?.width).toBe(
      1920,
    );
  });
});

describe("orderDisplays", () => {
  it("puts a real layout in reading order, whatever order the server listed it", () => {
    const layout = [screen(7, 1920, 1920), screen(3, 0, 1920)];
    expect(orderDisplays(layout, true).map((o) => o.id)).toEqual([3, 7]);
  });

  it("leaves the guesses in the order they were authored", () => {
    // Sorting by x would interleave every "Left ..." ahead of every "Right".
    const opts = buildDisplayOptions([], { w: 3840, h: 1080 }, null);
    expect(orderDisplays(opts, false)).toBe(opts);
  });
});
