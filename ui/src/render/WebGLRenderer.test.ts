/**
 * Coverage pruning: the rule that decides which queued rects are still worth
 * applying when updates arrive faster than they can be drawn.
 *
 * The renderer itself needs a real WebGL2 context, which jsdom does not have,
 * so the pruner is a pure function over rect metadata and is tested directly.
 * Everything that can corrupt the framebuffer lives in these rules, so they
 * are worth more coverage than the GL plumbing around them.
 */
import { describe, expect, it } from "vitest";
import { RectFormat } from "./frameProtocol";
import { MAX_PENDING_UPDATES, pruneUpdates, type PruneRect } from "./WebGLRenderer";

/** A rect with an id, so surviving rects can be identified in assertions. */
interface TestRect extends PruneRect {
  id: string;
}

function rect(id: string, format: number, x: number, y: number, w: number, h: number): TestRect {
  return { id, format, x, y, w, h };
}

const SCREEN = { w: 1920, h: 1080 };

function fullScreen(id: string, format = RectFormat.Jpeg): TestRect {
  return rect(id, format, 0, 0, SCREEN.w, SCREEN.h);
}

/** Ids of every surviving rect, flattened, in the order they would be applied. */
function survivors(kept: TestRect[][]): string[] {
  return kept.flatMap((rects) => rects.map((r) => r.id));
}

describe("pruneUpdates", () => {
  it("drops an RGBA rect a later full-screen rect completely covers", () => {
    const { kept, dropped } = pruneUpdates<TestRect>([
      [rect("old", RectFormat.Rgba, 100, 100, 64, 64)],
      [fullScreen("new", RectFormat.Rgba)],
    ]);
    expect(survivors(kept)).toEqual(["new"]);
    expect(dropped).toBe(1);
  });

  it("collapses a backlog of video-sized JPEG updates to the newest", () => {
    const backlog = Array.from({ length: 30 }, (_, i) => [fullScreen(`f${i}`)]);
    const { kept } = pruneUpdates<TestRect>(backlog);
    expect(survivors(kept)).toEqual(["f29"]);
  });

  it("keeps a rect only partially covered by later rects", () => {
    const { kept, dropped } = pruneUpdates<TestRect>([
      [rect("old", RectFormat.Jpeg, 0, 0, 200, 200)],
      [rect("new", RectFormat.Jpeg, 0, 0, 200, 100)], // covers the top half only
    ]);
    expect(survivors(kept)).toEqual(["old", "new"]);
    expect(dropped).toBe(0);
  });

  it("drops a rect covered by the union of two later rects", () => {
    const { kept } = pruneUpdates<TestRect>([
      [rect("old", RectFormat.Jpeg, 0, 0, 200, 200)],
      [
        rect("top", RectFormat.Jpeg, 0, 0, 200, 100),
        rect("bottom", RectFormat.Jpeg, 0, 100, 200, 100),
      ],
    ]);
    expect(survivors(kept)).toEqual(["top", "bottom"]);
  });

  it("drops a rect covered by a later rect in the same update", () => {
    const { kept } = pruneUpdates<TestRect>([
      [rect("under", RectFormat.Jpeg, 10, 10, 20, 20), fullScreen("over")],
    ]);
    expect(survivors(kept)).toEqual(["over"]);
  });

  it("never drops a CopyRect, and keeps everything older than one", () => {
    // The covered RGBA rect would go if the CopyRect were not there: the
    // CopyRect reads the pixels it puts down, so it must not.
    const { kept, dropped } = pruneUpdates<TestRect>([
      [rect("source", RectFormat.Rgba, 100, 100, 64, 64)],
      [rect("copy", RectFormat.CopyRect, 400, 400, 64, 64)],
      [fullScreen("new", RectFormat.Rgba)],
    ]);
    expect(survivors(kept)).toEqual(["source", "copy", "new"]);
    expect(dropped).toBe(0);
  });

  it("keeps rects that precede a CopyRect inside the same update", () => {
    const { kept } = pruneUpdates<TestRect>([
      [
        rect("before", RectFormat.Rgba, 0, 0, 64, 64),
        rect("copy", RectFormat.CopyRect, 0, 0, 64, 64),
      ],
      [fullScreen("new", RectFormat.Rgba)],
    ]);
    expect(survivors(kept)).toEqual(["before", "copy", "new"]);
  });

  it("prunes rects newer than a CopyRect, which only blocks older ones", () => {
    const { kept } = pruneUpdates<TestRect>([
      [rect("copy", RectFormat.CopyRect, 0, 0, 64, 64)],
      [rect("covered", RectFormat.Jpeg, 10, 10, 32, 32)],
      [fullScreen("new")],
    ]);
    expect(survivors(kept)).toEqual(["copy", "new"]);
  });

  it("never drops an H.264 rect", () => {
    const { kept, dropped } = pruneUpdates<TestRect>([
      [fullScreen("h1", RectFormat.H264)],
      [fullScreen("h2", RectFormat.H264)],
      [fullScreen("h3", RectFormat.H264)],
    ]);
    expect(survivors(kept)).toEqual(["h1", "h2", "h3"]);
    expect(dropped).toBe(0);
  });

  it("keeps an H.264 rect and everything queued before it", () => {
    const { kept } = pruneUpdates<TestRect>([
      [rect("older", RectFormat.Jpeg, 0, 0, 100, 100)],
      [fullScreen("video", RectFormat.H264)],
      [fullScreen("new")],
    ]);
    expect(survivors(kept)).toEqual(["older", "video", "new"]);
  });

  it("preserves protocol order among the survivors", () => {
    const { kept } = pruneUpdates<TestRect>([
      [
        rect("a", RectFormat.Jpeg, 0, 0, 100, 100),
        rect("b", RectFormat.Jpeg, 200, 0, 100, 100),
      ],
      [
        rect("c", RectFormat.Jpeg, 0, 0, 100, 100), // covers "a"
        rect("d", RectFormat.Jpeg, 400, 0, 100, 100),
      ],
    ]);
    expect(survivors(kept)).toEqual(["b", "c", "d"]);
    // Same update, same positions: pruning removes, it never reorders.
    expect(kept[0].map((r) => r.id)).toEqual(["b"]);
    expect(kept[1].map((r) => r.id)).toEqual(["c", "d"]);
  });

  it("leaves rects of unknown format alone", () => {
    const { kept } = pruneUpdates<TestRect>([
      [rect("odd", 99, 0, 0, 100, 100)],
      [fullScreen("new")],
    ]);
    expect(survivors(kept)).toEqual(["odd", "new"]);
  });

  it("keeps every update's array slot, so the queue can be rewritten in place", () => {
    const pending = [[fullScreen("old")], [fullScreen("new")]];
    const { kept } = pruneUpdates<TestRect>(pending);
    expect(kept).toHaveLength(pending.length);
    expect(kept[0]).toEqual([]);
  });

  describe("over the queue cap", () => {
    it("keeps only barriers and the newest update", () => {
      // None of these cover each other, so nothing is droppable on coverage
      // alone: this is the shed-everything path.
      const pending = Array.from({ length: 8 }, (_, i) => [
        rect(`r${i}`, RectFormat.Jpeg, i * 10, 0, 8, 8),
      ]);
      const { kept, dropped } = pruneUpdates<TestRect>(pending, true);
      expect(survivors(kept)).toEqual(["r7"]);
      expect(dropped).toBe(7);
    });

    it("still refuses to drop a CopyRect or an H.264 rect", () => {
      const { kept } = pruneUpdates<TestRect>(
        [
          [rect("a", RectFormat.Jpeg, 0, 0, 8, 8)],
          [rect("copy", RectFormat.CopyRect, 0, 0, 8, 8)],
          [fullScreen("video", RectFormat.H264)],
          [rect("b", RectFormat.Jpeg, 500, 0, 8, 8)],
          [rect("newest", RectFormat.Jpeg, 900, 0, 8, 8)],
        ],
        true,
      );
      expect(survivors(kept)).toEqual(["a", "copy", "video", "newest"]);
    });

    it("bounds a burst of many uncovered updates", () => {
      const burst = Array.from({ length: 200 }, (_, i) => [
        rect(`r${i}`, RectFormat.Rgba, (i * 7) % 1900, 0, 8, 8),
      ]);
      const { kept } = pruneUpdates<TestRect>(burst, burst.length > MAX_PENDING_UPDATES);
      expect(survivors(kept)).toHaveLength(1);
    });

    it("bounds a burst of overlapping full-screen updates without the cap", () => {
      const burst = Array.from({ length: 200 }, (_, i) => [fullScreen(`f${i}`)]);
      const { kept, dropped } = pruneUpdates<TestRect>(burst);
      expect(survivors(kept)).toEqual(["f199"]);
      expect(dropped).toBe(199);
    });
  });
});
