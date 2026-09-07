import { describe, expect, it } from "vitest";
import { coalesceByDamage, type DamagedUpdate } from "./WebGLRenderer";
import { RectFormat } from "./frameProtocol";

// Minimal rect matching PruneRect's shape.
const jpeg = (x: number, y: number, w: number, h: number) => ({ x, y, w, h, format: RectFormat.Jpeg });
const copy = (x: number, y: number, w: number, h: number) => ({ x, y, w, h, format: RectFormat.CopyRect });
const box = (x: number, y: number, w: number, h: number) => ({ x, y, w, h });

describe("coalesceByDamage", () => {
  it("collapses a video region across frames to the newest", () => {
    // Three frames all repainting the same region with slightly shifted tiles,
    // which the exact per-tile pruner cannot collapse.
    const u: DamagedUpdate<ReturnType<typeof jpeg>>[] = [
      { rects: [jpeg(100, 100, 40, 30)], damage: box(100, 100, 200, 150) },
      { rects: [jpeg(110, 105, 42, 28)], damage: box(100, 100, 200, 150) },
      { rects: [jpeg(105, 110, 38, 33)], damage: box(100, 100, 200, 150) },
    ];
    const r = coalesceByDamage(u);
    expect(r.kept[0]).toHaveLength(0); // superseded
    expect(r.kept[1]).toHaveLength(0); // superseded
    expect(r.kept[2]).toHaveLength(1); // newest kept
    expect(r.dropped).toBe(2);
  });

  it("keeps a menu whose damage box no video frame covers", () => {
    const u = [
      { rects: [jpeg(700, 500, 200, 300)], damage: box(700, 500, 200, 300) }, // the menu
      { rects: [jpeg(100, 100, 40, 30)], damage: box(100, 100, 200, 150) }, // video frame
      { rects: [jpeg(110, 105, 42, 28)], damage: box(100, 100, 200, 150) }, // video frame
    ];
    const r = coalesceByDamage(u);
    expect(r.kept[0]).toHaveLength(1); // menu survives
    expect(r.kept[2]).toHaveLength(1); // newest video survives
  });

  it("never drops past a CopyRect barrier", () => {
    const u = [
      { rects: [jpeg(100, 100, 40, 30)], damage: box(100, 100, 200, 150) },
      { rects: [copy(0, 0, 50, 50)], damage: box(0, 0, 50, 50) }, // barrier
      { rects: [jpeg(110, 105, 42, 28)], damage: box(100, 100, 200, 150) },
    ];
    const r = coalesceByDamage(u);
    expect(r.kept[0]).toHaveLength(1); // kept: walk stopped at the barrier above it
    expect(r.dropped).toBe(0);
  });
});
