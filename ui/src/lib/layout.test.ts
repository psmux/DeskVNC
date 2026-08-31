import { describe, expect, it } from "vitest";
import {
  closePane,
  cyclePane,
  dividerAt,
  evenAll,
  layoutGeometry,
  leaf,
  neighbour,
  panes,
  placedSessions,
  resizeSplit,
  setPaneSession,
  splitExtent,
  splitPane,
  swapPanes,
  type LayoutNode,
  type Rect,
} from "./layout";

const AREA: Rect = { x: 0, y: 0, width: 1000, height: 600 };

/** Panes by id, so a test can name the thing it just made. */
function ids(root: LayoutNode): string[] {
  return panes(root).map((p) => p.id);
}

function rectOf(root: LayoutNode, paneId: string, gap = 0): Rect {
  const found = layoutGeometry(root, AREA, gap).panes.find((p) => p.pane.id === paneId);
  if (!found) throw new Error(`no pane ${paneId}`);
  return found.rect;
}

describe("splitting", () => {
  it("turns a lone pane into a row of two, sharing the area", () => {
    const a = leaf("s1", "a");
    const root = splitPane(a, "a", "row", leaf("s2", "b"));
    expect(ids(root)).toEqual(["a", "b"]);
    expect(rectOf(root, "a")).toEqual({ x: 0, y: 0, width: 500, height: 600 });
    expect(rectOf(root, "b")).toEqual({ x: 500, y: 0, width: 500, height: 600 });
  });

  it("splits downward into a column", () => {
    const root = splitPane(leaf("s1", "a"), "a", "column", leaf("s2", "b"));
    expect(rectOf(root, "a")).toEqual({ x: 0, y: 0, width: 1000, height: 300 });
    expect(rectOf(root, "b")).toEqual({ x: 0, y: 300, width: 1000, height: 300 });
  });

  it("places the new pane before the old one when asked", () => {
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"), "before");
    expect(ids(root)).toEqual(["b", "a"]);
  });

  /**
   * The behaviour that makes this an n-ary tree rather than a binary one, and
   * the reason a third pane does not cost the second one half its width.
   */
  it("splitting again along the same axis extends the row instead of nesting", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "a", "row", leaf("s3", "c"));

    expect(root.kind).toBe("split");
    if (root.kind !== "split") throw new Error("expected a split");
    // One row of three, not a row containing a row.
    expect(root.children.every((child) => child.kind === "leaf")).toBe(true);
    expect(ids(root)).toEqual(["a", "c", "b"]);

    // `a` gave up half of its own half; `b` is untouched.
    expect(rectOf(root, "a").width).toBe(250);
    expect(rectOf(root, "c").width).toBe(250);
    expect(rectOf(root, "b").width).toBe(500);
  });

  it("splitting across the axis nests, and only within that pane's box", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "b", "column", leaf("s3", "c"));

    expect(rectOf(root, "a")).toEqual({ x: 0, y: 0, width: 500, height: 600 });
    expect(rectOf(root, "b")).toEqual({ x: 500, y: 0, width: 500, height: 300 });
    expect(rectOf(root, "c")).toEqual({ x: 500, y: 300, width: 500, height: 300 });
  });

  it("leaves a tree alone when the pane is not in it", () => {
    const root = splitPane(leaf("s1", "a"), "nope", "row", leaf("s2", "b"));
    expect(ids(root)).toEqual(["a"]);
  });
});

describe("closing", () => {
  it("hands the space back to the remaining sibling", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    const after = closePane(root, "b");
    expect(after).not.toBeNull();
    expect(ids(after!)).toEqual(["a"]);
    // The split collapsed, so the survivor is the whole area again.
    expect(rectOf(after!, "a")).toEqual(AREA);
  });

  it("shares a closed pane's space out in proportion", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "b", "row", leaf("s3", "c"));
    // a: 500, b: 250, c: 250
    const after = closePane(root, "a")!;
    expect(ids(after)).toEqual(["b", "c"]);
    expect(rectOf(after, "b").width).toBe(500);
    expect(rectOf(after, "c").width).toBe(500);
  });

  it("returns null when the last pane goes", () => {
    expect(closePane(leaf("s1", "a"), "a")).toBeNull();
  });

  it("flattens a nested split back out when it drops to one child", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b")); // row: a | b
    root = splitPane(root, "b", "column", leaf("s3", "c")); // b over c, inside the row
    root = splitPane(root, "c", "row", leaf("s4", "d")); // c | d, inside that column

    const after = closePane(root, "b")!;
    // The column had b over (c|d); losing b leaves the row (c|d), which is the
    // same axis as its grandparent and must merge into it.
    if (after.kind !== "split") throw new Error("expected a split");
    expect(after.dir).toBe("row");
    expect(after.children.every((child) => child.kind === "leaf")).toBe(true);
    expect(ids(after)).toEqual(["a", "c", "d"]);
    // a keeps its half; c and d share the other half that the column held.
    expect(rectOf(after, "a").width).toBe(500);
    expect(rectOf(after, "c").width).toBe(250);
    expect(rectOf(after, "d").width).toBe(250);
  });

  it("leaves a tree alone when the pane is not in it", () => {
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"));
    expect(closePane(root, "nope")).toBe(root);
  });
});

describe("sessions in panes", () => {
  it("moves a session between panes without moving the panes", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    const swapped = swapPanes(root, "a", "b");
    expect(panes(swapped).map((p) => p.sessionId)).toEqual(["s2", "s1"]);
    // Same boxes, only the contents traded.
    expect(rectOf(swapped, "a")).toEqual(rectOf(root, "a"));
  });

  it("empties a pane without removing it", () => {
    const root = setPaneSession(leaf("s1", "a"), "a", null);
    expect(panes(root)[0].sessionId).toBeNull();
    expect(placedSessions(root)).toEqual([]);
  });

  it("reports each placed session once", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s1", "b"));
    root = splitPane(root, "b", "row", leaf("s2", "c"));
    expect(placedSessions(root).sort()).toEqual(["s1", "s2"]);
  });

  it("returns the same tree when nothing would change", () => {
    const root = leaf("s1", "a");
    expect(setPaneSession(root, "a", "s1")).toBe(root);
  });
});

describe("dividers", () => {
  it("takes its thickness out of the panes, not out of the area", () => {
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"));
    const geo = layoutGeometry(root, AREA, 6);
    expect(geo.panes.map((p) => p.rect.width)).toEqual([497, 497]);
    expect(geo.dividers).toHaveLength(1);
    expect(geo.dividers[0].rect).toEqual({ x: 497, y: 0, width: 6, height: 600 });
    // Nothing is lost: pane, gap, pane covers the area exactly.
    expect(497 + 6 + 497).toBe(1000);
  });

  it("gives a row of three two dividers, one per gap", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "a", "row", leaf("s3", "c"));
    const geo = layoutGeometry(root, AREA, 4);
    expect(geo.dividers.map((d) => d.index)).toEqual([0, 1]);
    expect(geo.dividers.every((d) => d.dir === "row")).toBe(true);
  });

  it("finds the divider under the pointer, with slack for a mouse", () => {
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"));
    const geo = layoutGeometry(root, AREA, 4);
    expect(dividerAt(geo, 499, 300)).not.toBeNull();
    // Just outside the drawn gap, still within reach.
    expect(dividerAt(geo, 496, 300)).not.toBeNull();
    expect(dividerAt(geo, 400, 300)).toBeNull();
  });

  it("drags a divider by exactly the pixels asked for", () => {
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"));
    if (root.kind !== "split") throw new Error("expected a split");
    const extent = splitExtent(root, root.id, AREA, 0);
    expect(extent).toBe(1000);
    const dragged = resizeSplit(root, root.id, 0, 100, extent);
    expect(rectOf(dragged, "a").width).toBe(600);
    expect(rectOf(dragged, "b").width).toBe(400);
  });

  it("stops a pane at its minimum rather than collapsing it", () => {
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"));
    if (root.kind !== "split") throw new Error("expected a split");
    const dragged = resizeSplit(root, root.id, 0, -100000, 1000);
    expect(rectOf(dragged, "a").width).toBe(80);
    // The pair still adds up, so nothing else in the split moved.
    expect(rectOf(dragged, "b").width).toBe(920);
  });

  it("moves only the two panes either side of the divider", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "b", "row", leaf("s3", "c"));
    if (root.kind !== "split") throw new Error("expected a split");
    // a: 500, b: 250, c: 250. Drag the gap between b and c.
    const dragged = resizeSplit(root, root.id, 1, 50, 1000);
    expect(rectOf(dragged, "a").width).toBe(500);
    expect(rectOf(dragged, "b").width).toBe(300);
    expect(rectOf(dragged, "c").width).toBe(200);
  });

  it("scales a drag inside a nested split against that split's own extent", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b")); // two 500px columns
    root = splitPane(root, "b", "column", leaf("s3", "c")); // b over c, 300px each
    const inner = layoutGeometry(root, AREA, 0).dividers.find((d) => d.dir === "column");
    if (!inner) throw new Error("expected a horizontal divider");
    const extent = splitExtent(root, inner.splitId, AREA, 0);
    expect(extent).toBe(600);
    const dragged = resizeSplit(root, inner.splitId, 0, 60, extent);
    expect(rectOf(dragged, "b").height).toBe(360);
    expect(rectOf(dragged, "c").height).toBe(240);
    // The outer row is untouched.
    expect(rectOf(dragged, "a").width).toBe(500);
  });

  /**
   * A window can be narrower than twice the minimum pane size, at which point
   * the clamp has no room to work in. The first version of this returned the
   * wrong end of an inverted range, so a drag moved the divider the OTHER way
   * and wrote a negative weight, which then spread through every later split.
   */
  describe("in a window too narrow to honour the minimum", () => {
    /** Three panes across 150px: no pair can both reach MIN_PANE_PX. */
    function cramped(): LayoutNode {
      let root: LayoutNode = leaf("s1", "a");
      root = splitPane(root, "a", "row", leaf("s2", "b"));
      root = splitPane(root, "b", "row", leaf("s3", "c"));
      return root;
    }
    const NARROW: Rect = { x: 0, y: 0, width: 150, height: 100 };

    it("refuses the drag rather than moving the divider the wrong way", () => {
      const root = cramped();
      if (root.kind !== "split") throw new Error("expected a split");
      const before = layoutGeometry(root, NARROW, 6).panes.map((p) => p.rect.width);
      const dragged = resizeSplit(root, root.id, 0, -500, 138);
      const after = layoutGeometry(dragged, NARROW, 6).panes.map((p) => p.rect.width);
      expect(after).toEqual(before);
    });

    it("never writes a weight that is zero or negative", () => {
      let root = cramped();
      if (root.kind !== "split") throw new Error("expected a split");
      for (const delta of [-500, 500, -37, 37, -1000]) {
        for (const index of [0, 1]) {
          root = resizeSplit(root, root.id, index, delta, 138);
          if (root.kind !== "split") throw new Error("the shape must not change");
          expect(root.weights.every((w) => w > 0)).toBe(true);
        }
      }
    });

    it("keeps every pane inside the area, whatever the drag", () => {
      let root = cramped();
      if (root.kind !== "split") throw new Error("expected a split");
      root = resizeSplit(root, root.id, 0, -900, 138);
      root = resizeSplit(root, root.id, 1, -900, 138);
      const geo = layoutGeometry(root, NARROW, 6);
      for (const { rect } of geo.panes) {
        expect(rect.x).toBeGreaterThanOrEqual(0);
        expect(rect.width).toBeGreaterThanOrEqual(0);
        expect(rect.x + rect.width).toBeLessThanOrEqual(NARROW.width);
      }
    });
  });

  it("still stops at the minimum when there is room for one", () => {
    // 300px across two panes: one can reach 80 while the other keeps 220.
    const root = splitPane(leaf("s1", "a"), "a", "row", leaf("s2", "b"));
    if (root.kind !== "split") throw new Error("expected a split");
    const dragged = resizeSplit(root, root.id, 0, -500, 300);
    const widths = layoutGeometry(dragged, { x: 0, y: 0, width: 300, height: 100 }, 0)
      .panes.map((p) => p.rect.width);
    expect(widths).toEqual([80, 220]);
  });

  it("evens out a lopsided tree", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "a", "row", leaf("s3", "c"));
    const even = evenAll(root);
    const widths = layoutGeometry(even, AREA, 0).panes.map((p) => p.rect.width);
    expect(widths).toEqual([333, 334, 333]);
    expect(widths.reduce((x, y) => x + y, 0)).toBe(1000);
  });
});

describe("geometry", () => {
  it("leaves no seam between panes at any weight", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "b", "row", leaf("s3", "c"));
    if (root.kind !== "split") throw new Error("expected a split");
    root = resizeSplit(root, root.id, 0, 37, 1000);

    const rects = layoutGeometry(root, AREA, 0).panes.map((p) => p.rect);
    // Each pane starts exactly where the previous one ended.
    for (let i = 1; i < rects.length; i += 1) {
      expect(rects[i].x).toBe(rects[i - 1].x + rects[i - 1].width);
    }
    const last = rects[rects.length - 1];
    expect(last.x + last.width).toBe(1000);
  });

  it("never produces a negative size when the dividers outgrow the area", () => {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "b", "row", leaf("s3", "c"));
    const geo = layoutGeometry(root, { x: 0, y: 0, width: 8, height: 40 }, 10);
    expect(geo.panes.every((p) => p.rect.width >= 0 && p.rect.height >= 0)).toBe(true);
  });

  it("offsets every box by the area's origin", () => {
    const root = splitPane(leaf("s1", "a"), "a", "column", leaf("s2", "b"));
    const geo = layoutGeometry(root, { x: 40, y: 25, width: 200, height: 100 }, 0);
    expect(geo.panes[0].rect).toEqual({ x: 40, y: 25, width: 200, height: 50 });
    expect(geo.panes[1].rect).toEqual({ x: 40, y: 75, width: 200, height: 50 });
  });
});

describe("moving the focus", () => {
  /**
   *   +-----+-----+
   *   |  a  |  b  |
   *   +-----+-----+
   *   |  c  |  d  |
   *   +-----+-----+
   */
  function grid(): LayoutNode {
    let root: LayoutNode = leaf("s1", "a");
    root = splitPane(root, "a", "row", leaf("s2", "b"));
    root = splitPane(root, "a", "column", leaf("s3", "c"));
    root = splitPane(root, "b", "column", leaf("s4", "d"));
    return root;
  }

  it("crosses to the pane the user can see on that side", () => {
    const geo = layoutGeometry(grid(), AREA, 0);
    expect(neighbour(geo, "a", "right")).toBe("b");
    expect(neighbour(geo, "b", "left")).toBe("a");
    expect(neighbour(geo, "a", "down")).toBe("c");
    expect(neighbour(geo, "d", "up")).toBe("b");
  });

  it("stops at the edge of the layout", () => {
    const geo = layoutGeometry(grid(), AREA, 0);
    expect(neighbour(geo, "a", "left")).toBeNull();
    expect(neighbour(geo, "a", "up")).toBeNull();
    expect(neighbour(geo, "d", "right")).toBeNull();
    expect(neighbour(geo, "d", "down")).toBeNull();
  });

  it("ignores a pane that is diagonally across rather than beside", () => {
    // A tall left pane against two stacked right ones: from the top right
    // pane, "left" is the tall one, and from the bottom right it is too.
    let root: LayoutNode = leaf("s1", "tall");
    root = splitPane(root, "tall", "row", leaf("s2", "top"));
    root = splitPane(root, "top", "column", leaf("s3", "bottom"));
    const geo = layoutGeometry(root, AREA, 0);
    expect(neighbour(geo, "top", "left")).toBe("tall");
    expect(neighbour(geo, "bottom", "left")).toBe("tall");
    expect(neighbour(geo, "top", "down")).toBe("bottom");
    expect(neighbour(geo, "top", "right")).toBeNull();
  });

  it("picks the nearest pane when several sit on the same side", () => {
    // One tall pane on the left, three stacked on the right. Its own centre is
    // level with the middle one, which is the one to land on.
    let root: LayoutNode = leaf("s1", "tall");
    root = splitPane(root, "tall", "row", leaf("s2", "r1"));
    root = splitPane(root, "r1", "column", leaf("s3", "r2"));
    root = splitPane(root, "r2", "column", leaf("s4", "r3"));
    const geo = layoutGeometry(root, AREA, 0);
    expect(neighbour(geo, "tall", "right")).toBe("r2");
  });

  it("cycles through the panes in reading order, wrapping", () => {
    const root = grid();
    expect(ids(root)).toEqual(["a", "c", "b", "d"]);
    expect(cyclePane(root, "a", 1)).toBe("c");
    expect(cyclePane(root, "d", 1)).toBe("a");
    expect(cyclePane(root, "a", -1)).toBe("d");
  });

  it("falls back to the first pane when the current one has gone", () => {
    expect(cyclePane(grid(), "vanished", 1)).toBe("a");
  });
});
