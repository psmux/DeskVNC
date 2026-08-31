import { beforeEach, describe, expect, it } from "vitest";
import {
  forgetGroupLayout,
  hasSavedLayout,
  restoreLayout,
  savedProfiles,
  saveGroupLayout,
  serializeLayout,
} from "./groupLayout";
import {
  gridLayout,
  layoutGeometry,
  leaf,
  panes,
  resizeSplit,
  splitPane,
  type LayoutNode,
  type Rect,
} from "./layout";

const AREA: Rect = { x: 0, y: 0, width: 1200, height: 600 };

/** Sessions are named `s:<profile>` here, so the mapping is easy to read. */
const profileOf = (sessionId: string): string | null =>
  sessionId.startsWith("s:") ? sessionId.slice(2) : null;

function widths(root: LayoutNode): number[] {
  return layoutGeometry(root, AREA, 0).panes.map((p) => p.rect.width);
}

beforeEach(() => {
  localStorage.clear();
});

describe("ready made grids", () => {
  it("gives a lone pane no splits at all", () => {
    expect(panes(gridLayout(1)).length).toBe(1);
    expect(gridLayout(1).kind).toBe("leaf");
  });

  it("builds the counts people ask for in the shape they expect", () => {
    // [count, columns, rows]
    const expected: Array<[number, number, number]> = [
      [2, 2, 1],
      [4, 2, 2],
      [6, 3, 2],
      [8, 4, 2],
      [9, 3, 3],
      [12, 4, 3],
    ];
    for (const [count, cols, rows] of expected) {
      const root = gridLayout(count);
      expect(panes(root).length).toBe(count);
      const geo = layoutGeometry(root, AREA, 0);
      const distinctTops = new Set(geo.panes.map((p) => p.rect.y));
      const distinctLefts = new Set(geo.panes.map((p) => p.rect.x));
      expect(distinctTops.size).toBe(rows);
      expect(distinctLefts.size).toBe(cols);
    }
  });

  it("fills panes from the sessions given, in reading order", () => {
    const root = gridLayout(4, ["a", "b", "c"]);
    expect(panes(root).map((p) => p.sessionId)).toEqual(["a", "b", "c", null]);
  });

  it("leaves every pane empty when given no sessions", () => {
    expect(panes(gridLayout(6)).every((p) => p.sessionId === null)).toBe(true);
  });

  it("stretches a short last row rather than leaving a hole", () => {
    // 7 panes at 3 columns: 3, 3, then 1 that takes the whole width.
    const root = gridLayout(7);
    expect(panes(root).length).toBe(7);
    const all = widths(root);
    expect(all[all.length - 1]).toBe(AREA.width);
  });

  it("produces a tree the ordinary operations still work on", () => {
    // The point of building rows of splits rather than a special grid node:
    // everything downstream treats it as a layout the user built by hand.
    let root = gridLayout(4, ["a", "b", "c", "d"]);
    const target = panes(root)[0].id;
    root = splitPane(root, target, "row", leaf("e"));
    expect(panes(root).length).toBe(5);
  });

  it("refuses to build nothing", () => {
    expect(panes(gridLayout(0)).length).toBe(1);
    expect(panes(gridLayout(-3)).length).toBe(1);
  });
});

describe("saving an arrangement against a group", () => {
  it("remembers nothing until something is saved", () => {
    expect(hasSavedLayout("g1")).toBe(false);
    expect(restoreLayout("g1")).toBeNull();
    expect(savedProfiles("g1")).toEqual([]);
  });

  it("round-trips the shape, the hosts and the divider positions", () => {
    let root = gridLayout(4, ["s:one", "s:two", "s:three", "s:four"]);
    // Move a divider, so the test proves the weights survive too.
    const split = layoutGeometry(root, AREA, 0).dividers[0];
    root = resizeSplit(root, split.splitId, split.index, 120, 1200);
    const before = widths(root);

    saveGroupLayout("g1", serializeLayout(root, profileOf));
    expect(hasSavedLayout("g1")).toBe(true);

    const restored = restoreLayout("g1")!;
    expect(restored).not.toBeNull();
    // Panes come back empty, each paired with the host it is waiting for.
    expect(panes(restored.root).every((p) => p.sessionId === null)).toBe(true);
    expect(restored.places.map((x) => x.profileId)).toEqual(["one", "two", "three", "four"]);
    // Every named pane is really in the tree, and the shape is unchanged.
    const ids = panes(restored.root).map((p) => p.id);
    expect(restored.places.every((x) => ids.includes(x.paneId))).toBe(true);
    expect(widths(restored.root)).toEqual(before);
  });

  it("keeps a pane whose host stored no profile, and claims it for nobody", () => {
    // Pane one was ad-hoc, so it is remembered as a hole rather than as a host.
    const root = gridLayout(2, ["adhoc", "s:two"]);
    saveGroupLayout("g1", serializeLayout(root, profileOf));
    const restored = restoreLayout("g1")!;
    expect(panes(restored.root).length).toBe(2);
    expect(restored.places.map((x) => x.profileId)).toEqual(["two"]);
    // The claimed pane is the SECOND one, not the first: matching by position
    // would have put that machine in the ad-hoc pane's place.
    expect(restored.places[0].paneId).toBe(panes(restored.root)[1].id);
  });

  it("stores no host for an ad-hoc session, which has no profile to store", () => {
    const root = gridLayout(2, ["adhoc", "s:two"]);
    saveGroupLayout("g1", serializeLayout(root, profileOf));
    expect(savedProfiles("g1")).toEqual(["two"]);
  });

  it("lists the hosts it will need, in reading order", () => {
    const root = gridLayout(4, ["s:a", "s:b", "s:c", "s:d"]);
    saveGroupLayout("g1", serializeLayout(root, profileOf));
    expect(savedProfiles("g1")).toEqual(["a", "b", "c", "d"]);
  });

  it("keeps one group's arrangement clear of another's", () => {
    saveGroupLayout("g1", serializeLayout(gridLayout(2, ["s:a", "s:b"]), profileOf));
    saveGroupLayout("g2", serializeLayout(gridLayout(4, ["s:c"]), profileOf));
    expect(savedProfiles("g1")).toEqual(["a", "b"]);
    expect(savedProfiles("g2")).toEqual(["c"]);
    forgetGroupLayout("g1");
    expect(hasSavedLayout("g1")).toBe(false);
    expect(hasSavedLayout("g2")).toBe(true);
  });

  /**
   * Storage is shared with anything else on the origin and survives upgrades,
   * so a bad value has to read as "never arranged" rather than reaching the
   * layout code. A `NaN` weight would spread through every rectangle in the tab.
   */
  describe("refuses stored rubbish", () => {
    const bad: Array<[string, string]> = [
      ["not json at all", "{{{"],
      ["a bare number", "42"],
      ["an unknown node kind", '{"k":"x"}'],
      ["a split with one child", '{"k":"s","d":"row","w":[1],"c":[{"k":"l","p":null}]}'],
      [
        "weights that do not match the children",
        '{"k":"s","d":"row","w":[1],"c":[{"k":"l","p":null},{"k":"l","p":null}]}',
      ],
      [
        "a weight that is not a number",
        '{"k":"s","d":"row","w":[1,null],"c":[{"k":"l","p":null},{"k":"l","p":null}]}',
      ],
      [
        "a zero weight",
        '{"k":"s","d":"row","w":[1,0],"c":[{"k":"l","p":null},{"k":"l","p":null}]}',
      ],
      [
        "an axis it does not have",
        '{"k":"s","d":"sideways","w":[1,1],"c":[{"k":"l","p":null},{"k":"l","p":null}]}',
      ],
    ];
    for (const [what, raw] of bad) {
      it(what, () => {
        localStorage.setItem("deskvnc.grouplayout.g1", raw);
        expect(hasSavedLayout("g1")).toBe(false);
        expect(restoreLayout("g1")).toBeNull();
      });
    }
  });
});
