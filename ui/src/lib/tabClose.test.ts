import { describe, expect, it } from "vitest";
import { frontAfterClose, tabsToClose } from "./tabClose";

const ids = ["a", "b", "c", "d"];

describe("tabsToClose", () => {
  it("takes the tabs a browser would for each command", () => {
    expect(tabsToClose(ids, "b", "this")).toEqual(["b"]);
    expect(tabsToClose(ids, "b", "others")).toEqual(["a", "c", "d"]);
    expect(tabsToClose(ids, "b", "left")).toEqual(["a"]);
    expect(tabsToClose(ids, "b", "right")).toEqual(["c", "d"]);
    expect(tabsToClose(ids, "b", "all")).toEqual(ids);
  });

  it("has nothing to the left of the first tab or the right of the last", () => {
    expect(tabsToClose(ids, "a", "left")).toEqual([]);
    expect(tabsToClose(ids, "d", "right")).toEqual([]);
  });

  it("closes every tab from the library, which is never one of them", () => {
    expect(tabsToClose(ids, null, "all")).toEqual(ids);
    expect(tabsToClose(ids, null, "others")).toEqual([]);
  });

  it("closes nothing for a tab that has already gone", () => {
    expect(tabsToClose(ids, "z", "right")).toEqual([]);
  });
});

describe("frontAfterClose", () => {
  it("keeps the front tab when it survives", () => {
    expect(frontAfterClose(ids, "a", new Set(["c", "d"]))).toBe("a");
    expect(frontAfterClose(ids, null, new Set(ids))).toBeNull();
  });

  it("lands on the nearest survivor to the right, then to the left", () => {
    expect(frontAfterClose(ids, "b", new Set(["b", "c"]))).toBe("d");
    expect(frontAfterClose(ids, "c", new Set(["c", "d"]))).toBe("b");
  });

  it("falls back to the library when every tab goes", () => {
    expect(frontAfterClose(ids, "b", new Set(ids))).toBeNull();
  });
});
