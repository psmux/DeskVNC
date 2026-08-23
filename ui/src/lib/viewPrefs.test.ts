import { beforeEach, describe, expect, it } from "vitest";
import {
  FACTORY_DEFAULTS,
  readViewDefaults,
  readViewPrefs,
  sameViewPrefs,
  viewPrefsKey,
  writeViewDefaults,
  writeViewPrefs,
} from "./viewPrefs";

beforeEach(() => {
  localStorage.clear();
});

describe("viewPrefsKey", () => {
  it("keys by saved host, so renaming or re-addressing it keeps what it learnt", () => {
    expect(viewPrefsKey({ profileId: "abc", address: "10.0.0.1", port: 5900 })).toBe(
      viewPrefsKey({ profileId: "abc", address: "10.0.0.9", port: 5901 }),
    );
  });

  it("falls back to the endpoint for a quick connect, case and trailing dot aside", () => {
    expect(viewPrefsKey({ profileId: null, address: "Office.local.", port: 5900 })).toBe(
      viewPrefsKey({ profileId: null, address: "office.local", port: 5900 }),
    );
  });

  it("separates two ports on one address", () => {
    expect(viewPrefsKey({ profileId: null, address: "h", port: 5900 })).not.toBe(
      viewPrefsKey({ profileId: null, address: "h", port: 5901 }),
    );
  });

  it("has no key, and so remembers nothing, when there is nothing to key on", () => {
    expect(viewPrefsKey({ profileId: "  ", address: null, port: 5900 })).toBeNull();
  });
});

describe("readViewPrefs", () => {
  it("starts a computer off at the defaults Preferences set", () => {
    writeViewDefaults({ quality: "high", scalingMode: "actual" });
    const prefs = readViewPrefs("deskvnc.view.p:new-host");
    expect(prefs.quality).toBe("high");
    expect(prefs.scalingMode).toBe("actual");
  });

  it("lets what a computer remembers win over the defaults", () => {
    writeViewDefaults({ quality: "high" });
    const key = "deskvnc.view.p:abc";
    writeViewPrefs(key, { ...readViewPrefs(key), quality: "low" });
    expect(readViewPrefs(key).quality).toBe("low");
    // A later change to the defaults reaches the computers that have never
    // been adjusted, and leaves this one alone.
    writeViewDefaults({ quality: "medium" });
    expect(readViewPrefs(key).quality).toBe("low");
    expect(readViewPrefs("deskvnc.view.p:untouched").quality).toBe("medium");
  });

  it("remembers the chosen monitor", () => {
    const key = "deskvnc.view.p:abc";
    const display = { id: -101, x: 0, y: 0, width: 1920, height: 1080 };
    writeViewPrefs(key, { ...readViewPrefs(key), display });
    expect(readViewPrefs(key).display).toEqual(display);
  });

  it("ignores values it could not act on", () => {
    // localStorage is hand-editable and survives a downgrade; an unknown
    // scaling mode reaching the renderer would leave the view in a state the
    // UI has no way back out of.
    localStorage.setItem(
      "deskvnc.view.p:abc",
      JSON.stringify({ scalingMode: "sideways", quality: "ultra", zoom: "big", bwLevels: 7 }),
    );
    const prefs = readViewPrefs("deskvnc.view.p:abc");
    expect(prefs.scalingMode).toBe(FACTORY_DEFAULTS.scalingMode);
    expect(prefs.quality).toBe(FACTORY_DEFAULTS.quality);
    expect(prefs.zoom).toBe(FACTORY_DEFAULTS.zoom);
    expect(prefs.bwLevels).toBe(FACTORY_DEFAULTS.bwLevels);
  });

  it("clamps a zoom from outside the slider's range", () => {
    localStorage.setItem("deskvnc.view.p:abc", JSON.stringify({ zoom: 40 }));
    expect(readViewPrefs("deskvnc.view.p:abc").zoom).toBe(4);
  });

  it("drops a monitor rectangle that is not one", () => {
    localStorage.setItem(
      "deskvnc.view.p:abc",
      JSON.stringify({ display: { id: 1, x: 0, y: 0, width: 0, height: -5 } }),
    );
    expect(readViewPrefs("deskvnc.view.p:abc").display).toBeNull();
  });

  it("survives a blob that is not JSON at all", () => {
    localStorage.setItem("deskvnc.view.p:abc", "{oops");
    expect(readViewPrefs("deskvnc.view.p:abc")).toEqual(FACTORY_DEFAULTS);
  });

  it("gives a session with no key the plain defaults", () => {
    writeViewDefaults({ viewOnly: true });
    expect(readViewPrefs(null)).toEqual(readViewDefaults());
  });
});

describe("sameViewPrefs", () => {
  it("recognises an untouched session, which is what stops it being pinned", () => {
    const key = "deskvnc.view.p:abc";
    expect(sameViewPrefs(readViewPrefs(key), readViewDefaults())).toBe(true);
  });

  it("notices any one setting moving", () => {
    const base = readViewDefaults();
    expect(sameViewPrefs(base, { ...base, quality: "low" })).toBe(false);
    expect(sameViewPrefs(base, { ...base, zoom: 1.25 })).toBe(false);
    expect(sameViewPrefs(base, { ...base, passthrough: !base.passthrough })).toBe(false);
  });

  it("compares the chosen monitor by value, not by identity", () => {
    const base = readViewDefaults();
    const display = { id: 3, x: 0, y: 0, width: 1920, height: 1080 };
    const a = { ...base, display };
    expect(sameViewPrefs(a, { ...base, display: { ...display } })).toBe(true);
    expect(sameViewPrefs(a, { ...base, display: { ...display, x: 1920 } })).toBe(false);
    expect(sameViewPrefs(a, base)).toBe(false);
  });
});
