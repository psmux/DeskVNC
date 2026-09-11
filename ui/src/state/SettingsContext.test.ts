import { beforeEach, describe, expect, it } from "vitest";
import { DEFAULTS, loadSettings } from "./SettingsContext";

const STORAGE_KEY = "deskvnc.settings.v1";

beforeEach(() => {
  localStorage.clear();
});

describe("windowMode", () => {
  it("opens sessions as tabs on a machine that has never been configured", () => {
    expect(loadSettings().windowMode).toBe("tabs");
  });

  it("leaves someone who chose separate windows on separate windows", () => {
    // The whole settings object is persisted on every update, so an install
    // that predates the default flip carries windowMode explicitly. Honouring
    // it is the point: a new default is for new installs, not a migration
    // that overrides a choice somebody already made.
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ windowMode: "windows" }));
    expect(loadSettings().windowMode).toBe("windows");
  });

  it("keeps an explicit tabs choice", () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ windowMode: "tabs" }));
    expect(loadSettings().windowMode).toBe("tabs");
  });

  it("falls back to tabs when the stored value is not a mode", () => {
    // localStorage is hand-editable; an unknown mode would leave the shell
    // with no way to open anything at all.
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ windowMode: "flarp" }));
    expect(loadSettings().windowMode).toBe("tabs");
  });

  it("falls back to tabs when the blob is not JSON", () => {
    localStorage.setItem(STORAGE_KEY, "{not json");
    expect(loadSettings().windowMode).toBe("tabs");
  });

  it("keeps unrelated saved settings while defaulting the mode", () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ theme: "dark" }));
    const s = loadSettings();
    expect(s.theme).toBe("dark");
    expect(s.windowMode).toBe("tabs");
  });
});

describe("DEFAULTS", () => {
  it("ships tabs as the factory setting", () => {
    expect(DEFAULTS.windowMode).toBe("tabs");
  });
});
