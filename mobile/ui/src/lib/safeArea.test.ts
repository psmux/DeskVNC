import { describe, expect, it } from "vitest";
import { applyInsets, installSafeArea, parseInsets } from "./safeArea";

function fakeStyle() {
  const props: Record<string, string> = {};
  return { props, setProperty: (name: string, value: string | null) => void (props[name] = value ?? "") };
}

describe("reading the insets MainActivity sends", () => {
  it("takes top, right, bottom and left in CSS pixels", () => {
    // A Pixel 7 held sideways: status bar on top, camera hole on the left, gesture bar below.
    expect(parseInsets("28.19,0.00,24.00,52.95")).toEqual({ top: 28.19, right: 0, bottom: 24, left: 52.95 });
  });

  it("turns down anything else", () => {
    for (const bad of [undefined, null, 12, "", "1,2,3", "1,2,3,4,5", "a,b,c,d", "1,,3,4", "-1,0,0,0", "1,2,3,Infinity", "1,2,3,5000"]) {
      expect(parseInsets(bad)).toBeNull();
    }
  });

  it("sets --dv-native-safe-* and leaves them alone on bad input", () => {
    const style = fakeStyle();
    expect(applyInsets("28,0,24,53", style)).toBe(true);
    expect(style.props).toEqual({
      "--dv-native-safe-top": "28px",
      "--dv-native-safe-right": "0px",
      "--dv-native-safe-bottom": "24px",
      "--dv-native-safe-left": "53px",
    });
    expect(applyInsets("junk", style)).toBe(false);
    expect(style.props["--dv-native-safe-top"]).toBe("28px");
  });
});

describe("the bridge to MainActivity", () => {
  function fakeWindow(read?: () => string) {
    const style = fakeStyle();
    const win = {
      document: { documentElement: { style } } as unknown as Document,
      DeskVNCSafeArea: read ? { read } : undefined,
      __deskvncSafeArea: undefined as ((text: string) => void) | undefined,
    };
    return { win, style };
  }

  it("reads the insets once at start and takes each change after", () => {
    const { win, style } = fakeWindow(() => "45,0,24,0");
    installSafeArea(win);
    expect(style.props["--dv-native-safe-top"]).toBe("45px");
    // The phone turns sideways.
    win.__deskvncSafeArea!("28,0,24,53");
    expect(style.props["--dv-native-safe-top"]).toBe("28px");
    expect(style.props["--dv-native-safe-left"]).toBe("53px");
  });

  it("does nothing off Android, and survives a bridge that throws", () => {
    const off = fakeWindow();
    installSafeArea(off.win);
    expect(off.style.props).toEqual({});
    const broken = fakeWindow(() => {
      throw new Error("gone");
    });
    expect(() => installSafeArea(broken.win)).not.toThrow();
    expect(typeof broken.win.__deskvncSafeArea).toBe("function");
  });
});

// Android's WebView leaves the status bar and the gesture bar out of
// env(safe-area-inset-*). Anything that reads env() directly ends up under
// them on Android, as the session's chip, pill and keyboard button did, so
// only the --dv-safe-* definitions in index.css may.
// The UI has no Node types, and Vite hands CSS to tests as an empty string,
// so the files are read with Node's fs, typed here as far as it is used.
declare const process: { getBuiltinModule(name: "node:fs"): { readFileSync(path: URL, encoding: "utf8"): string } };

describe("every safe area goes through --dv-safe-*", () => {
  const files = Object.keys(import.meta.glob(["../**/*.{css,ts,tsx}", "!../**/*.test.ts"]));
  const read = (file: string): string => process.getBuiltinModule("node:fs").readFileSync(new URL(file, import.meta.url), "utf8");

  it("finds the sources", () => {
    expect(files).toContain("../index.css");
    expect(read("../session/session.css")).toContain("--s-safe-t:");
  });

  it("has no env(safe-area-inset-*) outside the definitions", () => {
    const offenders: string[] = [];
    for (const file of files) {
      read(file).split("\n").forEach((line, i) => {
        if (!line.includes("env(safe-area-inset")) return;
        if (/^\s*\*|^\s*\/\//.test(line)) return; // a comment naming it
        if (/^\s*--dv-safe-(top|right|bottom|left): max\(env\(safe-area-inset-\1, 0px\), var\(--dv-native-safe-\1, 0px\)\);/.test(line)) return;
        offenders.push(`${file}:${i + 1}: ${line.trim()}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});
