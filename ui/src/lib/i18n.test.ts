import { describe, expect, it, vi, beforeEach } from "vitest";
import { zhCN } from "../locales/zh-CN";
import {
  applyLocale,
  currentLocale,
  onLocaleChange,
  resolveLocale,
  systemLocale,
  translate,
} from "./i18n";

describe("translate", () => {
  it("returns the English text when the catalog has no entry", () => {
    expect(translate("en", "Search hosts")).toBe("Search hosts");
    expect(translate("zh-CN", "This string is not translated")).toBe(
      "This string is not translated",
    );
  });

  it("uses the catalog entry when there is one", () => {
    expect(zhCN["Skip"]).toBe("跳过");
    expect(translate("zh-CN", "Skip")).toBe("跳过");
  });

  it("substitutes named placeholders wherever they appear", () => {
    const vars = { name: "Office", count: 2 };
    expect(translate("en", "{count} hosts, {name}", vars)).toBe("2 hosts, Office");
    // A value may also be used more than once.
    expect(translate("en", "{name} and {name}", vars)).toBe("Office and Office");
  });

  it("leaves an unknown placeholder alone rather than dropping it", () => {
    // Visible in the UI, which is the point: it names the parameter that is
    // missing instead of rendering an empty gap.
    expect(translate("en", "Hello {who}", {})).toBe("Hello {who}");
  });

  it("falls back to English for a language with no catalog", () => {
    expect(translate("en", "Anything", {})).toBe("Anything");
  });
});

describe("the zh-CN catalog", () => {
  it("translates every entry to something other than the English key", () => {
    // A key left in the catalog with identical text is a string somebody meant
    // to translate and did not; it renders as English in a Chinese UI.
    const untranslated = Object.entries(zhCN)
      .filter(([key, value]) => value.trim() === key.trim())
      .map(([key]) => key);
    expect(untranslated).toEqual([]);
  });

  it("keeps every placeholder the English text uses", () => {
    // Dropping `{backend}` from a translation loses information the call site
    // passed in, and nothing else would notice. Tag pairs count too: they are
    // how `<Trans>` knows where emphasis starts and stops.
    const missing: string[] = [];
    for (const [key, value] of Object.entries(zhCN)) {
      const wanted = [
        ...key.matchAll(/\{(\w+)\}/g),
        ...key.matchAll(/<(\w+)>/g),
        ...key.matchAll(/<\/(\w+)>/g),
      ].map((m) => m[1]);
      for (const name of new Set(wanted)) {
        const present = value.includes(`{${name}}`) || value.includes(`<${name}>`);
        if (!present) missing.push(`${key} -> ${name}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("has no blank values", () => {
    expect(Object.entries(zhCN).filter(([, v]) => v.trim() === "")).toEqual([]);
  });

  it("has no entry without a call site", () => {
    // A key nothing asks for is either a typo in the catalog or a string that
    // was removed from the UI, and either way it will never be seen. Read the
    // sources rather than mocking the modules, so a key built inline by a
    // `Record` (tab names, theme names) still counts as used.
    const used = new Set<string>();
    const files = import.meta.glob("../**/*.{ts,tsx}", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
    for (const [path, source] of Object.entries(files)) {
      if (path.includes("/locales/")) continue;
      for (const m of source.matchAll(/"([^"\\]|\\.)*"/g)) {
        // Literal contents, unescaped enough for our keys (no keys contain \").
        used.add(m[0].slice(1, -1));
      }
      // `<Trans text="...">` passes its key as an attribute, not as a `tr()`
      // argument, so the literal scan above does not reach it.
      for (const m of source.matchAll(/text="((?:[^"\\]|\\.)*)"/g)) {
        used.add(m[1].replace(/\\"/g, '"'));
      }
    }
    const orphans = Object.keys(zhCN).filter((key) => !used.has(key));
    expect(orphans).toEqual([]);
  });
});

describe("systemLocale", () => {
  const nav = (languages: string[], language = languages[0] ?? "en") => {
    vi.stubGlobal("navigator", { languages, language });
  };

  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("picks Chinese for any zh tag", () => {
    nav(["zh-Hans-CN", "en-US"]);
    expect(systemLocale()).toBe("zh-CN");
    nav(["zh-TW"]);
    expect(systemLocale()).toBe("zh-CN");
  });

  it("uses the first matching language, not the first language", () => {
    nav(["fr-FR", "en-GB", "zh-CN"]);
    expect(systemLocale()).toBe("zh-CN");
  });

  it("falls back to English for languages with no catalog", () => {
    nav(["de-DE"]);
    expect(systemLocale()).toBe("en");
  });

  it("copes with navigator.languages missing", () => {
    vi.stubGlobal("navigator", { language: "zh-CN" });
    expect(systemLocale()).toBe("zh-CN");
    vi.stubGlobal("navigator", {});
    expect(systemLocale()).toBe("en");
    vi.stubGlobal("navigator", undefined);
    expect(systemLocale()).toBe("en");
  });
});

describe("resolveLocale", () => {
  it("passes an explicit choice through", () => {
    expect(resolveLocale("en")).toBe("en");
    expect(resolveLocale("zh-CN")).toBe("zh-CN");
  });
});

describe("applyLocale", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    vi.stubGlobal("navigator", { languages: ["en-US"], language: "en-US" });
  });

  it("notifies subscribers once per actual change", () => {
    const seen: string[] = [];
    const off = onLocaleChange(() => seen.push(currentLocale()));
    applyLocale("zh-CN");
    applyLocale("zh-CN");
    applyLocale("en");
    off();
    applyLocale("zh-CN");
    expect(seen).toEqual(["zh-CN", "en"]);
  });

  it("resolves a system choice against the OS language", () => {
    vi.stubGlobal("navigator", { languages: ["zh-Hans"], language: "zh-Hans" });
    applyLocale("system");
    expect(currentLocale()).toBe("zh-CN");
    applyLocale("en");
    expect(currentLocale()).toBe("en");
  });
});
