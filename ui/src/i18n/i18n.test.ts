import { afterEach, describe, expect, it, vi } from "vitest";
import {
  catalogFor,
  currentLanguage,
  formatNumber,
  matchLanguage,
  resolveLanguage,
  setLanguage,
  t,
  tn,
} from ".";
import { chooseLanguage, readLanguageState } from "./preference";

afterEach(() => {
  setLanguage("en");
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("falling back to English", () => {
  it("shows the English for a string the catalog does not have", () => {
    setLanguage("zh-CN");
    const english = "A sentence nobody has translated, about {name}";
    expect(english in catalogFor("zh-CN")).toBe(false);
    expect(t(english, { name: "build box" })).toBe(
      "A sentence nobody has translated, about build box",
    );
  });

  it("uses the translation where there is one", () => {
    setLanguage("zh-CN");
    expect(t("Language")).toBe(catalogFor("zh-CN").Language);
    expect(t("Language")).not.toBe("Language");
  });

  it("counts in English with both forms when nothing is translated", () => {
    setLanguage("zh-CN");
    expect(tn(1, "{count} untranslated thing", "{count} untranslated things")).toBe(
      "1 untranslated thing",
    );
    expect(tn(3, "{count} untranslated thing", "{count} untranslated things")).toBe(
      "3 untranslated things",
    );
  });

  it("counts in English by English rules", () => {
    expect(tn(1, "{count} host", "{count} hosts")).toBe("1 host");
    expect(tn(0, "{count} host", "{count} hosts")).toBe("0 hosts");
    expect(tn(1200, "{count} host", "{count} hosts")).toBe("1,200 hosts");
  });

  it("leaves a placeholder alone when its value is missing", () => {
    expect(t("Connect to {name}")).toBe("Connect to {name}");
  });
});

describe("following the system language", () => {
  it("matches the tags systems actually report", () => {
    expect(matchLanguage("zh-CN")).toBe("zh-CN");
    expect(matchLanguage("zh-Hans-CN")).toBe("zh-CN");
    expect(matchLanguage("zh_CN")).toBe("zh-CN");
    expect(matchLanguage("zh-SG")).toBe("zh-CN");
    expect(matchLanguage("zh")).toBe("zh-CN");
    expect(matchLanguage("en-GB")).toBe("en");
    // Traditional Chinese is not Simplified, and has no catalog yet.
    expect(matchLanguage("zh-TW")).toBeNull();
    expect(matchLanguage("zh-Hant-HK")).toBeNull();
    expect(matchLanguage("fr-FR")).toBeNull();
  });

  it("takes the first system language that has a catalog", () => {
    expect(resolveLanguage("system", ["zh-Hans-CN", "en-US"])).toBe("zh-CN");
    expect(resolveLanguage("system", ["fr-FR", "zh-CN"])).toBe("zh-CN");
    expect(resolveLanguage("system", ["fr-FR", "en-GB", "zh-CN"])).toBe("en");
    expect(resolveLanguage("system", ["zh-TW"])).toBe("en");
    expect(resolveLanguage("system", [])).toBe("en");
  });

  it("lets a chosen language win over the system", () => {
    expect(resolveLanguage("en", ["zh-CN"])).toBe("en");
    expect(resolveLanguage("zh-CN", ["en-US"])).toBe("zh-CN");
  });

  it("reads the system language when nothing has been chosen", async () => {
    vi.stubGlobal("navigator", { ...navigator, languages: ["zh-CN", "en-US"], language: "zh-CN" });
    const state = await readLanguageState();
    expect(state.preference).toBe("system");
    expect(state.language).toBe("zh-CN");
  });

  it("goes back to the system language after a choice is undone", async () => {
    vi.stubGlobal("navigator", { ...navigator, languages: ["zh-CN"], language: "zh-CN" });
    await chooseLanguage("en");
    expect(currentLanguage()).toBe("en");
    expect((await readLanguageState()).preference).toBe("en");
    await chooseLanguage("system");
    expect(currentLanguage()).toBe("zh-CN");
    expect(document.documentElement.lang).toBe("zh-CN");
  });
});

describe("numbers", () => {
  it("are written the way the language writes them", () => {
    setLanguage("zh-CN");
    expect(formatNumber(12345)).toBe(new Intl.NumberFormat("zh-CN").format(12345));
  });
});
