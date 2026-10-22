import { describe, expect, it, beforeEach } from "vitest";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { LanguagePicker } from "./LanguagePicker";
import { applyLocale } from "../lib/i18n";
import { SettingsProvider } from "../state/SettingsContext";

/**
 * The picker is the one component that proves the wiring end to end: it reads
 * the choice out of the settings store, renders through the catalog, and shows
 * each language spelled in itself. A unit test on `translate` would pass with
 * the provider unplugged.
 */
function render(): string {
  return renderToString(createElement(SettingsProvider, null, createElement(LanguagePicker)));
}

describe("LanguagePicker", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("lists both languages by their own names, whatever the UI is showing", () => {
    applyLocale("en");
    const html = render();
    expect(html).toContain("English");
    expect(html).toContain("简体中文");
  });

  it("draws its own copy in the stored language", () => {
    localStorage.setItem("deskvnc.settings.v1", JSON.stringify({ locale: "zh-CN" }));
    applyLocale("zh-CN");
    const html = render();
    expect(html).toContain("语言");
    expect(html).toContain("跟随系统");
    expect(html).not.toContain(">Language<");
  });

  it("marks the stored choice as the selected radio, and only that one", () => {
    localStorage.setItem("deskvnc.settings.v1", JSON.stringify({ locale: "zh-CN" }));
    applyLocale("zh-CN");
    const html = render();
    // One radio per choice: system, English, Chinese. Exactly one is checked,
    // and the button it sits in is the Chinese one.
    expect(html.match(/aria-checked="true"/g) ?? []).toHaveLength(1);
    const buttons = html.split("<button").filter((b) => b.includes("role=\"radio\""));
    const checkedButton = buttons.find((b) => b.includes('aria-checked="true"'));
    expect(checkedButton).toContain("简体中文");
  });
});
