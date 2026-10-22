/**
 * Translations, without a dependency or a build step.
 *
 * The English source text is the key. `t("Search hosts")` returns "Search
 * hosts" until a catalog says otherwise, so every call site reads the same as
 * it did before it was translated, a missing entry degrades to English rather
 * than to a raw key, and adding a string needs no extraction pass.
 *
 * Catalogs are plain objects in `../locales`. A language is added by writing
 * one and appending it to `LOCALES`.
 *
 * Two entry points, because not every call site is a component:
 *
 *   - `useT()` in components. Re-renders when the language changes.
 *   - `t()` elsewhere. The language is read from the settings the moment the
 *     string is built, matching how `lib/prefs` treats its own preferences.
 *
 * Windows: Preferences is its own webview, so a language change there has to
 * reach the library window. `localStorage` is shared by both, and its `storage`
 * event fires in the other one, which is what `syncFromStorage` listens for.
 */
import { useCallback, useEffect, useState } from "react";
import { zhCN } from "../locales/zh-CN";

/** A language the UI can be shown in. "system" follows the OS. */
export type LocaleChoice = "system" | "en" | "zh-CN";

export const LOCALES: readonly { id: Exclude<LocaleChoice, "system">; label: string }[] = [
  // Language names are written in their own language on purpose: someone who
  // cannot read the current one still has to find theirs in the list.
  { id: "en", label: "English" },
  { id: "zh-CN", label: "简体中文" },
];

export type Locale = Exclude<LocaleChoice, "system">;

const CATALOGS: Record<Locale, Record<string, string>> = {
  en: {},
  "zh-CN": zhCN,
};

export const SETTINGS_STORAGE_KEY = "deskvnc.settings.v1";

/**
 * The language the OS is set to, when it is one this app speaks.
 *
 * `navigator.languages` is the ordered preference list; the first entry that
 * matches a catalog wins. Anything else falls through to English.
 */
export function systemLocale(): Locale {
  const nav = typeof navigator === "undefined" ? undefined : navigator;
  const list =
    nav && Array.isArray(nav.languages) && nav.languages.length > 0
      ? nav.languages
      : nav?.language
        ? [nav.language]
        : [];
  for (const tag of list) {
    if (tag.toLowerCase().startsWith("zh")) return "zh-CN";
  }
  return "en";
}

/** The language actually in use for a choice. */
export function resolveLocale(choice: LocaleChoice): Locale {
  return choice === "system" ? systemLocale() : choice;
}

/** Read the choice back out of stored settings, tolerating a bad value. */
function storedChoice(): LocaleChoice {
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return "system";
    const v = (JSON.parse(raw) as { locale?: unknown }).locale;
    if (v === "en" || v === "zh-CN" || v === "system") return v;
  } catch {
    /* storage unavailable or unparsable */
  }
  return "system";
}

let current: Locale = resolveLocale(storedChoice());
const listeners = new Set<() => void>();

/** The language in use right now. */
export function currentLocale(): Locale {
  return current;
}

function setCurrent(next: Locale): void {
  if (next === current) return;
  current = next;
  for (const fn of listeners) fn();
}

/**
 * Point the module at the language the settings now hold.
 *
 * Called by the settings provider after it applies a change, and by the
 * storage listener for a change made in another window.
 */
export function applyLocale(choice: LocaleChoice): void {
  setCurrent(resolveLocale(choice));
}

/**
 * Re-read the stored choice. Registered once per document as a `storage`
 * listener, which fires only in the windows that did not make the change.
 */
export function syncFromStorage(): void {
  applyLocale(storedChoice());
}

if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === null || e.key === SETTINGS_STORAGE_KEY) syncFromStorage();
  });
}

export type Vars = Record<string, string | number>;

/**
 * Look a string up, substituting `{name}` placeholders.
 *
 * An unknown language or a missing entry returns the English text, so a
 * half-finished catalog is a partially translated UI, never a broken one.
 */
export function translate(locale: Locale, text: string, vars?: Vars): string {
  const found = CATALOGS[locale]?.[text];
  let out = found ?? text;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      out = out.split(`{${k}}`).join(String(v));
    }
  }
  return out;
}

/** Translate using the language currently in effect. */
export function t(text: string, vars?: Vars): string {
  return translate(current, text, vars);
}

/** Subscribe to language changes without React. */
export function onLocaleChange(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/**
 * Translate inside a component, re-rendering when the language changes.
 *
 * The returned function is stable for as long as the language is, so a
 * `useMemo` or `useCallback` that builds translated labels only has to list
 * `tr` in its dependencies to be correct and still memoise across renders.
 */
export function useT(): (text: string, vars?: Vars) => string {
  const [locale, setLocale] = useState<Locale>(current);
  useEffect(() => {
    setLocale(current);
    return onLocaleChange(() => setLocale(current));
  }, []);
  return useCallback((text: string, vars?: Vars) => translate(locale, text, vars), [locale]);
}

/** The document's `lang` attribute, so the webview hyphenates and wraps right. */
export function useLocaleCode(): Locale {
  const [locale, setLocale] = useState<Locale>(current);
  useEffect(() => {
    setLocale(current);
    return onLocaleChange(() => setLocale(current));
  }, []);
  return locale;
}
