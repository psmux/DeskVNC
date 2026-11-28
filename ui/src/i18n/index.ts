/**
 * The language the interface speaks.
 *
 * The English text in the source is the key. `t("Connect")` looks the string
 * up in the catalog for the language in use and hands back the English when
 * there is no entry, so a string nobody has translated yet still reads, in
 * English, rather than showing a key name. Adding a language is a new file in
 * `locales/` and a row in `LANGUAGES`; nothing else changes.
 *
 * Values go in with `{name}` placeholders, never by gluing translated pieces
 * together, because word order is not the same in every language:
 *
 *     t("Delete {name}?", { name: host.friendlyName })
 *
 * Counts go through `tn`, which picks the plural form by the language's own
 * rules (`Intl.PluralRules`). Chinese has one form; English has two; Polish
 * or Arabic have more, and the catalog entry for those can be an object of
 * forms keyed `one`, `few`, `many`, `other` and so on.
 *
 * The native menus are built in Rust from the same catalog file
 * (`src-tauri/src/i18n.rs` includes it), so a menu label is translated in the
 * same place as everything else.
 */
import { useSyncExternalStore } from "react";
import zhCN from "./locales/zh-CN.json";

/** A plural entry: one string per CLDR plural category the language uses. */
export type PluralForms = Partial<Record<Intl.LDMLPluralRule, string>>;
export type Catalog = Record<string, string | PluralForms>;

/**
 * Every language the interface can be shown in. `name` is the language's
 * name in itself, which is how a person looks for their own in a list.
 */
export const LANGUAGES = [
  { code: "en", name: "English" },
  { code: "zh-CN", name: "简体中文" },
] as const;

export type Language = (typeof LANGUAGES)[number]["code"];
/** What a person chose: a language, or to follow the system. */
export type LanguagePreference = Language | "system";

const CATALOGS: Record<Language, Catalog> = {
  en: {},
  "zh-CN": zhCN as Catalog,
};

export function catalogFor(language: Language): Catalog {
  return CATALOGS[language];
}

/**
 * The supported language a BCP 47 tag means, or null for one we do not have.
 *
 * Chinese is matched on script first. `zh-Hans`, `zh-CN`, `zh-SG` and a bare
 * `zh` are Simplified. Traditional (`zh-Hant`, `zh-TW`, `zh-HK`, `zh-MO`)
 * gets no match and so falls through to the next language the system lists,
 * or English, since showing Simplified to someone who reads Traditional is not
 * a translation they asked for. macOS and Windows write tags with an
 * underscore now and then (`zh_CN`), which is accepted too.
 */
export function matchLanguage(tag: string): Language | null {
  const parts = tag.trim().replace(/_/g, "-").toLowerCase().split("-");
  const lang = parts[0];
  if (lang === "en") return "en";
  if (lang === "zh") {
    const rest = parts.slice(1);
    if (rest.includes("hant")) return null;
    if (rest.includes("hans")) return "zh-CN";
    if (rest.some((p) => p === "tw" || p === "hk" || p === "mo")) return null;
    return "zh-CN";
  }
  return null;
}

/**
 * The language to show: the one chosen, or the first of the system's
 * preferred languages that we have, or English.
 *
 * Kept in step by hand with `resolve` in `src-tauri/src/i18n.rs`, which makes
 * the same choice for the native menus; both have tests on the same cases.
 */
export function resolveLanguage(
  preference: LanguagePreference,
  systemLanguages: readonly string[],
): Language {
  if (preference !== "system") return preference;
  for (const tag of systemLanguages) {
    const found = matchLanguage(tag);
    if (found) return found;
  }
  return "en";
}

export function isLanguagePreference(value: unknown): value is LanguagePreference {
  return value === "system" || LANGUAGES.some((l) => l.code === value);
}

// ---------------------------------------------------------------------------
// The language in use, and who is listening for it to change.
// ---------------------------------------------------------------------------

let current: Language = "en";
const listeners = new Set<() => void>();

export function currentLanguage(): Language {
  return current;
}

/** Switch the interface, and re-render every component that called `useT`. */
export function setLanguage(language: Language): void {
  if (language === current) return;
  current = language;
  if (typeof document !== "undefined") document.documentElement.lang = language;
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

// ---------------------------------------------------------------------------
// Looking text up.
// ---------------------------------------------------------------------------

export type Values = Record<string, string | number>;

/** Put values into `{name}` placeholders. A placeholder with no value stays. */
export function interpolate(text: string, values?: Values): string {
  if (!values) return text;
  return text.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const value = values[name];
    if (value === undefined) return whole;
    return typeof value === "number" ? formatNumber(value) : value;
  });
}

/** The translation of `english`, with values filled in. */
export function t(english: string, values?: Values): string {
  const entry = CATALOGS[current][english];
  const text = typeof entry === "string" ? entry : (entry?.other ?? english);
  return interpolate(text, values);
}

/**
 * A count. `one` and `other` are the English forms, and `{count}` in either
 * is the number, written the way the language writes numbers. The catalog is
 * keyed by the `other` form.
 */
export function tn(count: number, one: string, other: string, values?: Values): string {
  const all = { count, ...values };
  const entry = CATALOGS[current][other];
  if (entry === undefined) {
    const rule = new Intl.PluralRules("en").select(count);
    return interpolate(rule === "one" ? one : other, all);
  }
  if (typeof entry === "string") return interpolate(entry, all);
  const rule = new Intl.PluralRules(current).select(count);
  return interpolate(entry[rule] ?? entry.other ?? other, all);
}

/**
 * `t`, in a component that re-renders when the language changes. Every
 * component that shows translated text calls this once; the function it
 * returns is the same `t`, so it can be passed to helpers.
 */
export function useT(): typeof t {
  useSyncExternalStore(subscribe, currentLanguage, currentLanguage);
  return t;
}

/** The language in use, as a value that re-renders on change. */
export function useLanguage(): Language {
  return useSyncExternalStore(subscribe, currentLanguage, currentLanguage);
}

// ---------------------------------------------------------------------------
// Numbers and dates, through Intl, in the language in use.
// ---------------------------------------------------------------------------

export function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(current, options).format(value);
}

export function formatDate(
  value: Date | number,
  options: Intl.DateTimeFormatOptions = { dateStyle: "medium", timeStyle: "short" },
): string {
  return new Intl.DateTimeFormat(current, options).format(value);
}

/** "3 minutes ago", "yesterday", in the language in use. */
export function formatRelative(value: number, unit: Intl.RelativeTimeFormatUnit): string {
  return new Intl.RelativeTimeFormat(current, { numeric: "auto" }).format(value, unit);
}
