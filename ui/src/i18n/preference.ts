/**
 * Where the language preference lives, and how every window hears it change.
 *
 * The preference is kept in the Rust store rather than in `localStorage`,
 * because the native menus are built in Rust before any webview has loaded
 * and have to come up in the right language. Rust also reports the system's
 * preferred languages: a webview's `navigator.languages` is not a reliable
 * reading of them (WKWebView answers with the app bundle's localizations, so
 * a Chinese Mac can report `en-US`). A change is broadcast by Rust to every
 * window as `i18n://changed`, so a session window open beside the library
 * switches at the same moment as the Preferences that changed it.
 *
 * Outside Tauri (`npm run dev` in a browser) the same thing is done with
 * `localStorage` and `navigator.languages`.
 */
import { inTauri, safeInvoke, safeListen } from "../lib/tauri";
import {
  isLanguagePreference,
  resolveLanguage,
  setLanguage,
  type Language,
  type LanguagePreference,
} from ".";

export const LANGUAGE_CHANGED = "i18n://changed";
const BROWSER_KEY = "deskvnc.pref.language";

export interface LanguageState {
  preference: LanguagePreference;
  /** The system's preferred languages, most preferred first. */
  system: string[];
  /** What is shown, from the two above. */
  language: Language;
}

function browserState(): LanguageState {
  let stored: unknown = null;
  try {
    stored = localStorage.getItem(BROWSER_KEY);
  } catch {
    // Storage can be off; the system language still applies.
  }
  const preference = isLanguagePreference(stored) ? stored : "system";
  const system = [...(navigator.languages ?? [navigator.language])];
  return { preference, system, language: resolveLanguage(preference, system) };
}

export async function readLanguageState(): Promise<LanguageState> {
  if (!inTauri()) return browserState();
  const state = await safeInvoke<LanguageState | null>("ui_language", undefined, null);
  if (!state) return browserState();
  // Resolved again here rather than trusted, so the two sides cannot show
  // different languages if one of them is older than the other.
  const preference = isLanguagePreference(state.preference) ? state.preference : "system";
  return { preference, system: state.system, language: resolveLanguage(preference, state.system) };
}

let listening = false;

/**
 * Apply the saved language before the first render, and follow changes made
 * in any window from then on. Called once from `main.tsx`.
 */
export async function initLanguage(): Promise<void> {
  const state = await readLanguageState();
  setLanguage(state.language);
  if (listening) return;
  listening = true;
  void safeListen<{ language: string }>(LANGUAGE_CHANGED, ({ language }) => {
    if (isLanguagePreference(language) && language !== "system") setLanguage(language);
  });
}

/** Save a new preference and switch to it, here and in every other window. */
export async function chooseLanguage(preference: LanguagePreference): Promise<LanguageState> {
  if (!inTauri()) {
    try {
      localStorage.setItem(BROWSER_KEY, preference);
    } catch {
      // Not remembered, but still applied for this session.
    }
    const state = browserState();
    const applied = { ...state, preference, language: resolveLanguage(preference, state.system) };
    setLanguage(applied.language);
    return applied;
  }
  await safeInvoke("set_ui_language", { preference }, null);
  const state = await readLanguageState();
  setLanguage(state.language);
  return state;
}
