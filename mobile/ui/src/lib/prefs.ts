/**
 * Settings that live on this phone. Kept in localStorage because they are
 * conveniences: losing them only means the defaults come back.
 *
 * The session screen reads `touchMode` and `quality` from here as its
 * starting values (`usePrefs()` or `readPrefs()`).
 */
import { useSyncExternalStore } from "react";
import type { Quality } from "../api/contract";

export type ThemeChoice = "system" | "light" | "dark";
export type TouchMode = "trackpad" | "direct";

export interface Prefs {
  theme: ThemeChoice;
  touchMode: TouchMode;
  quality: Quality;
  haptics: boolean;
  onboarded: boolean;
  helperName: string;
  showDemo: boolean;
}

export const DEFAULT_PREFS: Prefs = {
  theme: "system",
  touchMode: "trackpad",
  quality: "auto",
  haptics: true,
  onboarded: false,
  helperName: "",
  showDemo: true,
};

const KEY = "deskvnc.mobile.prefs";
let current: Prefs = load();
const listeners = new Set<() => void>();

function load(): Prefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { ...DEFAULT_PREFS, ...(JSON.parse(raw) as Partial<Prefs>) };
  } catch {
    // Blocked storage or a broken value: start from the defaults.
  }
  return { ...DEFAULT_PREFS };
}

export function readPrefs(): Prefs {
  return current;
}

export function setPrefs(patch: Partial<Prefs>): void {
  current = { ...current, ...patch };
  try {
    localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    // Not saved, but this run still uses the new value.
  }
  applyTheme(current.theme);
  listeners.forEach((fn) => fn());
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function usePrefs(): Prefs {
  return useSyncExternalStore(subscribe, readPrefs, readPrefs);
}

/** `system` removes the attribute so the media query decides. */
export function applyTheme(choice: ThemeChoice): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (choice === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", choice);
}
