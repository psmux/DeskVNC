/**
 * A small tick on click and right click. Phone webviews have no haptics API
 * of their own, so this uses `navigator.vibrate` where there is one (Android)
 * and does nothing where there is not (iOS WKWebView). A Tauri haptics
 * plugin can take over here later without touching the callers.
 */
export type Tick = "click" | "right" | "soft";

const PATTERN: Record<Tick, number | number[]> = {
  click: 8,
  right: [10, 40, 10],
  soft: 4,
};

export function haptic(kind: Tick = "click"): void {
  try {
    const nav = typeof navigator !== "undefined" ? (navigator as Navigator & { vibrate?: (p: number | number[]) => boolean }) : null;
    nav?.vibrate?.(PATTERN[kind]);
  } catch {
    // Some webviews throw when vibration is blocked; a missing tick is fine.
  }
}
