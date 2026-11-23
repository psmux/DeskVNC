/**
 * The system bars, as the Android app measures them.
 *
 * The app draws edge to edge (Android 15 and later make every app do so), so
 * the status bar and the gesture or button bar lie over the page. iOS reports
 * them to the page as env(safe-area-inset-*). Android's WebView does not: it
 * reports only the display cutout there. A Pixel 7 held upright gets a top
 * inset because its camera hole sits in the status bar, but nothing at the
 * bottom for the gesture bar, and held sideways it gets the camera hole on
 * one side and no top inset at all. The status bar then covered the session's
 * connection chip, toolbar pill and keyboard button, and took taps meant for
 * them.
 *
 * MainActivity measures the system bars and the cutout itself and hands them
 * over as "top,right,bottom,left" in CSS pixels, through
 * window.DeskVNCSafeArea.read() when the page starts and through
 * window.__deskvncSafeArea() whenever they change (a turn, a fold, the
 * keyboard). They land as --dv-native-safe-* on the root element, and
 * index.css takes the larger of each and env(), as --dv-safe-*. Everything
 * that keeps clear of the system bars reads --dv-safe-*, never env() itself.
 */

export const SIDES = ["top", "right", "bottom", "left"] as const;
export type Side = (typeof SIDES)[number];
export type Insets = Record<Side, number>;

/** Insets from "top,right,bottom,left" in CSS pixels, or null when the text is not that. */
export function parseInsets(text: unknown): Insets | null {
  if (typeof text !== "string") return null;
  const parts = text.split(",");
  if (parts.length !== 4) return null;
  const values = parts.map((p) => (p.trim() === "" ? NaN : Number(p)));
  if (values.some((v) => !Number.isFinite(v) || v < 0 || v > 1000)) return null;
  const [top, right, bottom, left] = values;
  return { top, right, bottom, left };
}

/** Put the insets on an element's style as --dv-native-safe-*. Returns whether they were good. */
export function applyInsets(text: unknown, style: Pick<CSSStyleDeclaration, "setProperty">): boolean {
  const insets = parseInsets(text);
  if (!insets) return false;
  for (const side of SIDES) style.setProperty(`--dv-native-safe-${side}`, `${insets[side]}px`);
  return true;
}

interface SafeAreaWindow {
  document: Document;
  DeskVNCSafeArea?: { read(): string };
  __deskvncSafeArea?: (text: string) => void;
}

/** Take the native insets now and whenever MainActivity sends new ones. Does nothing off Android. */
export function installSafeArea(win: SafeAreaWindow = window as unknown as SafeAreaWindow): void {
  const style = win.document.documentElement.style;
  win.__deskvncSafeArea = (text) => {
    applyInsets(text, style);
  };
  try {
    if (win.DeskVNCSafeArea) applyInsets(win.DeskVNCSafeArea.read(), style);
  } catch {
    // The bridge is only there on Android; env() still covers iOS and the browser.
  }
}
