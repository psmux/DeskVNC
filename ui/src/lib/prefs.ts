/**
 * Webview-local preferences (`localStorage`), shared between the Preferences
 * screen that writes them and the code that acts on them.
 *
 * These are deliberately NOT the Rust-store settings in `useAppSetting`: those
 * exist because the backend has to consult them while building a connection.
 * Everything here is decided in the webview.
 *
 * Readers call [`readBoolPref`] at the moment they need the value rather than
 * holding it in React state. Preferences is its own window, so a cached copy
 * would need a cross-window change notification to stay honest; reading on use
 * means a toggle applies to the very next action with no plumbing at all.
 */

const PREFIX = "deskvnc.pref.";

/** Send the local clipboard to the remote automatically (master switch). */
export const PREF_CLIPBOARD_AUTO = "clipboardAuto";
/** Push the local clipboard when the session window regains focus. */
export const PREF_CLIPBOARD_ON_FOCUS = "clipboardOnFocus";
/** Match local scroll direction on the remote desktop ("natural" scrolling). */
export const PREF_NATURAL_SCROLL = "naturalScroll";
/**
 * Keys type what they type on THIS keyboard's layout, rather than what the
 * remote machine's layout assigns to the same physical key. Off by default:
 * scancode mode is what makes remote shortcuts and games behave, and the two
 * only disagree when the machines' layouts differ.
 */
export const PREF_MATCH_LOCAL_LAYOUT = "matchLocalKeyboardLayout";

export function prefStorageKey(key: string): string {
  return `${PREFIX}${key}`;
}

/**
 * Read a boolean preference, falling back to `fallback` when it has never been
 * set (or when storage is unavailable, as in a locked-down webview).
 */
export function readBoolPref(key: string, fallback: boolean): boolean {
  try {
    const raw = localStorage.getItem(prefStorageKey(key));
    return raw === null ? fallback : raw === "1";
  } catch {
    return fallback;
  }
}

export function writeBoolPref(key: string, value: boolean): void {
  try {
    localStorage.setItem(prefStorageKey(key), value ? "1" : "0");
  } catch {
    /* storage unavailable; the preference simply does not persist */
  }
}
