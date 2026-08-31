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
/**
 * Type text that dictation and automation tools insert (rather than press
 * keys for) into the remote desktop. Dead keys and CJK input methods are NOT
 * behind this switch: those are the user physically typing.
 */
export const PREF_FORWARD_INSERTED_TEXT = "forwardInsertedText";
/**
 * Push the local clipboard to the remote right before a forwarded paste
 * chord, so Cmd/Ctrl+V pastes what the clipboard holds at that moment.
 */
export const PREF_CLIPBOARD_ON_PASTE = "clipboardOnPaste";
/**
 * Ignore pinch-to-zoom in a session. The gesture is easy to trigger by
 * accident mid-scroll on a trackpad, and rescaling the view is rarely what
 * was meant; the toolbar's zoom controls still work while it is on.
 */
export const PREF_ZOOM_LOCKED = "zoomLocked";
/**
 * Scroll the view when the pointer reaches an edge, for a desktop larger
 * than the window. On by default, because without it the part of the screen
 * past the edge cannot be reached at all; off for anyone who finds the view
 * moving under them distracting. Space-drag panning works either way.
 */
export const PREF_EDGE_PAN = "edgePan";
/**
 * Take the floating toolbar out of the session view altogether.
 *
 * Everything it offers is also on the View and Session menus, which is what
 * makes switching it off a real choice rather than a loss: some people would
 * rather have nothing at all over the remote desktop, and a bar that fades to
 * a chevron still leaves the chevron. Off by default.
 */
export const PREF_HIDE_TOOLBAR = "hideToolbar";
/**
 * Take the agent counts out of the activity strip.
 *
 * Off by default, so the counts show wherever there is a plane to count: a
 * number of remote machines being driven by something other than the person
 * watching is not a thing to make somebody go looking for. With the plane
 * switched off there is no strip and this preference decides nothing.
 *
 * The strip is not the only way back: this switch lives in Preferences, which
 * is where it stays reachable after the counts are gone.
 */
export const PREF_HIDE_AGENT_STATUS = "hideAgentStatus";

/**
 * Fired on `window` when a boolean preference is written in THIS window.
 *
 * Preferences and the shell chrome share a window here, so a switch flipped in
 * one has to reach the other without a reload. Readers that want to follow a
 * preference live listen for this and re-read; readers that only need the
 * value at the moment they act, which is most of them, carry on calling
 * [`readBoolPref`] and ignore it entirely. `detail` carries the key so a
 * listener can drop the events that are not about it.
 */
export const PREF_CHANGED_EVENT = "deskvnc://pref-changed";

export interface PrefChanged {
  key: string;
  value: boolean;
}

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
  // Outside the try above on purpose: a webview that refuses storage still has
  // the value for as long as this window lives, and a listener that acts on it
  // should get the same answer either way.
  try {
    window.dispatchEvent(
      new CustomEvent<PrefChanged>(PREF_CHANGED_EVENT, { detail: { key, value } }),
    );
  } catch {
    /* no DOM (a unit test); nothing is listening in that case either */
  }
}
