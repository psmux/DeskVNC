/**
 * Suppress the webview's native context menu everywhere it does not belong.
 *
 * ## The bug this fixes
 *
 * Clicking a tab would occasionally pop up a "Paste" menu. The click had
 * nothing to do with it: a secondary click anywhere in the window produced it,
 * and a secondary click is easy to make by accident, since Ctrl+click and a
 * two-finger trackpad tap both count as one on macOS.
 *
 * What made it a *paste* menu is where the focus was. Both kinds of session
 * keep a focused, editable element to own keyboard input: a VNC or RDP session
 * has the transparent composition overlay in `render/input.ts` (a `textarea`
 * sized over the canvas, which dictation and IME need in the accessibility
 * tree), and an SSH session has xterm's own helper textarea. A webview offers
 * the editing menu based on the **focused** element, not the clicked one, so
 * with either of those focused the menu appeared over the tab strip, the
 * toolbar, anywhere. It only happened with a session open, which is also the
 * only time there are tabs to click, hence "occasionally".
 *
 * ## The rule
 *
 * A desktop app should not show a browser's context menu for its chrome. It
 * should show one in a real text field, where Cut, Copy, Paste and the spell
 * checker are exactly what the user wants. So: allow it for a genuine,
 * user-facing text field, and suppress it everywhere else.
 *
 * The hidden capture elements are deliberately excluded. They are editable for
 * the accessibility tree's benefit, not because anyone types into them
 * directly, and their own paste handling already has a path
 * (`render/input.ts` cancels paste on the overlay, and the terminal has
 * clipboard support of its own).
 */

/** Marks an element that is editable for machinery, not for a human. */
const CAPTURE_ATTRIBUTE = "data-remote-capture";

/**
 * Marks a field that is focused for convenience rather than because anyone
 * asked for it.
 *
 * An empty pane focuses its host search box so a split can be typed into
 * straight away. That is worth having, but it means a genuine text field now
 * holds the focus for as long as the pane sits empty, and the editing menu a
 * webview offers is built from the FOCUSED element rather than the clicked one
 * (see the note above). Suppressing the event we can see is not always enough
 * on that path, so a secondary click anywhere in the chrome also lets this kind
 * of field go: nothing is lost, because nobody chose to be in it.
 */
const COURTESY_FOCUS_ATTRIBUTE = "data-courtesy-focus";

/** xterm's hidden input element, which exists for the same reason. */
const TERMINAL_HELPER_CLASS = "xterm-helper-textarea";

/**
 * Should the webview's own context menu be allowed for this event target?
 *
 * Pure and exported so the rule can be tested without a webview: the failure
 * this guards against is invisible in a unit test otherwise, because jsdom has
 * no native menu to observe.
 */
export function allowsNativeContextMenu(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;

  // A field the user is actually typing into. `closest` rather than a tag
  // check on the target itself, because a click can land on a child of a
  // contenteditable region.
  const editable = target.closest<HTMLElement>(
    "input, textarea, [contenteditable=''], [contenteditable='true']",
  );
  if (!editable) return false;

  // The session's keyboard-capture elements are editable for the
  // accessibility tree, not for a person. Offering Paste over them is the
  // whole bug.
  if (editable.hasAttribute(CAPTURE_ATTRIBUTE)) return false;
  if (editable.classList.contains(TERMINAL_HELPER_CLASS)) return false;

  // A disabled or read-only field has nothing to offer either.
  if (editable instanceof HTMLInputElement || editable instanceof HTMLTextAreaElement) {
    if (editable.disabled || editable.readOnly) return false;
  }

  return true;
}

/**
 * Install the suppressor. Returns the undo, for symmetry with the other
 * listeners this app installs; in practice it lives for the window's lifetime.
 *
 * Bubble phase, not capture, and it respects `defaultPrevented`: the session
 * canvas forwards a right click to the remote desktop and handles the event
 * itself, so anything already dealt with is left alone rather than
 * second-guessed.
 */
export function installContextMenuSuppressor(root: Window = window): () => void {
  const onContextMenu = (e: Event): void => {
    if (e.defaultPrevented) return;
    if (allowsNativeContextMenu(e.target)) return;
    e.preventDefault();
    dropCourtesyFocus(root, e.target);
  };
  root.addEventListener("contextmenu", onContextMenu);
  return () => root.removeEventListener("contextmenu", onContextMenu);
}

/**
 * Let go of a field nobody chose to be in, when the click was somewhere else.
 *
 * `preventDefault` above deals with the menu the page is offered. It does not
 * reliably deal with the editing menu a webview puts up for whatever is
 * FOCUSED, which is the whole reason this module exists, and which came back
 * the moment a real text field started being focused as a courtesy. Blurring it
 * removes the thing that menu would have been about.
 *
 * Only ever a field marked as courtesy-focused, and only when the click landed
 * outside it: a search box the user deliberately clicked into keeps its focus
 * and its menu, which is the behaviour the rule above is there to protect.
 */
function dropCourtesyFocus(root: Window, target: EventTarget | null): void {
  const active = root.document.activeElement;
  if (!(active instanceof HTMLElement)) return;
  if (!active.hasAttribute(COURTESY_FOCUS_ATTRIBUTE)) return;
  if (target instanceof Node && active.contains(target)) return;
  active.blur();
}
