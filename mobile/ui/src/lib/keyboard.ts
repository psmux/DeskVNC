/**
 * Keep the field being typed in above the phone keyboard.
 *
 * The keyboard takes the bottom half of the screen. On Android MainActivity
 * shrinks the WebView for it, on iOS the visual viewport shrinks; either way
 * a field near the bottom (a sign in sheet's password, its Sign in button
 * under it) can end up behind the keyboard until something scrolls it into
 * view. This does, once the keyboard has finished opening.
 *
 * The session screen's hidden typing field is left alone: it is meant to sit
 * off screen, and scrolling to it would move the desktop.
 */

/** Fields that bring up a keyboard, and are not the session's hidden one. */
export function wantsKeyboardRoom(el: Element | null): el is HTMLElement {
  if (!el || !(el instanceof HTMLElement)) return false;
  if (el.closest(".dv-session") && el.classList.contains("dv-s-hidden-input")) return false;
  if (el instanceof HTMLTextAreaElement) return !el.readOnly;
  if (el instanceof HTMLInputElement) {
    if (el.readOnly || el.disabled) return false;
    return !["button", "checkbox", "radio", "range", "submit", "reset", "file", "color", "hidden", "image"].includes(el.type);
  }
  return el.isContentEditable === true;
}

/** Scroll the focused field into the middle of what is left, and again as the keyboard settles. */
export function installKeyboardRoom(win: Window = window): () => void {
  let timers: ReturnType<typeof setTimeout>[] = [];
  const reveal = (): void => {
    const el = win.document.activeElement;
    if (!wantsKeyboardRoom(el)) return;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    // Bring the form's submit button along when there is room for it.
    const submit = el.closest("form")?.querySelector<HTMLElement>('button[type="submit"]');
    if (submit) {
      const r = submit.getBoundingClientRect();
      const bottom = win.visualViewport ? win.visualViewport.height + win.visualViewport.offsetTop : win.innerHeight;
      const top = el.getBoundingClientRect().top;
      if (r.bottom > bottom && r.bottom - top < bottom * 0.8) submit.scrollIntoView({ block: "end", behavior: "smooth" });
    }
  };
  const onFocus = (e: FocusEvent): void => {
    if (!wantsKeyboardRoom(e.target as Element)) return;
    timers.forEach(clearTimeout);
    // The keyboard animates in over about a quarter of a second.
    timers = [setTimeout(reveal, 120), setTimeout(reveal, 400)];
  };
  const onResize = (): void => reveal();
  win.document.addEventListener("focusin", onFocus);
  win.addEventListener("resize", onResize);
  win.visualViewport?.addEventListener("resize", onResize);
  return () => {
    timers.forEach(clearTimeout);
    win.document.removeEventListener("focusin", onFocus);
    win.removeEventListener("resize", onResize);
    win.visualViewport?.removeEventListener("resize", onResize);
  };
}
