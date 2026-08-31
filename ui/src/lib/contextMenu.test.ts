import { afterEach, describe, expect, it } from "vitest";
import { allowsNativeContextMenu, installContextMenuSuppressor } from "./contextMenu";

/**
 * The reported bug, reproduced: clicking a tab occasionally showed a Paste
 * menu. The reproduction is the point of this file, so it is written the way
 * it actually happened rather than as an abstract assertion.
 */

let cleanup: Array<() => void> = [];

afterEach(() => {
  cleanup.forEach((fn) => fn());
  cleanup = [];
  document.body.innerHTML = "";
});

function install(): void {
  cleanup.push(installContextMenuSuppressor(window));
}

/** The session's keyboard-capture overlay, as `render/input.ts` builds it. */
function sessionCaptureOverlay(): HTMLTextAreaElement {
  const el = document.createElement("textarea");
  el.setAttribute("data-remote-capture", "true");
  document.body.appendChild(el);
  return el;
}

describe("the native context menu", () => {
  it("does not appear over a tab, which is the reported bug", () => {
    // A session is open, so its capture overlay owns the focus. This is the
    // condition that made the menu a *paste* menu: a webview offers the
    // editing menu for the FOCUSED element, not the clicked one.
    const overlay = sessionCaptureOverlay();
    overlay.focus();

    const tab = document.createElement("button");
    tab.textContent = "build-agent-3";
    document.body.appendChild(tab);
    install();

    // Ctrl+click and a two-finger trackpad tap both arrive as this.
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    tab.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
  });

  it("still appears in a real text field, where paste is the point", () => {
    const field = document.createElement("input");
    document.body.appendChild(field);
    install();

    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    field.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(false);
  });

  /**
   * The session canvas forwards a right click to the remote desktop and
   * handles the event itself. Anything already dealt with must be left alone,
   * or this suppressor would be second-guessing the code that owns the
   * gesture.
   */
  it("leaves an event another handler already dealt with alone", () => {
    const canvas = document.createElement("canvas");
    document.body.appendChild(canvas);
    canvas.addEventListener("contextmenu", (e) => e.preventDefault());
    install();

    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    canvas.dispatchEvent(event);

    // Prevented, but by the canvas, which is what should own it.
    expect(event.defaultPrevented).toBe(true);
  });
});

describe("the rule", () => {
  it("allows a genuine text field", () => {
    const input = document.createElement("input");
    const textarea = document.createElement("textarea");
    const editable = document.createElement("div");
    editable.setAttribute("contenteditable", "true");
    for (const el of [input, textarea, editable]) document.body.appendChild(el);

    expect(allowsNativeContextMenu(input)).toBe(true);
    expect(allowsNativeContextMenu(textarea)).toBe(true);
    expect(allowsNativeContextMenu(editable)).toBe(true);
  });

  it("allows it for a child of a contenteditable region", () => {
    const region = document.createElement("div");
    region.setAttribute("contenteditable", "true");
    const child = document.createElement("span");
    region.appendChild(child);
    document.body.appendChild(region);

    expect(allowsNativeContextMenu(child)).toBe(true);
  });

  /**
   * The two elements at the heart of the bug. Both are editable so dictation
   * and IME can find them in the accessibility tree, not because anyone types
   * into them directly, so neither should ever produce an editing menu.
   */
  it("refuses the session's hidden keyboard-capture overlay", () => {
    expect(allowsNativeContextMenu(sessionCaptureOverlay())).toBe(false);
  });

  it("refuses the terminal's hidden helper textarea", () => {
    const helper = document.createElement("textarea");
    helper.className = "xterm-helper-textarea";
    document.body.appendChild(helper);

    expect(allowsNativeContextMenu(helper)).toBe(false);
  });

  it("refuses app chrome", () => {
    const button = document.createElement("button");
    const div = document.createElement("div");
    for (const el of [button, div]) document.body.appendChild(el);

    expect(allowsNativeContextMenu(button)).toBe(false);
    expect(allowsNativeContextMenu(div)).toBe(false);
    expect(allowsNativeContextMenu(null)).toBe(false);
  });

  it("refuses a field with nothing to offer", () => {
    const disabled = document.createElement("input");
    disabled.disabled = true;
    const readOnly = document.createElement("input");
    readOnly.readOnly = true;
    for (const el of [disabled, readOnly]) document.body.appendChild(el);

    expect(allowsNativeContextMenu(disabled)).toBe(false);
    expect(allowsNativeContextMenu(readOnly)).toBe(false);
  });

  /**
   * The editing menu a webview offers is built from the FOCUSED element, not
   * the clicked one, which is the whole reason this module exists. A field that
   * was focused as a courtesy rather than by choice therefore has to let go
   * when the user's secondary click was plainly about something else.
   */
  describe("a field focused as a courtesy", () => {
    function courtesyField(): HTMLInputElement {
      const input = document.createElement("input");
      input.setAttribute("data-courtesy-focus", "true");
      document.body.appendChild(input);
      input.focus();
      return input;
    }

    it("is let go when the secondary click lands on the chrome", () => {
      const input = courtesyField();
      const tab = document.createElement("button");
      document.body.appendChild(tab);
      expect(document.activeElement).toBe(input);

      const undo = installContextMenuSuppressor(window);
      tab.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
      undo();

      expect(document.activeElement).not.toBe(input);
    });

    it("keeps its focus, and its menu, when the click is inside it", () => {
      const input = courtesyField();

      const undo = installContextMenuSuppressor(window);
      input.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
      undo();

      // It is still a genuine text field, so Cut/Copy/Paste is exactly right.
      expect(allowsNativeContextMenu(input)).toBe(true);
      expect(document.activeElement).toBe(input);
    });

    it("leaves a field the user chose alone", () => {
      const search = document.createElement("input");
      document.body.appendChild(search);
      search.focus();
      const tab = document.createElement("button");
      document.body.appendChild(tab);

      const undo = installContextMenuSuppressor(window);
      tab.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
      undo();

      expect(document.activeElement).toBe(search);
    });
  });
});
