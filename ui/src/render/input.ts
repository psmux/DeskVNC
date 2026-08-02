/**
 * Session input capture: pointer + wheel + keyboard -> compact binary packets
 * for the `send_input` command. Lives entirely outside React.
 *
 * ── Wire format (all multi-byte fields LITTLE-ENDIAN) ──────────────────────
 * Byte-exact contract: src-tauri/FRAME_FORMAT.md §"Input events", decoded by
 * `framing::decode_input`. There is NO padding byte after `kind`.
 *   Pointer : u8 kind=0 | u16 x | u16 y | u16 buttonMask              (7 bytes)
 *   Key     : u8 kind=1 | u8 down | u32 keysym | u32 keycode(0=none) (10 bytes)
 *   ReleaseAll : u8 kind=2                                            (1 byte)
 * Packets may be concatenated in one buffer (e.g. wheel press+release).
 * The whole buffer is the raw invoke body; the session id travels in the
 * `x-session-id` invoke header (see Session.tsx / sendInputFactory).
 *
 * Button mask bits: 0=left 1=middle 2=right 3=wheel-up 4=wheel-down
 *                   5=wheel-left 6=wheel-right
 */
import type { WebGLRenderer } from "./WebGLRenderer";
import { codePointToKeysym, keyEventToIds, type KeyIds } from "./keysyms";

export type SendInput = (packet: Uint8Array) => void;

export interface SessionInputOptions {
  renderer: WebGLRenderer;
  send: SendInput;
  releaseAllKeys: () => void;
  /** Return true to swallow the event locally (app hotkeys). */
  onAppHotkey: (e: KeyboardEvent) => boolean;
  /** Ctrl/Cmd+wheel zoom gesture; receives the proposed zoom factor. */
  onZoomGesture?: (zoom: number) => void;
  /**
   * Awaited before a forwarded paste chord is sent, so the remote pastes the
   * CURRENT local clipboard rather than whatever it last heard about. See
   * `deferForPaste` for the ordering contract.
   */
  onForwardedPaste?: () => Promise<unknown>;
}

const WHEEL_STEP = 40; // px of deltaY per click when deltaMode is pixels
const MAX_WHEEL_CLICKS_PER_EVENT = 10; // cap a single momentum-scroll flick

/**
 * How long a paste chord may wait for the clipboard push before going out
 * anyway. A wedged clipboard read must degrade to "pastes slightly stale
 * text", never to "typing is frozen".
 */
const PASTE_SYNC_TIMEOUT_MS = 300;

/** X11 keysym for AltGr/ISO Level 3 Shift, once confirmed (see handleAltGrPair). */
const ISO_LEVEL3_SHIFT = 0xfe03;
/** Windows fires ControlLeft then AltRight this close together for a real AltGr press. */
const ALTGR_PAIR_WINDOW_MS = 50;

/**
 * `e.code`'s own character on a plain layout: "a".."z" for the letter row,
 * "0".."9" for the digit row. Used to tell "Alt changed what this key
 * produces" (AltGr / Option composing a character) apart from "Alt is simply
 * held for an ordinary Alt+letter shortcut", which still reports the base
 * letter in `e.key` on most layouts. Returns null for keys this can't cheaply
 * decide (punctuation varies too much by layout to guess a baseline for).
 */
function baseCharForCode(code: string): string | null {
  const key = /^Key([A-Z])$/.exec(code);
  if (key) return key[1].toLowerCase();
  const digit = /^Digit([0-9])$/.exec(code);
  if (digit) return digit[1];
  return null;
}

/**
 * Selector for "this keystroke belongs to our own UI, not the remote desktop".
 *
 * The keyboard listeners sit on `window` in the CAPTURE phase, they have to,
 * to beat the browser to shortcuts, so they also see keys typed into our own
 * overlays. Forwarding those would be actively harmful: the credentials dialog
 * (PRD/10 §3.4) would type the user's password into the remote desktop, and
 * the unconditional `preventDefault()` would swallow Enter and Escape before
 * the dialog could act on them.
 */
const LOCAL_UI_SELECTOR =
  'input, textarea, select, [contenteditable="true"], [role="dialog"], [role="menu"]';

function isLocalUiTarget(e: KeyboardEvent): boolean {
  const el = e.target as Element | null;
  if (!el || typeof el.closest !== "function") return false;
  // The session's own hidden capture element is a textarea, but keys aimed at
  // it are precisely the ones that belong to the remote desktop.
  if (el.closest("[data-remote-capture]") !== null) return false;
  return el.closest(LOCAL_UI_SELECTOR) !== null;
}

/**
 * DOM named-key values ("Enter", "ArrowLeft", "MediaPlayPause") are ASCII
 * CamelCase identifiers. Anything else multi-character in `e.key` is not a
 * key name at all, it is TEXT that something injected as a synthetic
 * keystroke: dictation tools (Wispr Flow and friends post unicode-string key
 * events carrying a word at a time), automation, password managers. Named
 * keys we support resolved through the keysym tables before this is ever
 * consulted, so matching the name shape here only drops the ones we could
 * not type anyway.
 */
function isInjectedText(key: string): boolean {
  return Array.from(key).length > 1 && !/^[A-Z][A-Za-z0-9]*$/.test(key);
}

/** A keydown that will make the REMOTE paste: Cmd/Ctrl+V (any extra
 *  modifiers, so paste-without-formatting and terminal Ctrl+Shift+V count)
 *  or the classic X11 Shift+Insert. */
function isPasteChord(e: KeyboardEvent): boolean {
  if (e.code === "KeyV" && (e.metaKey || e.ctrlKey)) return true;
  return e.code === "Insert" && e.shiftKey;
}

/** Event `kind` discriminators, must match `framing::decode_input` exactly. */
const KIND_POINTER = 0;
const KIND_KEY = 1;
const KIND_RELEASE_ALL = 2;
const KIND_POINTER_LEN = 7;
const KIND_KEY_LEN = 10;

export class SessionInput {
  private canvas: HTMLCanvasElement;
  private renderer: WebGLRenderer;
  private send: SendInput;
  private releaseAll: () => void;
  private onAppHotkey: (e: KeyboardEvent) => boolean;
  private onZoomGesture?: (zoom: number) => void;
  private onForwardedPaste?: () => Promise<unknown>;

  /** Packets parked behind an in-flight paste sync; null = nothing pending. */
  private pendingSends: Uint8Array[] | null = null;

  private viewOnly = false;
  private passthrough = false;
  private naturalScroll = false;
  private forwardInsertedText = true;
  private attached = false;

  private buttonMask = 0;
  private lastX = 0;
  private lastY = 0;
  private moveDirty = false;
  private moveRaf = 0;
  private wheelAccumX = 0;
  private wheelAccumY = 0;
  private panning = false;
  private spaceHeld = false;
  private panButton = -1;
  private panLastX = 0;
  private panLastY = 0;

  /** When the last ControlLeft keydown was forwarded (see handleAltGrPair). */
  private ctrlLeftDownAt = 0;
  /** Hidden offscreen element that owns dead-key composition; see attach(). */
  private compositionEl: HTMLTextAreaElement | null = null;

  private pressedKeys = new Map<string, { keysym: number; keycode: number }>();

  // reusable scratch buffers, nothing allocated per event on the hot path
  private ptrBuf = new Uint8Array(KIND_POINTER_LEN);
  private ptrView = new DataView(this.ptrBuf.buffer);
  private keyBuf = new Uint8Array(KIND_KEY_LEN);
  private keyView = new DataView(this.keyBuf.buffer);
  private wheelBuf = new Uint8Array(KIND_POINTER_LEN * 2);
  private wheelView = new DataView(this.wheelBuf.buffer);

  constructor(canvas: HTMLCanvasElement, opts: SessionInputOptions) {
    this.canvas = canvas;
    this.renderer = opts.renderer;
    this.send = opts.send;
    this.releaseAll = opts.releaseAllKeys;
    this.onAppHotkey = opts.onAppHotkey;
    this.onZoomGesture = opts.onZoomGesture;
    this.onForwardedPaste = opts.onForwardedPaste;
  }

  /**
   * Send a packet, or park a COPY of it while a paste sync is in flight:
   * nothing may overtake the paste chord it followed, or a fast synthetic
   * paste (dictation tools post Cmd+V with the keyup milliseconds behind the
   * keydown) would release V before pressing it. Copies because the scratch
   * buffers are reused per event.
   */
  private dispatch(buf: Uint8Array): void {
    if (this.pendingSends) this.pendingSends.push(buf.slice());
    else this.send(buf);
  }

  setViewOnly(v: boolean): void {
    this.viewOnly = v;
    if (v) this.releaseAllLocal();
  }

  setPassthrough(v: boolean): void {
    this.passthrough = v;
  }

  getPassthrough(): boolean {
    return this.passthrough;
  }

  setNaturalScroll(v: boolean): void {
    this.naturalScroll = v;
  }

  /** Preferences ▸ Input ▸ "Type text inserted by dictation tools". */
  setForwardInsertedText(v: boolean): void {
    this.forwardInsertedText = v;
  }

  attach(): void {
    if (this.attached) return;
    this.attached = true;
    const c = this.canvas;
    c.addEventListener("pointerdown", this.onPointerDown);
    c.addEventListener("pointermove", this.onPointerMove);
    c.addEventListener("pointerup", this.onPointerUp);
    c.addEventListener("pointercancel", this.onPointerUp);
    c.addEventListener("wheel", this.onWheel, { passive: false });
    c.addEventListener("contextmenu", this.onContextMenu);
    window.addEventListener("keydown", this.onKeyDown, true);
    window.addEventListener("keyup", this.onKeyUp, true);
    window.addEventListener("blur", this.onBlur);
    this.compositionEl = this.createCompositionOverlay();
  }

  detach(): void {
    if (!this.attached) return;
    this.attached = false;
    // Let go of anything still held. Detaching only unhooks the listeners, so
    // without this the keyup (or pointerup) that would have released it goes
    // somewhere else and the remote desktop is left with the key down. `blur`
    // used to be the only way to stop owning the keyboard mid-keystroke;
    // switching away from a session tab is now another, and the switch gesture
    // itself is usually a modifier plus a key.
    this.releaseAllLocal();
    const c = this.canvas;
    c.removeEventListener("pointerdown", this.onPointerDown);
    c.removeEventListener("pointermove", this.onPointerMove);
    c.removeEventListener("pointerup", this.onPointerUp);
    c.removeEventListener("pointercancel", this.onPointerUp);
    c.removeEventListener("wheel", this.onWheel);
    c.removeEventListener("contextmenu", this.onContextMenu);
    window.removeEventListener("keydown", this.onKeyDown, true);
    window.removeEventListener("keyup", this.onKeyUp, true);
    window.removeEventListener("blur", this.onBlur);
    cancelAnimationFrame(this.moveRaf);
    this.compositionEl?.remove();
    this.compositionEl = null;
  }

  /**
   * Hidden, 1px offscreen textarea that owns keyboard focus while the session
   * has it, so every way an OS can produce text lands somewhere we can see:
   *
   * - Ordinary keys still arrive at the window-level capture listeners and
   *   are forwarded from `keydown`; their `preventDefault()` keeps them out
   *   of the textarea, so nothing is ever double-sent.
   * - Dead keys and CJK IMEs need a focused editable element to compose in;
   *   the finished string comes back through `compositionend`.
   * - Dictation (macOS system dictation, Wispr Flow in its insertion mode)
   *   and accessibility tools insert text directly into the focused element,
   *   which surfaces as `beforeinput` here and would otherwise vanish
   *   entirely: a canvas cannot receive inserted text.
   *
   * The `data-remote-capture` marker exempts it from the local-UI guard, and
   * the autocorrect family is disabled so the webview cannot rewrite what
   * the user actually produced before we forward it.
   */
  private createCompositionOverlay(): HTMLTextAreaElement {
    const el = document.createElement("textarea");
    el.setAttribute("aria-hidden", "true");
    el.setAttribute("data-remote-capture", "true");
    el.setAttribute("autocapitalize", "off");
    el.setAttribute("autocomplete", "off");
    el.setAttribute("autocorrect", "off");
    el.spellcheck = false;
    el.tabIndex = -1;
    el.style.cssText =
      "position:fixed;left:-1px;top:-1px;width:1px;height:1px;opacity:0;padding:0;border:0;resize:none;";
    el.addEventListener("compositionend", this.onCompositionEnd);
    el.addEventListener("beforeinput", this.onBeforeInput);
    // A Cmd/Ctrl+V that is NOT being passed through to the remote used to hit
    // the non-editable canvas and do nothing; keep that contract now that
    // focus sits on an editable element. Remote paste has its own path
    // (clipboard sync + the forwarded keystroke under pass-through).
    el.addEventListener("paste", (ev) => ev.preventDefault());
    document.body.appendChild(el);
    return el;
  }

  /**
   * Give the session the keyboard. Focus lands on the hidden capture element
   * rather than the canvas, see `createCompositionOverlay` for why.
   */
  focus(): void {
    (this.compositionEl ?? this.canvas).focus({ preventScroll: true });
  }

  // ------------------------------------------------------------- pointer

  private fbPoint(e: { clientX: number; clientY: number }): { x: number; y: number } {
    const rect = this.canvas.getBoundingClientRect();
    return this.renderer.cssPointToFramebuffer(e.clientX, e.clientY, rect);
  }

  /**
   * Cancel any pending coalesced move and snap `lastX`/`lastY` to `e`.
   *
   * Without this, a pointerup's release packet went out at the current point
   * while a move queued by the rAF coalescer in `onPointerMove` still fired
   * afterwards carrying the OLD point, a stale `move(P_old)` arriving right
   * after `release(P_new)`. Called from every path that resolves a pointer
   * event without going through the normal `sendPointer` call below.
   */
  private syncLastPoint(e: { clientX: number; clientY: number }): { x: number; y: number } {
    if (this.moveDirty) {
      cancelAnimationFrame(this.moveRaf);
      this.moveDirty = false;
    }
    const p = this.fbPoint(e);
    this.lastX = p.x;
    this.lastY = p.y;
    return p;
  }

  private sendPointer(x: number, y: number, mask: number): void {
    // Keep the locally-composited cursor under the real pointer.
    //
    // The remote cursor is drawn client-side from the server's cursor SHAPE so
    // it stays responsive when frames are slow (PRD/01 §3.5), but the shape
    // carries no position. `WebGLRenderer.setCursorPosition` was previously fed
    // only by the server's CursorPosition pseudo-encoding, which is a VMware
    // extension almost nothing sends, so the sprite sat at (0,0) forever and
    // the remote pointer appeared stuck in the top-left corner.
    this.renderer.setCursorPosition(x, y);

    this.ptrView.setUint8(0, KIND_POINTER);
    this.ptrView.setUint16(1, x, true);
    this.ptrView.setUint16(3, y, true);
    this.ptrView.setUint16(5, mask, true);
    this.dispatch(this.ptrBuf);
  }

  private onPointerDown = (e: PointerEvent): void => {
    this.focus();
    // Space-drag always pans. Middle-drag pans only with Alt held: reserving
    // plain middle-button for panning whenever the content overflowed the
    // viewport meant a middle-click (X11 paste-from-selection) worked or not
    // depending on zoom level; Alt+middle-drag keeps the gesture available
    // without swallowing the plain click.
    if (this.spaceHeld || (e.button === 1 && e.altKey)) {
      this.panning = true;
      this.panButton = e.button;
      this.panLastX = e.clientX;
      this.panLastY = e.clientY;
      this.canvas.setPointerCapture(e.pointerId);
      e.preventDefault();
      if (e.button === 1) {
        this.syncLastPoint(e);
        return;
      }
    }
    if (this.viewOnly || this.panning) {
      this.syncLastPoint(e);
      return;
    }
    this.canvas.setPointerCapture(e.pointerId);
    const bit = e.button === 0 ? 0 : e.button === 1 ? 1 : e.button === 2 ? 2 : -1;
    if (bit < 0) {
      this.syncLastPoint(e);
      return;
    }
    this.buttonMask |= 1 << bit;
    const p = this.syncLastPoint(e);
    this.sendPointer(p.x, p.y, this.buttonMask); // button transitions go immediately
    e.preventDefault();
  };

  private onPointerUp = (e: PointerEvent): void => {
    // Only release panning for the button that started it: onPointerUp used
    // to early-return for ANY button while panning, so releasing the left
    // button during a middle-drag pan never reached the mask update below and
    // buttonMask kept bit 0 set, a permanently "stuck" left button.
    if (this.panning && e.button === this.panButton) {
      this.panning = false;
      this.panButton = -1;
      this.syncLastPoint(e);
      return;
    }
    if (this.viewOnly) {
      this.syncLastPoint(e);
      return;
    }
    const bit = e.button === 0 ? 0 : e.button === 1 ? 1 : e.button === 2 ? 2 : -1;
    if (bit < 0) {
      this.syncLastPoint(e);
      return;
    }
    this.buttonMask &= ~(1 << bit);
    const p = this.syncLastPoint(e);
    this.sendPointer(p.x, p.y, this.buttonMask);
    e.preventDefault();
  };

  private onPointerMove = (e: PointerEvent): void => {
    if (this.panning) {
      const dpr = this.canvas.width / Math.max(1, this.canvas.getBoundingClientRect().width);
      this.renderer.panBy((this.panLastX - e.clientX) * dpr, (this.panLastY - e.clientY) * dpr);
      this.panLastX = e.clientX;
      this.panLastY = e.clientY;
      return;
    }
    if (this.viewOnly) return;
    const p = this.fbPoint(e);
    if (p.x === this.lastX && p.y === this.lastY) return;
    this.lastX = p.x;
    this.lastY = p.y;
    // coalesce to one pointer message per rAF
    if (!this.moveDirty) {
      this.moveDirty = true;
      this.moveRaf = requestAnimationFrame(() => {
        this.moveDirty = false;
        this.sendPointer(this.lastX, this.lastY, this.buttonMask);
      });
    }
  };

  private onContextMenu = (e: Event): void => {
    e.preventDefault(); // right-click belongs to the remote desktop
  };

  // --------------------------------------------------------------- wheel

  /** One wheel click = press+release of the scroll button bit, both in one buffer. */
  private sendWheel(bit: number, x: number, y: number): void {
    const v = this.wheelView;
    // press: 7-byte pointer event with the scroll bit set
    v.setUint8(0, KIND_POINTER);
    v.setUint16(1, x, true);
    v.setUint16(3, y, true);
    v.setUint16(5, this.buttonMask | (1 << bit), true);
    // release: a second 7-byte pointer event back at the resting mask
    v.setUint8(7, KIND_POINTER);
    v.setUint16(8, x, true);
    v.setUint16(10, y, true);
    v.setUint16(12, this.buttonMask, true);
    this.dispatch(this.wheelBuf);
  }

  private onWheel = (e: WheelEvent): void => {
    e.preventDefault();
    if (this.viewOnly) return;
    // Ctrl/Cmd + wheel = zoom, handled by the app layer via renderer
    if (e.ctrlKey || e.metaKey) {
      const z = this.renderer.getZoom() * (e.deltaY < 0 ? 1.1 : 0.9);
      if (this.onZoomGesture) {
        this.onZoomGesture(z);
      } else {
        this.renderer.setScalingMode("custom");
        this.renderer.setZoom(z);
      }
      return;
    }
    // Line (1) and page (2) mode already report "one unit per click"; only
    // pixel mode (0) needs dividing down by an assumed line height. Page mode
    // used to fall into the pixel branch (WHEEL_STEP=40), so a whole page's
    // worth of pixels was needed to register as a single click, scrolling was
    // effectively dead for any device that reports DOM_DELTA_PAGE.
    const step = e.deltaMode === 0 ? WHEEL_STEP : 1;
    let dy = e.deltaY / step;
    let dx = e.deltaX / step;
    if (this.naturalScroll) {
      dy = -dy;
      dx = -dx;
    }
    this.wheelAccumY += dy;
    this.wheelAccumX += dx;
    const p = this.fbPoint(e);
    // A single trackpad "flick" can hand us a momentum delta worth hundreds
    // of clicks at once; uncapped, that's hundreds of synchronous send_input
    // invokes from one event. Whatever doesn't fit stays in the accumulator
    // for the next wheel event instead of being dropped.
    let clicks = 0;
    while (this.wheelAccumY <= -1 && clicks < MAX_WHEEL_CLICKS_PER_EVENT) {
      this.wheelAccumY += 1;
      this.sendWheel(3, p.x, p.y); // up
      clicks++;
    }
    while (this.wheelAccumY >= 1 && clicks < MAX_WHEEL_CLICKS_PER_EVENT) {
      this.wheelAccumY -= 1;
      this.sendWheel(4, p.x, p.y); // down
      clicks++;
    }
    while (this.wheelAccumX <= -1 && clicks < MAX_WHEEL_CLICKS_PER_EVENT) {
      this.wheelAccumX += 1;
      this.sendWheel(5, p.x, p.y); // left
      clicks++;
    }
    while (this.wheelAccumX >= 1 && clicks < MAX_WHEEL_CLICKS_PER_EVENT) {
      this.wheelAccumX -= 1;
      this.sendWheel(6, p.x, p.y); // right
      clicks++;
    }
  };

  // ------------------------------------------------------------ keyboard

  private sendKey(keysym: number, keycode: number, down: boolean): void {
    this.keyView.setUint8(0, KIND_KEY);
    this.keyView.setUint8(1, down ? 1 : 0);
    this.keyView.setUint32(2, keysym, true);
    this.keyView.setUint32(6, keycode, true);
    this.dispatch(this.keyBuf);
  }

  /** Public: synthesize a key combo (Send menu: Ctrl+Alt+Del etc.). */
  sendKeyCombo(combo: KeyIds[]): void {
    if (this.viewOnly) return;
    for (const k of combo) this.sendKey(k.keysym, k.keycode, true);
    for (let i = combo.length - 1; i >= 0; i--) this.sendKey(combo[i].keysym, combo[i].keycode, false);
  }

  private onKeyDown = (e: KeyboardEvent): void => {
    // Typing in one of our own dialogs/fields: leave it alone entirely. This
    // also covers every keystroke of an in-progress dead-key sequence once
    // focus has moved to the composition overlay below.
    if (isLocalUiTarget(e)) return;
    if (this.onAppHotkey(e)) {
      e.preventDefault();
      return;
    }
    // Without pass-through, let OS-level shortcuts (Cmd/Win combos) through.
    if (!this.passthrough && (e.metaKey || (e.ctrlKey && e.altKey && e.code === "Delete"))) {
      return;
    }
    // Mid-composition keystrokes (dead-key sequences, CJK IMEs) belong to the
    // browser's composition machinery, not the wire: forwarding them would
    // both break the composition and double-type its pieces. The finished
    // string arrives once, via compositionend. keyCode 229 is the legacy
    // "IME is handling this" marker some engines still use.
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === "Dead") {
      // Do NOT preventDefault: that would kill the composition outright. The
      // capture element already holds focus, so the browser composes the
      // accented character there; the result comes back via
      // onCompositionEnd / onBeforeInput.
      this.focus();
      return;
    }
    if (this.handleAltGrPair(e)) return;
    e.preventDefault();
    if (this.viewOnly) return;
    if (this.handleComposedChar(e)) return;
    if (e.code === "ControlLeft") this.ctrlLeftDownAt = performance.now();
    const ids = keyEventToIds(e);
    if (!ids) {
      // A multi-character `e.key` that is not a DOM key name is text some
      // tool injected as a synthetic keystroke (dictation apps post a word
      // or phrase per event). One down/up per code point types it on the
      // remote; there is no physical key to track for a matching keyup.
      if (this.forwardInsertedText && isInjectedText(e.key)) this.forwardText(e.key);
      return;
    }
    this.pressedKeys.set(e.code, ids);
    if (isPasteChord(e)) {
      this.deferForPaste(ids);
      return;
    }
    this.sendKey(ids.keysym, ids.keycode, true);
  };

  /**
   * A forwarded paste should paste what the user's clipboard holds NOW.
   *
   * The automatic sync pushes on window focus, which covers "copy somewhere
   * else, come back, paste", but not clipboard writes that happen without a
   * focus change: dictation tools in clipboard mode (Wispr Flow's paste
   * insertion writes the transcript and synthesizes Cmd+V milliseconds
   * later), clipboard managers, and scripts. So the paste chord itself
   * triggers a push and waits for it; the ClipboardText command and the
   * keystrokes travel the same ordered command channel, so by the time the
   * remote sees V go down, the text is already there. Everything produced
   * while waiting is parked behind it (see `dispatch`), and a timeout keeps
   * a wedged clipboard read from freezing typing.
   */
  private deferForPaste(ids: KeyIds): void {
    const push = this.onForwardedPaste;
    if (!push || this.pendingSends) {
      this.sendKey(ids.keysym, ids.keycode, true);
      return;
    }
    const queue: Uint8Array[] = [];
    this.pendingSends = queue;
    let flushed = false;
    const flush = (): void => {
      if (flushed) return;
      flushed = true;
      if (this.pendingSends === queue) this.pendingSends = null;
      this.sendKey(ids.keysym, ids.keycode, true);
      for (const p of queue) this.send(p);
    };
    const timer = window.setTimeout(flush, PASTE_SYNC_TIMEOUT_MS);
    push()
      .catch(() => undefined)
      .finally(() => {
        window.clearTimeout(timer);
        flush();
      });
  }

  /** Type a string on the remote, one keysym press+release per code point. */
  private forwardText(text: string): void {
    if (this.viewOnly) return;
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (cp === undefined) continue;
      const keysym = codePointToKeysym(cp);
      this.sendKey(keysym, 0, true);
      this.sendKey(keysym, 0, false);
    }
  }

  /**
   * Windows synthesizes AltGr as ControlLeft down immediately followed
   * (within ALTGR_PAIR_WINDOW_MS) by AltRight down, both for the same
   * physical keypress. Forwarded literally that's Ctrl+Alt, a shortcut chord,
   * instead of "the start of an AltGr-composed character". ControlLeft still
   * goes out the moment it arrives, like any other key (delaying it would lag
   * every plain Ctrl press); the moment AltRight confirms this really was
   * AltGr, ControlLeft gets a synthetic keyup retracting it and
   * ISO_Level3_Shift goes out for AltRight in its place.
   */
  private handleAltGrPair(e: KeyboardEvent): boolean {
    if (e.code !== "AltRight") return false;
    const ctrl = this.pressedKeys.get("ControlLeft");
    if (!ctrl || performance.now() - this.ctrlLeftDownAt >= ALTGR_PAIR_WINDOW_MS) return false;
    this.pressedKeys.delete("ControlLeft");
    this.sendKey(ctrl.keysym, ctrl.keycode, false);
    const keycode = keyEventToIds(e)?.keycode ?? 0;
    const level3: KeyIds = { keysym: ISO_LEVEL3_SHIFT, keycode };
    this.pressedKeys.set(e.code, level3);
    this.sendKey(level3.keysym, level3.keycode, true);
    e.preventDefault();
    return true;
  }

  /**
   * AltGr (Windows: ControlLeft+AltRight) and macOS Option both report the
   * composed character in a perfectly ordinary keydown: `e.key` is the
   * printable glyph ("@", "€", "é"), not the physical key's base letter, but
   * `ctrlKey`/`altKey` are still set from the modifiers physically held.
   * Forwarded as-is that's Ctrl+Alt+char or Alt+char, which types nothing (or
   * the wrong thing) on the remote. Fix is the standard fake-modifier dance:
   * lift whichever modifiers we actually forwarded a down for, send the
   * composed character on its own, then put the modifiers back. Their
   * eventual real keyup still finds the entry in `pressedKeys` untouched and
   * releases normally, exactly once, no separate bookkeeping needed.
   */
  private handleComposedChar(e: KeyboardEvent): boolean {
    if (!e.altKey) return false;
    if (Array.from(e.key).length !== 1) return false; // not a single composed grapheme
    const code = e.code;
    // The modifier keys' own keydowns are handleAltGrPair / plain-modifier
    // territory, never a composed character.
    if (code === "AltLeft" || code === "AltRight" || code === "ControlLeft" || code === "ControlRight") {
      return false;
    }
    // Plain Alt+letter/digit shortcuts still report the unmodified base
    // character in `e.key` on most layouts; only a character that actually
    // differs is AltGr/Option doing composition.
    const base = baseCharForCode(code);
    if (base !== null && e.key.toLowerCase() === base) return false;
    const cp = e.key.codePointAt(0);
    if (cp === undefined) return false;
    const keysym = codePointToKeysym(cp);

    const held = (["AltLeft", "AltRight", "ControlLeft", "ControlRight"] as const).filter((c) =>
      this.pressedKeys.has(c),
    );
    for (const c of held) {
      const ids = this.pressedKeys.get(c)!;
      this.sendKey(ids.keysym, ids.keycode, false);
    }
    this.sendKey(keysym, 0, true);
    this.sendKey(keysym, 0, false);
    for (const c of held) {
      const ids = this.pressedKeys.get(c)!;
      this.sendKey(ids.keysym, ids.keycode, true);
    }
    return true;
  }

  /** Text arrived through the capture element (dead key, IME, dictation);
   *  forward it and reset the element for the next round. */
  private finishComposition(text: string): void {
    if (this.compositionEl) this.compositionEl.value = "";
    this.forwardText(text);
  }

  private onCompositionEnd = (e: CompositionEvent): void => {
    // Fires for every composition that resolves in the capture element: a
    // dead-key sequence, a CJK IME commit, or engine-side dictation that
    // routes through marked text. None of the keystrokes involved were
    // forwarded (the isComposing guard in onKeyDown), so the whole string
    // goes out here, exactly once.
    this.finishComposition(e.data ?? "");
  };

  private onBeforeInput = (e: InputEvent): void => {
    // Mid-composition updates are provisional; compositionend gets the final
    // text. What lands here with composition NOT in progress is text some
    // assistive layer inserted directly into the focused element, macOS
    // dictation and dictation utilities being the ones that matter: no
    // keystroke ever existed for it, so this is its only path to the remote.
    if (e.isComposing || e.inputType === "insertCompositionText") return;
    if (!e.data) return;
    if (e.inputType !== "insertText" && e.inputType !== "insertReplacementText") return;
    e.preventDefault();
    // Unlike composition (a user physically typing through an IME), text
    // landing here was inserted by software, which is exactly what the
    // preference lets people turn off.
    if (!this.forwardInsertedText) {
      if (this.compositionEl) this.compositionEl.value = "";
      return;
    }
    this.finishComposition(e.data);
  };

  private onKeyUp = (e: KeyboardEvent): void => {
    const held = this.pressedKeys.get(e.code);
    if (!held) return; // never sent the down (or it was typed into our own UI); nothing to release
    // A modifier held down when focus moved to one of our own dialogs must
    // still release on the remote, or it would be stuck down forever; the
    // isLocalUiTarget guard therefore only ever matters for keys we never
    // forwarded a down for, handled by the `!held` case above.
    e.preventDefault();
    this.pressedKeys.delete(e.code);
    if (this.viewOnly) return;
    this.sendKey(held.keysym, held.keycode, false);
  };

  setSpaceHeld(v: boolean): void {
    this.spaceHeld = v;
  }

  /**
   * Drop every key/button we believe is held. One kind-2 event covers the
   * whole keyboard (the shell tracks what it actually pressed), so this is a
   * single packet instead of one per held key.
   */
  private releaseAllLocal(): void {
    const hadKeys = this.pressedKeys.size > 0;
    const hadButtons = this.buttonMask !== 0;
    if (!hadKeys && !hadButtons) return;
    this.pressedKeys.clear();
    this.buttonMask = 0;
    const buf = new Uint8Array(1 + (hadButtons ? KIND_POINTER_LEN : 0));
    buf[0] = KIND_RELEASE_ALL;
    if (hadButtons) {
      const v = new DataView(buf.buffer);
      v.setUint8(1, KIND_POINTER);
      v.setUint16(2, this.lastX, true);
      v.setUint16(4, this.lastY, true);
      v.setUint16(6, 0, true);
    }
    this.dispatch(buf);
  }

  private onBlur = (): void => {
    this.releaseAllLocal();
    this.releaseAll(); // backend-side stuck-modifier safety
  };
}
