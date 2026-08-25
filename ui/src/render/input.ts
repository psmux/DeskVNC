/**
 * Session input capture: pointer + wheel + keyboard -> compact binary packets
 * for the `send_input` command. Lives entirely outside React.
 *
 * ── Wire format (all multi-byte fields LITTLE-ENDIAN) ──────────────────────
 * Byte-exact contract: src-tauri/FRAME_FORMAT.md §"Input events", decoded by
 * `framing::decode_input`. There is NO padding byte after `kind`.
 *   Pointer  : u8 kind=0 | u16 x | u16 y | u16 buttonMask              (7 bytes)
 *   Key      : u8 kind=1 | u8 down | u32 keysym | u32 keycode(0=none) (10 bytes)
 *   ReleaseAll : u8 kind=2                                            (1 byte)
 *   TerminalInput  : u8 kind=3 | u32 len | len bytes of payload  (5 + len bytes)
 *   TerminalResize : u8 kind=4 | u16 cols | u16 rows                  (5 bytes)
 * Packets may be concatenated in one buffer (e.g. wheel press+release, or a
 * terminal input chunk followed by a resize). The whole buffer is the raw
 * invoke body; the session id travels in the `x-session-id` invoke header
 * (see Session.tsx / sendInputFactory).
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

/**
 * How long a synthesised right click waits for a real button-2 press to show
 * up and cancel it. Long enough to cover the gap between `pointerdown` and
 * `contextmenu` in one gesture, short enough not to be felt as lag.
 */
const CONTEXT_MENU_SETTLE_MS = 60;
/** A real right button this recently means the gesture is already covered. */
const CONTEXT_MENU_DEDUP_MS = 500;

/**
 * Edge auto-scroll, for a view larger than its window (1:1 on a big desktop).
 *
 * Panning already existed but only through space-drag, which nobody finds,
 * so parts of the remote screen were simply unreachable (issue #1). Moving
 * the pointer into this band of the edge scrolls toward it, the way RealVNC
 * does, at a speed that grows as the pointer gets closer to the edge.
 */
const EDGE_SCROLL_ZONE_PX = 56;
/** Device pixels per frame at the very edge; ~1000 px/s at 60fps. */
const EDGE_SCROLL_MAX_SPEED = 17;

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
const KIND_TERMINAL_INPUT = 3;
const KIND_TERMINAL_RESIZE = 4;

/**
 * Same cap `framing::decode_input` enforces (`MAX_TERMINAL_INPUT_LEN`): a
 * `len` above this fails the WHOLE `send_input` body, not just this event, so
 * a paste larger than one chunk has to be split before it ever reaches the
 * wire rather than relied on the backend to reject gracefully.
 */
const MAX_TERMINAL_INPUT_LEN = 64 * 1024;

/**
 * Encode one terminal-input event (kind 3): raw bytes to write to the remote
 * PTY, keystrokes, a paste, an IME commit. A body over the 64 KiB cap is
 * split into several kind-3 events concatenated in the returned buffer
 * (`decode_input` walks a body as a sequence of events, so this is still one
 * `send_input` call), rather than sent whole and rejected by the decoder.
 */
export function encodeTerminalInput(bytes: Uint8Array): Uint8Array {
  if (bytes.byteLength <= MAX_TERMINAL_INPUT_LEN) return encodeTerminalInputChunk(bytes);
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (let off = 0; off < bytes.byteLength; off += MAX_TERMINAL_INPUT_LEN) {
    const chunk = encodeTerminalInputChunk(bytes.subarray(off, off + MAX_TERMINAL_INPUT_LEN));
    chunks.push(chunk);
    total += chunk.byteLength;
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

function encodeTerminalInputChunk(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + bytes.byteLength);
  new DataView(out.buffer).setUint32(1, bytes.byteLength, true);
  out[0] = KIND_TERMINAL_INPUT;
  out.set(bytes, 5);
  return out;
}

/** Encode a terminal-resize event (kind 4): the new grid size in character
 *  cells, not pixels, 80 columns is not 80 pixels. */
export function encodeTerminalResize(cols: number, rows: number): Uint8Array {
  const out = new Uint8Array(5);
  const view = new DataView(out.buffer);
  view.setUint8(0, KIND_TERMINAL_RESIZE);
  view.setUint16(1, cols, true);
  view.setUint16(3, rows, true);
  return out;
}

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
  private zoomLocked = false;
  private edgePan = true;
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
  private panButton = -1;
  private panLastX = 0;
  private panLastY = 0;

  private autoScrollRaf = 0;
  private autoScrollVX = 0;
  private autoScrollVY = 0;
  private lastClientX = 0;
  private lastClientY = 0;
  /** When a real right button was last pressed (see onContextMenu). */
  private lastRightButtonAt = Number.NEGATIVE_INFINITY;
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
  /** Press and release of a synthesised click, which travel as one packet. */
  private clickBuf = new Uint8Array(KIND_POINTER_LEN * 2);
  private clickView = new DataView(this.clickBuf.buffer);

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

  /** Toolbar ▸ Scaling ▸ "Lock zoom": ignore pinch-to-zoom gestures. */
  setZoomLocked(v: boolean): void {
    this.zoomLocked = v;
  }

  /** Toolbar ▸ Scaling ▸ "Pan by moving to edges". */
  setEdgePan(v: boolean): void {
    this.edgePan = v;
    if (!v) this.stopEdgeScroll();
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
    // Capture can be taken away without a pointerup ever arriving: an OS
    // gesture claims the pointer, or the canvas is replaced under us. Both
    // land here, and both used to leave a button held down forever.
    c.addEventListener("lostpointercapture", this.onPointerUp);
    c.addEventListener("wheel", this.onWheel, { passive: false });
    c.addEventListener("contextmenu", this.onContextMenu);
    c.addEventListener("pointerleave", this.onPointerLeave);
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
    c.removeEventListener("lostpointercapture", this.onPointerUp);
    c.removeEventListener("wheel", this.onWheel);
    c.removeEventListener("contextmenu", this.onContextMenu);
    c.removeEventListener("pointerleave", this.onPointerLeave);
    window.removeEventListener("keydown", this.onKeyDown, true);
    window.removeEventListener("keyup", this.onKeyUp, true);
    window.removeEventListener("blur", this.onBlur);
    cancelAnimationFrame(this.moveRaf);
    this.stopEdgeScroll();
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
    // Deliberately NOT aria-hidden, and sized over the canvas rather than
    // parked 1px offscreen: dictation tools decide whether there is anywhere
    // to insert text by asking the accessibility tree about the focused
    // element, and an element excluded from that tree (aria-hidden) or
    // pruned as invisible reads as "not a text input", so they refuse to
    // deliver anything. Transparent and pointer-events:none, so it is
    // invisible and clicks fall through to the canvas, but to accessibility
    // machinery it is an honest, focused, canvas-sized text area. This also
    // puts IME candidate windows near the session instead of a corner.
    el.setAttribute("aria-label", "Remote desktop keyboard input");
    el.setAttribute("data-remote-capture", "true");
    el.setAttribute("autocapitalize", "off");
    el.setAttribute("autocomplete", "off");
    el.setAttribute("autocorrect", "off");
    el.spellcheck = false;
    el.tabIndex = -1;
    // Invisible through transparency rather than `opacity: 0`: a fully
    // transparent element is a candidate for being treated as not rendered,
    // and an accessibility client that filters those back out would be shown
    // nothing again. Transparent text on a transparent background is
    // ordinary, visible-to-the-tree content that simply cannot be seen.
    el.style.cssText =
      "position:absolute;inset:0;width:100%;height:100%;pointer-events:none;" +
      "padding:0;border:0;margin:0;outline:none;resize:none;overflow:hidden;" +
      "background:transparent;color:transparent;caret-color:transparent;";
    el.addEventListener("compositionend", this.onCompositionEnd);
    el.addEventListener("beforeinput", this.onBeforeInput);
    el.addEventListener("input", this.onInputFallback);
    // A Cmd/Ctrl+V that is NOT being passed through to the remote used to hit
    // the non-editable canvas and do nothing; keep that contract now that
    // focus sits on an editable element. Remote paste has its own path
    // (clipboard sync + the forwarded keystroke under pass-through).
    el.addEventListener("paste", (ev) => ev.preventDefault());
    // Into the canvas's container (position:relative), so inset:0 tracks the
    // session area with no per-frame geometry syncing.
    (this.canvas.parentElement ?? document.body).appendChild(el);
    return el;
  }

  /**
   * Last-resort insertion catch: text that reached the element's VALUE
   * without going through beforeinput or composition. Accessibility-API
   * insertion (AXSetValue) can do this, and it is one of the ways dictation
   * tools deliver a transcript. Handled paths never get here: forwarded
   * keydowns are preventDefault'ed, handled beforeinput is
   * preventDefault'ed, and composition clears the value in finishComposition
   * with mid-composition updates skipped via isComposing.
   */
  private onInputFallback = (e: Event): void => {
    if ((e as InputEvent).isComposing) return;
    const el = this.compositionEl;
    if (!el || !el.value) return;
    const text = el.value;
    el.value = "";
    if (this.forwardInsertedText) this.forwardText(text);
  };

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
    this.stopEdgeScroll();
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
    // Alt+middle-drag pans deliberately. There was a space-drag here too,
    // but nothing ever told the handler the space bar was down, so it never
    // worked at all -- and wiring it up would have been wrong anyway: space
    // is an ordinary key that belongs to the remote desktop, so holding it
    // to pan would stop it typing. Edge scrolling covers the case it was
    // meant for.
    if (e.button === 1 && e.altKey) {
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
    // `buttons` outranks our running total. If a release went missing while
    // the pointer was off the canvas, this is where it is noticed. The bit
    // for this press is forced on because a browser need not have folded it
    // into `buttons` yet.
    this.buttonMask = SessionInput.buttonsToMask(e.buttons) | (1 << bit);
    // A real right button press cancels the contextmenu-synthesised click
    // that would otherwise duplicate this gesture (see onContextMenu).
    if (bit === 2) this.lastRightButtonAt = performance.now();
    const p = this.syncLastPoint(e);
    this.sendPointer(p.x, p.y, this.buttonMask); // button transitions go immediately
    e.preventDefault();
  };

  private onPointerUp = (e: PointerEvent): void => {
    // Only release panning for the button that started it: onPointerUp used
    // to early-return for ANY button while panning, so releasing the left
    // button during a middle-drag pan never reached the mask update below and
    // buttonMask kept bit 0 set, a permanently "stuck" left button.
    // `e.button` is -1 on pointercancel and lostpointercapture, which no pan
    // button can equal, so a cancelled pan used to leave `panning` set and
    // every later press took the early return below: pointer input stopped
    // entirely until the session was reattached.
    if (this.panning && (e.button === this.panButton || e.button < 0)) {
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
      // A cancel, a lost capture, or a button we do not forward. The first two
      // carry `buttons` of 0, so this is what releases what was held.
      const q = this.syncLastPoint(e);
      this.reconcileButtons(e, q.x, q.y);
      return;
    }
    this.buttonMask = SessionInput.buttonsToMask(e.buttons) & ~(1 << bit);
    const p = this.syncLastPoint(e);
    this.sendPointer(p.x, p.y, this.buttonMask);
    e.preventDefault();
  };

  /**
   * The buttons the browser says are really held, in our wire order.
   *
   * `PointerEvent.buttons` is a live set carried on every event, so it is
   * right even when a transition was never delivered. `button` reports only
   * the one that changed and is -1 on `pointercancel` and
   * `lostpointercapture`, which is what let a stuck button survive. The bit
   * order is not ours: 1 is left, 2 is RIGHT and 4 is middle, against our
   * bit 0 left, bit 1 middle, bit 2 right.
   */
  private static buttonsToMask(buttons: number): number {
    return (
      (buttons & 1 ? 1 << 0 : 0) | (buttons & 4 ? 1 << 1 : 0) | (buttons & 2 ? 1 << 2 : 0)
    );
  }

  /**
   * Put `buttonMask` back in step with the browser, and tell the remote if it
   * had drifted.
   *
   * Any divergence is a button the remote believes is held and the user is not
   * holding. That is not a cosmetic error: with the right button stuck, the
   * next right press is no transition at all so it does nothing, its release
   * arrives much later as an unpaired up, and an ordinary left click reaches
   * the desktop as a left press underneath a held right button, which is a
   * context menu. Correcting it on the very next pointer event keeps the
   * window in which that can happen to a single event.
   */
  private reconcileButtons(e: PointerEvent, x: number, y: number): void {
    const held = SessionInput.buttonsToMask(e.buttons);
    if (held === this.buttonMask) return;
    this.buttonMask = held;
    this.sendPointer(x, y, held);
  }

  private onPointerMove = (e: PointerEvent): void => {
    if (this.panning) {
      const dpr = this.canvas.width / Math.max(1, this.canvas.getBoundingClientRect().width);
      this.renderer.panBy((this.panLastX - e.clientX) * dpr, (this.panLastY - e.clientY) * dpr);
      this.panLastX = e.clientX;
      this.panLastY = e.clientY;
      return;
    }
    this.lastClientX = e.clientX;
    this.lastClientY = e.clientY;
    this.updateEdgeScroll();
    if (this.viewOnly) return;
    const p = this.fbPoint(e);
    // Before the early return below, so a mask that drifted is corrected even
    // while the pointer sits still. This is the backstop for a release that
    // happened somewhere we get no event at all, such as outside the window.
    this.reconcileButtons(e, p.x, p.y);
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

  /**
   * Right button pressed and released at one point, as a context gesture.
   *
   * Both halves go in ONE packet, exactly as the wheel does. Two separate
   * `sendPointer` calls are two independent IPC requests, and nothing
   * guarantees the shell handles them in the order they were issued: land the
   * release first and the remote is left holding the right button, so the
   * click does nothing until some later pointer event happens to carry a mask
   * without that bit. A press and its release that belong to one gesture must
   * never be able to overtake each other.
   */
  private sendRightClick(x: number, y: number): void {
    const right = 1 << 2;
    const v = this.clickView;
    v.setUint8(0, KIND_POINTER);
    v.setUint16(1, x, true);
    v.setUint16(3, y, true);
    v.setUint16(5, this.buttonMask | right, true);
    v.setUint8(7, KIND_POINTER);
    v.setUint16(8, x, true);
    v.setUint16(10, y, true);
    v.setUint16(12, this.buttonMask, true);
    this.dispatch(this.clickBuf);
  }

  /**
   * A context-menu gesture the remote never heard about.
   *
   * A two-finger tap on a macOS trackpad (System Settings ▸ Trackpad ▸
   * "Secondary click") is delivered to the page as a `contextmenu` event and
   * nothing else: there is no button-2 `pointerdown`/`pointerup` pair, which
   * is the only thing `onPointerDown` forwards. So the gesture every Mac
   * laptop user makes to right-click produced exactly nothing on the remote
   * desktop, while a physical right button worked.
   *
   * Synthesising the click here covers the gesture whatever the OS chooses
   * to send. The short delay is the de-duplication: a real right button
   * fires `pointerdown` and *then* `contextmenu` in the same gesture, so
   * waiting a moment lets that arrive and cancel this, and it also works if
   * an engine ever sends the two in the other order.
   */
  /**
   * Set the auto-scroll velocity from where the pointer is, and run or stop
   * the loop accordingly. Only scrolls toward an edge that still has content
   * behind it, so it is inert whenever the desktop already fits.
   */
  private updateEdgeScroll(): void {
    if (!this.edgePan) return this.stopEdgeScroll();
    const rect = this.canvas.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return this.stopEdgeScroll();
    const dpr = this.canvas.width / rect.width;
    const room = this.renderer.panRoom();

    // How far into each edge band the pointer is, 0 (outside) to 1 (at it).
    const depth = (distance: number): number =>
      distance >= EDGE_SCROLL_ZONE_PX ? 0 : Math.min(1, (EDGE_SCROLL_ZONE_PX - distance) / EDGE_SCROLL_ZONE_PX);
    const left = depth(this.lastClientX - rect.left);
    const right = depth(rect.right - this.lastClientX);
    const up = depth(this.lastClientY - rect.top);
    const down = depth(rect.bottom - this.lastClientY);

    // Inside the canvas only: a pointer that has left entirely must not keep
    // the view sliding.
    const inside =
      this.lastClientX >= rect.left &&
      this.lastClientX <= rect.right &&
      this.lastClientY >= rect.top &&
      this.lastClientY <= rect.bottom;

    const speed = EDGE_SCROLL_MAX_SPEED * dpr;
    let vx = 0;
    let vy = 0;
    if (inside) {
      if (left > 0 && room.left > 0) vx = -left * speed;
      else if (right > 0 && room.right > 0) vx = right * speed;
      if (up > 0 && room.up > 0) vy = -up * speed;
      else if (down > 0 && room.down > 0) vy = down * speed;
    }
    this.autoScrollVX = vx;
    this.autoScrollVY = vy;
    if (vx === 0 && vy === 0) this.stopEdgeScroll();
    else if (this.autoScrollRaf === 0) this.autoScrollRaf = requestAnimationFrame(this.stepEdgeScroll);
  }

  private stopEdgeScroll(): void {
    if (this.autoScrollRaf !== 0) {
      cancelAnimationFrame(this.autoScrollRaf);
      this.autoScrollRaf = 0;
    }
    this.autoScrollVX = 0;
    this.autoScrollVY = 0;
  }

  private stepEdgeScroll = (): void => {
    this.autoScrollRaf = 0;
    if (this.autoScrollVX === 0 && this.autoScrollVY === 0) return;
    // `panBy` moves the VIEW, not the content: `contentTransform` places the
    // content at `-panX`, and the space-drag reads the same way round. The
    // velocities below are already in view terms (negative = look further
    // left), so they are passed straight through. Negating them here, on the
    // assumption that panning moved the content, sent every edge the wrong
    // way.
    this.renderer.panBy(this.autoScrollVX, this.autoScrollVY);
    // The same screen point is now a different framebuffer pixel, so the
    // remote pointer has to be told, or it lags behind the moving view.
    if (!this.viewOnly) {
      const p = this.fbPoint({ clientX: this.lastClientX, clientY: this.lastClientY });
      if (p.x !== this.lastX || p.y !== this.lastY) {
        this.lastX = p.x;
        this.lastY = p.y;
        this.sendPointer(p.x, p.y, this.buttonMask);
      }
    }
    // Re-evaluate: the room may have run out at the new position.
    this.updateEdgeScroll();
  };

  private onPointerLeave = (): void => {
    this.stopEdgeScroll();
  };

  private onContextMenu = (e: MouseEvent): void => {
    e.preventDefault(); // the menu belongs to the remote desktop, not to us
    if (this.viewOnly) return;
    const p = this.fbPoint(e);
    const at = performance.now();
    window.setTimeout(() => {
      if (this.lastRightButtonAt >= at - CONTEXT_MENU_DEDUP_MS) return;
      this.sendRightClick(p.x, p.y);
    }, CONTEXT_MENU_SETTLE_MS);
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
    // Ctrl/Cmd + wheel = zoom, handled by the app layer via renderer.
    // A trackpad pinch arrives exactly this way, which is why locking zoom
    // has to be handled here: the gesture is easy to trigger by accident
    // in the middle of a two-finger scroll, and the zoom it caused was
    // landing on the remote desktop as an unwanted scale change. Locked, the
    // gesture is swallowed rather than forwarded, so it neither zooms nor
    // turns into scroll events the remote would act on.
    if (e.ctrlKey || e.metaKey) {
      if (this.zoomLocked) return;
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
