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
import { keyEventToIds } from "./keysyms";

export type SendInput = (packet: Uint8Array) => void;

export interface SessionInputOptions {
  renderer: WebGLRenderer;
  send: SendInput;
  releaseAllKeys: () => void;
  /** Return true to swallow the event locally (app hotkeys). */
  onAppHotkey: (e: KeyboardEvent) => boolean;
  /** Ctrl/Cmd+wheel zoom gesture; receives the proposed zoom factor. */
  onZoomGesture?: (zoom: number) => void;
}

const WHEEL_STEP = 40; // px of deltaY per click when deltaMode is pixels

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
  return !!el && typeof el.closest === "function" && el.closest(LOCAL_UI_SELECTOR) !== null;
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

  private viewOnly = false;
  private passthrough = false;
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
  private panLastX = 0;
  private panLastY = 0;

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
  }

  // ------------------------------------------------------------- pointer

  private contentOverflows(): boolean {
    const t = this.renderer.contentTransform();
    const { width, height } = this.renderer.getRemoteSize();
    return width * t.scaleX > this.canvas.width + 1 || height * t.scaleY > this.canvas.height + 1;
  }

  private fbPoint(e: { clientX: number; clientY: number }): { x: number; y: number } {
    const rect = this.canvas.getBoundingClientRect();
    return this.renderer.cssPointToFramebuffer(e.clientX, e.clientY, rect);
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
    this.send(this.ptrBuf);
  }

  private onPointerDown = (e: PointerEvent): void => {
    this.canvas.focus({ preventScroll: true });
    // space-drag or middle-drag pans, but only when content overflows the viewport
    if (this.spaceHeld || (e.button === 1 && this.contentOverflows())) {
      this.panning = true;
      this.panLastX = e.clientX;
      this.panLastY = e.clientY;
      this.canvas.setPointerCapture(e.pointerId);
      e.preventDefault();
      if (e.button === 1) return; // middle button reserved for panning gesture
    }
    if (this.viewOnly || this.panning) return;
    this.canvas.setPointerCapture(e.pointerId);
    const bit = e.button === 0 ? 0 : e.button === 1 ? 1 : e.button === 2 ? 2 : -1;
    if (bit < 0) return;
    this.buttonMask |= 1 << bit;
    const p = this.fbPoint(e);
    this.lastX = p.x;
    this.lastY = p.y;
    this.sendPointer(p.x, p.y, this.buttonMask); // button transitions go immediately
    e.preventDefault();
  };

  private onPointerUp = (e: PointerEvent): void => {
    if (this.panning) {
      this.panning = false;
      return;
    }
    if (this.viewOnly) return;
    const bit = e.button === 0 ? 0 : e.button === 1 ? 1 : e.button === 2 ? 2 : -1;
    if (bit < 0) return;
    this.buttonMask &= ~(1 << bit);
    const p = this.fbPoint(e);
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
    this.send(this.wheelBuf);
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
    const step = e.deltaMode === 1 ? 1 : WHEEL_STEP; // line vs pixel mode
    this.wheelAccumY += e.deltaY / step;
    this.wheelAccumX += e.deltaX / step;
    const p = this.fbPoint(e);
    while (this.wheelAccumY <= -1) {
      this.wheelAccumY += 1;
      this.sendWheel(3, p.x, p.y); // up
    }
    while (this.wheelAccumY >= 1) {
      this.wheelAccumY -= 1;
      this.sendWheel(4, p.x, p.y); // down
    }
    while (this.wheelAccumX <= -1) {
      this.wheelAccumX += 1;
      this.sendWheel(5, p.x, p.y); // left
    }
    while (this.wheelAccumX >= 1) {
      this.wheelAccumX -= 1;
      this.sendWheel(6, p.x, p.y); // right
    }
  };

  // ------------------------------------------------------------ keyboard

  private sendKey(keysym: number, keycode: number, down: boolean): void {
    this.keyView.setUint8(0, KIND_KEY);
    this.keyView.setUint8(1, down ? 1 : 0);
    this.keyView.setUint32(2, keysym, true);
    this.keyView.setUint32(6, keycode, true);
    this.send(this.keyBuf);
  }

  /** Public: synthesize a key combo (Send menu: Ctrl+Alt+Del etc.). */
  sendKeyCombo(keysyms: number[]): void {
    if (this.viewOnly) return;
    for (const ks of keysyms) this.sendKey(ks, 0, true);
    for (let i = keysyms.length - 1; i >= 0; i--) this.sendKey(keysyms[i], 0, false);
  }

  private onKeyDown = (e: KeyboardEvent): void => {
    // Typing in one of our own dialogs/fields: leave it alone entirely.
    if (isLocalUiTarget(e)) return;
    if (this.onAppHotkey(e)) {
      e.preventDefault();
      return;
    }
    // Without pass-through, let OS-level shortcuts (Cmd/Win combos) through.
    if (!this.passthrough && (e.metaKey || (e.ctrlKey && e.altKey && e.code === "Delete"))) {
      return;
    }
    e.preventDefault();
    if (this.viewOnly) return;
    const ids = keyEventToIds(e);
    if (!ids) return;
    this.pressedKeys.set(e.code, ids);
    this.sendKey(ids.keysym, ids.keycode, true);
  };

  private onKeyUp = (e: KeyboardEvent): void => {
    if (isLocalUiTarget(e)) return;
    const held = this.pressedKeys.get(e.code);
    if (!held) return; // never sent the down, don't send a stray up
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
    this.send(buf);
  }

  private onBlur = (): void => {
    this.releaseAllLocal();
    this.releaseAll(); // backend-side stuck-modifier safety
  };
}
