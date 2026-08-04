/**
 * Pointer-input behaviour that is easy to break and impossible to notice.
 *
 * These drive the real `SessionInput` against a stub renderer and decode the
 * binary packets it produces, so they assert what actually reaches the wire
 * rather than that a method was called.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SessionInput } from "./input";
import type { WebGLRenderer } from "./WebGLRenderer";

const KIND_POINTER = 0;
const POINTER_LEN = 7;
const RIGHT = 1 << 2;

interface Pointer {
  x: number;
  y: number;
  mask: number;
}

/** Decode every pointer event out of the packets that were sent. */
function pointers(packets: Uint8Array[]): Pointer[] {
  const out: Pointer[] = [];
  for (const packet of packets) {
    const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
    let at = 0;
    while (at + POINTER_LEN <= packet.byteLength && view.getUint8(at) === KIND_POINTER) {
      out.push({
        x: view.getUint16(at + 1, true),
        y: view.getUint16(at + 3, true),
        mask: view.getUint16(at + 5, true),
      });
      at += POINTER_LEN;
    }
  }
  return out;
}

function setup() {
  const canvas = document.createElement("canvas");
  // jsdom implements neither of these, and the real handler captures the
  // pointer so a drag that leaves the canvas keeps reporting.
  canvas.setPointerCapture = () => {};
  canvas.releasePointerCapture = () => {};
  document.body.appendChild(canvas);
  const sent: Uint8Array[] = [];
  // The renderer is only asked to map CSS points and park the cursor sprite.
  const renderer = {
    cssPointToFramebuffer: (x: number, y: number) => ({ x: Math.round(x), y: Math.round(y) }),
    setCursorPosition: () => {},
    getZoom: () => 1,
    setZoom: () => {},
    setScalingMode: () => {},
  } as unknown as WebGLRenderer;

  const zoomed: number[] = [];

  const input = new SessionInput(canvas, {
    renderer,
    // Copy: the class reuses its scratch buffers between events.
    send: (packet) => sent.push(packet.slice()),
    releaseAllKeys: () => {},
    onAppHotkey: () => false,
    onZoomGesture: (z) => zoomed.push(z),
  });
  input.attach();
  return { canvas, input, sent, zoomed };
}

describe("context-menu gestures", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("sends a right click for a two-finger tap, which arrives as contextmenu alone", () => {
    // The macOS trackpad "secondary click" gesture reaches the page as a
    // contextmenu event with no button-2 pointerdown/pointerup pair, so
    // without synthesising one the remote desktop never sees a right click.
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new MouseEvent("contextmenu", { clientX: 120, clientY: 80, bubbles: true }),
    );
    vi.advanceTimersByTime(100);

    expect(pointers(sent)).toEqual([
      { x: 120, y: 80, mask: RIGHT },
      { x: 120, y: 80, mask: 0 },
    ]);
  });

  it("does not double up when a real right button already covered the gesture", () => {
    // A physical right button fires pointerdown and then contextmenu for one
    // gesture; synthesising on top of that would right-click twice.
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 2, clientX: 10, clientY: 10, bubbles: true }),
    );
    canvas.dispatchEvent(
      new MouseEvent("contextmenu", { clientX: 10, clientY: 10, bubbles: true }),
    );
    vi.advanceTimersByTime(100);

    // Just the real press; the release follows from the real pointerup.
    expect(pointers(sent)).toEqual([{ x: 10, y: 10, mask: RIGHT }]);
  });

  it("stays silent in view-only mode", () => {
    const { canvas, input, sent } = setup();
    input.setViewOnly(true);
    canvas.dispatchEvent(
      new MouseEvent("contextmenu", { clientX: 5, clientY: 5, bubbles: true }),
    );
    vi.advanceTimersByTime(100);
    expect(pointers(sent)).toEqual([]);
  });
});

describe("pinch to zoom", () => {
  it("zooms the view and sends nothing to the remote", () => {
    // A trackpad pinch arrives as a ctrl+wheel event.
    const { canvas, sent, zoomed } = setup();
    canvas.dispatchEvent(
      new WheelEvent("wheel", { deltaY: -120, ctrlKey: true, clientX: 1, clientY: 1, bubbles: true }),
    );
    expect(zoomed.length).toBe(1);
    expect(pointers(sent)).toEqual([]);
  });

  it("does nothing at all once zoom is locked", () => {
    // The gesture is easy to trigger by accident mid-scroll, so locked it
    // must neither rescale the view nor fall through to the remote as
    // scroll-wheel clicks.
    const { canvas, input, sent, zoomed } = setup();
    input.setZoomLocked(true);
    canvas.dispatchEvent(
      new WheelEvent("wheel", { deltaY: -120, ctrlKey: true, clientX: 1, clientY: 1, bubbles: true }),
    );
    expect(zoomed).toEqual([]);
    expect(pointers(sent)).toEqual([]);
  });

  it("leaves ordinary scrolling alone while locked", () => {
    const { canvas, input, sent } = setup();
    input.setZoomLocked(true);
    canvas.dispatchEvent(
      new WheelEvent("wheel", { deltaY: 40, clientX: 1, clientY: 1, bubbles: true }),
    );
    // One wheel-down click (WHEEL_STEP px): press then release of bit 4.
    expect(pointers(sent).map((p) => p.mask)).toEqual([1 << 4, 0]);
  });
});
