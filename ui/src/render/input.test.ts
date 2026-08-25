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
    panRoom: () => panRoom,
    panBy: (dx: number, dy: number) => panned.push([dx, dy]),
  } as unknown as WebGLRenderer;

  const zoomed: number[] = [];
  const panned: [number, number][] = [];
  // Room to scroll in every direction unless a test says otherwise.
  const panRoom = { left: 500, right: 500, up: 500, down: 500 };

  const input = new SessionInput(canvas, {
    renderer,
    // Copy: the class reuses its scratch buffers between events.
    send: (packet) => sent.push(packet.slice()),
    releaseAllKeys: () => {},
    onAppHotkey: () => false,
    onZoomGesture: (z) => zoomed.push(z),
  });
  input.attach();
  return { canvas, input, sent, zoomed, panned, panRoom };
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

  it("sends the press and release as one packet, so they cannot arrive reversed", () => {
    // Two invokes are two independent IPC requests with no ordering
    // guarantee between them. Reversed, the remote is left holding the right
    // button and the click does nothing until a later event happens to carry
    // a mask without that bit, which is the "nothing happened, then ages
    // later it did" this gesture was reported with.
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new MouseEvent("contextmenu", { clientX: 120, clientY: 80, bubbles: true }),
    );
    vi.advanceTimersByTime(100);

    expect(sent).toHaveLength(1);
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

describe("edge auto-scroll", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  // jsdom gives every element a zero-size rect, so the canvas has to claim a
  // real one for the edge bands to mean anything.
  function sized(canvas: HTMLCanvasElement, w = 800, h = 600) {
    canvas.getBoundingClientRect = () =>
      ({ left: 0, top: 0, right: w, bottom: h, width: w, height: h, x: 0, y: 0 }) as DOMRect;
    Object.defineProperty(canvas, "width", { value: w, configurable: true });
    Object.defineProperty(canvas, "height", { value: h, configurable: true });
  }

  it("scrolls toward the edge the pointer is held against", () => {
    // Issue #1: at 1:1 on a desktop larger than the window, everything past
    // the edge was unreachable; panning existed only as an undiscoverable
    // space-drag.
    const { canvas, panned } = setup();
    sized(canvas);
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { clientX: 2, clientY: 300, bubbles: true }),
    );
    vi.advanceTimersToNextFrame();
    expect(panned.length).toBeGreaterThan(0);
    // `panBy` moves the VIEW, so looking further left is negative. This
    // assertion had the sign backwards and happily confirmed a bug that sent
    // every edge scrolling the wrong way.
    expect(panned[0][0]).toBeLessThan(0);
  });

  it("scrolls right at the right edge, and down at the bottom", () => {
    const { canvas, panned } = setup();
    sized(canvas);
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { clientX: 798, clientY: 598, bubbles: true }),
    );
    vi.advanceTimersToNextFrame();
    expect(panned[0][0]).toBeGreaterThan(0);
    expect(panned[0][1]).toBeGreaterThan(0);
  });

  it("scrolls up at the top edge", () => {
    const { canvas, panned } = setup();
    sized(canvas);
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { clientX: 400, clientY: 2, bubbles: true }),
    );
    vi.advanceTimersToNextFrame();
    expect(panned[0][1]).toBeLessThan(0);
  });

  it("stays still in the middle of the view", () => {
    const { canvas, panned } = setup();
    sized(canvas);
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { clientX: 400, clientY: 300, bubbles: true }),
    );
    vi.advanceTimersToNextFrame();
    expect(panned).toEqual([]);
  });

  it("stays still once the user turns it off", () => {
    const { canvas, input, panned } = setup();
    sized(canvas);
    input.setEdgePan(false);
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { clientX: 2, clientY: 300, bubbles: true }),
    );
    vi.advanceTimersToNextFrame();
    expect(panned).toEqual([]);
  });

  it("stays still when the desktop already fits", () => {
    const { canvas, panned, panRoom } = setup();
    sized(canvas);
    panRoom.left = 0;
    panRoom.right = 0;
    panRoom.up = 0;
    panRoom.down = 0;
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { clientX: 2, clientY: 300, bubbles: true }),
    );
    vi.advanceTimersToNextFrame();
    expect(panned).toEqual([]);
  });
});

describe("a button that is never let go of", () => {
  // `PointerEvent.button` is -1 on pointercancel and on lostpointercapture,
  // which matches no button we forward, so the release path used to take its
  // "not a button we care about" early return and the bit stayed set for the
  // rest of the session.
  //
  // A stuck right button is not a small thing. The next right press ORs a bit
  // that is already set, so the mask does not change and the backend computes
  // no transition: the click does nothing. The release that follows clears it
  // and arrives on its own, long after the gesture. And in between, a left
  // press goes out as left AND right together, so the desktop opens a context
  // menu when the user left-clicked.

  it("releases the button when the pointer is cancelled", () => {
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 2, buttons: 2, clientX: 5, clientY: 5 }),
    );
    // pointercancel carries button -1 and buttons 0.
    canvas.dispatchEvent(
      new PointerEvent("pointercancel", { button: -1, buttons: 0, clientX: 5, clientY: 5 }),
    );

    expect(pointers(sent)).toEqual([
      { x: 5, y: 5, mask: RIGHT },
      { x: 5, y: 5, mask: 0 },
    ]);
  });

  it("releases the button when pointer capture is taken away", () => {
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 2, buttons: 2, clientX: 5, clientY: 5 }),
    );
    canvas.dispatchEvent(
      new PointerEvent("lostpointercapture", { button: -1, buttons: 0, clientX: 5, clientY: 5 }),
    );

    expect(pointers(sent).at(-1)).toEqual({ x: 5, y: 5, mask: 0 });
  });

  it("corrects a mask that drifted, on the next move", () => {
    // The backstop for a release that happens where we get no event at all,
    // such as outside the window. `buttons` is a live set carried on every
    // event, so the very next move puts it right.
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 2, buttons: 2, clientX: 5, clientY: 5 }),
    );
    sent.length = 0;
    canvas.dispatchEvent(
      new PointerEvent("pointermove", { buttons: 0, clientX: 40, clientY: 40 }),
    );

    expect(pointers(sent)[0]).toEqual({ x: 40, y: 40, mask: 0 });
  });

  it("does not turn a left click into a right click after a cancel", () => {
    // The reported symptom, end to end.
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 2, buttons: 2, clientX: 5, clientY: 5 }),
    );
    canvas.dispatchEvent(
      new PointerEvent("pointercancel", { button: -1, buttons: 0, clientX: 5, clientY: 5 }),
    );
    sent.length = 0;

    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 0, buttons: 1, clientX: 5, clientY: 5 }),
    );
    canvas.dispatchEvent(
      new PointerEvent("pointerup", { button: 0, buttons: 0, clientX: 5, clientY: 5 }),
    );

    expect(pointers(sent)).toEqual([
      { x: 5, y: 5, mask: 1 },
      { x: 5, y: 5, mask: 0 },
    ]);
  });

  it("does not wedge pointer input when a pan is cancelled", () => {
    // onPointerUp only ended a pan for `e.button === panButton`, and no pan
    // button is -1, so a cancelled pan left `panning` set. Every later press
    // then took the pan early return and nothing reached the remote at all.
    const { canvas, sent } = setup();
    canvas.dispatchEvent(
      new PointerEvent("pointerdown", {
        button: 1,
        buttons: 4,
        altKey: true,
        clientX: 5,
        clientY: 5,
      }),
    );
    canvas.dispatchEvent(
      new PointerEvent("pointercancel", { button: -1, buttons: 0, clientX: 5, clientY: 5 }),
    );
    sent.length = 0;

    canvas.dispatchEvent(
      new PointerEvent("pointerdown", { button: 0, buttons: 1, clientX: 9, clientY: 9 }),
    );
    expect(pointers(sent)).toEqual([{ x: 9, y: 9, mask: 1 }]);
  });
});
