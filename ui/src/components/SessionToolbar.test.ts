import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { SessionToolbar, type SessionToolbarProps } from "./SessionToolbar";
import { readPos } from "./SessionToolbar";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/*
 * jsdom does no layout, so the one rule that matters here is modelled by hand.
 * A `position: fixed` box with `left` set and an automatic width shrinks to
 * fit the room between `left` and the right side of the window, and the
 * toolbar wraps its buttons onto more rows when it gets less than it wants.
 * That is what made a toolbar docked to the right edge chase its own width
 * (issue #35). A box asking for `max-content` keeps the width it prefers.
 */
const WINDOW_W = 1600;
const WINDOW_H = 1000;
const PREFERRED_W = 900;
/**
 * The narrowest thing that can move between rows. Dividers and the gaps
 * between buttons are a few pixels wide, less than the 12px margin, so each
 * pass that hands the bar 12px more room lets it take some of it.
 */
const STEP_W = 4;
const ROW_H = 32;

function layoutWidth(el: HTMLElement): number {
  if (el.style.width === "max-content") return PREFERRED_W;
  const left = parseFloat(el.style.left) || 0;
  const room = Math.max(0, WINDOW_W - left);
  if (room >= PREFERRED_W) return PREFERRED_W;
  return Math.max(STEP_W, Math.floor(room / STEP_W) * STEP_W);
}

let root: Root;
let host: HTMLDivElement;
let errors: unknown[];

beforeEach(() => {
  localStorage.clear();
  errors = [];
  Object.defineProperty(window, "innerWidth", { configurable: true, value: WINDOW_W });
  Object.defineProperty(window, "innerHeight", { configurable: true, value: WINDOW_H });
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe(): void {}
      disconnect(): void {}
    },
  );
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (
    this: HTMLElement,
  ) {
    if (this.style.position !== "fixed") return new DOMRect(0, 0, 0, 0);
    const w = layoutWidth(this);
    const rows = Math.ceil(PREFERRED_W / w);
    const left = parseFloat(this.style.left) || 0;
    const top = parseFloat(this.style.top) || 0;
    return new DOMRect(left, top, w, rows * ROW_H);
  });
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host, {
    onUncaughtError: (e) => errors.push(e),
    onCaughtError: (e) => errors.push(e),
  });
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const noop = (): void => {};

function props(): SessionToolbarProps {
  return {
    desktopName: "Test desktop",
    protocol: "vnc",
    state: { state: "connected" },
    stats: null,
    scalingMode: "fit",
    zoom: 1,
    quality: "auto",
    bwLevels: 0,
    passthrough: false,
    captureStatus: { state: "inactive" },
    viewOnly: false,
    recallSignal: 0,
    onScalingMode: noop,
    onZoom: noop,
    zoomLocked: false,
    onZoomLocked: noop,
    edgePan: false,
    onEdgePan: noop,
    screens: [],
    layoutKnown: false,
    displayId: null,
    onDisplay: noop,
    onDetectDisplays: noop,
    showRemoteCursor: true,
    onShowRemoteCursor: noop,
    localCursor: "dot",
    onLocalCursor: noop,
    onQuality: noop,
    alwaysRefresh: false,
    onAlwaysRefresh: noop,
    onBwLevels: noop,
    onPassthrough: noop,
    onCapturePermission: noop,
    onSendCombo: noop,
    onClipboardSend: noop,
    onFiles: noop,
    filesAvailable: null,
    onTerminal: noop,
    terminalAvailable: null,
    onFullscreen: noop,
    onViewOnly: noop,
    onScreenshot: noop,
    onRefresh: noop,
    onDisconnect: noop,
  } as unknown as SessionToolbarProps;
}

function mount(): HTMLElement {
  act(() => root.render(createElement(SessionToolbar, props())));
  const bar = host.querySelector<HTMLElement>('[role="toolbar"]');
  if (!bar) throw new Error("toolbar did not render");
  return bar.parentElement as HTMLElement;
}

function pointer(type: string, x: number, y: number, target: EventTarget = window): void {
  const ev = new MouseEvent(type, { bubbles: true, clientX: x, clientY: y });
  Object.defineProperty(ev, "pointerId", { value: 1 });
  act(() => {
    target.dispatchEvent(ev);
  });
}

describe("SessionToolbar docked at the right edge (issue #35)", () => {
  it("opens a session whose saved position is docked right without a render loop", () => {
    // Exactly what 0.35.3 wrote after the toolbar was dropped at the far right.
    localStorage.setItem(
      "deskvnc.toolbar.pos",
      JSON.stringify({ edge: "right", ratio: 0.5, x: 0.4, y: 0.47 }),
    );
    const box = mount();
    expect(errors).toEqual([]);
    expect(parseFloat(box.style.left) + PREFERRED_W).toBeLessThanOrEqual(WINDOW_W);
  });

  it("survives being dragged to the far right and opened again", () => {
    const box = mount();
    const grip = host.querySelector<HTMLElement>('[aria-label="Drag to move toolbar"]')!;
    pointer("pointerdown", 360, 20, grip);
    pointer("pointermove", 900, 400);
    pointer("pointermove", WINDOW_W + 200, 400);
    pointer("pointerup", WINDOW_W + 200, 400);
    expect(errors).toEqual([]);
    const saved = JSON.parse(localStorage.getItem("deskvnc.toolbar.pos")!);
    expect(saved.edge).toBe("right");
    expect(parseFloat(box.style.left) + PREFERRED_W).toBeLessThanOrEqual(WINDOW_W);

    act(() => root.unmount());
    root = createRoot(host, {
      onUncaughtError: (e) => errors.push(e),
      onCaughtError: (e) => errors.push(e),
    });
    mount();
    expect(errors).toEqual([]);
  });
});

describe("readPos", () => {
  it("falls back to the default for junk and pulls stray numbers back on screen", () => {
    localStorage.setItem("deskvnc.toolbar.pos", "{not json");
    expect(readPos()).toEqual({ edge: "top", ratio: 0.5, x: 0.5, y: 0 });

    localStorage.setItem(
      "deskvnc.toolbar.pos",
      JSON.stringify({ edge: "sideways", ratio: 7, x: -3, y: 1e9 }),
    );
    expect(readPos()).toEqual({ edge: "top", ratio: 1, x: 0, y: 1 });

    localStorage.setItem("deskvnc.toolbar.pos", JSON.stringify(null));
    expect(readPos()).toEqual({ edge: "top", ratio: 0.5, x: 0.5, y: 0 });
  });
});
