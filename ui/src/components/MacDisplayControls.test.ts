import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { MacDisplayControls } from "./MacDisplayControls";

let root: Root | undefined;
afterEach(() => {
  if (root) act(() => root?.unmount());
  root = undefined;
  document.body.replaceChildren();
  vi.unstubAllGlobals();
});

function panel(extra: Partial<Parameters<typeof MacDisplayControls>[0]> = {}) {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  act(() => root!.render(createElement(MacDisplayControls, {
    info: null, notice: null, busy: false, size: { w: 2700, h: 1754 },
    native: { w: 3600, h: 2338 }, onStreamResize: vi.fn(), onPanelMode: vi.fn(),
    ...extra,
  })));
  act(() => host.querySelector("button")!.click());
  return host;
}

it("keeps requested, layout, media-answer and decoded sizes separate", () => {
  const host = panel({
    media: {
      requestedWidth: 2700, requestedHeight: 1754,
      desktopWidth: 1800, desktopHeight: 1169,
      layoutWidth: 2700, layoutHeight: 1754,
      canvasWidth: 2700, canvasHeight: 1754,
      tiles: 1, pictures: 100, lost: 0, dropped: 0, recoveries: 0, requests: 0,
      packets: 100, bytes: 1000, stalls: 0, jitterMs: 0, inputLatencyMs: 0, inputWorstMs: 0,
    },
    stats: {
      pictureWidth: 3600, pictureHeight: 2338,
      frameWidth: 3600, frameHeight: 2338,
      submitted: 90, decoded: 89, queued: 1, latencyMs: 20,
    },
  });
  const text = host.textContent!;
  expect(text).toContain("Requested: 2700×1754 pixels");
  expect(text).toContain("Server layout: 2700×1754 pixels");
  expect(text).toContain("Media answer: 2700×1754 pixels");
  expect(text).toContain("Decoded picture: 3600×2338 pixels");
  expect(text).toContain("100 assembled pictures");
  expect(text).toContain("0 dropped locally");
  expect(text).toContain("0 feedback packets sent");
  expect(text).not.toContain("Streaming at 2700×1754");
});

it("does not describe a layout-only size as a decoded stream", () => {
  const host = panel();
  expect(host.textContent).toContain("No decoded picture yet");
  expect(host.textContent).not.toContain("Streaming at");
});
