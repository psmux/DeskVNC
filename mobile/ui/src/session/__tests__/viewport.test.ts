import { describe, expect, it } from "vitest";
import { clampView, ensureVisible, fbToScreen, initialView, isFit, momentumStep, panBy, screenToFb, toggleZoomAt, zoomAt } from "../input/viewport";

const screen = { w: 400, h: 800 };
const fb = { w: 1600, h: 900 };

describe("viewport", () => {
  it("fits the desktop and maps points both ways", () => {
    const v = clampView(initialView(fb), screen, fb);
    const c = fbToScreen(v, screen, fb, 800, 450);
    expect(c.x).toBeCloseTo(200);
    expect(c.y).toBeCloseTo(400);
    const back = screenToFb(v, screen, fb, 0, 400);
    expect(back.x).toBeCloseTo(0);
  });

  it("zooming keeps the point under the fingers still", () => {
    const v0 = clampView(initialView(fb), screen, fb);
    const before = screenToFb(v0, screen, fb, 300, 420);
    const v1 = zoomAt(v0, screen, fb, 6, 300, 420);
    const after = screenToFb(v1, screen, fb, 300, 420);
    expect(after.x).toBeCloseTo(before.x, 5);
    expect(after.y).toBeCloseTo(before.y, 5);
    expect(v1.zoom).toBe(6);
  });

  it("never zooms out past the whole desktop or pans off it", () => {
    const v = zoomAt(clampView(initialView(fb), screen, fb), screen, fb, 0.2, 0, 0);
    expect(v.zoom).toBe(1);
    const z = zoomAt(v, screen, fb, 4, 200, 400);
    const far = panBy(z, screen, fb, 100000, 0);
    expect(fbToScreen(far, screen, fb, 0, 0).x).toBeCloseTo(0);
  });

  it("follows the pointer to the edges", () => {
    const z = zoomAt(clampView(initialView(fb), screen, fb), screen, fb, 4, 200, 400);
    const moved = ensureVisible(z, screen, fb, 1500, 450, 40);
    const p = fbToScreen(moved, screen, fb, 1500, 450);
    expect(p.x).toBeLessThanOrEqual(screen.w - 40 + 0.001);
    expect(ensureVisible(z, screen, fb, z.cx, z.cy, 40)).toBe(z);
  });

  it("double tap zooms in, then back out", () => {
    const v0 = clampView(initialView(fb), screen, fb);
    const v1 = toggleZoomAt(v0, screen, fb, 100, 400);
    expect(isFit(v1)).toBe(false);
    expect(isFit(toggleZoomAt(v1, screen, fb, 100, 400))).toBe(true);
  });

  it("momentum slows down and stops", () => {
    let vx = 2;
    let steps = 0;
    while (vx !== 0 && steps < 1000) {
      vx = momentumStep(vx, 0, 16).vx;
      steps++;
    }
    expect(vx).toBe(0);
    expect(steps).toBeLessThan(200);
  });
});
