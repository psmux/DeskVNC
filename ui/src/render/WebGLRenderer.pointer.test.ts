import { describe, expect, it } from "vitest";
import { WebGLRenderer } from "./WebGLRenderer";

/**
 * The pointer has to land where the picture is.
 *
 * The picture is drawn with the content transform, and the pointer is
 * mapped back through it. If the two disagree, the remote pointer drifts
 * away from the local one, and the further from the origin the view is,
 * the worse it gets: a window that is scaled down and panned is exactly
 * where a person notices.
 *
 * These tests are the arithmetic, not the picture: they put a point on the
 * screen, map it to a framebuffer pixel, and then ask where that pixel is
 * DRAWN. The two answers have to be the same place.
 */
function renderer(overrides: Record<string, unknown> = {}) {
  return Object.assign(Object.create(WebGLRenderer.prototype), {
    fbWidth: 3600,
    fbHeight: 2338,
    viewX: 0,
    viewY: 0,
    viewW: 0,
    viewH: 0,
    canvas: { width: 1600, height: 900 },
    mode: "fit",
    zoom: 1,
    panX: 0,
    panY: 0,
    ...overrides,
  });
}

/** The device pixel a framebuffer pixel is drawn at. */
function drawnAt(r: any, fx: number, fy: number): { x: number; y: number } {
  const t = r.contentTransform();
  const v = r.viewRect();
  return {
    x: t.x + (fx - v.x) * t.scaleX,
    y: t.y + (fy - v.y) * t.scaleY,
  };
}

describe("the pointer mapping is the inverse of the drawing", () => {
  it("a scaled view maps the corners to the corners", () => {
    const r = renderer();
    const rect = { left: 0, top: 0, width: 800, height: 450 };
    // The canvas is 1600 device pixels wide and 800 CSS pixels wide, so
    // everything is twice as big in device pixels.
    const centre = r.cssPointToFramebuffer(400, 225, rect);
    expect(centre.x).toBe(1800);
    expect(centre.y).toBe(1169);
    const left = r.cssPointToFramebuffer(0, 0, rect);
    expect(left.x).toBe(0);
    expect(left.y).toBe(0);
    const right = r.cssPointToFramebuffer(800, 450, rect);
    expect(right.x).toBe(3599);
    expect(right.y).toBe(2337);
  });

  it("a point on the picture is drawn where the pointer says it is", () => {
    for (const mode of ["fit", "aspect-fit", "actual", "custom"]) {
      const r = renderer({ mode, zoom: 1.7 });
      const rect = { left: 10, top: 20, width: 800, height: 450 };
      for (const [cx, cy] of [
        [0, 0],
        [400, 225],
        [799, 449],
        [123, 300],
      ]) {
        const p = r.cssPointToFramebuffer(rect.left + cx, rect.top + cy, rect);
        // The point has to be over the picture for the two to be able to
        // agree: in an aspect-preserving view the picture is letterboxed,
        // and a pointer in the margin is held at the edge of the picture.
        const t = r.contentTransform();
        const v = r.viewRect();
        const device = {
          x: (cx * r.canvas.width) / rect.width,
          y: (cy * r.canvas.height) / rect.height,
        };
        const overPicture =
          device.x >= t.x && device.x <= t.x + v.w * t.scaleX &&
          device.y >= t.y && device.y <= t.y + v.h * t.scaleY;
        if (!overPicture) continue;
        const drawn = drawnAt(r, p.x, p.y);
        // Half a framebuffer pixel of slack, which is what the rounding in
        // the mapping costs.
        const slack = 0.5 * t.scaleX;
        expect(Math.abs(drawn.x - device.x)).toBeLessThanOrEqual(slack);
        expect(Math.abs(drawn.y - device.y)).toBeLessThanOrEqual(slack);
      }
    }
  });

  it("a pointer in the margin of an aspect-preserving view is held at the edge", () => {
    // This is where a windowed view looks like it has a pointer offset: the
    // picture is letterboxed, and a pointer in the margin is outside the
    // remote screen, so it is held at the edge of the picture. The remote
    // cursor is then drawn at that edge, which is a little way inside the
    // window, and the two cursors do not agree.
    //
    // It is not a mapping mistake: over the picture the mapping is exact,
    // as the test above shows. It is the margin, and the only honest way
    // to make it look right is to say that the pointer is off the picture.
    const r = renderer({ mode: "aspect-fit" });
    const rect = { left: 0, top: 0, width: 800, height: 450 };
    const t = r.contentTransform();
    expect(t.x).toBeGreaterThan(0); // there is a margin on the left
    const inMargin = r.cssPointToFramebuffer(1, 225, rect);
    expect(inMargin.x).toBe(0);
    const drawn = drawnAt(r, inMargin.x, inMargin.y);
    expect(drawn.x).toBeCloseTo(t.x, 5); // the picture's left edge
  });

  it("a panned view still maps the point to where it is drawn", () => {
    const r = renderer({ mode: "custom", zoom: 1, panX: 137, panY: -42 });
    const rect = { left: 0, top: 0, width: 1600, height: 900 };
    const p = r.cssPointToFramebuffer(700, 300, rect);
    const drawn = drawnAt(r, p.x, p.y);
    expect(Math.abs(drawn.x - 700)).toBeLessThanOrEqual(0.5);
    expect(Math.abs(drawn.y - 300)).toBeLessThanOrEqual(0.5);
  });

  it("a pointer outside the picture is held at the edge", () => {
    const r = renderer();
    const rect = { left: 0, top: 0, width: 800, height: 450 };
    const beyond = r.cssPointToFramebuffer(-500, -500, rect);
    expect(beyond.x).toBe(0);
    expect(beyond.y).toBe(0);
    const past = r.cssPointToFramebuffer(5000, 5000, rect);
    expect(past.x).toBe(3599);
    expect(past.y).toBe(2337);
  });
});
