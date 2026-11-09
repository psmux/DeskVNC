/**
 * Zoom and pan of the remote desktop on the phone screen, as plain math so
 * it can be tested without a DOM.
 *
 * Everything here is in CSS pixels on the screen side and framebuffer pixels
 * on the desktop side. `zoom` is relative to "fit": 1 shows the whole desktop,
 * 2 shows it twice as big. `cx`, `cy` is the desktop point at the centre of
 * the screen.
 */

export interface View {
  zoom: number;
  cx: number;
  cy: number;
}

export interface Size {
  w: number;
  h: number;
}

export const MIN_ZOOM = 1;
export const MAX_ZOOM = 8;
/** Zoom that a double tap goes to. */
export const DOUBLE_TAP_ZOOM = 2.5;

export function fitScale(screen: Size, fb: Size): number {
  if (fb.w <= 0 || fb.h <= 0) return 1;
  return Math.min(screen.w / fb.w, screen.h / fb.h);
}

/** CSS pixels per framebuffer pixel. */
export function scaleOf(v: View, screen: Size, fb: Size): number {
  return fitScale(screen, fb) * v.zoom;
}

export function initialView(fb: Size): View {
  return { zoom: 1, cx: fb.w / 2, cy: fb.h / 2 };
}

/** Keep the zoom in range and the desktop covering as much of the screen as it can. */
export function clampView(v: View, screen: Size, fb: Size): View {
  const zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.zoom));
  const s = fitScale(screen, fb) * zoom;
  const halfW = screen.w / (2 * s);
  const halfH = screen.h / (2 * s);
  const cx = fb.w <= 2 * halfW ? fb.w / 2 : Math.min(fb.w - halfW, Math.max(halfW, v.cx));
  const cy = fb.h <= 2 * halfH ? fb.h / 2 : Math.min(fb.h - halfH, Math.max(halfH, v.cy));
  return { zoom, cx, cy };
}

/** Top left of the desktop on screen, plus the scale. */
export function placement(v: View, screen: Size, fb: Size): { x: number; y: number; scale: number } {
  const scale = scaleOf(v, screen, fb);
  return { x: screen.w / 2 - v.cx * scale, y: screen.h / 2 - v.cy * scale, scale };
}

export function screenToFb(v: View, screen: Size, fb: Size, sx: number, sy: number): { x: number; y: number } {
  const p = placement(v, screen, fb);
  return { x: (sx - p.x) / p.scale, y: (sy - p.y) / p.scale };
}

export function fbToScreen(v: View, screen: Size, fb: Size, fx: number, fy: number): { x: number; y: number } {
  const p = placement(v, screen, fb);
  return { x: p.x + fx * p.scale, y: p.y + fy * p.scale };
}

/** Clamp a desktop point inside the framebuffer. */
export function clampToFb(fb: Size, x: number, y: number): { x: number; y: number } {
  return {
    x: Math.max(0, Math.min(Math.max(0, fb.w - 1), x)),
    y: Math.max(0, Math.min(Math.max(0, fb.h - 1), y)),
  };
}

/** Multiply the zoom by `factor`, keeping the desktop point under (sx, sy) where it is. */
export function zoomAt(v: View, screen: Size, fb: Size, factor: number, sx: number, sy: number): View {
  const anchor = screenToFb(v, screen, fb, sx, sy);
  const zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.zoom * factor));
  const s = fitScale(screen, fb) * zoom;
  // anchor must land on (sx, sy): sx = W/2 - cx*s + anchor.x*s
  const cx = anchor.x - (sx - screen.w / 2) / s;
  const cy = anchor.y - (sy - screen.h / 2) / s;
  return clampView({ zoom, cx, cy }, screen, fb);
}

/** Move the picture by (dx, dy) screen pixels, the way a finger drags it. */
export function panBy(v: View, screen: Size, fb: Size, dx: number, dy: number): View {
  const s = scaleOf(v, screen, fb);
  return clampView({ zoom: v.zoom, cx: v.cx - dx / s, cy: v.cy - dy / s }, screen, fb);
}

/**
 * Pan just enough that the desktop point (fx, fy) sits at least `margin`
 * screen pixels inside the edges. This is how the view follows the pointer
 * when zoomed in.
 */
export function ensureVisible(v: View, screen: Size, fb: Size, fx: number, fy: number, margin: number): View {
  const s = scaleOf(v, screen, fb);
  const p = fbToScreen(v, screen, fb, fx, fy);
  const m = Math.min(margin, screen.w / 3, screen.h / 3);
  let dx = 0;
  let dy = 0;
  if (p.x < m) dx = m - p.x;
  else if (p.x > screen.w - m) dx = screen.w - m - p.x;
  if (p.y < m) dy = m - p.y;
  else if (p.y > screen.h - m) dy = screen.h - m - p.y;
  if (dx === 0 && dy === 0) return v;
  return clampView({ zoom: v.zoom, cx: v.cx - dx / s, cy: v.cy - dy / s }, screen, fb);
}

/** Zoom in on a spot, or back out to the whole screen. */
export function toggleZoomAt(v: View, screen: Size, fb: Size, sx: number, sy: number): View {
  if (v.zoom > 1.05) return clampView(initialView(fb), screen, fb);
  return zoomAt(v, screen, fb, DOUBLE_TAP_ZOOM / v.zoom, sx, sy);
}

export function isFit(v: View): boolean {
  return v.zoom <= 1.02;
}

/** Linear blend of two views, for animating a double tap zoom. */
export function lerpView(a: View, b: View, t: number): View {
  const e = t < 0 ? 0 : t > 1 ? 1 : 1 - Math.pow(1 - t, 3);
  return { zoom: a.zoom + (b.zoom - a.zoom) * e, cx: a.cx + (b.cx - a.cx) * e, cy: a.cy + (b.cy - a.cy) * e };
}

/**
 * One step of momentum after a pan lets go. Velocity is in screen pixels per
 * millisecond and decays by friction; returns the new velocity, zero once it
 * is too slow to see.
 */
export function momentumStep(vx: number, vy: number, dtMs: number): { vx: number; vy: number; dx: number; dy: number } {
  const decay = Math.pow(0.995, dtMs);
  const nvx = vx * decay;
  const nvy = vy * decay;
  const done = Math.hypot(nvx, nvy) < 0.02;
  return { vx: done ? 0 : nvx, vy: done ? 0 : nvy, dx: vx * dtMs, dy: vy * dtMs };
}
