/**
 * The floating keyboard button: where it sits, how a drag differs from a tap,
 * and where it lands after a drag. Pure, so it can be tested without a DOM.
 *
 * The position is kept as an edge and a fraction of the free height, never in
 * pixels, so it means the same thing after the phone turns or a foldable opens
 * or closes. 0 is the top of the free area, 1 the bottom.
 */

export type KeyButtonEdge = "left" | "right";

export interface KeyButtonPos {
  edge: KeyButtonEdge;
  /** 0 at the top of the free area, 1 at the bottom. */
  y: number;
}

/** The box the button lives in: the safe area, in CSS pixels. */
export interface KeyButtonArea {
  w: number;
  h: number;
  /** What covers the bottom of the area: the phone keyboard where it
   *  overlays the page (iOS), plus the key bar when it shows. */
  bottomInset: number;
}

export const KEY_BUTTON_SIZE = 48;
/** Gap to the side and bottom edges. */
export const KEY_BUTTON_MARGIN = 12;
/** Kept clear at the top for the toolbar pill and the connection chip. */
export const KEY_BUTTON_TOP = 64;
/** Finger travel, in CSS pixels, before a press becomes a drag. */
export const DRAG_SLOP = 8;

export const DEFAULT_KEY_BUTTON_POS: KeyButtonPos = { edge: "right", y: 1 };

const clamp = (v: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, v));

/** A stored value back into a usable position; anything odd gives the default. */
export function sanitizeKeyButtonPos(raw: unknown): KeyButtonPos {
  if (!raw || typeof raw !== "object") return { ...DEFAULT_KEY_BUTTON_POS };
  const r = raw as Partial<KeyButtonPos>;
  const edge: KeyButtonEdge = r.edge === "left" ? "left" : "right";
  const y = typeof r.y === "number" && Number.isFinite(r.y) ? clamp(r.y, 0, 1) : DEFAULT_KEY_BUTTON_POS.y;
  return { edge, y };
}

/** The highest and lowest top the button may have in this area. When the
 *  area is too short for the reserved band (landscape with the keyboard up),
 *  the band gives way first so the button stays visible. */
export function verticalRange(area: KeyButtonArea): { min: number; max: number } {
  const max = Math.max(0, area.h - area.bottomInset - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
  const min = Math.min(KEY_BUTTON_TOP, max);
  return { min, max };
}

export function horizontalRange(area: KeyButtonArea): { min: number; max: number } {
  const min = KEY_BUTTON_MARGIN;
  const max = Math.max(min, area.w - KEY_BUTTON_SIZE - KEY_BUTTON_MARGIN);
  return { min, max };
}

/** True when the free area is too short to keep the top band clear, as on
 *  a phone held sideways with the keyboard and the key bar up. */
export function isCramped(area: KeyButtonArea): boolean {
  return verticalRange(area).max < KEY_BUTTON_TOP;
}

/** The button's top left corner in the area for a stored position. When the
 *  area is cramped the button rises into the top band, and on the left edge
 *  the quality badge would cover it there, so it shows on the right until
 *  there is room again. The stored edge is kept. */
export function placeKeyButton(pos: KeyButtonPos, area: KeyButtonArea): { x: number; y: number } {
  const h = horizontalRange(area);
  const v = verticalRange(area);
  const edge: KeyButtonEdge = isCramped(area) ? "right" : pos.edge;
  return {
    x: edge === "left" ? h.min : h.max,
    y: Math.round(v.min + clamp(pos.y, 0, 1) * (v.max - v.min)),
  };
}

/** Keep a dragged corner inside the area. */
export function clampKeyButton(x: number, y: number, area: KeyButtonArea): { x: number; y: number } {
  const h = horizontalRange(area);
  const v = verticalRange(area);
  return { x: clamp(x, h.min, h.max), y: clamp(y, v.min, v.max) };
}

/** Where a drag that ended with the corner at (x, y) lands: the nearer side
 *  edge, at the same height as a fraction. */
export function snapKeyButton(x: number, y: number, area: KeyButtonArea): KeyButtonPos {
  const centre = x + KEY_BUTTON_SIZE / 2;
  const edge: KeyButtonEdge = centre < area.w / 2 ? "left" : "right";
  const v = verticalRange(area);
  const span = v.max - v.min;
  const frac = span > 0 ? (clamp(y, v.min, v.max) - v.min) / span : 1;
  return { edge, y: Math.round(frac * 1000) / 1000 };
}

/** What a tap on the button should do to the phone keyboard. `focused` is
 *  the hidden field having focus; `shown` is the keyboard actually being on
 *  screen. Android can hide the keyboard (Back, the hide key) and leave the
 *  field focused, and focusing an already focused field does not bring the
 *  keyboard back, so that case blurs and focuses again. */
export function keyButtonTap(focused: boolean, shown: boolean): "show" | "hide" | "reshow" {
  if (focused && shown) return "hide";
  if (focused) return "reshow";
  return "show";
}

/**
 * Tells a tap from a drag. A press stays a tap until the finger has moved
 * more than DRAG_SLOP from where it went down; after that it is a drag for
 * good, even if the finger comes back.
 */
export class DragTracker {
  private start: { x: number; y: number } | null = null;
  private dragging = false;

  down(x: number, y: number): void {
    this.start = { x, y };
    this.dragging = false;
  }

  /** True once the press has become a drag. */
  move(x: number, y: number): boolean {
    if (!this.start) return false;
    if (!this.dragging && Math.hypot(x - this.start.x, y - this.start.y) > DRAG_SLOP) this.dragging = true;
    return this.dragging;
  }

  /** How the press ended. Null when there was no press. */
  up(): "tap" | "drag" | null {
    if (!this.start) return null;
    const r = this.dragging ? "drag" : "tap";
    this.start = null;
    this.dragging = false;
    return r;
  }

  cancel(): void {
    this.start = null;
    this.dragging = false;
  }

  get active(): boolean {
    return this.start !== null;
  }

  get isDragging(): boolean {
    return this.dragging;
  }
}
