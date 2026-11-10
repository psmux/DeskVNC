/**
 * Touch gestures for the session screen, as a pure state machine.
 *
 * The screen feeds every touch event in (with the touches still down after
 * it and a timestamp) and calls `tick` from a timer for the time based parts
 * (long press, the wait that tells a tap from a double tap). Out come plain
 * actions, which the screen turns into pointer packets and view changes.
 * Nothing here touches the DOM, so the tests drive it with made up touches.
 *
 * Trackpad mode:
 *   one finger drag      moves the pointer (relative, like a laptop trackpad)
 *   tap                  left click
 *   tap, then drag       hold the left button while dragging (select, move)
 *   two finger tap       right click
 *   two finger drag      scroll
 *   three finger tap     open the keyboard
 *
 * Direct touch mode:
 *   tap                  left click where the finger is
 *   long press           right click there, with a ring that fills first
 *   one finger drag      left button drag from where the finger went down
 *   two finger drag      scroll
 *   two finger tap       right click
 *   three finger tap     open the keyboard
 *
 * Both modes:
 *   pinch                zoom around the fingers, sliding pans, and a
 *                        flick keeps the picture gliding when let go
 *   double tap           zoom in on that spot, while the whole desktop is
 *                        showing (once zoomed in, a double tap is a double
 *                        click, so the desktop still gets those)
 */

export type TouchMode = "trackpad" | "direct";

export interface Pt {
  id: number;
  x: number;
  y: number;
}

export interface TouchInput {
  type: "start" | "move" | "end" | "cancel";
  /** Milliseconds, any clock, increasing. */
  t: number;
  /** Every touch still on the screen after this event. */
  touches: Pt[];
}

export type GestureAction =
  | { type: "move"; dx: number; dy: number }
  | { type: "point"; x: number; y: number }
  | { type: "click"; button: "left" | "right"; x?: number; y?: number }
  | { type: "down"; x?: number; y?: number }
  | { type: "up" }
  | { type: "scroll"; dx: number; dy: number }
  | { type: "zoom"; factor: number; x: number; y: number }
  | { type: "pan"; dx: number; dy: number }
  | { type: "panEnd"; vx: number; vy: number }
  | { type: "doubleTapZoom"; x: number; y: number }
  | { type: "keyboard" }
  | { type: "ring"; state: "start" | "cancel" | "done"; x: number; y: number };

export interface GestureContext {
  /** True while the whole desktop is showing, so a double tap should zoom. */
  canDoubleTapZoom(): boolean;
}

/** Finger travel below this is still a tap, in CSS pixels. */
export const TAP_SLOP = 10;
/** A tap is shorter than this. */
export const TAP_MAX_MS = 300;
/** How long a first tap waits for a second one. */
export const DOUBLE_TAP_MS = 260;
/** Second tap must land this close to the first. */
export const DOUBLE_TAP_DISTANCE = 44;
/** The long press ring shows after this... */
export const RING_DELAY_MS = 150;
/** ...and the right click fires here. */
export const LONG_PRESS_MS = 550;
/** Change in finger spread that makes a two finger gesture a pinch. */
export const PINCH_THRESHOLD = 28;
/** Centroid travel that makes a two finger gesture a scroll. */
export const SCROLL_THRESHOLD = 12;

interface One {
  kind: "one";
  id: number;
  t0: number;
  x0: number;
  y0: number;
  x: number;
  y: number;
  moved: boolean;
  /** Left button held (tap then drag, or a direct drag). */
  dragging: boolean;
  /** Started within the double tap window of a previous tap. */
  afterTap: boolean;
  ring: "none" | "shown" | "fired";
}

interface Multi {
  kind: "multi";
  t0: number;
  maxTouches: number;
  mode: "undecided" | "scroll" | "pinch";
  cx0: number;
  cy0: number;
  d0: number;
  cx: number;
  cy: number;
  d: number;
  samples: { t: number; x: number; y: number }[];
}

type State = { kind: "idle" } | One | Multi;

interface PendingTap {
  t: number;
  x: number;
  y: number;
}

const centroid = (ts: Pt[]): { x: number; y: number } => {
  let x = 0;
  let y = 0;
  for (const p of ts) {
    x += p.x;
    y += p.y;
  }
  return { x: x / ts.length, y: y / ts.length };
};

const spread = (ts: Pt[]): number => (ts.length < 2 ? 0 : Math.hypot(ts[0].x - ts[1].x, ts[0].y - ts[1].y));

export class GestureRecognizer {
  private state: State = { kind: "idle" };
  private pending: PendingTap | null = null;

  constructor(
    public mode: TouchMode,
    private readonly ctx: GestureContext,
  ) {}

  setMode(mode: TouchMode): void {
    this.mode = mode;
    this.state = { kind: "idle" };
    this.pending = null;
  }

  /** True when a timer should keep calling `tick`. */
  wantsTick(): boolean {
    return this.pending !== null || (this.state.kind === "one" && this.mode === "direct" && this.state.ring !== "fired");
  }

  feed(e: TouchInput): GestureAction[] {
    const out: GestureAction[] = [];
    const st = this.state;
    if (e.type === "cancel") {
      this.abort(out);
      this.state = { kind: "idle" };
      return out;
    }

    if (st.kind === "idle") {
      if (e.type === "start" && e.touches.length === 1) {
        const p = e.touches[0];
        const afterTap =
          this.pending !== null && e.t - this.pending.t < DOUBLE_TAP_MS && Math.hypot(p.x - this.pending.x, p.y - this.pending.y) < DOUBLE_TAP_DISTANCE * 2;
        if (!afterTap) this.flushPending(out);
        this.state = { kind: "one", id: p.id, t0: e.t, x0: p.x, y0: p.y, x: p.x, y: p.y, moved: false, dragging: false, afterTap, ring: "none" };
      } else if (e.touches.length >= 2) {
        this.flushPending(out);
        this.state = this.startMulti(e);
      }
      return out;
    }

    if (st.kind === "one") {
      if (e.touches.length >= 2) {
        // A second finger joined: whatever one finger was doing stops here.
        this.abort(out);
        this.flushPending(out);
        this.state = this.startMulti(e);
        return out;
      }
      if (e.type === "move") {
        const p = e.touches.find((q) => q.id === st.id) ?? e.touches[0];
        if (!p) return out;
        this.oneMove(st, p, out);
        return out;
      }
      if (e.type === "end" && e.touches.length === 0) {
        this.oneEnd(st, e.t, out);
        this.state = { kind: "idle" };
      }
      return out;
    }

    // multi
    if (e.touches.length > st.maxTouches) st.maxTouches = e.touches.length;
    if (e.type === "start" && e.touches.length >= 2) {
      // Re-anchor so a finger landing late does not read as a jump.
      const c = centroid(e.touches.slice(0, 2));
      st.cx = c.x;
      st.cy = c.y;
      st.d = spread(e.touches);
      return out;
    }
    if (e.type === "move" && e.touches.length >= 2) {
      this.multiMove(st, e, out);
      return out;
    }
    if (e.type === "end" && e.touches.length === 0) {
      this.multiEnd(st, e.t, out);
      this.state = { kind: "idle" };
    }
    return out;
  }

  tick(now: number): GestureAction[] {
    const out: GestureAction[] = [];
    const st = this.state;
    if (st.kind === "one" && this.mode === "direct" && !st.moved && !st.afterTap) {
      const held = now - st.t0;
      if (st.ring === "none" && held >= RING_DELAY_MS) {
        st.ring = "shown";
        out.push({ type: "ring", state: "start", x: st.x, y: st.y });
      }
      if (st.ring === "shown" && held >= LONG_PRESS_MS) {
        st.ring = "fired";
        out.push({ type: "ring", state: "done", x: st.x, y: st.y });
        out.push({ type: "click", button: "right", x: st.x, y: st.y });
      }
    }
    if (this.pending && now - this.pending.t >= DOUBLE_TAP_MS && st.kind !== "one") {
      this.flushPending(out);
    }
    return out;
  }

  // ----------------------------------------------------------------- one

  private oneMove(st: One, p: Pt, out: GestureAction[]): void {
    const dx = p.x - st.x;
    const dy = p.y - st.y;
    if (!st.moved) {
      if (Math.hypot(p.x - st.x0, p.y - st.y0) < TAP_SLOP) return;
      st.moved = true;
      if (st.ring === "shown") out.push({ type: "ring", state: "cancel", x: st.x, y: st.y });
      if (st.ring === "fired") {
        // The right click already went; the rest of this touch is ignored.
        return;
      }
      if (this.mode === "trackpad") {
        if (st.afterTap) {
          // Tap, then drag: the first tap becomes a held button.
          this.pending = null;
          st.dragging = true;
          out.push({ type: "down" });
        }
      } else {
        this.pending = null;
        st.dragging = true;
        out.push({ type: "point", x: st.x0, y: st.y0 }, { type: "down", x: st.x0, y: st.y0 });
      }
    }
    if (st.ring === "fired") return;
    st.x = p.x;
    st.y = p.y;
    if (this.mode === "trackpad") {
      out.push({ type: "move", dx, dy });
    } else {
      out.push({ type: "point", x: p.x, y: p.y });
    }
  }

  private oneEnd(st: One, t: number, out: GestureAction[]): void {
    if (st.dragging) {
      out.push({ type: "up" });
      return;
    }
    if (st.ring === "fired") return;
    if (st.ring === "shown") out.push({ type: "ring", state: "cancel", x: st.x, y: st.y });
    if (st.moved || t - st.t0 > TAP_MAX_MS) {
      this.flushPending(out);
      // A slow hold in direct mode that never reached the long press is
      // still a deliberate touch: click it.
      if (!st.moved && this.mode === "direct") out.push({ type: "click", button: "left", x: st.x0, y: st.y0 });
      return;
    }
    this.tap(st.x0, st.y0, t, out);
  }

  private tap(x: number, y: number, t: number, out: GestureAction[]): void {
    const direct = this.mode === "direct";
    const prev = this.pending;
    if (prev && t - prev.t < DOUBLE_TAP_MS + TAP_MAX_MS && Math.hypot(x - prev.x, y - prev.y) < DOUBLE_TAP_DISTANCE) {
      this.pending = null;
      if (this.ctx.canDoubleTapZoom()) {
        out.push({ type: "doubleTapZoom", x: prev.x, y: prev.y });
      } else if (direct) {
        out.push({ type: "click", button: "left", x: prev.x, y: prev.y }, { type: "click", button: "left", x: prev.x, y: prev.y });
      } else {
        out.push({ type: "click", button: "left" }, { type: "click", button: "left" });
      }
      return;
    }
    this.flushPending(out);
    if (direct && !this.ctx.canDoubleTapZoom()) {
      // Zoomed in: click at once, a second tap makes a double click by itself.
      out.push({ type: "click", button: "left", x, y });
      return;
    }
    // Wait a moment: a second tap may follow (double click or zoom), and in
    // trackpad mode a tap followed by a drag must not click first.
    this.pending = { t, x, y };
  }

  private flushPending(out: GestureAction[]): void {
    const p = this.pending;
    if (!p) return;
    this.pending = null;
    if (this.mode === "direct") out.push({ type: "click", button: "left", x: p.x, y: p.y });
    else out.push({ type: "click", button: "left" });
  }

  private abort(out: GestureAction[]): void {
    const st = this.state;
    if (st.kind === "one") {
      if (st.dragging) out.push({ type: "up" });
      if (st.ring === "shown") out.push({ type: "ring", state: "cancel", x: st.x, y: st.y });
    }
  }

  // --------------------------------------------------------------- multi

  private startMulti(e: TouchInput): Multi {
    const two = e.touches.slice(0, 2);
    const c = centroid(two);
    const d = spread(two);
    return {
      kind: "multi",
      t0: e.t,
      maxTouches: e.touches.length,
      mode: "undecided",
      cx0: c.x,
      cy0: c.y,
      d0: d,
      cx: c.x,
      cy: c.y,
      d,
      samples: [{ t: e.t, x: c.x, y: c.y }],
    };
  }

  private multiMove(st: Multi, e: TouchInput, out: GestureAction[]): void {
    if (st.maxTouches >= 3) return;
    const two = e.touches.slice(0, 2);
    const c = centroid(two);
    const d = spread(two);
    if (st.mode === "undecided") {
      if (Math.abs(d - st.d0) > PINCH_THRESHOLD) st.mode = "pinch";
      else if (Math.hypot(c.x - st.cx0, c.y - st.cy0) > SCROLL_THRESHOLD) st.mode = "scroll";
      else return;
      // Start from here, so the threshold itself does not jump the view.
      st.cx = c.x;
      st.cy = c.y;
      st.d = d;
      st.samples = [{ t: e.t, x: c.x, y: c.y }];
      return;
    }
    if (st.mode === "pinch") {
      if (st.d > 0 && d > 0 && d !== st.d) out.push({ type: "zoom", factor: d / st.d, x: c.x, y: c.y });
      if (c.x !== st.cx || c.y !== st.cy) out.push({ type: "pan", dx: c.x - st.cx, dy: c.y - st.cy });
      st.samples.push({ t: e.t, x: c.x, y: c.y });
      while (st.samples.length > 2 && e.t - st.samples[0].t > 100) st.samples.shift();
    } else {
      out.push({ type: "scroll", dx: c.x - st.cx, dy: c.y - st.cy });
    }
    st.cx = c.x;
    st.cy = c.y;
    st.d = d;
  }

  private multiEnd(st: Multi, t: number, out: GestureAction[]): void {
    const quick = t - st.t0 < 400;
    if (st.mode === "undecided" && quick) {
      if (st.maxTouches >= 3) out.push({ type: "keyboard" });
      else if (this.mode === "direct") out.push({ type: "click", button: "right", x: st.cx0, y: st.cy0 });
      else out.push({ type: "click", button: "right" });
      return;
    }
    if (st.mode === "pinch") {
      const s = st.samples;
      let vx = 0;
      let vy = 0;
      if (s.length >= 2) {
        const a = s[0];
        const b = s[s.length - 1];
        const dt = b.t - a.t;
        // A finger that stopped before lifting should not fling.
        if (dt > 0 && t - b.t < 80) {
          vx = (b.x - a.x) / dt;
          vy = (b.y - a.y) / dt;
        }
      }
      out.push({ type: "panEnd", vx, vy });
    }
  }
}
