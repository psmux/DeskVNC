/**
 * Guess where two side-by-side monitors meet inside one framebuffer.
 *
 * The TightVNC family serves a multi-head desktop as a single wide picture
 * and the protocol carries no layout, so the only place the boundary exists
 * is in the pixels: two desktops almost never agree at the seam (different
 * wallpapers, a taskbar that stops dead, a letterbox band), which shows up
 * as a column where left and right disagree far more than columns generally
 * do. This module scores that disagreement, but ONLY at positions where a
 * monitor boundary could plausibly be, so an ordinary window edge in the
 * middle of a desktop cannot masquerade as one.
 *
 * It can fail honestly: mirrored wallpapers, or a window straddling the
 * seam at sampling time, leave nothing to find, and the caller keeps the
 * manual splits. Detection is a labelling aid, never a substitute for them.
 */

export interface SeamGuess {
  /** Framebuffer x of the boundary: left monitor is [0, x), right is [x, w). */
  x: number;
  /** Mean per-channel disagreement at the seam, for logging/thresholds. */
  strength: number;
}

/**
 * Monitor widths that actually ship, for candidate seam positions. Includes
 * the common laptop and desktop panels plus their HiDPI halves.
 */
const COMMON_WIDTHS = [
  800, 1024, 1152, 1280, 1366, 1440, 1512, 1536, 1600, 1680, 1728, 1792,
  1920, 2048, 2160, 2240, 2304, 2560, 2880, 3008, 3024, 3440, 3840,
];

/** Narrowest strip that could still be a monitor. */
const MIN_SIDE = 320;

/**
 * Plausible seam x positions for a desktop `w` wide: the midpoint, and every
 * common monitor width measured from either edge. Sorted, deduplicated.
 */
export function candidateSeams(w: number): number[] {
  const set = new Set<number>();
  const half = Math.floor(w / 2);
  if (half >= MIN_SIDE && w - half >= MIN_SIDE) set.add(half);
  for (const cw of COMMON_WIDTHS) {
    for (const x of [cw, w - cw]) {
      if (x >= MIN_SIDE && w - x >= MIN_SIDE) set.add(x);
    }
  }
  return [...set].sort((a, b) => a - b);
}

/** Mean L1 RGB difference between columns x-1 and x over the sampled rows. */
function columnDiff(pixels: Uint8Array, width: number, rows: number, x: number): number {
  let sum = 0;
  for (let r = 0; r < rows; r++) {
    const base = (r * width + x) * 4;
    sum +=
      Math.abs(pixels[base] - pixels[base - 4]) +
      Math.abs(pixels[base + 1] - pixels[base - 3]) +
      Math.abs(pixels[base + 2] - pixels[base - 2]);
  }
  return sum / (rows * 3);
}

/** A seam must disagree at least this much per channel (0..255). */
const MIN_STRENGTH = 18;
/** ...and stand this far above the desktop's ordinary column-to-column noise. */
const NOISE_RATIO = 4;
/** ...and above its own immediate neighbourhood, so a soft gradient never wins. */
const LOCAL_RATIO = 3;

/**
 * Find the one candidate column that looks like a monitor boundary, or null.
 *
 * `pixels` is `rows` full-width RGBA rows packed row-major (a sampled band,
 * not the whole frame; see detectMonitors below).
 */
export function detectVerticalSeam(
  pixels: Uint8Array,
  width: number,
  rows: number,
  candidates: number[] = candidateSeams(width),
): SeamGuess | null {
  if (rows < 8 || width < 2 * MIN_SIDE) return null;
  const usable = candidates.filter((x) => x >= 8 && x <= width - 8);
  if (usable.length === 0) return null;

  // The desktop's ordinary column-to-column disagreement, from reference
  // columns spread across the width, kept clear of every candidate. Median,
  // not mean: a busy window puts big diffs at SOME references, and the noise
  // floor must describe the typical column, not the loudest.
  const refs: number[] = [];
  for (let x = 16; x < width - 16; x += 37) {
    if (usable.every((c) => Math.abs(c - x) > 3)) {
      refs.push(columnDiff(pixels, width, rows, x));
    }
  }
  refs.sort((a, b) => a - b);
  const noise = refs.length ? refs[Math.floor(refs.length / 2)] : 0;

  let best: SeamGuess | null = null;
  for (const x of usable) {
    const d = columnDiff(pixels, width, rows, x);
    if (d < MIN_STRENGTH) continue;
    if (d < NOISE_RATIO * noise) continue;
    // The neighbourhood on both sides, skipping the columns right next to
    // the seam (antialiasing and JPEG ringing smear it a pixel or two).
    let local = 0;
    let n = 0;
    for (const dx of [-12, -8, -4, 4, 8, 12]) {
      const nx = x + dx;
      if (nx >= 1 && nx < width) {
        local += columnDiff(pixels, width, rows, nx);
        n++;
      }
    }
    if (n > 0 && d < LOCAL_RATIO * (local / n)) continue;
    if (!best || d > best.strength) best = { x, strength: d };
  }
  return best;
}

/** One monitor's rectangle inside the framebuffer, in framebuffer pixels. */
export interface MonitorRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** A whole framebuffer, top-down RGBA (see WebGLRenderer.readFramebufferRGBA). */
export interface FrameRGBA {
  width: number;
  height: number;
  pixels: Uint8Array;
}

/**
 * A pixel counts as unused desktop when no channel is above this. The area a
 * shorter monitor leaves empty is painted pure black by the server; a little
 * headroom covers lossy encodings. A dark taskbar is well above it.
 */
const BLACK_MAX = 10;

/**
 * Unused area thinner than this is not taken as a missing strip of screen:
 * a few black rows at the very edge of a monitor are just dark content.
 */
function minGap(h: number): number {
  return Math.max(32, Math.round(h * 0.04));
}

/** For each column, the first and last row that is not black, or -1 for both. */
function columnExtents(f: FrameRGBA): { top: Int32Array; bottom: Int32Array } {
  const { width: w, height: h, pixels } = f;
  const top = new Int32Array(w).fill(-1);
  const bottom = new Int32Array(w).fill(-1);
  const lit = (x: number, y: number): boolean => {
    const i = (y * w + x) * 4;
    return pixels[i] > BLACK_MAX || pixels[i + 1] > BLACK_MAX || pixels[i + 2] > BLACK_MAX;
  };
  for (let x = 0; x < w; x++) {
    let y = 0;
    while (y < h && !lit(x, y)) y++;
    if (y === h) continue;
    top[x] = y;
    let b = h - 1;
    while (b > y && !lit(x, b)) b--;
    bottom[x] = b;
  }
  return { top, bottom };
}

function median(values: number[]): number {
  const s = [...values].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

/**
 * Find a monitor shorter than the desktop from the black band it leaves.
 *
 * When two monitors of different heights sit side by side, the framebuffer is
 * as tall as the taller one and the server paints the rest of the shorter
 * one's column black. That band is the most reliable clue there is: it starts
 * at one edge of the desktop, spans exactly the shorter monitor's width, and
 * has the same depth in every column. `depth` is how many black rows each
 * column has at its top or bottom edge.
 *
 * Returns the seam x, or null when no edge carries such a band.
 */
function seamFromBlackBand(depth: number[], h: number): number | null {
  const w = depth.length;
  const gap = minGap(h);
  for (const fromLeft of [true, false]) {
    const at = (i: number): number => depth[fromLeft ? i : w - 1 - i];
    // The first MIN_SIDE columns are inside the edge monitor whatever its
    // width, so their typical depth is the depth of its band, if it has one.
    const probe: number[] = [];
    for (let i = 0; i < MIN_SIDE; i++) probe.push(at(i));
    const d = median(probe);
    if (d < gap || d >= h) continue;
    // Every column of the short monitor has at least that much black under
    // (or over) it; its own content can only add black, never remove it.
    let run = 0;
    while (run < w && at(run) >= d - 2) run++;
    if (run < MIN_SIDE || w - run < MIN_SIDE) continue;
    return fromLeft ? run : w - run;
  }
  return null;
}

/**
 * The part of columns [x0, x1) that holds picture: from the highest lit row
 * to the lowest, over the whole strip. A black band thinner than the gap is
 * ignored, so a dark edge of a full height monitor stays full height.
 */
function stripRect(x0: number, x1: number, top: Int32Array, bottom: Int32Array, h: number): MonitorRect | null {
  let y0 = h;
  let y1 = -1;
  for (let x = x0; x < x1; x++) {
    if (top[x] < 0) continue;
    if (top[x] < y0) y0 = top[x];
    if (bottom[x] > y1) y1 = bottom[x];
  }
  if (y1 < 0) return null;
  const gap = minGap(h);
  if (y0 < gap) y0 = 0;
  if (h - 1 - y1 < gap) y1 = h - 1;
  return { x: x0, y: y0, width: x1 - x0, height: y1 + 1 - y0 };
}

/**
 * Find two side by side monitors in one framebuffer, each with its real
 * rectangle, or null when the picture shows nothing to go on.
 *
 * Works in framebuffer pixels on the current frame. The seam comes from the
 * black band a shorter monitor leaves when there is one (its edge is exact),
 * else from the column where the two pictures disagree
 * ({@link detectVerticalSeam}). Each side is then trimmed to the rows that
 * hold picture, so a shorter monitor's rectangle leaves out the black under
 * or over it.
 */
export function detectMonitors(frame: FrameRGBA): MonitorRect[] | null {
  const { width: w, height: h, pixels } = frame;
  if (w < 2 * MIN_SIDE || h < 8 || pixels.length < w * h * 4) return null;
  const { top, bottom } = columnExtents(frame);

  const below: number[] = [];
  const above: number[] = [];
  for (let x = 0; x < w; x++) {
    below.push(top[x] < 0 ? h : h - 1 - bottom[x]);
    above.push(top[x] < 0 ? h : top[x]);
  }
  let seam = seamFromBlackBand(below, h) ?? seamFromBlackBand(above, h);

  if (seam === null) {
    // Same height monitors leave no band: read the picture for the join, on
    // evenly spaced full width rows.
    const n = Math.min(96, h);
    const rows = new Uint8Array(w * n * 4);
    for (let i = 0; i < n; i++) {
      const y = Math.floor(((i + 0.5) / n) * h);
      rows.set(pixels.subarray(y * w * 4, (y + 1) * w * 4), i * w * 4);
    }
    seam = detectVerticalSeam(rows, w, n)?.x ?? null;
  }
  if (seam === null) return null;

  const left = stripRect(0, seam, top, bottom, h);
  const right = stripRect(seam, w, top, bottom, h);
  if (!left || !right) return null;
  return [left, right];
}
