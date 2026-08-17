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
 * not the whole frame; see WebGLRenderer.readSampledRowsRGBA).
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
