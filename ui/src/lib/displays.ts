/**
 * Working out what "one monitor of this desktop" can mean, and holding on to
 * the answer across a reconnect.
 *
 * A VNC server may describe its monitor layout (ExtendedDesktopSize) or say
 * nothing at all, in which case a multi-head desktop arrives as one wide
 * framebuffer and the boundary has to be guessed at: found in the pixels by
 * the seam detector, or cut by hand at a plausible width. Those three sources
 * produce one flat list of {@link DisplayOption} rows, which the toolbar's
 * Displays menu and the native View ▸ Displays submenu both render.
 *
 * Kept out of the session view so the matching rules below can be tested
 * without a WebGL context.
 */
import type { DisplayOption, RemoteScreen } from "./types";

/**
 * Ids for the pair the seam detector finds.
 *
 * Negative, like the manual cuts, so they can never collide with a wire
 * screen id, and distinct from the cuts so a remembered choice can tell "the
 * left monitor, wherever the seam turns out to be" from "the leftmost 1920
 * pixels" (see {@link matchDisplay}).
 */
export const DETECTED_LEFT_ID = -101;
export const DETECTED_RIGHT_ID = -102;

/**
 * A remembered monitor choice.
 *
 * Both the id and the rectangle are kept because neither alone survives every
 * way a layout can come back different. See {@link matchDisplay}.
 */
export interface DisplayChoice {
  id: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Candidate ways to cut a desktop the server never described into monitors.
 *
 * TightVNC-family servers serve a multi-head desktop as one wide framebuffer
 * and say nothing about where the seams are, so the only honest offer is a
 * short list of plausible cuts: equal halves, and one common monitor width
 * (the widest of 2560/1920/1440 that leaves a usable remainder) on either
 * side, both ways round because nothing says which side the big monitor is
 * on. Ids are negative so they can never collide with a wire screen id.
 */
export function syntheticSplits(w: number, h: number): DisplayOption[] {
  const out: DisplayOption[] = [];
  let id = -1;
  const add = (x: number, width: number, label: string): void => {
    out.push({ id: id--, x, y: 0, width, height: h, label });
  };
  if (w < 1280) return out;
  const half = Math.floor(w / 2);
  add(0, half, `Left half (${half}×${h})`);
  add(half, w - half, `Right half (${w - half}×${h})`);
  for (const mw of [2560, 1920, 1440]) {
    const rest = w - mw;
    if (rest >= 320 && mw !== half) {
      add(0, mw, `Left ${mw}×${h}`);
      add(mw, rest, `Right ${rest}×${h}`);
      if (rest !== mw) {
        add(0, rest, `Left ${rest}×${h}`);
        add(rest, mw, `Right ${mw}×${h}`);
      }
      break; // one width is a menu; three is a wall
    }
  }
  if (w >= 3 * 1024) {
    const t = Math.floor(w / 3);
    add(0, t, `Left third (${t}×${h})`);
    add(t, t, `Middle third (${t}×${h})`);
    add(2 * t, w - 2 * t, `Right third (${w - 2 * t}×${h})`);
  }
  return out;
}

/**
 * The rows the Displays menus offer: the server's own monitor layout when it
 * sent one; else the detected pair when the seam detector found one, on top of
 * synthetic width splits, so a TightVNC-style multi-head desktop is still
 * separable by hand when detection has nothing to see.
 *
 * `seam` is the detected boundary column, or null. `size` is null before the
 * first frame has told us how big the desktop is.
 */
export function buildDisplayOptions(
  screens: RemoteScreen[],
  size: { w: number; h: number } | null,
  seam: number | null,
): DisplayOption[] {
  if (screens.length >= 2) return screens;
  if (!size) return [];
  const opts: DisplayOption[] = [];
  if (seam !== null && seam > 0 && seam < size.w) {
    opts.push(
      {
        id: DETECTED_LEFT_ID,
        x: 0,
        y: 0,
        width: seam,
        height: size.h,
        label: `Display 1 (detected, ${seam}×${size.h})`,
      },
      {
        id: DETECTED_RIGHT_ID,
        x: seam,
        y: 0,
        width: size.w - seam,
        height: size.h,
        label: `Display 2 (detected, ${size.w - seam}×${size.h})`,
      },
    );
  }
  // Manual cuts that duplicate the detected pair would read as a choice where
  // there is none; drop them.
  for (const s of syntheticSplits(size.w, size.h)) {
    if (!opts.some((o) => o.x === s.x && o.width === s.width)) opts.push(s);
  }
  return opts;
}

/**
 * Find the row a remembered choice now refers to, or null when the desktop has
 * changed enough that it no longer refers to anything.
 *
 * Two of the three id ranges are an identity, and those are matched by id
 * first: a wire screen id names a monitor the server keeps track of wherever
 * it moves it to, and the detected pair names "the left one" and "the right
 * one" however far the seam drifts between runs. Only if the id is gone does
 * the rectangle stand in, which is the graceful case where detection came back
 * empty and the equivalent manual cut is all that is left.
 *
 * A manual cut has no identity: its id only ever meant "the nth guess at this
 * width", so on a desktop of another size it would name a different rectangle
 * entirely. Those match on the rectangle alone, which still finds the same
 * pixels wherever they are still on offer.
 */
export function matchDisplay(
  want: DisplayChoice | null,
  options: DisplayOption[],
): DisplayOption | null {
  if (!want) return null;
  const byRect = (): DisplayOption | null =>
    options.find(
      (o) => o.x === want.x && o.y === want.y && o.width === want.width && o.height === want.height,
    ) ?? null;
  const isIdentity =
    want.id >= 0 || want.id === DETECTED_LEFT_ID || want.id === DETECTED_RIGHT_ID;
  if (!isIdentity) return byRect();
  return options.find((o) => o.id === want.id) ?? byRect();
}

/** Narrow a chosen row down to what is worth remembering about it. */
export function toChoice(option: DisplayOption | null | undefined): DisplayChoice | null {
  if (!option) return null;
  const { id, x, y, width, height } = option;
  return { id, x, y, width, height };
}

/**
 * A real layout goes in reading order (left to right, top to bottom), so
 * "Display 1" is the leftmost monitor rather than whichever id the server
 * listed first. Synthetic splits keep their authored order: sorting them by x
 * would interleave every "Left ..." variant ahead of every "Right".
 */
export function orderDisplays(options: DisplayOption[], layoutKnown: boolean): DisplayOption[] {
  return layoutKnown ? [...options].sort((a, b) => a.x - b.x || a.y - b.y) : options;
}

/** What a row is called in a menu, falling back to its position in the list. */
export function displayLabel(option: DisplayOption, index: number): string {
  return option.label ?? `Display ${index + 1} (${option.width}×${option.height})`;
}
