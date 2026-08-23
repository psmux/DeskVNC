/**
 * Multi-selection maths for the Library grid and list.
 *
 * Kept away from React so the fiddly parts (what a shift-click means when the
 * anchor has since been filtered out, whether a marquee touches a tile) can be
 * tested directly rather than through a rendered grid.
 *
 * The model is the one every file manager uses: a set of selected ids plus an
 * anchor, where the anchor is the last id the user picked deliberately and is
 * what a shift-click measures its range from.
 */

export interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export interface SelectionState {
  ids: Set<string>;
  anchor: string | null;
}

/** Modifier keys of the gesture that is changing the selection. */
export interface SelectionMods {
  /** Cmd on macOS, Ctrl elsewhere: add or remove one item. */
  toggle: boolean;
  /** Shift: extend from the anchor to here. */
  range: boolean;
}

/** A rectangle from two corners, in any order. */
export function rectFromPoints(x0: number, y0: number, x1: number, y1: number): Rect {
  return {
    left: Math.min(x0, x1),
    top: Math.min(y0, y1),
    right: Math.max(x0, x1),
    bottom: Math.max(y0, y1),
  };
}

/** Do two rectangles overlap at all? Touching edges do not count. */
export function rectsIntersect(a: Rect, b: Rect): boolean {
  return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
}

/** The ids whose rectangle the marquee touches, in `order`. */
export function idsInRect(rects: readonly { id: string; rect: Rect }[], marquee: Rect): string[] {
  return rects.filter((r) => rectsIntersect(r.rect, marquee)).map((r) => r.id);
}

/** Inclusive slice of `order` between two ids, whichever comes first. */
export function idsBetween(order: readonly string[], a: string, b: string): string[] {
  const i = order.indexOf(a);
  const j = order.indexOf(b);
  if (i < 0 || j < 0) return [];
  return order.slice(Math.min(i, j), Math.max(i, j) + 1);
}

/**
 * What a press on `id` does to the selection.
 *
 * Called on pointer DOWN, not click, because a drag has to be able to start
 * from a tile that is already part of a multi-selection without collapsing it
 * first. That is also why pressing an already-selected tile with no modifier
 * leaves the set alone: `collapseOnRelease` says to reduce it to that one tile
 * if the press turns out to be a plain click after all.
 */
export function pressSelection(
  prev: SelectionState,
  order: readonly string[],
  id: string,
  mods: SelectionMods,
): SelectionState & { collapseOnRelease: boolean } {
  if (mods.toggle) {
    const ids = new Set(prev.ids);
    if (ids.has(id)) ids.delete(id);
    else ids.add(id);
    return { ids, anchor: id, collapseOnRelease: false };
  }
  if (mods.range && prev.anchor && order.includes(prev.anchor)) {
    return {
      ids: new Set(idsBetween(order, prev.anchor, id)),
      // The anchor stays put so a second shift-click re-measures from the same
      // end, rather than walking it along with every extension.
      anchor: prev.anchor,
      collapseOnRelease: false,
    };
  }
  if (prev.ids.has(id) && prev.ids.size > 1) {
    return { ids: prev.ids, anchor: id, collapseOnRelease: true };
  }
  return { ids: new Set([id]), anchor: id, collapseOnRelease: false };
}

/**
 * The selection while a marquee is being dragged: whatever it touches, plus
 * the set that existed when the drag began if the user is holding a modifier.
 */
export function marqueeSelection(
  base: ReadonlySet<string>,
  hits: readonly string[],
  additive: boolean,
): Set<string> {
  const ids = additive ? new Set(base) : new Set<string>();
  for (const id of hits) ids.add(id);
  return ids;
}

/** Drop the ids that are no longer on screen (filter changed, host deleted). */
export function pruneSelection(ids: ReadonlySet<string>, present: readonly string[]): Set<string> {
  const alive = new Set(present);
  const next = new Set<string>();
  for (const id of ids) if (alive.has(id)) next.add(id);
  return next;
}

/**
 * The ids a drag gesture carries: the whole selection when the pressed tile is
 * part of it, otherwise just that tile.
 */
export function dragPayload(selected: ReadonlySet<string>, pressed: string): string[] {
  return selected.has(pressed) ? [...selected] : [pressed];
}
