/**
 * Finder-style multi-selection and drag for the Library.
 *
 * Two gestures, one pointer pipeline:
 *   * press empty space and sweep, a marquee selects every tile it touches;
 *   * press a tile and sweep, the selection is dragged onto a group or a tag
 *     in the sidebar.
 *
 * Deliberately pointer events, NOT the HTML5 drag-and-drop API. The shell
 * keeps `dragDropEnabled` on for the window (a session accepts dropped files
 * for upload), and with that handler installed WebView2 swallows in-page
 * HTML5 drop events on Windows, so a `dragstart`/`drop` implementation would
 * work on macOS and quietly do nothing there. Pointer events are also what
 * makes the marquee possible at all.
 *
 * Drop targets announce themselves with `data-drop="group:<id>"`,
 * `data-drop="tag:<id>"` or `data-drop="ungroup"`; tiles and rows with
 * `data-host-id="<id>"`. Hit testing reads the DOM rather than React state so
 * the grid and the list view need no separate handling.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  dragPayload,
  marqueeSelection,
  pressSelection,
  pruneSelection,
  rectFromPoints,
  idsInRect,
  type Rect,
} from "../lib/selection";

/** Pointer travel, in px, before a press becomes a drag rather than a click. */
const DRAG_THRESHOLD = 5;

export type DropTarget =
  | { kind: "group"; id: string }
  | { kind: "tag"; id: string }
  | { kind: "ungroup" };

export interface DragState {
  ids: string[];
  /** Viewport coordinates of the pointer, for the drag ghost. */
  x: number;
  y: number;
  /** `data-drop` value currently under the pointer, or null. */
  over: string | null;
}

/** `data-drop="group:abc"` -> `{ kind: "group", id: "abc" }`. */
export function parseDropKey(key: string | null): DropTarget | null {
  if (!key) return null;
  if (key === "ungroup") return { kind: "ungroup" };
  const [kind, ...rest] = key.split(":");
  const id = rest.join(":");
  if (!id) return null;
  if (kind === "group") return { kind: "group", id };
  if (kind === "tag") return { kind: "tag", id };
  return null;
}

interface PressState {
  id: string;
  x: number;
  y: number;
  /** The press landed inside an existing multi-selection: a plain click reduces it to this one tile. */
  collapse: boolean;
  ids: string[];
}

interface MarqueeState {
  x: number;
  y: number;
  base: Set<string>;
  additive: boolean;
}

export function useHostDragSelect({
  order,
  onDrop,
}: {
  /** Visible host ids, in display order: what a shift-click range spans. */
  order: string[];
  onDrop: (hostIds: string[], target: DropTarget) => void;
}): {
  selectedIds: Set<string>;
  selectOnly: (id: string) => void;
  selectAll: () => void;
  clear: () => void;
  containerRef: React.RefObject<HTMLDivElement | null>;
  onPointerDown: (e: React.PointerEvent) => void;
  /** Is a press, a sweep or a drag in progress right now? */
  isGesturing: () => boolean;
  /** Abandon the gesture in progress, restoring the selection it started from. */
  cancelGesture: () => void;
  marquee: Rect | null;
  drag: DragState | null;
} {
  const [selectedIds, setSelectedIdsState] = useState<Set<string>>(() => new Set());
  const [marquee, setMarquee] = useState<Rect | null>(null);
  const [drag, setDrag] = useState<DragState | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const anchorRef = useRef<string | null>(null);
  const pressRef = useRef<PressState | null>(null);
  const marqueeRef = useRef<MarqueeState | null>(null);
  const dragRef = useRef<DragState | null>(null);
  /** Tile rectangles for the sweep in progress; null means "measure again". */
  const rectCache = useRef<{ id: string; rect: Rect }[] | null>(null);
  const selectedRef = useRef(selectedIds);
  const orderRef = useRef(order);
  const onDropRef = useRef(onDrop);
  orderRef.current = order;
  onDropRef.current = onDrop;

  /**
   * Store a new selection, ignoring one that holds exactly the same ids.
   *
   * A marquee recomputes its hits on every pointermove, and most moves change
   * nothing. Without this guard each one hands React a fresh Set, which
   * re-renders every tile and the sidebar at pointer-move rate.
   */
  const setSelectedIds = useCallback((ids: Set<string>): void => {
    const prev = selectedRef.current;
    if (ids === prev) return;
    if (ids.size === prev.size) {
      let same = true;
      for (const id of ids) {
        if (!prev.has(id)) {
          same = false;
          break;
        }
      }
      if (same) return;
    }
    selectedRef.current = ids;
    setSelectedIdsState(ids);
  }, []);

  const clear = useCallback((): void => {
    anchorRef.current = null;
    setSelectedIds(new Set());
  }, [setSelectedIds]);

  const selectOnly = useCallback(
    (id: string): void => {
      anchorRef.current = id;
      setSelectedIds(new Set([id]));
    },
    [setSelectedIds],
  );

  const selectAll = useCallback((): void => {
    setSelectedIds(new Set(orderRef.current));
  }, [setSelectedIds]);

  // A host that is no longer listed (deleted, or filtered out by a search or a
  // group switch) must not stay selected: it would otherwise be dragged
  // somewhere by a gesture aimed at the tiles that ARE on screen.
  useEffect(() => {
    const pruned = pruneSelection(selectedRef.current, order);
    if (pruned.size !== selectedRef.current.size) setSelectedIds(pruned);
  }, [order, setSelectedIds]);

  /**
   * Tile rectangles in viewport coordinates.
   *
   * Cached for the duration of one sweep: the tiles do not move while a
   * marquee is drawn, and measuring every one of them on every pointermove
   * forces a layout per tile per frame. The cache is dropped when the grid
   * scrolls (see the gesture effect), which is the one thing that does move
   * them mid-sweep.
   */
  const tileRects = useCallback((): { id: string; rect: Rect }[] => {
    if (rectCache.current) return rectCache.current;
    const root = containerRef.current;
    if (!root) return [];
    const rects = [...root.querySelectorAll<HTMLElement>("[data-host-id]")].map((el) => {
      const r = el.getBoundingClientRect();
      return {
        id: el.dataset.hostId ?? "",
        rect: { left: r.left, top: r.top, right: r.right, bottom: r.bottom },
      };
    });
    rectCache.current = rects;
    return rects;
  }, []);

  const dropKeyAt = useCallback((x: number, y: number): string | null => {
    const el = document.elementFromPoint(x, y);
    return el?.closest<HTMLElement>("[data-drop]")?.dataset.drop ?? null;
  }, []);

  /**
   * True while a gesture owns the pointer.
   *
   * The Library binds Escape to "clear the selection". During a sweep, Escape
   * means "cancel this sweep and put the selection back", and both handlers
   * sit on `window`: without this the restore would be undone a moment later
   * by the clear.
   */
  const isGesturing = useCallback(
    (): boolean => pressRef.current !== null || marqueeRef.current !== null,
    [],
  );

  const endGesture = useCallback((): void => {
    pressRef.current = null;
    marqueeRef.current = null;
    dragRef.current = null;
    rectCache.current = null;
    setMarquee(null);
    setDrag(null);
  }, []);

  /**
   * Abandon the gesture and put the selection back as it was.
   *
   * Escape during a sweep has to undo what the sweep picked up, or cancelling
   * a marquee would leave exactly the selection the user was cancelling.
   */
  const cancelGesture = useCallback((): void => {
    const band = marqueeRef.current;
    if (band) setSelectedIds(band.base);
    endGesture();
  }, [endGesture, setSelectedIds]);

  const onPointerDown = useCallback(
    (e: React.PointerEvent): void => {
      // Left button only: a right-click opens the context menu, and the
      // Library selects the host it landed on itself.
      if (e.button !== 0) return;
      const target = e.target as HTMLElement;
      // The tile's own hover actions (Connect, Edit, Wake) and any form
      // control keep their normal click behaviour.
      if (target.closest("button, a, input, select, textarea")) return;

      const mods = { toggle: e.metaKey || e.ctrlKey, range: e.shiftKey };
      const tile = target.closest<HTMLElement>("[data-host-id]");

      if (tile?.dataset.hostId) {
        const id = tile.dataset.hostId;
        const next = pressSelection(
          { ids: selectedRef.current, anchor: anchorRef.current },
          orderRef.current,
          id,
          mods,
        );
        anchorRef.current = next.anchor;
        setSelectedIds(next.ids);
        pressRef.current = {
          id,
          x: e.clientX,
          y: e.clientY,
          collapse: next.collapseOnRelease,
          ids: dragPayload(next.ids, id),
        };
      } else {
        const additive = mods.toggle || mods.range;
        marqueeRef.current = {
          x: e.clientX,
          y: e.clientY,
          base: additive ? new Set(selectedRef.current) : new Set(),
          additive,
        };
        if (!additive) clear();
      }
    },
    [clear, setSelectedIds],
  );

  // One set of window listeners for the life of the hook: a gesture that ends
  // outside the window (or with Escape) still has to be cleaned up.
  useEffect(() => {
    const onMove = (e: PointerEvent): void => {
      const press = pressRef.current;
      const band = marqueeRef.current;
      if (!press && !band) return;

      // The button is no longer down, so the pointerup was lost: the window
      // was switched away mid-drag, or a native menu ate it. Without this the
      // pipeline stays armed with a stale payload and the NEXT ordinary click
      // would be read as dropping it, writing to the database on a gesture the
      // user never made.
      if (e.buttons === 0) {
        cancelGesture();
        return;
      }

      if (press) {
        const moved = Math.hypot(e.clientX - press.x, e.clientY - press.y);
        if (!dragRef.current && moved < DRAG_THRESHOLD) return;
        // Past the threshold this is a drag, not a click, so the press can no
        // longer collapse the selection on release.
        press.collapse = false;
        const over = dropKeyAt(e.clientX, e.clientY);
        const next: DragState = { ids: press.ids, x: e.clientX, y: e.clientY, over };
        dragRef.current = next;
        setDrag(next);
        return;
      }

      if (band) {
        const rect = rectFromPoints(band.x, band.y, e.clientX, e.clientY);
        setMarquee(rect);
        setSelectedIds(marqueeSelection(band.base, idsInRect(tileRects(), rect), band.additive));
      }
    };

    const onUp = (e: PointerEvent): void => {
      const press = pressRef.current;
      if (dragRef.current) {
        const target = parseDropKey(dropKeyAt(e.clientX, e.clientY));
        const ids = dragRef.current.ids;
        if (target && ids.length > 0) onDropRef.current(ids, target);
      } else if (press?.collapse) {
        // A plain click on a tile inside a multi-selection: now that it is
        // certainly not a drag, reduce the selection to that one tile.
        anchorRef.current = press.id;
        setSelectedIds(new Set([press.id]));
      }
      endGesture();
    };

    // The tiles move under a marquee only when the grid scrolls, so that is
    // the one event that has to invalidate the measurements.
    const onScroll = (): void => {
      rectCache.current = null;
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", cancelGesture);
    // A window that loses focus mid-drag never sends the pointerup at all.
    window.addEventListener("blur", cancelGesture);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", cancelGesture);
      window.removeEventListener("blur", cancelGesture);
      window.removeEventListener("scroll", onScroll, true);
    };
    // Escape is deliberately NOT handled here. The Library binds it too, and
    // two window listeners racing to interpret one key press is how the
    // gesture's "put the selection back" got undone by the Library's "clear
    // the selection" a microtask later. It calls `cancelGesture` itself.
  }, [cancelGesture, dropKeyAt, endGesture, setSelectedIds, tileRects]);

  return {
    selectedIds,
    selectOnly,
    selectAll,
    clear,
    containerRef,
    onPointerDown,
    isGesturing,
    cancelGesture,
    marquee,
    drag,
  };
}
