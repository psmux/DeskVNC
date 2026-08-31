/**
 * The session half of the library window: every open session, laid out.
 *
 * One decision shapes this whole file. Every mounted session lives in ONE flat
 * list of absolutely positioned boxes, keyed by session id, and the layout tree
 * only decides where each box goes. Nothing is nested per tab and nothing is
 * nested per split.
 *
 * The reason is that a viewer cannot survive being moved in the DOM. Its canvas
 * carries a live WebGL context and its texture is the framebuffer; re-parenting
 * the element destroys both, and React re-parents whenever an element's place
 * in the tree changes. A tree of splits changes shape on every split, close and
 * drag, and dragging a session into a pane of another tab changes it twice. A
 * flat list keyed by session id never changes shape at all: splitting a pane in
 * half is a change of two numbers on a style attribute, and the connection
 * inside it does not notice.
 *
 * Sizes stay real even for a tab nobody is looking at, for the same reason the
 * old single-session panes did: a hidden box with no size would collapse its
 * canvas to zero, take the GL viewport with it, and have to rebuild the whole
 * framebuffer on the way back. So geometry is computed for every tab against
 * the same measured area, and `visibility` is all that changes.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Session } from "../screens/Session";
import { PaneVisible } from "./Pane";
import { PaneHeader, PANE_HEADER_PX } from "./PaneHeader";
import { PanePicker } from "./PanePicker";
import { useTabs } from "../state/TabsContext";
import { useAgentActivity } from "../state/AgentActivityContext";
import { drivenByAgent } from "../lib/agentActivity";
import {
  layoutGeometry,
  panes,
  splitExtent,
  type DividerRect,
  type LayoutNode,
  type Rect,
} from "../lib/layout";

/**
 * Take the pointer if the browser will give it, and shrug if it will not.
 *
 * `setPointerCapture` throws for a pointer it no longer considers active, and
 * both drags here track the pointer on `window` regardless, so capture is worth
 * asking for and never worth failing over.
 */
function capturePointer(el: HTMLElement, pointerId: number): void {
  try {
    el.setPointerCapture?.(pointerId);
  } catch {
    /* the drag works without it */
  }
}

/** Release it again, if it was ever taken. */
function releasePointer(el: HTMLElement, pointerId: number): void {
  try {
    if (el.hasPointerCapture?.(pointerId)) el.releasePointerCapture(pointerId);
  } catch {
    /* already gone */
  }
}

/** The panel the tab strip points every session tab at. */
export const SESSION_PANEL_ID = "pane-sessions";

/**
 * The gap between panes, and so the width of a divider.
 *
 * Wide enough to grab (the hit box is grown further in `dividerAt`) and narrow
 * enough that four panes do not read as four windows. It is a gap rather than a
 * border because a border on a pane would eat into the desktop inside it, and a
 * remote desktop scaled to fit is unforgiving about a few missing pixels.
 */
const GAP = 6;

/** The area the panes are laid out in, and where that sits on screen. */
interface Area extends Rect {
  /** Distance from the viewport's origin to the area's, for `position: fixed`. */
  originX: number;
  originY: number;
}

/**
 * Measure the box the panes divide up.
 *
 * Both numbers matter and they are not the same: pane rectangles are local to
 * this element, while a session toolbar is `position: fixed` and needs the
 * viewport. The offset changes without the size doing so (the tab strip
 * appearing pushes everything down), so a resize observer alone is not enough.
 */
function useArea(ref: React.RefObject<HTMLDivElement | null>): Area {
  const [area, setArea] = useState<Area>({
    x: 0, y: 0, width: 0, height: 0, originX: 0, originY: 0,
  });

  const measure = useCallback((): void => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setArea((prev) =>
      prev.width === r.width &&
      prev.height === r.height &&
      prev.originX === r.left &&
      prev.originY === r.top
        ? prev
        : { x: 0, y: 0, width: r.width, height: r.height, originX: r.left, originY: r.top },
    );
  }, [ref]);

  /**
   * After every render, not only when an observer says so.
   *
   * A `ResizeObserver` reports a change of SIZE and says nothing about a change
   * of POSITION, and this element moves without resizing: the tab strip appears
   * the moment the first session connects and pushes it down. Relying on the
   * observer alone left `originY` reading zero while the panel actually started
   * below the strip, which is not a cosmetic error. Pane rectangles are derived
   * from this, the canvas fills its pane, and `SessionInput` maps the pointer
   * through `canvas.getBoundingClientRect()`, so a stale origin puts the remote
   * pointer somewhere the user is not pointing and every click lands on the
   * wrong thing.
   *
   * `setArea` returns the previous object unchanged when nothing moved, so the
   * common case is one `getBoundingClientRect` and no re-render.
   */
  useLayoutEffect(measure);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    // The observers still earn their place: they catch what happens with no
    // render of ours behind it, such as the user resizing the window.
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", measure, true);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", measure);
      window.removeEventListener("scroll", measure, true);
    };
  }, [ref, measure]);

  return area;
}

export function SplitView({
  onAppHotkey,
}: {
  /** First refusal on a keystroke, handed down to every mounted viewer. */
  onAppHotkey: (e: KeyboardEvent) => boolean;
}): ReactNode {
  const {
    tabs, sessions, activeId, close, closePane, focusPane, setTitle, setState, resize,
    reportArea, split: splitPane, adopt, toggleZoom,
  } = useTabs();
  const { forSession, takeWheel, stopAgent } = useAgentActivity();
  const areaRef = useRef<HTMLDivElement>(null);
  const area = useArea(areaRef);

  /** The pane being dragged by its header, and the one it is currently over. */
  const [drag, setDrag] = useState<{
    tabId: string;
    paneId: string;
    overPaneId: string | null;
  } | null>(null);

  // "The pane to the left of this one" is a question about pixels, and only
  // this component has measured them.
  useEffect(() => reportArea(area, GAP), [area, reportArea]);

  const active = tabs.find((t) => t.id === activeId) ?? null;

  /**
   * Geometry for every tab, not only the one in front.
   *
   * A background tab's panes have to keep a real size (see the file header),
   * and its dividers cost nothing to compute, so there is no case worth
   * special-casing.
   */
  const geometries = tabs.map((tab) => {
    const geometry = layoutGeometry(tab.root, area, GAP);
    if (tab.zoomedPaneId === null) return { tab, geometry, zoomed: false };
    // Maximising moves one rectangle and hides the rest. Deliberately NOT a
    // different layout: every other pane keeps the box it had, so its canvas
    // keeps its size and its framebuffer survives, and restoring is a matter
    // of drawing them again rather than of rebuilding anything.
    const panesOut = geometry.panes.map((p) =>
      p.pane.id === tab.zoomedPaneId ? { ...p, rect: { ...area } } : p,
    );
    return {
      tab,
      geometry: { panes: panesOut, dividers: [] as typeof geometry.dividers },
      zoomed: true,
    };
  });

  // Read inside pointer handlers, which are registered once per drag and must
  // not close over a snapshot that the drag itself is changing.
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const areaRef2 = useRef(area);
  areaRef2.current = area;

  /**
   * Drag a pane by its header onto another, and the two trade places.
   *
   * The pane under the pointer is found from the geometry rather than from the
   * DOM, because what sits under the pointer for most of a drag is a canvas
   * with its own opinions about pointer events. Swapping (through `adopt`) then
   * exchanges only the contents, so both boxes stay exactly where they are and
   * nothing else on screen jumps to make room.
   */
  const beginPaneDrag = useCallback(
    (e: React.PointerEvent, tabId: string, paneId: string): void => {
      // Only the primary button drags. Without this a secondary click on the
      // header began one, and `preventDefault` on it also stopped the focus
      // moving where the click said it should.
      if (e.button !== 0) return;
      const zoomedNow = tabsRef.current.find((t) => t.id === tabId)?.zoomedPaneId;
      // A maximised pane covers the whole tab, so there is nothing to drop it
      // on and no neighbour to trade places with.
      if (zoomedNow !== null && zoomedNow !== undefined) return;
      e.preventDefault();
      const handle = e.currentTarget as HTMLElement;
      setDrag({ tabId, paneId, overPaneId: null });
      // A nicety rather than a requirement: the drag is tracked on `window`,
      // so it works with or without capture. Taking it first, and unguarded,
      // meant a throw here (a pointer the browser no longer considers active)
      // aborted the whole gesture before it had begun.
      capturePointer(handle, e.pointerId);

      const paneAt = (clientX: number, clientY: number): string | null => {
        const tab = tabsRef.current.find((t) => t.id === tabId);
        if (!tab) return null;
        const a = areaRef2.current;
        const x = clientX - a.originX;
        const y = clientY - a.originY;
        const hit = layoutGeometry(tab.root, a, GAP).panes.find(
          ({ rect }) =>
            x >= rect.x && x <= rect.x + rect.width && y >= rect.y && y <= rect.y + rect.height,
        );
        return hit?.pane.id ?? null;
      };

      const sessionIn = (id: string): string | null =>
        tabsRef.current
          .find((t) => t.id === tabId)
          ?.root
          ? (panes(tabsRef.current.find((t) => t.id === tabId)!.root).find((p) => p.id === id)
              ?.sessionId ?? null)
          : null;

      const stop = (): void => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", finish);
        window.removeEventListener("pointercancel", stop);
        releasePointer(handle, e.pointerId);
        setDrag(null);
      };

      const move = (ev: PointerEvent): void => {
        const over = paneAt(ev.clientX, ev.clientY);
        setDrag((prev) => (prev && prev.overPaneId !== over ? { ...prev, overPaneId: over } : prev));
      };

      const finish = (ev: PointerEvent): void => {
        const over = paneAt(ev.clientX, ev.clientY);
        stop();
        // Dropping on itself, or outside the layout, is what changing your mind
        // looks like rather than an error.
        if (!over || over === paneId) return;
        const dragged = sessionIn(paneId);
        // `adopt` moves a SESSION into a pane, so an empty pane has nothing to
        // move: run it the other way and the swap is the same either way round.
        if (dragged) adopt(tabId, over, dragged);
        else {
          const target = sessionIn(over);
          if (target) adopt(tabId, paneId, target);
        }
      };

      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", finish);
      window.addEventListener("pointercancel", stop);
    },
    [adopt],
  );

  const dragDivider = useCallback(
    (e: React.PointerEvent, tabId: string, root: LayoutNode, divider: DividerRect): void => {
      e.preventDefault();
      capturePointer(e.target as HTMLElement, e.pointerId);
      const horizontal = divider.dir === "row";
      // Fixed for the whole drag: only the two weights either side of this
      // divider change, and this split's own share of its parent does not.
      const extent = splitExtent(root, divider.splitId, area, GAP);
      let last = horizontal ? e.clientX : e.clientY;

      const move = (ev: PointerEvent): void => {
        const now = horizontal ? ev.clientX : ev.clientY;
        const delta = now - last;
        if (delta === 0) return;
        last = now;
        // Sent as an increment rather than a total. The weights clamp at the
        // minimum pane size, so a total measured from where the drag started
        // would keep pushing past the clamp and the divider would not come back
        // until the pointer had travelled all the way to where it left off.
        resize(tabId, divider.splitId, divider.index, delta, extent);
      };
      // `pointercancel` as well as `pointerup`: a touch interrupted by a system
      // gesture, or a divider that stops existing mid-drag because the layout
      // changed underneath it, ends the drag without ever firing `pointerup`.
      // Listening for only that one left `move` bound to the window for good,
      // and every mouse movement anywhere in the app then resized that split.
      const target = e.target as HTMLElement;
      const up = (): void => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        window.removeEventListener("pointercancel", up);
        releasePointer(target, e.pointerId);
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      window.addEventListener("pointercancel", up);
    },
    [area, resize],
  );

  return (
    <div
      ref={areaRef}
      id={SESSION_PANEL_ID}
      role="tabpanel"
      aria-label={active ? "Session" : "No session"}
      className="absolute inset-0"
      style={{ visibility: active ? "visible" : "hidden" }}
      aria-hidden={active ? undefined : true}
      inert={active ? undefined : true}
    >
      {/*
        One flat list across every tab, never grouped per tab. Grouping would
        give each tab its own parent element, and a session dragged from one
        tab into a pane of another would be re-parented, which is exactly the
        thing its WebGL canvas cannot survive. See the file header.
      */}
      {geometries.flatMap(({ tab, geometry, zoomed }) => {
        const onScreen = tab.id === activeId;
        const split = geometry.panes.length > 1;
        return geometry.panes.map(({ pane, rect }) => {
          const focused = onScreen && pane.id === tab.focusedPaneId;
          // While one pane is maximised the others are still laid out and
          // still taking frames; they are simply not drawn.
          const drawn = onScreen && (!zoomed || pane.id === tab.zoomedPaneId);
          const session = pane.sessionId ? sessions[pane.sessionId] : undefined;
          const agent = session ? forSession(session.id) : null;
          const driven = drivenByAgent(agent ?? undefined);
          /*
            A lone pane grows a header while something else is driving it.

            Splits were the only reason to spend 24 pixels before, and a single
            pane stayed full bleed. A robot on the machine in front of you is
            the other reason: without this, the one arrangement most people use
            most of the time is the one arrangement with nowhere to say that an
            agent is at the wheel and no way to take it back.
          */
          const showHeader = split || driven || agent?.preempted != null;
          // Per pane rather than per tab, now that a pane can have a header its
          // neighbours do not. The toolbar's frame is measured from this, and
          // an offset that belonged to a different pane would put the toolbar
          // over the desktop it is meant to sit above.
          const headerPx = showHeader ? PANE_HEADER_PX : 0;
          return (
            <div
              // Keyed by the session, not by the pane: this box is the one
              // thing that must not be re-created when the layout moves, and a
              // session outlives whichever pane it happens to be sitting in.
              key={session ? `s:${session.id}` : `p:${pane.id}`}
              className="absolute flex flex-col overflow-hidden rounded-xs bg-canvas"
              style={{
                left: rect.x,
                top: rect.y,
                width: rect.width,
                height: rect.height,
                visibility: drawn ? "visible" : "hidden",
                // The maximised pane has to paint over its neighbours, which
                // are still sitting in their own boxes underneath it.
                zIndex: zoomed && pane.id === tab.zoomedPaneId ? 5 : undefined,
              }}
              aria-hidden={drawn ? undefined : true}
              inert={drawn ? undefined : true}
              // Clicking a pane moves the keyboard to it. Capture phase, so it
              // answers before anything inside does, and deliberately without
              // `preventDefault`: the click is spent on taking the focus and
              // does not reach the remote desktop. That is the safer of the two
              // readings when the desktop in question belongs to a machine the
              // user was not typing at a moment ago.
              //
              // Clicking a pane an agent is driving takes the wheel as well as
              // the focus, and the two are the same gesture on purpose: a
              // person who has started typing at a machine has already decided
              // they are driving it, and asking them to press something first
              // would mean their first few keystrokes went in alongside a
              // robot's. A human outranks an agent by default (`00 R11`), so
              // this needs nothing from the agent and waits for nothing; it is
              // a no-op on every pane a person already holds, which is all of
              // them until the plane is switched on.
              onPointerDownCapture={() => {
                if (session) takeWheel(session.id);
                if (!focused) focusPane(tab.id, pane.id);
              }}
            >
              {showHeader ? (
                <PaneHeader
                  title={session ? session.title : "Empty pane"}
                  protocol={session ? session.params.protocol : null}
                  state={session ? session.state : null}
                  focused={focused}
                  dragging={drag?.paneId === pane.id}
                  dropTarget={drag !== null && drag.overPaneId === pane.id && drag.paneId !== pane.id}
                  zoomed={tab.zoomedPaneId === pane.id}
                  agent={agent}
                  onStopAgent={session ? () => stopAgent(session.id) : undefined}
                  onZoom={() => toggleZoom(tab.id, pane.id)}
                  onClose={() => closePane(tab.id, pane.id)}
                  onPointerDown={(e) => beginPaneDrag(e, tab.id, pane.id)}
                />
              ) : null}
              <div className="relative min-h-0 flex-1">
                <PaneVisible value={focused}>
                  {session ? (
                  <Session
                    params={session.params}
                    embedded
                    onScreen={onScreen}
                    focused={focused}
                    frame={{
                      x: area.originX + rect.x,
                      y: area.originY + rect.y + headerPx,
                      width: rect.width,
                      height: Math.max(0, rect.height - headerPx),
                    }}
                    onSplit={(dir) => {
                      // The button is on the focused pane's toolbar, but say so
                      // outright rather than relying on it: `split` acts on
                      // whichever pane holds the keyboard.
                      focusPane(tab.id, pane.id);
                      splitPane(dir);
                    }}
                    onClose={() => (split ? closePane(tab.id, pane.id) : close(tab.id))}
                    onDesktopName={(name) => setTitle(session.id, name)}
                    onState={(state) => setState(session.id, state)}
                    onAppHotkey={onAppHotkey}
                  />
                  ) : (
                    <PanePicker
                      tabId={tab.id}
                      paneId={pane.id}
                      onClose={() => closePane(tab.id, pane.id)}
                    />
                  )}
                </PaneVisible>
              </div>

              {/*
                Which pane has the keyboard, drawn as a ring inside its edge.

                A separate element on top of the session rather than a border or
                an inset shadow on the box itself, because both of those paint
                underneath the box's own children, and the child here is a
                canvas filling every pixel of it: the ring was there in the
                style and invisible on screen. `pointer-events-none` keeps it
                out of the way of the desktop it is drawn over, and it costs
                nothing to leave mounted, so it renders only when there is more
                than one pane to tell apart.
              */}
              {split ? (
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-0 z-40 rounded-xs"
                  style={{
                    boxShadow: focused
                      ? "inset 0 0 0 2px var(--accent)"
                      : "inset 0 0 0 1px var(--border-strong)",
                  }}
                />
              ) : null}
            </div>
          );
        });
      })}

      {geometries.flatMap(({ tab, geometry }) => {
        const onScreen = tab.id === activeId;
        return geometry.dividers.map((divider) => (
          <div
            key={`${tab.id}:${divider.id}`}
            role="separator"
            aria-orientation={divider.dir === "row" ? "vertical" : "horizontal"}
            aria-label="Resize panes"
            className="absolute z-10 bg-transparent transition-colors hover:bg-accent/40"
            style={{
              left: divider.rect.x,
              top: divider.rect.y,
              width: divider.rect.width,
              height: divider.rect.height,
              visibility: onScreen ? "visible" : "hidden",
              cursor: divider.dir === "row" ? "col-resize" : "row-resize",
              // The drawn gap is thin; the grab area is not. Growing the box
              // itself would push the panes apart instead.
              padding: divider.dir === "row" ? "0 3px" : "3px 0",
              boxSizing: "content-box",
              marginLeft: divider.dir === "row" ? -3 : 0,
              marginTop: divider.dir === "row" ? 0 : -3,
            }}
            inert={onScreen ? undefined : true}
            onPointerDown={(e) => dragDivider(e, tab.id, tab.root, divider)}
          />
        ));
      })}

    </div>
  );
}
