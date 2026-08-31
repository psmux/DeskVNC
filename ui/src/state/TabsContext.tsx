/**
 * Open sessions in the library window (PRD/05 §5, tabbed view), and how the
 * window's area is divided between them.
 *
 * The alternative to one OS window per session: every session is mounted in
 * the library window and switched between the way browser tabs are. The
 * library itself is the first tab and is never closable, so `activeId === null`
 * means "the library is in front".
 *
 * A tab used to be one session. It is now a layout tree (see `lib/layout.ts`),
 * so one tab can show a VNC desktop beside an RDP one above a shell, the way
 * tmux divides a terminal. That forces a separation this file did not need
 * before: a tab owns a SHAPE, and the sessions are held in a registry of their
 * own, addressed by id. A pane names the session it shows. Moving a session
 * from one pane to another, or from one tab to another, therefore rewrites two
 * fields and touches nothing that a mounted viewer can see, which is the only
 * way a live framebuffer survives being rearranged.
 *
 * This still holds no connection state. A session is the parameters to mount a
 * viewer with; the viewer connects itself exactly as it does in a window, and
 * reports its name and connection state back here so the strip can label it.
 *
 * The strip is rendered whenever there is at least one tab, whatever the
 * `windowMode` preference currently says. Switching the preference decides
 * where the NEXT session goes; it never orphans sessions that are already
 * running, which is the only way a live framebuffer could be lost.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { SessionParams } from "../hooks/useSession";
import type { SessionState } from "../lib/types";
import { safeInvoke } from "../lib/tauri";
import { serializeLayout } from "../lib/groupLayout";
import {
  closePane as closePaneIn,
  cyclePane,
  evenAll,
  gridLayout,
  layoutGeometry,
  leaf,
  neighbour,
  nextId,
  panes,
  paneForSession,
  placedSessions,
  resizeSplit,
  setPaneSession,
  splitPane,
  swapPanes,
  type Direction,
  type LayoutNode,
  type Placement,
  type Rect,
  type Side,
} from "../lib/layout";

/** A connected session, wherever it happens to be shown. */
export interface LiveSession {
  /** The session id: what the shell knows it by, and its React key. */
  id: string;
  /** Stable across renders; remounting a viewer would drop its connection. */
  params: SessionParams;
  /** What the server calls this desktop, falling back to the dialled name. */
  title: string;
  state: SessionState;
}

/** One tab: a shape, and which of its panes has the keyboard. */
export interface WorkspaceTab {
  /**
   * Tab identity, deliberately not a session id. A tab outlives the session it
   * was opened for: close that pane while three others are still connected and
   * a tab named after it would be naming nothing.
   */
  id: string;
  root: LayoutNode;
  focusedPaneId: string;
  /**
   * A pane temporarily filling the whole tab, or null for the ordinary layout.
   *
   * Held beside the tree rather than in it, so maximising is not an edit of the
   * layout: the arrangement underneath is untouched, every other pane keeps its
   * rectangle and therefore its canvas size, and restoring is a matter of
   * forgetting this field rather than of rebuilding anything.
   */
  zoomedPaneId: string | null;
}

/** What the strip needs to draw a tab, without knowing about layout trees. */
export interface TabSummary {
  id: string;
  title: string;
  state: SessionState;
  /** How many panes it is divided into. One means an ordinary tab. */
  paneCount: number;
}

/** Where a session should be put when it finishes connecting. */
export interface PaneTarget {
  tabId: string;
  paneId: string;
}

interface TabsContextValue {
  tabs: readonly WorkspaceTab[];
  sessions: Readonly<Record<string, LiveSession>>;
  /** One entry per tab, in strip order. */
  summaries: readonly TabSummary[];
  /** The tab in front, or null for the library. */
  activeId: string | null;
  activeTab: WorkspaceTab | null;
  /**
   * Mount a session. With no `target` it opens a tab of its own; with one it
   * fills that pane, which is how a split gets something in it.
   */
  open: (id: string, params: SessionParams, target?: PaneTarget) => void;
  /** Close a tab and everything in it. Every viewer unmounts, disconnecting. */
  close: (id: string) => void;
  /** Bring a tab (or, for null, the library) to the front. */
  select: (id: string | null) => void;
  /** Bring the tab holding this session forward and focus its pane. */
  selectSession: (sessionId: string) => void;
  /** Is this session open in some pane of some tab? */
  has: (sessionId: string) => boolean;
  /** Move `delta` tabs along, wrapping, counting the library as the first. */
  selectRelative: (delta: number) => void;
  /** Select by position, the library being 0. Out of range does nothing. */
  selectIndex: (index: number) => void;
  /** Close whatever is in front. A no-op on the library, which cannot close. */
  closeActive: () => void;
  setTitle: (sessionId: string, title: string) => void;
  setState: (sessionId: string, state: SessionState) => void;

  // ------------------------------------------------------------- panes

  /** Divide the focused pane, leaving the new one empty and focused. */
  split: (dir: Direction, place?: Placement) => void;
  /** Close one pane. The last one closes the tab. */
  closePane: (tabId: string, paneId: string) => void;
  /** Give a pane the keyboard, bringing its tab forward if it is not already. */
  focusPane: (tabId: string, paneId: string) => void;
  /**
   * Tell the context how big the laid-out area is.
   *
   * Only the view knows, and only the context can answer "which pane is to the
   * left of this one", because that question is about pixels rather than about
   * the tree (see `neighbour`). Held in a ref: it changes on every window
   * resize and nothing renders from it.
   */
  reportArea: (area: Rect, gap: number) => void;
  /** Move the focus geometrically, the way the arrow keys read on screen. */
  moveFocus: (side: Side) => void;
  /** Move the focus in reading order, wrapping. */
  cycleFocus: (delta: number) => void;
  /** Pull an already-open session into a pane, swapping with what was there. */
  adopt: (tabId: string, paneId: string, sessionId: string) => void;
  /** Drag a divider. `deltaPx` and `extentPx` are along the split's own axis. */
  resize: (tabId: string, splitId: string, index: number, deltaPx: number, extentPx: number) => void;
  /** Give every split in a tab equal shares. */
  evenOut: (tabId: string) => void;
  /**
   * Blow one pane up to fill the tab, or put it back. The layout underneath is
   * untouched, so this is a way of looking rather than a way of arranging.
   */
  toggleZoom: (tabId: string, paneId: string) => void;
  /**
   * Lay the tab in front out as a grid of `count` panes, keeping whatever is
   * already connected and filling the rest with empty ones.
   */
  arrange: (count: number) => void;
  /**
   * Open a tab already shaped like `root`, and hand back its pane ids so the
   * caller can connect machines into them. Synchronous on purpose: opening a
   * group as a grid dials several hosts at once, and each one needs to know
   * which pane it is destined for before any of them have answered.
   */
  openArranged: (root: LayoutNode) => { tabId: string; paneIds: string[] };
  /** The tab in front, as something that can be written down. */
  serializeActive: () => string | null;
}

const TabsContext = createContext<TabsContextValue | null>(null);

const CONNECTING: SessionState = { state: "connecting" };

export function TabsProvider({ children }: { children: ReactNode }): ReactNode {
  const [tabs, setTabs] = useState<readonly WorkspaceTab[]>([]);
  const [sessions, setSessions] = useState<Readonly<Record<string, LiveSession>>>({});
  const [activeId, setActiveId] = useState<string | null>(null);

  // The keyboard shortcuts are handed to session viewers as stable callbacks,
  // so they read the current state through refs rather than closing over it.
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const activeRef = useRef(activeId);
  activeRef.current = activeId;
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;

  const has = useCallback(
    (sessionId: string): boolean =>
      tabsRef.current.some((t) => placedSessions(t.root).includes(sessionId)),
    [],
  );

  /**
   * Selecting a tab that is not open would leave the window showing nothing at
   * all: the library would not be in front, no pane would match, and with no
   * tabs there would not even be a strip to click. Fall back to the library
   * rather than trusting the caller.
   */
  const select = useCallback((id: string | null): void => {
    setActiveId(id !== null && !tabsRef.current.some((t) => t.id === id) ? null : id);
  }, []);

  /** Rewrite one tab, leaving the list untouched if nothing changed. */
  const patchTab = useCallback(
    (tabId: string, change: (tab: WorkspaceTab) => WorkspaceTab): void => {
      setTabs((prev) => {
        const index = prev.findIndex((t) => t.id === tabId);
        if (index < 0) return prev;
        const next = change(prev[index]);
        if (next === prev[index]) return prev;
        const list = prev.slice();
        list[index] = next;
        return list;
      });
    },
    [],
  );

  /**
   * Hand the session id back to the shell.
   *
   * Unmounting a viewer disconnects it, but a pane closed before it ever
   * connected leaves the shell holding a claim on that machine, and a claim
   * naming the library window is never invalidated by the window going away.
   */
  const releaseClaim = useCallback((sessionId: string): void => {
    void safeInvoke("release_session_claim", { sessionId }, null);
    setSessions((prev) => {
      if (!(sessionId in prev)) return prev;
      const next = { ...prev };
      delete next[sessionId];
      return next;
    });
  }, []);

  /**
   * `open` hands over to `adopt` for a session that is already placed, and
   * `adopt` is defined further down, once the things it reaches for exist.
   */
  const adoptRef = useRef<(tabId: string, paneId: string, sessionId: string) => void>(
    () => undefined,
  );

  const open = useCallback(
    (id: string, params: SessionParams, target?: PaneTarget): void => {
      // A session may only be in one pane. Two panes naming it would mount two
      // viewers on one connection, and the shell would answer the second one's
      // frames into a canvas the first one also owns. `adopt` is the operation
      // that moves an existing session, so hand over to it rather than placing
      // a second copy.
      const placed = tabsRef.current.find((t) => paneForSession(t.root, id));

      /**
       * The pane a caller asked for may be gone.
       *
       * Connecting is asynchronous: the picker asks the shell to dial, waits,
       * and only then says where the result should go, and the user is free to
       * close that pane or its whole tab in between. Placing the session into a
       * pane that no longer exists put it in the registry and in no pane at
       * all, which meant no viewer ever mounted for it, which meant no viewer
       * ever unmounted, so the shell was left holding a claim on that machine
       * for the life of the app and every later attempt to reach it was
       * answered "already open".
       */
      const stillThere =
        target !== undefined &&
        tabsRef.current.some(
          (t) => t.id === target.tabId && panes(t.root).some((p) => p.id === target.paneId),
        );

      setSessions((prev) =>
        prev[id] ? prev : { ...prev, [id]: { id, params, title: params.name, state: CONNECTING } },
      );

      if (target && stillThere) {
        if (placed) {
          adoptRef.current(target.tabId, target.paneId, id);
          return;
        }
        patchTab(target.tabId, (tab) => ({
          ...tab,
          root: setPaneSession(tab.root, target.paneId, id),
          focusedPaneId: target.paneId,
        }));
        setActiveId(target.tabId);
        return;
      }
      // A target that has gone falls through to the no-target path, which opens
      // a tab of its own. A connected machine the user has to close is a far
      // better outcome than one they cannot see and cannot reconnect to.

      // Already somewhere? Bring that tab forward rather than opening a second
      // view of one connection, which the shell would refuse to connect anyway.
      if (placed) {
        const pane = paneForSession(placed.root, id);
        patchTab(placed.id, (tab) => ({ ...tab, focusedPaneId: pane?.id ?? tab.focusedPaneId }));
        setActiveId(placed.id);
        return;
      }

      const pane = leaf(id);
      const tab: WorkspaceTab = {
        id: nextId("tab"), root: pane, focusedPaneId: pane.id, zoomedPaneId: null,
      };
      setTabs((prev) => [...prev, tab]);
      setActiveId(tab.id);
    },
    [patchTab],
  );

  const close = useCallback(
    (id: string): void => {
      // Computed out here rather than inside the `setTabs` updater: an updater
      // has to be pure, and React runs it twice in development.
      const list = tabsRef.current;
      const index = list.findIndex((t) => t.id === id);
      if (index < 0) return;
      for (const sessionId of placedSessions(list[index].root)) releaseClaim(sessionId);
      const next = list.filter((t) => t.id !== id);
      // Through an updater, so a focus or a resize queued earlier in the same
      // batch is not thrown away by a list snapshot taken at render time.
      // `next` is still used below, but only to pick which neighbour to land
      // on, which no pending update can change.
      setTabs((prev) => prev.filter((t) => t.id !== id));
      // Closing the tab in front lands on its neighbour, the way a browser
      // does, rather than dumping the user back on the library every time.
      if (activeRef.current === id) {
        setActiveId((next[index] ?? next[index - 1])?.id ?? null);
      }
    },
    [releaseClaim],
  );

  const closePane = useCallback(
    (tabId: string, paneId: string): void => {
      const tab = tabsRef.current.find((t) => t.id === tabId);
      if (!tab) return;
      const pane = panes(tab.root).find((p) => p.id === paneId);
      if (!pane) return;

      // The last pane going means the tab goes, which takes the close path
      // above so the neighbour-selection and claim release stay in one place.
      // Only the decision is taken from the snapshot: whether this was the last
      // pane cannot change under a pending update, since nothing else adds or
      // removes panes without going through here.
      if (closePaneIn(tab.root, paneId) === null) {
        close(tabId);
        return;
      }
      if (pane.sessionId) releaseClaim(pane.sessionId);

      // The rewrite itself runs against the tab as it is when the update is
      // applied, not against the snapshot read above, so a divider drag or a
      // focus change queued in the same batch is not silently dropped. Safe to
      // do inside an updater because `closePane` here is pure; the claim
      // release above is the side effect, and it stays out.
      patchTab(tabId, (t) => {
        const next = closePaneIn(t.root, paneId);
        // Already gone, or the tab is down to nothing, which the branch above
        // has already routed to `close`.
        if (next === null || next === t.root) return t;
        const remaining = panes(next);
        // The keyboard has to land somewhere. Reading order rather than
        // geometry: the pane that took over the space is not always the one
        // beside it, but the next one along always exists.
        const wanted =
          t.focusedPaneId === paneId ? cyclePane(t.root, paneId, 1) : t.focusedPaneId;
        const focusedPaneId = remaining.some((p) => p.id === wanted)
          ? (wanted as string)
          : remaining[0].id;
        return {
          ...t,
          root: next,
          focusedPaneId,
          // A pane that no longer exists cannot still be the maximised one.
          zoomedPaneId: t.zoomedPaneId === paneId ? null : t.zoomedPaneId,
        };
      });
    },
    [close, patchTab, releaseClaim],
  );

  const selectRelative = useCallback((delta: number): void => {
    const list = tabsRef.current;
    if (list.length === 0) return;
    // The library occupies index 0, so the ring is one longer than the tabs.
    const size = list.length + 1;
    const current = activeRef.current === null
      ? 0
      : list.findIndex((t) => t.id === activeRef.current) + 1;
    const next = ((current + delta) % size + size) % size;
    setActiveId(next === 0 ? null : list[next - 1].id);
  }, []);

  const selectIndex = useCallback((index: number): void => {
    if (index === 0) {
      setActiveId(null);
      return;
    }
    const tab = tabsRef.current[index - 1];
    if (tab) setActiveId(tab.id);
  }, []);

  const closeActive = useCallback((): void => {
    const id = activeRef.current;
    if (id !== null) close(id);
  }, [close]);

  const focusPane = useCallback(
    (tabId: string, paneId: string): void => {
      setActiveId(tabId);
      patchTab(tabId, (tab) =>
        tab.focusedPaneId === paneId ? tab : { ...tab, focusedPaneId: paneId },
      );
    },
    [patchTab],
  );

  const selectSession = useCallback(
    (sessionId: string): void => {
      const tab = tabsRef.current.find((t) => paneForSession(t.root, sessionId));
      if (!tab) return;
      const pane = paneForSession(tab.root, sessionId);
      if (pane) focusPane(tab.id, pane.id);
    },
    [focusPane],
  );

  const split = useCallback(
    (dir: Direction, place: Placement = "after"): void => {
      const tabId = activeRef.current;
      if (tabId === null) return;
      const tab = tabsRef.current.find((t) => t.id === tabId);
      if (!tab) return;
      // A pane with nothing in it yet has nothing to divide, and splitting it
      // would leave two host pickers side by side, neither of them asked for.
      const current = panes(tab.root).find((p) => p.id === tab.focusedPaneId);
      if (!current || current.sessionId === null) return;
      const added = leaf(null);
      patchTab(tabId, (t) => ({
        ...t,
        root: splitPane(t.root, t.focusedPaneId, dir, added, place),
        focusedPaneId: added.id,
      }));
    },
    [patchTab],
  );

  const areaRef = useRef<{ area: Rect; gap: number }>({
    area: { x: 0, y: 0, width: 0, height: 0 },
    gap: 0,
  });

  const reportArea = useCallback((area: Rect, gap: number): void => {
    areaRef.current = { area, gap };
  }, []);

  const moveFocus = useCallback(
    (side: Side): void => {
      const tabId = activeRef.current;
      if (tabId === null) return;
      const tab = tabsRef.current.find((t) => t.id === tabId);
      if (!tab) return;
      const { area, gap } = areaRef.current;
      const target = neighbour(layoutGeometry(tab.root, area, gap), tab.focusedPaneId, side);
      if (target) focusPane(tabId, target);
    },
    [focusPane],
  );

  const cycleFocus = useCallback(
    (delta: number): void => {
      const tabId = activeRef.current;
      if (tabId === null) return;
      const tab = tabsRef.current.find((t) => t.id === tabId);
      if (!tab) return;
      const target = cyclePane(tab.root, tab.focusedPaneId, delta);
      if (target) focusPane(tabId, target);
    },
    [focusPane],
  );

  /**
   * Put an already-open session into this pane.
   *
   * A swap rather than a move: the session that was here has to go somewhere,
   * and trading places is the only answer that neither closes a connection nor
   * needs a rule about where the displaced one lands. When it comes from
   * another tab there is nothing to trade with, so it simply moves.
   */
  const adopt = useCallback(
    (tabId: string, paneId: string, sessionId: string): void => {
      const home = tabsRef.current.find((t) => paneForSession(t.root, sessionId));
      if (!home) return;
      const source = paneForSession(home.root, sessionId);
      if (!source) return;

      if (home.id === tabId) {
        if (source.id === paneId) return;
        patchTab(tabId, (t) => ({
          ...t,
          root: swapPanes(t.root, source.id, paneId),
          focusedPaneId: paneId,
        }));
        setActiveId(tabId);
        return;
      }

      const target = tabsRef.current.find((t) => t.id === tabId);
      if (!target) return;
      // The pane has to still exist before the source is emptied. Without this
      // check a stale target (the pane closed while a connect was in flight)
      // took the session out of the pane it was in and put it nowhere: the
      // viewer unmounted, the connection dropped, and the tab was left with a
      // `focusedPaneId` naming no pane, so nothing at all held the keyboard.
      const destination = panes(target.root).find((p) => p.id === paneId);
      if (!destination) return;
      const displaced = destination.sessionId;
      // Empty the pane it came from rather than closing it: the tab it left
      // keeps its shape, and the hole is a host picker the user can refill.
      patchTab(home.id, (t) => ({ ...t, root: setPaneSession(t.root, source.id, displaced) }));
      patchTab(tabId, (t) => ({
        ...t,
        root: setPaneSession(t.root, paneId, sessionId),
        focusedPaneId: paneId,
      }));
      setActiveId(tabId);
    },
    [patchTab],
  );
  adoptRef.current = adopt;

  const resize = useCallback(
    (tabId: string, splitId: string, index: number, deltaPx: number, extentPx: number): void => {
      patchTab(tabId, (tab) => {
        const root = resizeSplit(tab.root, splitId, index, deltaPx, extentPx);
        return root === tab.root ? tab : { ...tab, root };
      });
    },
    [patchTab],
  );

  const evenOut = useCallback(
    (tabId: string): void => {
      patchTab(tabId, (tab) => ({ ...tab, root: evenAll(tab.root) }));
    },
    [patchTab],
  );

  const toggleZoom = useCallback(
    (tabId: string, paneId: string): void => {
      patchTab(tabId, (tab) => {
        if (tab.zoomedPaneId === paneId) return { ...tab, zoomedPaneId: null };
        // Nothing to maximise a lone pane out of, and the focus follows the
        // zoom: a maximised pane the keyboard is not pointed at would be a
        // reliable way to type into the wrong machine.
        if (panes(tab.root).length < 2) return tab;
        return { ...tab, zoomedPaneId: paneId, focusedPaneId: paneId };
      });
    },
    [patchTab],
  );

  /**
   * Reshape the tab in front into a grid.
   *
   * The machines already connected in it are kept and re-placed in reading
   * order, so asking for six panes when two are open moves nothing and adds
   * four holes. Asking for fewer panes than there are sessions is the one case
   * that has to lose something: the surplus is dropped from the layout, and
   * each dropped session is disconnected rather than left running invisibly,
   * which is what closing a pane by hand does too.
   */
  const arrange = useCallback(
    (count: number): void => {
      const tabId = activeRef.current;
      if (tabId === null) return;
      const tab = tabsRef.current.find((t) => t.id === tabId);
      if (!tab) return;

      const existing = panes(tab.root)
        .map((p) => p.sessionId)
        .filter((s): s is string => s !== null);
      for (const dropped of existing.slice(count)) releaseClaim(dropped);

      const root = gridLayout(count, existing.slice(0, count));
      const list = panes(root);
      // Keep the keyboard on the same machine where that is still possible,
      // rather than dumping it on the first pane every time the shape changes.
      const stayWith = panes(tab.root).find((p) => p.id === tab.focusedPaneId)?.sessionId ?? null;
      const kept = stayWith === null ? undefined : list.find((p) => p.sessionId === stayWith);
      patchTab(tabId, (t) => ({ ...t, root, focusedPaneId: (kept ?? list[0]).id }));
    },
    [patchTab, releaseClaim],
  );

  const openArranged = useCallback(
    (root: LayoutNode): { tabId: string; paneIds: string[] } => {
      const list = panes(root);
      const tab: WorkspaceTab = {
        id: nextId("tab"), root, focusedPaneId: list[0].id, zoomedPaneId: null,
      };
      setTabs((prev) => [...prev, tab]);
      // Put it in the ref as well, right now.
      //
      // The whole point of handing the pane ids back is that the caller fills
      // them immediately, and every one of those calls asks `open` whether the
      // pane still exists. The ref is only refreshed on the next render, so
      // without this the answer for a tab created a moment ago is "no", and
      // each machine ends up in a tab of its own instead of in the grid that
      // was just built for it. The next render overwrites this with the real
      // state, which by then says the same thing.
      tabsRef.current = [...tabsRef.current, tab];
      setActiveId(tab.id);
      return { tabId: tab.id, paneIds: list.map((p) => p.id) };
    },
    [],
  );

  const serializeActive = useCallback((): string | null => {
    const tab = tabsRef.current.find((t) => t.id === activeRef.current);
    if (!tab) return null;
    // A session knows the host it was opened from; an ad-hoc one has no profile
    // and is stored as an empty pane, since there would be nothing to dial.
    return serializeLayout(tab.root, (id) => sessionsRef.current[id]?.params.profileId ?? null);
  }, []);

  /**
   * Replace one field of one session, or return the map untouched.
   *
   * Returning `prev` unchanged is load-bearing, not an optimisation: these are
   * called from effects in the viewers, so an update that always allocated a
   * fresh object would re-render the shell, re-run those effects, and spin.
   */
  const patchSession = useCallback((id: string, change: Partial<LiveSession>): void => {
    setSessions((prev) => {
      const current = prev[id];
      if (!current) return prev;
      if (Object.entries(change).every(([k, v]) => current[k as keyof LiveSession] === v)) {
        return prev;
      }
      return { ...prev, [id]: { ...current, ...change } };
    });
  }, []);

  const setTitle = useCallback(
    (id: string, title: string): void => patchSession(id, { title }),
    [patchSession],
  );

  const setState = useCallback(
    (id: string, state: SessionState): void => patchSession(id, { state }),
    [patchSession],
  );

  /**
   * What the strip shows.
   *
   * A tab is labelled by its focused pane, so the name on the tab is the
   * machine the keyboard is pointed at. The pane count is how a split announces
   * itself on a strip that otherwise looks exactly as it did.
   */
  const summaries = useMemo(
    (): TabSummary[] =>
      tabs.map((tab) => {
        const list = panes(tab.root);
        const focused = list.find((p) => p.id === tab.focusedPaneId) ?? list[0];
        const session = focused?.sessionId ? sessions[focused.sessionId] : undefined;
        const named = list
          .map((p) => (p.sessionId ? sessions[p.sessionId]?.title : null))
          .filter((t): t is string => Boolean(t));
        return {
          id: tab.id,
          title: session?.title ?? named[0] ?? "New pane",
          state: session?.state ?? CONNECTING,
          paneCount: list.length,
        };
      }),
    [tabs, sessions],
  );

  const activeTab = useMemo(
    () => tabs.find((t) => t.id === activeId) ?? null,
    [tabs, activeId],
  );

  const value = useMemo(
    () => ({
      tabs,
      sessions,
      summaries,
      activeId,
      activeTab,
      open,
      close,
      select,
      selectSession,
      has,
      selectRelative,
      selectIndex,
      closeActive,
      setTitle,
      setState,
      split,
      closePane,
      focusPane,
      reportArea,
      moveFocus,
      cycleFocus,
      adopt,
      resize,
      evenOut,
      toggleZoom,
      arrange,
      openArranged,
      serializeActive,
    }),
    [
      tabs, sessions, summaries, activeId, activeTab, open, close, select, selectSession,
      has, selectRelative, selectIndex, closeActive, setTitle, setState, split, closePane,
      focusPane, reportArea, moveFocus, cycleFocus, adopt, resize, evenOut, toggleZoom, arrange,
      openArranged, serializeActive,
    ],
  );

  return <TabsContext.Provider value={value}>{children}</TabsContext.Provider>;
}

export function useTabs(): TabsContextValue {
  const ctx = useContext(TabsContext);
  if (!ctx) throw new Error("useTabs outside TabsProvider");
  return ctx;
}
