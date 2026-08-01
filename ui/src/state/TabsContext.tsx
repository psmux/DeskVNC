/**
 * Open session tabs in the library window (PRD/05 §5, tabbed view).
 *
 * The alternative to one OS window per session: every session is mounted in
 * the library window and switched between the way browser tabs are. The
 * library itself is the first tab and is never closable, so `activeId === null`
 * means "the library is in front".
 *
 * This holds no connection state of its own. A tab is a session id plus the
 * parameters to mount a viewer with; the viewer connects itself exactly as it
 * does in a window, and reports its name and connection state back here so the
 * strip can label it.
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

export interface SessionTab {
  /** The session id: React key, tab identity, and what the shell knows it by. */
  id: string;
  /** Stable across renders, remounting a viewer would drop its connection. */
  params: SessionParams;
  /** What the server calls this desktop, falling back to the dialled name. */
  title: string;
  state: SessionState;
}

interface TabsContextValue {
  tabs: readonly SessionTab[];
  /** The tab in front, or null for the library. */
  activeId: string | null;
  /** Add a tab and bring it to the front. Selects it if it is already open. */
  open: (id: string, params: SessionParams) => void;
  /** Close a tab. The viewer unmounts, which disconnects it. */
  close: (id: string) => void;
  /** Bring a tab (or, for null, the library) to the front. */
  select: (id: string | null) => void;
  /** Move `delta` tabs along, wrapping, counting the library as the first. */
  selectRelative: (delta: number) => void;
  /** Select by position, the library being 0. Out of range does nothing. */
  selectIndex: (index: number) => void;
  /** Close whatever is in front. A no-op on the library, which cannot close. */
  closeActive: () => void;
  setTitle: (id: string, title: string) => void;
  setState: (id: string, state: SessionState) => void;
}

const TabsContext = createContext<TabsContextValue | null>(null);

const CONNECTING: SessionState = { state: "connecting" };

export function TabsProvider({ children }: { children: ReactNode }): ReactNode {
  const [tabs, setTabs] = useState<readonly SessionTab[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);

  // The keyboard shortcuts are handed to session viewers as a stable callback,
  // so they read the current list through a ref rather than closing over it.
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const activeRef = useRef(activeId);
  activeRef.current = activeId;

  const select = useCallback((id: string | null): void => {
    setActiveId(id);
  }, []);

  const open = useCallback((id: string, params: SessionParams): void => {
    setTabs((prev) =>
      prev.some((t) => t.id === id)
        ? prev
        : [...prev, { id, params, title: params.name, state: CONNECTING }],
    );
    setActiveId(id);
  }, []);

  const close = useCallback((id: string): void => {
    // Computed out here rather than inside the `setTabs` updater: an updater
    // has to be pure, and React runs it twice in development.
    const list = tabsRef.current;
    const index = list.findIndex((t) => t.id === id);
    if (index < 0) return;
    const next = list.filter((t) => t.id !== id);
    setTabs(next);
    // Closing the tab in front lands on its neighbour, the way a browser does,
    // rather than dumping the user back on the library every time.
    if (activeRef.current === id) {
      setActiveId((next[index] ?? next[index - 1])?.id ?? null);
    }
  }, []);

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

  /**
   * Replace one field of one tab, or return the list untouched.
   *
   * Returning `prev` unchanged is load-bearing, not an optimisation: these are
   * called from effects in the viewers, so an update that always allocated a
   * fresh array would re-render the shell, re-run those effects, and spin.
   */
  const patch = useCallback((id: string, change: Partial<SessionTab>): void => {
    setTabs((prev) => {
      const index = prev.findIndex((t) => t.id === id);
      if (index < 0) return prev;
      const current = prev[index];
      if (Object.entries(change).every(([k, v]) => current[k as keyof SessionTab] === v)) {
        return prev;
      }
      const next = prev.slice();
      next[index] = { ...current, ...change };
      return next;
    });
  }, []);

  const setTitle = useCallback(
    (id: string, title: string): void => patch(id, { title }),
    [patch],
  );

  const setState = useCallback(
    (id: string, state: SessionState): void => patch(id, { state }),
    [patch],
  );

  const value = useMemo(
    () => ({
      tabs,
      activeId,
      open,
      close,
      select,
      selectRelative,
      selectIndex,
      closeActive,
      setTitle,
      setState,
    }),
    [tabs, activeId, open, close, select, selectRelative, selectIndex, closeActive, setTitle, setState],
  );

  return <TabsContext.Provider value={value}>{children}</TabsContext.Provider>;
}

export function useTabs(): TabsContextValue {
  const ctx = useContext(TabsContext);
  if (!ctx) throw new Error("useTabs outside TabsProvider");
  return ctx;
}
