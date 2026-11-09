/**
 * App wide state: the saved computers, their card pictures, which ones were
 * seen on the network lately, and the navigation (tab, wizard, session).
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import type { ConnectTarget, FoundComputer, Host, HostDraft } from "../api/contract";
import type { TabKey } from "../art/Icons";
import { haptic } from "../lib/haptics";
import { newWizard, type WizardState } from "../lib/wizard";

export interface SessionRequest {
  target: ConnectTarget;
  /** What to call it while connecting. */
  title: string;
  key: number;
}

interface AppState {
  hosts: Host[];
  loaded: boolean;
  thumbs: Record<string, string | null>;
  /** Addresses the last scan saw, so cards can show an online dot. */
  seen: Set<string>;
  scanning: boolean;
  found: FoundComputer[];
  tab: TabKey;
  setTab: (t: TabKey) => void;
  wizard: WizardState | null;
  openWizard: (s?: WizardState) => void;
  closeWizard: () => void;
  session: SessionRequest | null;
  connect: (target: ConnectTarget, title: string) => void;
  endSession: () => void;
  refresh: () => Promise<void>;
  scan: () => Promise<void>;
  saveHost: (draft: HostDraft) => Promise<Host>;
  deleteHost: (id: string) => Promise<void>;
  toggleFavorite: (host: Host) => Promise<void>;
  toast: string | null;
  showToast: (text: string) => void;
}

const Ctx = createContext<AppState | null>(null);

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp outside AppProvider");
  return v;
}

export function presenceKey(address: string, port: number): string {
  return `${address}:${port}`;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [thumbs, setThumbs] = useState<Record<string, string | null>>({});
  const [seen, setSeen] = useState<Set<string>>(new Set());
  const [found, setFound] = useState<FoundComputer[]>([]);
  const [scanning, setScanning] = useState(false);
  const [tab, setTabState] = useState<TabKey>("computers");
  const [wizard, setWizard] = useState<WizardState | null>(null);
  const [session, setSession] = useState<SessionRequest | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sessionKey = useRef(0);
  const scanDone = useRef<(() => void) | null>(null);

  const loadThumbs = useCallback(async (list: Host[]) => {
    const entries = await Promise.all(
      list.filter((h) => h.hasThumbnail).map(async (h) => [h.id, await api.hostsThumbnail(h.id).catch(() => null)] as const),
    );
    setThumbs((t) => ({ ...t, ...Object.fromEntries(entries) }));
  }, []);

  const refresh = useCallback(async () => {
    try {
      const list = await api.hostsList();
      setHosts(list);
      void loadThumbs(list);
    } finally {
      setLoaded(true);
    }
  }, [loadThumbs]);

  const scan = useCallback(async () => {
    if (scanDone.current) return new Promise<void>((r) => setTimeout(r, 0));
    setScanning(true);
    setFound([]);
    const nextSeen = new Set<string>();
    await new Promise<void>((resolve) => {
      scanDone.current = resolve;
      api
        .scanStart((e) => {
          if (e.type === "found") {
            nextSeen.add(presenceKey(e.item.address, e.item.port));
            setSeen(new Set(nextSeen));
            setFound((f) => (f.some((x) => x.address === e.item.address && x.port === e.item.port) ? f : [...f, e.item]));
          } else if (e.type === "complete") {
            resolve();
          }
        })
        .catch(() => resolve());
    });
    scanDone.current = null;
    setScanning(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const showToast = useCallback((text: string) => {
    setToast(text);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2600);
  }, []);

  const saveHost = useCallback(
    async (draft: HostDraft) => {
      const saved = await api.hostsSave(draft);
      setHosts((list) => (list.some((h) => h.id === saved.id) ? list.map((h) => (h.id === saved.id ? saved : h)) : [...list, saved]));
      return saved;
    },
    [],
  );

  const deleteHost = useCallback(async (id: string) => {
    await api.hostsDelete(id);
    setHosts((list) => list.filter((h) => h.id !== id));
    haptic("warning");
  }, []);

  const toggleFavorite = useCallback(
    async (host: Host) => {
      haptic("select");
      const { hasPassword: _p, lastConnectedAt: _l, hasThumbnail: _t, ...draft } = host;
      setHosts((list) => list.map((h) => (h.id === host.id ? { ...h, favorite: !h.favorite } : h)));
      await saveHost({ ...draft, favorite: !host.favorite });
    },
    [saveHost],
  );

  const value = useMemo<AppState>(
    () => ({
      hosts,
      loaded,
      thumbs,
      seen,
      scanning,
      found,
      tab,
      setTab: (t) => {
        haptic("select");
        setTabState(t);
      },
      wizard,
      openWizard: (s) => setWizard(s ?? newWizard()),
      closeWizard: () => setWizard(null),
      session,
      connect: (target, title) => {
        haptic("tap");
        sessionKey.current += 1;
        setSession({ target, title, key: sessionKey.current });
      },
      endSession: () => {
        setSession(null);
        // The session may have saved a new card picture.
        void refresh();
      },
      refresh,
      scan,
      saveHost,
      deleteHost,
      toggleFavorite,
      toast,
      showToast,
    }),
    [hosts, loaded, thumbs, seen, scanning, found, tab, wizard, session, refresh, scan, saveHost, deleteHost, toggleFavorite, toast, showToast],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
