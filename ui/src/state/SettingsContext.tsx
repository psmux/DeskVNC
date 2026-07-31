import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type ThemeChoice = "system" | "light" | "dark";
export type LibraryView = "grid" | "list";
export type SortKey = "name" | "last-connected" | "frequency" | "group";

export interface Settings {
  theme: ThemeChoice;
  libraryView: LibraryView;
  sortKey: SortKey;
  compact: boolean;
  onboarded: boolean;
  probeOnline: boolean;
  /**
   * Draw the remote machine's own pointer.
   *
   * The remote cursor is composited client-side so it tracks your mouse even
   * when frames are slow. Some people find the two pointers distracting (or
   * the remote one is drawn badly by the server), so it can be turned off, * input is unaffected either way.
   */
  showRemoteCursor: boolean;
  /**
   * Addresses reached through QuickConnect, most recent first.
   *
   * These live here rather than in the store's `history` table because that
   * table is keyed by host id, and the whole point of a quick connect is that
   * there is no host record. Kept to {@link MAX_QUICK_CONNECT_HISTORY} entries.
   */
  quickConnectHistory: string[];
}

export const MAX_QUICK_CONNECT_HISTORY = 8;

const DEFAULTS: Settings = {
  theme: "system",
  libraryView: "grid",
  sortKey: "name",
  compact: false,
  onboarded: false,
  probeOnline: true,
  showRemoteCursor: true,
  quickConnectHistory: [],
};

const STORAGE_KEY = "deskvnc.settings.v1";

interface SettingsContextValue {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

function load(): Settings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const merged = { ...DEFAULTS, ...(JSON.parse(raw) as Partial<Settings>) };
    // localStorage is hand-editable, and a history that is not an array would
    // throw on every render of the QuickConnect bar rather than degrade.
    if (!Array.isArray(merged.quickConnectHistory)) merged.quickConnectHistory = [];
    return merged;
  } catch {
    return DEFAULTS;
  }
}

export function SettingsProvider({ children }: { children: ReactNode }): ReactNode {
  const [settings, setSettings] = useState<Settings>(load);

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  }, []);

  // Apply theme: Follow System removes the attribute so prefers-color-scheme rules.
  useEffect(() => {
    const root = document.documentElement;
    if (settings.theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", settings.theme);
  }, [settings.theme]);

  const value = useMemo(() => ({ settings, update }), [settings, update]);
  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings outside SettingsProvider");
  return ctx;
}
