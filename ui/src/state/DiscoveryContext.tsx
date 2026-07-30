import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { DiscoveredHost, DiscoveryEventPayload, ScanProgress } from "../lib/types";
import { inTauri, safeInvoke, safeListen } from "../lib/tauri";
import { MOCK_DISCOVERED, useMockData } from "../lib/mock";

interface DiscoveryContextValue {
  discovered: DiscoveredHost[];
  scan: ScanProgress;
  startScan: () => Promise<void>;
}

const DiscoveryContext = createContext<DiscoveryContextValue | null>(null);

export function DiscoveryProvider({ children }: { children: ReactNode }): ReactNode {
  const mock = useMockData();
  const [discovered, setDiscovered] = useState<DiscoveredHost[]>([]);
  const [scan, setScan] = useState<ScanProgress>({ running: false, done: 0, total: 0 });
  const started = useRef(false);

  useEffect(() => {
    if (mock) {
      setDiscovered(MOCK_DISCOVERED);
      return;
    }
    if (!inTauri() || started.current) return;
    started.current = true;
    let unlisten: (() => void) | undefined;
    void safeListen<DiscoveryEventPayload>("discovery://event", (ev) => {
      if (!ev || typeof ev !== "object") return;
      switch (ev.type) {
        case "found":
        case "updated":
          setDiscovered((prev) => {
            const i = prev.findIndex((d) => d.id === ev.host.id);
            if (i >= 0) {
              const next = prev.slice();
              next[i] = ev.host;
              return next;
            }
            return [...prev, ev.host];
          });
          break;
        case "lost":
          setDiscovered((prev) => prev.filter((d) => d.id !== ev.id));
          break;
        case "scan-progress":
          setScan({ running: true, done: ev.done, total: ev.total });
          break;
        case "scan-complete":
          setScan((s) => ({ ...s, running: false }));
          break;
        default:
          break;
      }
    }).then((fn) => {
      unlisten = fn;
    });
    void safeInvoke("start_discovery", undefined, null);
    return () => {
      unlisten?.();
      void safeInvoke("stop_discovery", undefined, null);
    };
  }, [mock]);

  const startScan = useCallback(async (): Promise<void> => {
    if (mock) {
      setScan({ running: true, done: 0, total: 100 });
      let done = 0;
      const iv = window.setInterval(() => {
        done += 10;
        setScan({ running: done < 100, done, total: 100 });
        if (done >= 100) window.clearInterval(iv);
      }, 200);
      return;
    }
    setScan({ running: true, done: 0, total: 0 });
    await safeInvoke("scan_network", undefined, null);
  }, [mock]);

  const value = useMemo(
    () => ({ discovered, scan, startScan }),
    [discovered, scan, startScan],
  );
  return <DiscoveryContext.Provider value={value}>{children}</DiscoveryContext.Provider>;
}

export function useDiscovery(): DiscoveryContextValue {
  const ctx = useContext(DiscoveryContext);
  if (!ctx) throw new Error("useDiscovery outside DiscoveryProvider");
  return ctx;
}
