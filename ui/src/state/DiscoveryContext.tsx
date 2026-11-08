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
import type {
  DiscoveredHost,
  DiscoveryEventPayload,
  ScanNetwork,
  ScanProgress,
  ScanTarget,
} from "../lib/types";
import { inTauri, mustInvoke, safeInvoke, safeListen } from "../lib/tauri";
import { MOCK_DISCOVERED, useMockData } from "../lib/mock";

interface DiscoveryContextValue {
  discovered: DiscoveredHost[];
  scan: ScanProgress;
  /**
   * No target: scan the local subnets the shell deems safe, as the button
   * always did. A target: scan just those ranges; a refusal (too large, not
   * private, a scan already running) rejects, so the caller can say why.
   */
  startScan: (target?: ScanTarget) => Promise<void>;
  /** The networks this computer can scan (`scan_networks`). */
  listNetworks: () => Promise<ScanNetwork[]>;
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

  const startScan = useCallback(async (target?: ScanTarget): Promise<void> => {
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
    if (!target) {
      await safeInvoke("scan_network", undefined, null);
      return;
    }
    try {
      await mustInvoke("scan_network", { subnets: target.cidrs, allowLarge: target.allowLarge });
    } catch (err) {
      setScan((s) => ({ ...s, running: false }));
      throw err;
    }
  }, [mock]);

  const listNetworks = useCallback(
    (): Promise<ScanNetwork[]> => safeInvoke<ScanNetwork[]>("scan_networks", undefined, []),
    [],
  );

  const value = useMemo(
    () => ({ discovered, scan, startScan, listNetworks }),
    [discovered, scan, startScan, listNetworks],
  );
  return <DiscoveryContext.Provider value={value}>{children}</DiscoveryContext.Provider>;
}

export function useDiscovery(): DiscoveryContextValue {
  const ctx = useContext(DiscoveryContext);
  if (!ctx) throw new Error("useDiscovery outside DiscoveryProvider");
  return ctx;
}
