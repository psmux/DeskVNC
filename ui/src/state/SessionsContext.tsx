/**
 * Live-session registry for the Library window (main window only).
 *
 * The composed framebuffer only exists in each session window's WebGL texture,
 * and the bandwidth counters only exist in Rust, so this context is the
 * Library's one ear on both: it seeds from `list_active_sessions`, then keeps
 * itself current from three app-wide events:
 *
 *   `sessions://event`, session lifecycle (started / state / ended), Rust
 *   `sessions://stats`, 1 Hz per connected session, Rust
 *   `library://preview`, ~2 fps JPEG data-URL frames, emitted by the session
 *                          window's JS (see hooks/useLivePreview.ts)
 *
 * Tiles look themselves up by the SAME key the thumbnail store uses: a saved
 * host's profile id, or `discovered:<address>:<port>` for an ad-hoc session
 * (`discoveredThumbKey` in components/HostTile.tsx).
 */
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
import { emit } from "@tauri-apps/api/event";
import type { ProtocolKind, SessionStats } from "../lib/types";
import { isProtocolKind } from "../lib/types";
import { inTauri, safeInvoke, safeListen } from "../lib/tauri";
import { discoveredThumbKey } from "../components/HostTile";

// ---------------------------------------------------------------- contracts

/** Rust KV key for the Library's live-previews toggle ("1" / "0", default off). */
export const LIVE_PREVIEWS_KEY = "livePreviews";
/** App-wide JS event the Library emits when the toggle changes: `{ enabled }`. */
export const LIVE_PREVIEWS_EVENT = "library://live-previews";
/** App-wide JS event carrying one downscaled preview frame per publish tick. */
export const PREVIEW_EVENT = "library://preview";

const SESSIONS_EVENT = "sessions://event";
const SESSIONS_STATS_EVENT = "sessions://stats";

/** No stats sample for this long ⇒ the bandwidth overlay is hidden. */
const STALE_MS = 3000;
/** Ring buffer length: ~60 s of 1 Hz samples per session. */
const MAX_SAMPLES = 60;

/** Payload of `library://preview` (JS → JS, emitted from the session window). */
export interface PreviewPayload {
  sessionId: string;
  /** profileId if the session has one, else `discovered:<address>:<port>`. */
  key: string;
  address: string;
  port: number;
  /** "data:image/jpeg;base64,…", downscaled to ≤360 px wide. */
  dataUrl: string;
  width: number;
  height: number;
}

/** Flat payloads of `sessions://event` (Rust `app.emit`, camelCase). */
type SessionsEventPayload =
  | { type: "started"; sessionId: string; profileId: string | null; address: string; port: number }
  | { type: "state"; sessionId: string; state: string }
  | { type: "ended"; sessionId: string };

/** Payload of `sessions://stats`, top-level camelCase, `stats` snake_case. */
interface SessionsStatsPayload {
  sessionId: string;
  profileId: string | null;
  address: string;
  port: number;
  stats: SessionStats;
}

/** One row of `list_active_sessions`. */
interface ActiveSessionRow {
  sessionId: string;
  profileId: string | null;
  address: string;
  port: number;
  /** Optional because an older shell sends no such key. */
  protocol?: ProtocolKind;
}

// ------------------------------------------------------------------- state

interface BandwidthSample {
  /** RX bits/sec (`throughput_bps`). */
  rx: number;
  /** TX bits/sec (`throughput_up_bps`). */
  tx: number;
}

interface LiveSession {
  sessionId: string;
  profileId: string | null;
  address: string;
  port: number;
  protocol: ProtocolKind;
  /** Kebab-case state tag ("connecting", "connected", …). */
  state: string;
  /** Last ~60 s of 1 Hz throughput samples, oldest first. */
  samples: BandwidthSample[];
  latest: BandwidthSample | null;
  totals: { bytesReceived: number; bytesSent: number } | null;
  /** Wall-clock ms of the newest stats sample; 0 = none yet. */
  lastStatsAt: number;
}

interface PreviewFrame {
  sessionId: string;
  dataUrl: string;
  width: number;
  height: number;
}

/** What a tile gets back for its key. */
export interface TileActivity {
  /** Fresh bandwidth (a stats sample within the last 3 s), else null. */
  bandwidth: { rx: number; tx: number; samples: readonly BandwidthSample[] } | null;
  /** Latest live preview frame for this key, else null. Toggle-independent, * the tile combines it with `livePreviews` before showing it. */
  preview: { dataUrl: string; width: number; height: number } | null;
}

interface SessionsContextValue {
  /** Lookup by tile key: `host.id` or `discoveredThumbKey(address, port)`. */
  forKey: (key: string) => TileActivity;
  /** The persisted Library toggle (default off). */
  livePreviews: boolean;
  /** Flip the toggle: persists it and broadcasts `library://live-previews`. */
  setLivePreviews: (enabled: boolean) => void;
}

const SessionsContext = createContext<SessionsContextValue | null>(null);

const EMPTY_ACTIVITY: TileActivity = { bandwidth: null, preview: null };

const num = (v: unknown): number =>
  typeof v === "number" && Number.isFinite(v) ? v : 0;

/** The tile key a session's data lands under, same convention as thumbnails. */
function sessionKeyOf(s: { profileId: string | null; address: string; port: number }): string {
  return s.profileId ?? discoveredThumbKey(s.address, s.port);
}

function blankSession(row: ActiveSessionRow, state: string): LiveSession {
  return {
    sessionId: row.sessionId,
    // Carried so a tile can show which protocol is live on it. The tile KEY
    // deliberately does not change: two protocols to one machine use
    // different ports, so `discovered:<address>:<port>` is already distinct
    // and a VNC and an RDP session to one box get two tiles, which is
    // correct, they are two different things to look at.
    protocol: isProtocolKind(row.protocol) ? row.protocol : "vnc",
    profileId: typeof row.profileId === "string" && row.profileId ? row.profileId : null,
    address: typeof row.address === "string" ? row.address : "",
    port: num(row.port) || 5900,
    state,
    samples: [],
    latest: null,
    totals: null,
    lastStatsAt: 0,
  };
}

// ---------------------------------------------------------------- provider

export function SessionsProvider({ children }: { children: ReactNode }): ReactNode {
  const [sessions, setSessions] = useState<Record<string, LiveSession>>({});
  const [previews, setPreviews] = useState<Record<string, PreviewFrame>>({});

  // ------------------------------------------------------- live-previews toggle

  const [livePreviews, setLivePreviewsState] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void safeInvoke<string | null>("get_app_setting", { key: LIVE_PREVIEWS_KEY }, null).then(
      (raw) => {
        if (!cancelled && raw === "1") setLivePreviewsState(true);
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  const setLivePreviews = useCallback((enabled: boolean): void => {
    setLivePreviewsState(enabled);
    void safeInvoke("set_app_setting", { key: LIVE_PREVIEWS_KEY, value: enabled ? "1" : "0" }, null);
    // Session windows read the setting once at startup and listen for this
    // broadcast thereafter (item 6 of the live-thumbs contract).
    if (inTauri()) {
      void emit(LIVE_PREVIEWS_EVENT, { enabled }).catch((err: unknown) => {
        console.warn(`[sessions] emit "${LIVE_PREVIEWS_EVENT}" failed:`, err);
      });
    }
  }, []);

  // ------------------------------------------------------------ event intake

  const onEvent = useCallback((ev: SessionsEventPayload): void => {
    if (!ev || typeof ev !== "object" || typeof ev.sessionId !== "string" || !ev.sessionId) return;
    switch (ev.type) {
      case "started":
        // A seed row or an earlier stats event may already have the entry;
        // never wipe accumulated samples with a blank.
        setSessions((prev) =>
          prev[ev.sessionId]
            ? prev
            : { ...prev, [ev.sessionId]: blankSession(ev, "connecting") },
        );
        break;
      case "state":
        setSessions((prev) => {
          const cur = prev[ev.sessionId];
          if (!cur || typeof ev.state !== "string" || cur.state === ev.state) return prev;
          return { ...prev, [ev.sessionId]: { ...cur, state: ev.state } };
        });
        break;
      case "ended":
        setSessions((prev) => {
          if (!(ev.sessionId in prev)) return prev;
          const next = { ...prev };
          delete next[ev.sessionId];
          return next;
        });
        // Drop the session's frozen last frame too, or a closed session would
        // leave its tile stuck on a stale "live" picture.
        setPreviews((prev) => {
          const keep = Object.entries(prev).filter(([, p]) => p.sessionId !== ev.sessionId);
          return keep.length === Object.keys(prev).length ? prev : Object.fromEntries(keep);
        });
        break;
      default:
        break;
    }
  }, []);

  const onStats = useCallback((ev: SessionsStatsPayload): void => {
    if (!ev || typeof ev !== "object" || typeof ev.sessionId !== "string" || !ev.sessionId) return;
    if (!ev.stats || typeof ev.stats !== "object") return;
    const sample: BandwidthSample = {
      rx: num(ev.stats.throughput_bps),
      tx: num(ev.stats.throughput_up_bps),
    };
    const now = Date.now();
    setSessions((prev) => {
      // Stats can outrun the seed and the `started` event, upsert.
      const cur = prev[ev.sessionId] ?? blankSession(ev, "connected");
      const samples = [...cur.samples, sample];
      if (samples.length > MAX_SAMPLES) samples.splice(0, samples.length - MAX_SAMPLES);
      return {
        ...prev,
        [ev.sessionId]: {
          ...cur,
          // Stats only flow while connected; a missed state event must not
          // leave the entry stuck on "connecting".
          state: "connected",
          samples,
          latest: sample,
          totals: {
            bytesReceived: num(ev.stats.bytes_received),
            bytesSent: num(ev.stats.bytes_sent),
          },
          lastStatsAt: now,
        },
      };
    });
  }, []);

  const onPreview = useCallback((ev: PreviewPayload): void => {
    if (!ev || typeof ev !== "object") return;
    if (typeof ev.key !== "string" || !ev.key) return;
    // The data URL is rendered as an <img src>; accept only what the publisher
    // actually produces, never an arbitrary string from a stray event.
    if (typeof ev.dataUrl !== "string" || !ev.dataUrl.startsWith("data:image/")) return;
    setPreviews((prev) => ({
      // One stored frame per key, each publish replaces the last.
      ...prev,
      [ev.key]: {
        sessionId: typeof ev.sessionId === "string" ? ev.sessionId : "",
        dataUrl: ev.dataUrl,
        width: num(ev.width),
        height: num(ev.height),
      },
    }));
  }, []);

  useEffect(() => {
    let cancelled = false;
    const unlisteners: Array<() => void> = [];
    const hook = <T,>(event: string, handler: (payload: T) => void): void => {
      void safeListen<T>(event, (payload) => {
        if (!cancelled) handler(payload);
      }).then((fn) => {
        if (cancelled) fn();
        else unlisteners.push(fn);
      });
    };
    hook<SessionsEventPayload>(SESSIONS_EVENT, onEvent);
    hook<SessionsStatsPayload>(SESSIONS_STATS_EVENT, onStats);
    hook<PreviewPayload>(PREVIEW_EVENT, onPreview);

    // Seed with whatever is already connected (this window may have been
    // reopened mid-session). The command lands with the Rust side of this
    // feature; until then the safeInvoke fallback is just an empty seed.
    void safeInvoke<ActiveSessionRow[]>("list_active_sessions", undefined, []).then((rows) => {
      if (cancelled || !Array.isArray(rows)) return;
      setSessions((prev) => {
        let next = prev;
        for (const row of rows) {
          if (!row || typeof row.sessionId !== "string" || !row.sessionId) continue;
          if (next[row.sessionId]) continue; // an event got here first, keep it
          if (next === prev) next = { ...prev };
          next[row.sessionId] = blankSession(row, "connected");
        }
        return next;
      });
    });

    return () => {
      cancelled = true;
      for (const fn of unlisteners) fn();
    };
  }, [onEvent, onStats, onPreview]);

  // ------------------------------------------------------------- staleness

  // Freshness is judged at read time, so a session whose stats stop (window
  // closing, backend hiccup) needs a re-render to actually disappear from the
  // tiles. Tick only while a fresh→stale transition is still possible; once
  // everything is stale there is nothing left to hide.
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;
  const [staleTick, setStaleTick] = useState(0);
  useEffect(() => {
    const iv = window.setInterval(() => {
      const now = Date.now();
      const pending = Object.values(sessionsRef.current).some(
        (s) => s.lastStatsAt > 0 && now - s.lastStatsAt <= STALE_MS + 1500,
      );
      if (pending) setStaleTick((t) => t + 1);
    }, 1000);
    return () => window.clearInterval(iv);
  }, []);

  // -------------------------------------------------------------- lookups

  const forKey = useCallback(
    (key: string): TileActivity => {
      if (!key) return EMPTY_ACTIVITY;
      // More than one session can map to one key (the "several windows per
      // computer" preference); the one with the newest stats speaks for the tile.
      let best: LiveSession | null = null;
      for (const s of Object.values(sessions)) {
        if (sessionKeyOf(s) !== key) continue;
        if (!best || s.lastStatsAt > best.lastStatsAt) best = s;
      }
      const now = Date.now();
      let bandwidth: TileActivity["bandwidth"] = null;
      if (best && best.latest && now - best.lastStatsAt <= STALE_MS) {
        bandwidth = { rx: best.latest.rx, tx: best.latest.tx, samples: best.samples };
      }
      // A preview is only live while its session still exists, `ended` (and
      // the guard here, for a missed event) keeps closed sessions off tiles.
      const frame = best ? previews[key] : undefined;
      const preview = frame
        ? { dataUrl: frame.dataUrl, width: frame.width, height: frame.height }
        : null;
      return bandwidth || preview ? { bandwidth, preview } : EMPTY_ACTIVITY;
    },
    // `staleTick` is not read in the body, it exists to re-evaluate the
    // Date.now() freshness checks above after stats stop arriving.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sessions, previews, staleTick],
  );

  const value = useMemo(
    () => ({ forKey, livePreviews, setLivePreviews }),
    [forKey, livePreviews, setLivePreviews],
  );

  return <SessionsContext.Provider value={value}>{children}</SessionsContext.Provider>;
}

export function useSessions(): SessionsContextValue {
  const ctx = useContext(SessionsContext);
  if (!ctx) throw new Error("useSessions outside SessionsProvider");
  return ctx;
}
