/**
 * File-transfer state for one session (PRD/08).
 *
 * Owns the SFTP sidecar connection, both panes' listings, and the transfer
 * queue. Progress arrives on `files://event` at ~10 Hz per transfer (Rust
 * throttles it), so keeping it in React state is cheap, unlike framebuffer
 * data, which never touches React at all.
 *
 * SECURITY: `path` and `name` on a `RemoteEntry` are server-supplied. This
 * hook only ever passes them straight back to Rust, which normalises and
 * rejects traversal; it never builds a local path from them.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  filesCancel,
  filesConnect,
  filesDisconnect,
  filesDownload,
  filesList,
  filesLocalHome,
  filesLocalList,
  filesLocalMkdir,
  filesLocalRemove,
  filesLocalRename,
  filesMkdir,
  filesRemove,
  filesRename,
  filesUpload,
  listenFiles,
  type FilesConnectConfig,
  type FilesConnectOutcome,
  type FilesEventPayload,
  type LocalEntry,
  type RemoteEntry,
} from "../lib/tauri";

export type SortKey = "name" | "size" | "date";
export type Pane = "local" | "remote";

/** A row in either pane, normalised so one renderer handles both. */
export interface PaneEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modified: number | null;
  isSymlink: boolean;
}

export interface PaneState {
  path: string;
  entries: PaneEntry[];
  loading: boolean;
  error: string | null;
  selected: string[];
  sort: SortKey;
  sortAsc: boolean;
  showHidden: boolean;
}

/** One row of the transfer queue / completed log. */
export interface Transfer {
  id: string;
  name: string;
  direction: "upload" | "download";
  total: number;
  transferred: number;
  bytesPerSec: number;
  state: "running" | "completed" | "failed" | "cancelled";
  error: string | null;
  startedAt: number;
  endedAt: number | null;
}

export type FilesConnState =
  | { state: "idle" }
  | { state: "connecting" }
  | { state: "connected"; host: string; username: string; home: string }
  | { state: "host-key-prompt"; host: string; port: number; keyType: string; fingerprint: string }
  | { state: "host-key-changed"; host: string; port: number; expected: string; actual: string }
  | { state: "error"; message: string };

export interface FilesApi {
  conn: FilesConnState;
  local: PaneState;
  remote: PaneState;
  transfers: Transfer[];
  /** Transfers that are still moving bytes. */
  active: Transfer[];
  connect: (config: FilesConnectConfig, acceptHostKey?: string) => Promise<void>;
  /** Re-run the last connect, pinning the fingerprint the user just accepted. */
  acceptHostKey: (fingerprint: string) => void;
  disconnect: () => void;
  navigate: (pane: Pane, path: string) => void;
  goUp: (pane: Pane) => void;
  refresh: (pane: Pane) => void;
  setSelection: (pane: Pane, paths: string[]) => void;
  setSort: (pane: Pane, key: SortKey) => void;
  setShowHidden: (pane: Pane, show: boolean) => void;
  upload: (localPaths: string[], remoteDir?: string) => Promise<void>;
  download: (remotePaths: string[], localDir?: string) => Promise<void>;
  mkdir: (pane: Pane, name: string) => Promise<void>;
  rename: (pane: Pane, from: string, newName: string) => Promise<void>;
  remove: (pane: Pane, paths: string[]) => Promise<void>;
  cancel: (transferId: string) => void;
  clearFinished: () => void;
}

const emptyPane = (sort: SortKey = "name"): PaneState => ({
  path: "",
  entries: [],
  loading: false,
  error: null,
  selected: [],
  sort,
  sortAsc: true,
  showHidden: false,
});

/** POSIX-ish parent of a path, for the ".." / Backspace action. */
export function parentDir(path: string): string {
  if (!path) return path;
  const sep = path.includes("\\") && !path.startsWith("/") ? "\\" : "/";
  const trimmed = path.length > 1 ? path.replace(/[/\\]+$/, "") : path;
  const cut = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  if (cut < 0) return trimmed;
  if (cut === 0) return sep === "/" ? "/" : trimmed;
  return trimmed.slice(0, cut);
}

/** Join a directory with a child name using the directory's own separator. */
export function joinPath(dir: string, name: string): string {
  if (!dir) return name;
  const sep = dir.includes("\\") && !dir.startsWith("/") ? "\\" : "/";
  return dir.endsWith(sep) ? `${dir}${name}` : `${dir}${sep}${name}`;
}

/** Breadcrumb segments: [label, path] pairs, root first. */
export function breadcrumbs(path: string): Array<{ label: string; path: string }> {
  if (!path) return [];
  const win = /^[A-Za-z]:/.test(path);
  const sep = win ? "\\" : "/";
  const parts = path.split(/[/\\]+/).filter((p) => p.length > 0);
  const out: Array<{ label: string; path: string }> = [];
  let acc = win ? "" : "";
  if (!win) out.push({ label: "/", path: "/" });
  parts.forEach((part, i) => {
    acc = i === 0 && win ? part : `${acc}${sep}${part}`;
    out.push({ label: part, path: win ? acc : acc });
  });
  return out;
}

export function sortEntries(entries: PaneEntry[], key: SortKey, asc: boolean): PaneEntry[] {
  const dir = asc ? 1 : -1;
  return [...entries].sort((a, b) => {
    // Directories always lead, whatever the sort, the universal file-manager
    // convention; sorting them among files makes navigation miserable.
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    switch (key) {
      case "size":
        return (a.size - b.size) * dir;
      case "date":
        return ((a.modified ?? 0) - (b.modified ?? 0)) * dir;
      default:
        return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }) * dir;
    }
  });
}

export function isHidden(name: string): boolean {
  return name.startsWith(".");
}

const toPaneEntry = (e: RemoteEntry | LocalEntry): PaneEntry => ({
  name: e.name,
  path: e.path,
  isDir: e.isDir,
  size: e.size,
  modified: e.modified,
  isSymlink: e.isSymlink,
});

export function useFiles(sessionId: string, enabled: boolean): FilesApi {
  const [conn, setConn] = useState<FilesConnState>({ state: "idle" });
  const [local, setLocal] = useState<PaneState>(emptyPane());
  const [remote, setRemote] = useState<PaneState>(emptyPane());
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const connected = conn.state === "connected";
  const connectedRef = useRef(false);
  /** Last config passed to `connect`, so a TOFU accept can retry it verbatim. */
  const lastConfig = useRef<FilesConnectConfig | null>(null);
  connectedRef.current = connected;

  // --------------------------------------------------------------- events

  useEffect(() => {
    if (!enabled) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void listenFiles((ev: FilesEventPayload) => {
      if (cancelled) return;
      if (ev.sessionId && ev.sessionId !== sessionId) return;
      setTransfers((prev) => applyEvent(prev, ev));
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [enabled, sessionId]);

  // A finished transfer changes the remote (or local) directory: refresh the
  // affected pane once things go quiet rather than on every event.
  const settledCount = transfers.filter((t) => t.state !== "running").length;
  const runningCount = transfers.length - settledCount;

  // ------------------------------------------------------------- listings

  const loadLocal = useCallback(async (path: string): Promise<void> => {
    setLocal((p) => ({ ...p, loading: true, error: null }));
    try {
      const entries = await filesLocalList(path || null);
      setLocal((p) => ({
        ...p,
        path: path || p.path,
        entries: entries.map(toPaneEntry),
        loading: false,
        error: null,
        selected: [],
      }));
    } catch (err) {
      setLocal((p) => ({ ...p, loading: false, error: describe(err) }));
    }
  }, []);

  const loadRemote = useCallback(
    async (path: string): Promise<void> => {
      if (!connectedRef.current) return;
      setRemote((p) => ({ ...p, loading: true, error: null }));
      try {
        const entries = await filesList(sessionId, path);
        setRemote((p) => ({
          ...p,
          path,
          entries: entries.map(toPaneEntry),
          loading: false,
          error: null,
          selected: [],
        }));
      } catch (err) {
        setRemote((p) => ({ ...p, loading: false, error: describe(err) }));
      }
    },
    [sessionId],
  );

  // Open the local pane at $HOME as soon as the panel is used.
  useEffect(() => {
    if (!enabled || local.path) return;
    void (async () => {
      const home = await filesLocalHome();
      await loadLocal(home);
    })();
  }, [enabled, local.path, loadLocal]);

  // ------------------------------------------------------------- connect

  const connect = useCallback(
    async (config: FilesConnectConfig, acceptHostKey?: string): Promise<void> => {
      lastConfig.current = config;
      setConn({ state: "connecting" });
      try {
        const outcome: FilesConnectOutcome = await filesConnect(sessionId, config, acceptHostKey);
        switch (outcome.status) {
          case "connected":
            connectedRef.current = true;
            setConn({
              state: "connected",
              host: outcome.host,
              username: outcome.username,
              home: outcome.home,
            });
            await loadRemote(config.defaultRemoteDir || outcome.home);
            break;
          case "host-key-prompt":
            setConn({
              state: "host-key-prompt",
              host: outcome.host,
              port: outcome.port,
              keyType: outcome.keyType,
              fingerprint: outcome.fingerprint,
            });
            break;
          case "host-key-changed":
            setConn({
              state: "host-key-changed",
              host: outcome.host,
              port: outcome.port,
              expected: outcome.expected,
              actual: outcome.actual,
            });
            break;
        }
      } catch (err) {
        setConn({ state: "error", message: describe(err) });
      }
    },
    [sessionId, loadRemote],
  );

  const acceptHostKey = useCallback(
    (fingerprint: string): void => {
      const config = lastConfig.current;
      if (config) void connect(config, fingerprint);
    },
    [connect],
  );

  const disconnect = useCallback((): void => {
    connectedRef.current = false;
    void filesDisconnect(sessionId);
    setConn({ state: "idle" });
    setRemote(emptyPane());
  }, [sessionId]);

  // ------------------------------------------------------------- actions

  const refresh = useCallback(
    (pane: Pane): void => {
      if (pane === "local") void loadLocal(local.path);
      else void loadRemote(remote.path);
    },
    [loadLocal, loadRemote, local.path, remote.path],
  );

  // Refresh once every transfer has settled, so the destination pane shows
  // what actually landed.
  const prevRunning = useRef(0);
  useEffect(() => {
    if (prevRunning.current > 0 && runningCount === 0) {
      if (local.path) void loadLocal(local.path);
      if (remote.path) void loadRemote(remote.path);
    }
    prevRunning.current = runningCount;
  }, [runningCount, local.path, remote.path, loadLocal, loadRemote]);

  const navigate = useCallback(
    (pane: Pane, path: string): void => {
      if (pane === "local") void loadLocal(path);
      else void loadRemote(path);
    },
    [loadLocal, loadRemote],
  );

  const goUp = useCallback(
    (pane: Pane): void => {
      const current = pane === "local" ? local.path : remote.path;
      const up = parentDir(current);
      if (up && up !== current) navigate(pane, up);
    },
    [local.path, remote.path, navigate],
  );

  const setSelection = useCallback((pane: Pane, paths: string[]): void => {
    const update = (p: PaneState): PaneState => ({ ...p, selected: paths });
    if (pane === "local") setLocal(update);
    else setRemote(update);
  }, []);

  const setSort = useCallback((pane: Pane, key: SortKey): void => {
    const update = (p: PaneState): PaneState =>
      p.sort === key ? { ...p, sortAsc: !p.sortAsc } : { ...p, sort: key, sortAsc: true };
    if (pane === "local") setLocal(update);
    else setRemote(update);
  }, []);

  const setShowHidden = useCallback((pane: Pane, show: boolean): void => {
    const update = (p: PaneState): PaneState => ({ ...p, showHidden: show });
    if (pane === "local") setLocal(update);
    else setRemote(update);
  }, []);

  const upload = useCallback(
    async (localPaths: string[], remoteDir?: string): Promise<void> => {
      const dir = remoteDir || remote.path;
      if (!connectedRef.current || localPaths.length === 0 || !dir) return;
      try {
        await filesUpload(sessionId, localPaths, dir);
      } catch (err) {
        setRemote((p) => ({ ...p, error: describe(err) }));
      }
    },
    [sessionId, remote.path],
  );

  const download = useCallback(
    async (remotePaths: string[], localDir?: string): Promise<void> => {
      const dir = localDir || local.path;
      if (!connectedRef.current || remotePaths.length === 0 || !dir) return;
      try {
        await filesDownload(sessionId, remotePaths, dir);
      } catch (err) {
        setLocal((p) => ({ ...p, error: describe(err) }));
      }
    },
    [sessionId, local.path],
  );

  const mkdir = useCallback(
    async (pane: Pane, name: string): Promise<void> => {
      const dir = pane === "local" ? local.path : remote.path;
      const target = joinPath(dir, name);
      try {
        if (pane === "local") {
          await filesLocalMkdir(target);
          await loadLocal(dir);
        } else {
          await filesMkdir(sessionId, target);
          await loadRemote(dir);
        }
      } catch (err) {
        const update = (p: PaneState): PaneState => ({ ...p, error: describe(err) });
        if (pane === "local") setLocal(update);
        else setRemote(update);
      }
    },
    [sessionId, local.path, remote.path, loadLocal, loadRemote],
  );

  const rename = useCallback(
    async (pane: Pane, from: string, newName: string): Promise<void> => {
      const dir = parentDir(from);
      const to = joinPath(dir, newName);
      if (to === from) return;
      try {
        if (pane === "local") {
          await filesLocalRename(from, to);
          await loadLocal(local.path);
        } else {
          await filesRename(sessionId, from, to);
          await loadRemote(remote.path);
        }
      } catch (err) {
        const update = (p: PaneState): PaneState => ({ ...p, error: describe(err) });
        if (pane === "local") setLocal(update);
        else setRemote(update);
      }
    },
    [sessionId, local.path, remote.path, loadLocal, loadRemote],
  );

  const remove = useCallback(
    async (pane: Pane, paths: string[]): Promise<void> => {
      try {
        for (const path of paths) {
          if (pane === "local") await filesLocalRemove(path, true);
          else await filesRemove(sessionId, path, true);
        }
        if (pane === "local") await loadLocal(local.path);
        else await loadRemote(remote.path);
      } catch (err) {
        const update = (p: PaneState): PaneState => ({ ...p, error: describe(err) });
        if (pane === "local") setLocal(update);
        else setRemote(update);
      }
    },
    [sessionId, local.path, remote.path, loadLocal, loadRemote],
  );

  const cancel = useCallback(
    (transferId: string): void => {
      void filesCancel(sessionId, transferId);
    },
    [sessionId],
  );

  const clearFinished = useCallback((): void => {
    setTransfers((prev) => prev.filter((t) => t.state === "running"));
  }, []);

  const active = useMemo(() => transfers.filter((t) => t.state === "running"), [transfers]);

  return {
    conn,
    local,
    remote,
    transfers,
    active,
    connect,
    acceptHostKey,
    disconnect,
    navigate,
    goUp,
    refresh,
    setSelection,
    setSort,
    setShowHidden,
    upload,
    download,
    mkdir,
    rename,
    remove,
    cancel,
    clearFinished,
  };
}

/** Reduce one `files://event` into the queue. Exported for tests. */
export function applyEvent(prev: Transfer[], ev: FilesEventPayload): Transfer[] {
  switch (ev.type) {
    case "started": {
      const row: Transfer = {
        id: ev.id,
        name: ev.name,
        direction: ev.direction,
        total: ev.total,
        transferred: 0,
        bytesPerSec: 0,
        state: "running",
        error: null,
        startedAt: Date.now(),
        endedAt: null,
      };
      return [row, ...prev.filter((t) => t.id !== ev.id)];
    }
    case "progress":
      return prev.map((t) =>
        t.id === ev.id
          ? { ...t, transferred: ev.transferred, total: ev.total, bytesPerSec: ev.bytesPerSec }
          : t,
      );
    case "completed":
      return prev.map((t) =>
        t.id === ev.id
          ? { ...t, state: "completed", transferred: t.total, endedAt: Date.now() }
          : t,
      );
    case "failed":
      return prev.map((t) =>
        t.id === ev.id ? { ...t, state: "failed", error: ev.error, endedAt: Date.now() } : t,
      );
    case "cancelled":
      return prev.map((t) =>
        t.id === ev.id ? { ...t, state: "cancelled", endedAt: Date.now() } : t,
      );
    default:
      return prev;
  }
}

function describe(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return String(err);
}
