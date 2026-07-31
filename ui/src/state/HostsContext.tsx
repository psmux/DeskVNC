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
import { blankHostProfile, type HostGroup, type HostProfile, type HostTag } from "../lib/types";
import { inTauri, safeInvoke, safeListen } from "../lib/tauri";
import {
  MOCK_GROUPS,
  MOCK_HOSTS,
  MOCK_TAGS,
  MOCK_THUMBNAIL_EVENT,
  mockThumbnail,
  useMockData,
  withMockThumbnails,
  type ThumbnailUpdate,
} from "../lib/mock";

/**
 * Broadcast by the shell after `capture_thumbnail` writes a PNG (see
 * `src-tauri/src/thumbnail.rs`). The session that captured it lives in a
 * different window, so this is the only way the Library hears about it.
 */
const THUMBNAIL_EVENT = "library://thumbnail";

/**
 * Session lifecycle broadcast (`src-tauri/src/commands/session.rs`). The
 * Library only cares about one of its payloads: `host-adopted`, sent when a
 * quick connect that ticked "remember this password" gained a host profile,
 * because the password had nowhere else to live. That host was created in
 * another window's session, so this is the only way the tile appears without
 * the user reopening the Library.
 */
const SESSIONS_EVENT = "sessions://event";

interface SessionsEvent {
  type?: string;
}

interface HostsContextValue {
  hosts: HostProfile[];
  groups: HostGroup[];
  tags: HostTag[];
  loading: boolean;
  refresh: () => Promise<void>;
  saveHost: (host: Partial<HostProfile> & { id?: string }) => Promise<HostProfile | null>;
  deleteHost: (id: string) => Promise<void>;
  saveGroup: (group: Partial<HostGroup> & { name: string }) => Promise<void>;
  deleteGroup: (id: string) => Promise<void>;
  saveTag: (tag: Partial<HostTag> & { name: string }) => Promise<void>;
  deleteTag: (id: string) => Promise<void>;
  setHostTags: (hostId: string, tagIds: string[]) => Promise<void>;
  savePassword: (hostId: string, password: string) => Promise<void>;
  deletePassword: (hostId: string) => Promise<void>;
  wakeHost: (hostId: string) => Promise<void>;
  /**
   * blob: URL for a thumbnail, or null.
   *
   * The key is a host id for a saved profile and `discovered:<address>:<port>`
   * for a machine connected to straight from the Nearby list, the store keys
   * the PNG file the same way, and neither side consults the `hosts` table.
   */
  thumbnailUrl: (key: string) => string | null;
  requestThumbnail: (key: string) => void;
  /** Drop one cached thumbnail and re-read it from the store. */
  refreshThumbnail: (key: string) => void;
}

const HostsContext = createContext<HostsContextValue | null>(null);

/** Mock thumbnails are `data:` URLs; only the real PNG blobs need revoking. */
function revokeThumb(url: string | null | undefined): void {
  if (url && url.startsWith("blob:")) URL.revokeObjectURL(url);
}

export function HostsProvider({ children }: { children: ReactNode }): ReactNode {
  const mock = useMockData();
  const [hosts, setHosts] = useState<HostProfile[]>([]);
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [tags, setTags] = useState<HostTag[]>([]);
  const [loading, setLoading] = useState(true);
  /**
   * Tile images live in React state, NOT a ref: a ref plus a bump counter left
   * outside the context value never reaches the tiles, because re-rendering
   * this provider with an unchanged `children` element and an unchanged
   * context value is a React bailout, the fetched thumbnail was cached and
   * then silently never painted.
   *
   * A host present as a key has been resolved (`null` = "no thumbnail");
   * absent means "not fetched yet".
   */
  const [thumbs, setThumbs] = useState<Record<string, string | null>>({});
  /** Hosts already resolved or in flight, keeps `requestThumbnail` stable. */
  const thumbKnown = useRef(new Set<string>());
  const thumbPending = useRef(new Set<string>());
  /** Bumped on invalidation so a slow in-flight fetch cannot overwrite a newer one. */
  const thumbGeneration = useRef(new Map<string, number>());
  /** False once this provider is gone: a late fetch must not leak a blob URL. */
  const mounted = useRef(true);

  /** Store one resolved thumbnail, revoking whatever it replaces. */
  const putThumb = useCallback((key: string, url: string | null): void => {
    setThumbs((prev) => {
      const old = prev[key];
      if (old && old !== url) revokeThumb(old);
      return { ...prev, [key]: url };
    });
  }, []);

  const requestThumbnail = useCallback(
    (key: string): void => {
      if (!key || thumbKnown.current.has(key) || thumbPending.current.has(key)) return;
      thumbKnown.current.add(key);
      if (!inTauri()) {
        // Browser dev: whatever the mock session captured, if anything.
        putThumb(key, mockThumbnail(key)?.url ?? null);
        return;
      }
      const generation = thumbGeneration.current.get(key) ?? 0;
      thumbPending.current.add(key);
      // NB: `get_thumbnail` reads `thumbnails/<key>.png` directly, it does not
      // look the key up in the hosts table, which is what lets a discovered
      // endpoint have a tile image without ever being saved.
      void safeInvoke<ArrayBuffer | number[] | null>("get_thumbnail", { hostId: key }, null).then(
        (data) => {
          thumbPending.current.delete(key);
          let url: string | null = null;
          if (data) {
            const bytes =
              data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data);
            if (bytes.byteLength > 0) {
              url = URL.createObjectURL(
                new Blob([bytes.buffer as ArrayBuffer], { type: "image/png" }),
              );
            }
          }
          // A newer capture landed while this read was in flight, or the
          // window went away, either way the blob must not survive us.
          if (!mounted.current || (thumbGeneration.current.get(key) ?? 0) !== generation) {
            revokeThumb(url);
            return;
          }
          putThumb(key, url);
        },
      );
    },
    [putThumb],
  );

  /** Drop one cached thumbnail and read it back from the store. */
  const refreshThumbnail = useCallback(
    (key: string): void => {
      thumbGeneration.current.set(key, (thumbGeneration.current.get(key) ?? 0) + 1);
      thumbKnown.current.delete(key);
      thumbPending.current.delete(key);
      requestThumbnail(key);
    },
    [requestThumbnail],
  );

  /** Forget a thumbnail entirely (its host is gone), releasing the blob. */
  const forgetThumbnail = useCallback((key: string): void => {
    thumbGeneration.current.set(key, (thumbGeneration.current.get(key) ?? 0) + 1);
    thumbKnown.current.delete(key);
    thumbPending.current.delete(key);
    setThumbs((prev) => {
      if (!(key in prev)) return prev;
      revokeThumb(prev[key]);
      const next = { ...prev };
      delete next[key];
      return next;
    });
  }, []);

  /**
   * Re-read every thumbnail we already hold, keeping the current image on
   * screen until its replacement arrives.
   *
   * This deliberately does NOT clear the cache first. Dropping the blob URLs
   * and waiting for the tiles to ask again does not work: a tile only asks
   * from an effect keyed on the host, and reloading the host list produces the
   * same key, so React never re-runs it, and every tile in the library went
   * blank until the window was reopened. That is the "thumbnails aren't
   * remembered" report: the picture survived on disk, the screen did not.
   */
  const revalidateThumbnails = useCallback((): void => {
    for (const key of [...thumbKnown.current]) refreshThumbnail(key);
  }, [refreshThumbnail]);

  const refresh = useCallback(async (): Promise<void> => {
    revalidateThumbnails();
    if (mock) {
      setHosts(withMockThumbnails(MOCK_HOSTS));
      setGroups(MOCK_GROUPS);
      setTags(MOCK_TAGS);
      setLoading(false);
      return;
    }
    const [h, g, t] = await Promise.all([
      safeInvoke<HostProfile[]>("list_hosts", undefined, []),
      safeInvoke<HostGroup[]>("list_groups", undefined, []),
      safeInvoke<HostTag[]>("list_tags", undefined, []),
    ]);
    setHosts(Array.isArray(h) ? h : []);
    setGroups(Array.isArray(g) ? g : []);
    setTags(Array.isArray(t) ? t : []);
    setLoading(false);
  }, [mock, revalidateThumbnails]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Latest host list, for callbacks that must not change identity with it. */
  const hostsRef = useRef(hosts);
  hostsRef.current = hosts;

  const saveHost = useCallback(
    async (host: Partial<HostProfile> & { id?: string }): Promise<HostProfile | null> => {
      // `save_host` deserializes a COMPLETE vnc_store::HostProfile and upserts
      // every column, so a partial patch would not merely be rejected, the
      // missing fields would be written as blanks. Fill in from the profile
      // we already hold (the edit dialog knows nothing about `thumbnailAt`,
      // `lastConnected` or `connectCount`; renaming a host must not erase its
      // picture and its history), falling back to a blank for a new host.
      const existing = host.id ? hostsRef.current.find((h) => h.id === host.id) : undefined;
      const full: HostProfile = {
        ...(existing ?? blankHostProfile()),
        ...host,
        // The id doubles as the keyring account key on the Rust side, so a
        // new host gets a real uuid rather than a timestamp.
        id: host.id || crypto.randomUUID(),
      };
      if (mock || !inTauri()) {
        setHosts((prev) => {
          const i = prev.findIndex((p) => p.id === full.id);
          if (i >= 0) {
            const next = prev.slice();
            next[i] = { ...prev[i], ...full };
            return next;
          }
          return [...prev, full];
        });
        return full;
      }
      // UI-local fields are not columns on the Rust struct; drop them so the
      // payload is exactly the backend contract.
      const { favorite: _favorite, online: _online, ...profile } = full;
      const saved = await safeInvoke<HostProfile | null>("save_host", { profile }, null);
      await refresh();
      return saved;
    },
    [mock, refresh],
  );

  const deleteHost = useCallback(
    async (id: string): Promise<void> => {
      // `delete_host` also removes the PNG, so drop the cached blob rather
      // than let it linger for a host that no longer exists.
      forgetThumbnail(id);
      if (mock) {
        setHosts((prev) => prev.filter((h) => h.id !== id));
        return;
      }
      await safeInvoke("delete_host", { hostId: id }, null);
      await refresh();
    },
    [mock, refresh, forgetThumbnail],
  );

  const saveGroup = useCallback(
    async (group: Partial<HostGroup> & { name: string }): Promise<void> => {
      if (mock) {
        setGroups((prev) => [
          ...prev,
          { id: `g-${Date.now()}`, name: group.name, parentId: group.parentId ?? null, sort: prev.length },
        ]);
        return;
      }
      await safeInvoke("save_group", { group }, null);
      await refresh();
    },
    [mock, refresh],
  );

  const deleteGroup = useCallback(
    async (id: string): Promise<void> => {
      await safeInvoke("delete_group", { groupId: id }, null);
      await refresh();
    },
    [refresh],
  );

  const saveTag = useCallback(
    async (tag: Partial<HostTag> & { name: string }): Promise<void> => {
      if (mock) {
        setTags((prev) => [
          ...prev,
          { id: `t-${Date.now()}`, name: tag.name, color: tag.color ?? "#4f8ef7" },
        ]);
        return;
      }
      await safeInvoke("save_tag", { tag }, null);
      await refresh();
    },
    [mock, refresh],
  );

  const deleteTag = useCallback(
    async (id: string): Promise<void> => {
      await safeInvoke("delete_tag", { tagId: id }, null);
      await refresh();
    },
    [refresh],
  );

  const setHostTags = useCallback(
    async (hostId: string, tagIds: string[]): Promise<void> => {
      if (mock) {
        setHosts((prev) => prev.map((h) => (h.id === hostId ? { ...h, tags: tagIds } : h)));
        return;
      }
      await safeInvoke("set_host_tags", { hostId, tagIds }, null);
      await refresh();
    },
    [mock, refresh],
  );

  const savePassword = useCallback(
    async (hostId: string, password: string): Promise<void> => {
      await safeInvoke("save_password", { hostId, creds: { vncPassword: password } }, null);
      setHosts((prev) => prev.map((h) => (h.id === hostId ? { ...h, hasPassword: true } : h)));
    },
    [],
  );

  const deletePassword = useCallback(
    async (hostId: string): Promise<void> => {
      await safeInvoke("delete_password", { hostId }, null);
      setHosts((prev) => prev.map((h) => (h.id === hostId ? { ...h, hasPassword: false } : h)));
    },
    [],
  );

  const wakeHost = useCallback(async (hostId: string): Promise<void> => {
    await safeInvoke("wake_host", { profileId: hostId }, null);
  }, []);

  const thumbnailUrl = useCallback((key: string): string | null => thumbs[key] ?? null, [thumbs]);

  /**
   * A session in another window just stored a fresh screenshot (PRD/03 §3.1:
   * on connect, and again on the way out). Without this the tile keeps showing
   * whatever it read at startup, or the colour-hash placeholder, until the
   * app is restarted.
   */
  useEffect(() => {
    const onUpdate = (ev: ThumbnailUpdate | undefined): void => {
      if (!ev || typeof ev.hostId !== "string" || !ev.hostId) return;
      // Keep the in-memory profile in step with the column the store just
      // wrote. `hostId` is a `discovered:` key for an ad-hoc session, which
      // matches no profile, the re-read below is what puts the picture on
      // that tile, and it does not care whether the host is saved.
      setHosts((prev) =>
        prev.map((h) => (h.id === ev.hostId ? { ...h, thumbnailAt: ev.capturedAt } : h)),
      );
      refreshThumbnail(ev.hostId);
    };

    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void safeListen<ThumbnailUpdate>(THUMBNAIL_EVENT, onUpdate).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });

    // Browser dev: the mock session dispatches the same payload on the window.
    const onMock = (e: Event): void => onUpdate((e as CustomEvent<ThumbnailUpdate>).detail);
    window.addEventListener(MOCK_THUMBNAIL_EVENT, onMock);
    return () => {
      cancelled = true;
      unlisten?.();
      window.removeEventListener(MOCK_THUMBNAIL_EVENT, onMock);
    };
  }, [refreshThumbnail]);

  /** A session just turned itself into a saved host: re-read the list. */
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void safeListen<SessionsEvent>(SESSIONS_EVENT, (ev) => {
      if (cancelled || ev?.type !== "host-adopted") return;
      void refresh();
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [refresh]);

  // Unmount: release every blob: URL still held.
  const thumbsRef = useRef(thumbs);
  thumbsRef.current = thumbs;
  useEffect(() => {
    // Re-armed on mount: StrictMode's dev remount runs the cleanup below once
    // before the real mount, and a permanently false flag would then throw
    // away every thumbnail fetched afterwards.
    mounted.current = true;
    return () => {
      mounted.current = false;
      for (const url of Object.values(thumbsRef.current)) revokeThumb(url);
    };
  }, []);

  const value = useMemo(
    () => ({
      hosts, groups, tags, loading, refresh, saveHost, deleteHost, saveGroup,
      deleteGroup, saveTag, deleteTag, setHostTags, savePassword, deletePassword,
      wakeHost, thumbnailUrl, requestThumbnail, refreshThumbnail,
    }),
    [
      hosts, groups, tags, loading, refresh, saveHost, deleteHost, saveGroup,
      deleteGroup, saveTag, deleteTag, setHostTags, savePassword, deletePassword,
      wakeHost, thumbnailUrl, requestThumbnail, refreshThumbnail,
    ],
  );

  return <HostsContext.Provider value={value}>{children}</HostsContext.Provider>;
}

export function useHosts(): HostsContextValue {
  const ctx = useContext(HostsContext);
  if (!ctx) throw new Error("useHosts outside HostsProvider");
  return ctx;
}
