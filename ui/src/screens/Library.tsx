/** The Library, home surface (PRD/03 §2, PRD/11 §3.1). */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import { useHosts } from "../state/HostsContext";
import { useDiscovery } from "../state/DiscoveryContext";
import { useSettings, MAX_QUICK_CONNECT_HISTORY, type SortKey } from "../state/SettingsContext";
import { useToasts } from "../state/ToastContext";
import type { DiscoveredHost, HostProfile } from "../lib/types";
import { hostMac, resolvedOsHint } from "../lib/types";
import { allowsMultipleSessions, inTauri, openSessionWindow, safeInvoke, safeListen, forgetCertificate } from "../lib/tauri";
import { seedMockThumbnails, useMockData } from "../lib/mock";
import { useSessions } from "../state/SessionsContext";
import { classNames, formatBps, fuzzyMatch, modKeyLabel, timeAgo } from "../lib/util";
import { Sidebar, type SidebarSelection } from "../components/Sidebar";
import { HostTile, DiscoveredTile, osLabel } from "../components/HostTile";
import { CommandPalette, type PaletteAction } from "../components/CommandPalette";
import { HostDialog, draftFromHost, type HostDraft } from "../components/HostDialog";
import { QuickConnect } from "../components/QuickConnect";
import { ContextMenu, Dialog, EmptyState, Select, TileSkeleton, type MenuItem } from "../components/primitives";
import {
  IconActivity,
  IconGrid,
  IconList,
  IconMonitor,
  IconPlus,
  IconSearch,
  IconZap,
} from "../components/icons";

interface CtxMenuState {
  x: number;
  y: number;
  host: HostProfile;
}

/**
 * `.host-grid` uses `auto-fit`, so a two-host library would otherwise stretch
 * those two tiles across the whole window. Capping the grid's width at
 * "how wide N tiles are allowed to be" keeps tiles at a sane size while still
 * letting them fill the content area as soon as there are enough of them.
 */
const TILE_MAX_WIDTH = { normal: 440, compact: 320 };
const TILE_GAP = { normal: 16, compact: 12 };

function gridCap(count: number, compact: boolean): CSSProperties | undefined {
  if (count <= 0) return undefined;
  const density = compact ? "compact" : "normal";
  return { maxWidth: count * TILE_MAX_WIDTH[density] + (count - 1) * TILE_GAP[density] };
}

export function Library({
  onOpenPreferences,
  onOpenAbout,
  autoAddDiscoveredId = null,
  onAutoAddHandled,
}: {
  onOpenPreferences: () => void;
  onOpenAbout: () => void;
  autoAddDiscoveredId?: string | null;
  onAutoAddHandled?: () => void;
}): ReactNode {
  const { hosts, groups, tags, loading, saveHost, deleteHost, saveGroup, saveTag, setHostTags, savePassword, wakeHost, refresh, refreshThumbnail } = useHosts();
  const { discovered, scan, startScan } = useDiscovery();
  const { settings, update } = useSettings();
  const { livePreviews, setLivePreviews } = useSessions();
  const { push } = useToasts();

  const [selection, setSelection] = useState<SidebarSelection>({ kind: "all" });
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [hostDialog, setHostDialog] = useState<HostDraft | null>(null);
  const [ctxMenu, setCtxMenu] = useState<CtxMenuState | null>(null);
  const [activeTagIds, setActiveTagIds] = useState<Set<string>>(new Set());
  const [tagMode, setTagMode] = useState<"and" | "or">("or");
  const [namePrompt, setNamePrompt] = useState<"group" | "tag" | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const quickConnectRef = useRef<HTMLInputElement>(null);

  const focusQuickConnect = useCallback((): void => {
    quickConnectRef.current?.focus();
    quickConnectRef.current?.select();
  }, []);

  // ------------------------------------------------------------ connect

  /**
   * One window per computer (unless the preference says otherwise): the shell
   * decides, we only report what it did. `reused` means an already-open
   * session window was raised, nothing new was connected, so the history
   * counter must not be bumped either.
   */
  const connectHost = useCallback(
    (host: HostProfile, forceNew = false): void => {
      if (inTauri()) {
        void openSessionWindow({ profileId: host.id, forceNew }).then((outcome) => {
          if (outcome?.reused) {
            push("info", `${host.friendlyName} is already open, brought it to the front`);
            return;
          }
          void safeInvoke("touch_connected", { hostId: host.id }, null);
        });
      } else {
        // browser dev: open the session screen in-window so it stays explorable.
        // `profileId` rides along exactly as the shell would set it, so the mock
        // session's thumbnail capture attaches to this host.
        window.location.search =
          `?sessionId=dev&profileId=${encodeURIComponent(host.id)}` +
          `&name=${encodeURIComponent(host.friendlyName)}`;
      }
    },
    [push],
  );

  const connectAdHoc = useCallback((address: string, port: number): void => {
    if (inTauri()) {
      void openSessionWindow({ address, port }).then((outcome) => {
        if (outcome?.reused) {
          push("info", `${address} is already open, brought it to the front`);
        }
      });
    } else {
      // Endpoint rides along exactly as the shell sets it: an ad-hoc session
      // is keyed by `discovered:<address>:<port>`, so without it the browser
      // dev session has nothing to attach its capture to.
      window.location.search =
        `?sessionId=dev&address=${encodeURIComponent(address)}&port=${port}` +
        `&name=${encodeURIComponent(address)}`;
    }
  }, [push]);

  /** Most recent first, no duplicates, oldest dropped past the cap. */
  const rememberQuickConnect = useCallback(
    (address: string): void => {
      update({
        quickConnectHistory: [
          address,
          ...settings.quickConnectHistory.filter((a) => a !== address),
        ].slice(0, MAX_QUICK_CONNECT_HISTORY),
      });
    },
    [settings.quickConnectHistory, update],
  );

  // "Connect in new window" only makes sense when the user has allowed more
  // than one window per computer; otherwise it would be a second Connect.
  // Re-read when a menu opens, since Preferences may have changed it since.
  const [allowMultiple, setAllowMultiple] = useState(false);
  const refreshAllowMultiple = useCallback(() => {
    void allowsMultipleSessions().then(setAllowMultiple);
  }, []);
  useEffect(refreshAllowMultiple, [refreshAllowMultiple]);

  const openCtxMenu = useCallback(
    (e: { clientX: number; clientY: number }, host: HostProfile): void => {
      refreshAllowMultiple();
      setSelectedId(host.id);
      setCtxMenu({ x: e.clientX, y: e.clientY, host });
    },
    [refreshAllowMultiple],
  );

  // Browser dev only: stand in for "this machine was connected to once
  // already" so a Nearby tile can be seen with a real picture (see mock.ts).
  const mock = useMockData();
  useEffect(() => {
    if (mock) seedMockThumbnails();
  }, [mock]);

  // ------------------------------------------------------------ filtering

  const visibleHosts = useMemo((): HostProfile[] => {
    let list = hosts;
    switch (selection.kind) {
      case "favorites":
        list = list.filter((h) => h.favorite);
        break;
      case "recents":
        list = list.filter((h) => h.lastConnected !== null);
        break;
      case "group": {
        const childIds = groups.filter((g) => g.parentId === selection.id).map((g) => g.id);
        list = list.filter(
          (h) => h.groupId === selection.id || (h.groupId !== null && childIds.includes(h.groupId)),
        );
        break;
      }
      default:
        break;
    }
    if (activeTagIds.size > 0) {
      list = list.filter((h) =>
        tagMode === "and"
          ? [...activeTagIds].every((t) => h.tags.includes(t))
          : [...activeTagIds].some((t) => h.tags.includes(t)),
      );
    }
    if (search.trim()) {
      const tagNames = new Map(tags.map((t) => [t.id, t.name] as const));
      list = list.filter((h) =>
        fuzzyMatch(
          search,
          `${h.friendlyName} ${h.address} ${h.tags.map((t) => tagNames.get(t) ?? "").join(" ")}`,
        ),
      );
    }
    const sorted = [...list];
    const key: SortKey = settings.sortKey;
    sorted.sort((a, b) => {
      switch (key) {
        case "last-connected":
          return (b.lastConnected ?? 0) - (a.lastConnected ?? 0);
        case "frequency":
          return b.connectCount - a.connectCount;
        case "group": {
          const gname = (h: HostProfile): string =>
            groups.find((g) => g.id === h.groupId)?.name ?? "￿";
          return gname(a).localeCompare(gname(b)) || a.friendlyName.localeCompare(b.friendlyName);
        }
        default:
          return a.friendlyName.localeCompare(b.friendlyName);
      }
    });
    if (selection.kind === "recents") {
      sorted.sort((a, b) => (b.lastConnected ?? 0) - (a.lastConnected ?? 0));
    }
    return sorted;
  }, [hosts, groups, tags, selection, search, activeTagIds, tagMode, settings.sortKey]);

  const unsavedDiscovered = useMemo(
    () =>
      discovered.filter(
        (d) =>
          d.savedHostId === null &&
          !hosts.some((h) => h.address === d.address && h.port === d.port) &&
          (!search.trim() || fuzzyMatch(search, `${d.name} ${d.address}`)),
      ),
    [discovered, hosts, search],
  );

  const showNearbyBand =
    (selection.kind === "all" || selection.kind === "nearby") && unsavedDiscovered.length > 0;

  // ------------------------------------------------------------ actions

  /**
   * Carry everything discovery learned into the new-host draft.
   *
   * The MAC especially: Wake-on-LAN cannot work without one and the app has no
   * other way to find it out, so dropping it here means the user must go read
   * it off the machine by hand. `osHint` goes through `resolvedOsHint` so a
   * name proven to come from Windows wins over the server-string guess.
   */
  const addDiscovered = useCallback((d: DiscoveredHost): void => {
    setHostDialog(
      draftFromHost(null, {
        friendlyName: d.name,
        address: d.address,
        port: d.port,
        osHint: resolvedOsHint(d),
        wolMac: hostMac(d),
      }),
    );
  }, []);

  /** The MAC discovery is currently reporting for this endpoint, if any. */
  const discoveredMacFor = useCallback(
    (address: string, port: number): string | null => {
      const d = discovered.find((x) => x.address === address && x.port === port);
      return hostMac(d);
    },
    [discovered],
  );

  /**
   * Edit a saved host, offering the MAC discovery has since learned when the
   * profile has none. It is only a pre-fill, nothing is written until Save, * so a host added before NetBIOS lookups existed can pick one up simply by
   * being opened.
   */
  const editHost = useCallback(
    (host: HostProfile): void => {
      setHostDialog(
        draftFromHost(
          host,
          host.wolMac ? undefined : { wolMac: discoveredMacFor(host.address, host.port) },
        ),
      );
    },
    [discoveredMacFor],
  );

  const saveDraft = useCallback(
    async (draft: HostDraft): Promise<void> => {
      const saved = await saveHost({
        id: draft.id,
        friendlyName: draft.friendlyName,
        address: draft.address,
        port: draft.port,
        groupId: draft.groupId,
        osHint: draft.osHint,
        securityPref: draft.securityPref,
        qualityPref: draft.qualityPref,
        scalingMode: draft.scalingMode,
        keyboardMode: draft.keyboardMode,
        passthrough: draft.passthrough,
        wolMac: draft.wolMac,
        tags: draft.tagIds,
        hasPassword: draft.hasPassword,
      });
      const id = saved?.id ?? draft.id;
      if (id) {
        if (draft.password) await savePassword(id, draft.password);
        await setHostTags(id, draft.tagIds);
      }
      setHostDialog(null);
      push("success", draft.id ? "Host updated" : `Added ${draft.friendlyName}`);
    },
    [saveHost, savePassword, setHostTags, push],
  );

  const paletteActions = useMemo((): PaletteAction[] => {
    return [
      { id: "new-host", label: "New host…", hint: "", run: () => setHostDialog(draftFromHost(null)) },
      { id: "quick-connect", label: "Connect to an address…", hint: `${modKeyLabel}T`, run: focusQuickConnect },
      { id: "scan", label: "Scan network", hint: "", run: () => void startScan() },
      {
        id: "toggle-view",
        label: settings.libraryView === "grid" ? "Switch to list view" : "Switch to grid view",
        run: () => update({ libraryView: settings.libraryView === "grid" ? "list" : "grid" }),
      },
      { id: "preferences", label: "Open Preferences", run: onOpenPreferences },
      { id: "refresh", label: "Refresh library", run: () => void refresh() },
      { id: "help", label: "Help & keyboard shortcuts", run: onOpenAbout },
      { id: "about", label: "About DeskVNCViewer", run: onOpenAbout },
    ];
  }, [settings.libraryView, update, startScan, focusQuickConnect, onOpenPreferences, onOpenAbout, refresh]);

  // Onboarding hand-off: open the add dialog pre-filled from a discovered host
  useEffect(() => {
    if (!autoAddDiscoveredId) return;
    const d = discovered.find((x) => x.id === autoAddDiscoveredId);
    if (d) addDiscovered(d);
    onAutoAddHandled?.();
  }, [autoAddDiscoveredId, discovered, addDiscovered, onAutoAddHandled]);

  // ------------------------------------------------------------ hotkeys

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      } else if (mod && e.key.toLowerCase() === "t") {
        e.preventDefault();
        focusQuickConnect();
      } else if (mod && e.key.toLowerCase() === "f") {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (mod && e.key.toLowerCase() === "n") {
        e.preventDefault();
        setHostDialog(draftFromHost(null));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [focusQuickConnect]);

  // The same two things off the native File menu. menu.rs routes them here
  // whichever window has focus, so they work from inside a session too.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      if (id === "menu:quick-connect") focusQuickConnect();
      else if (id === "menu:new-host") setHostDialog(draftFromHost(null));
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [focusQuickConnect]);

  // ------------------------------------------------------------ context menu

  const menuItemsFor = useCallback(
    (host: HostProfile): MenuItem[] => [
      { label: "Connect", onSelect: () => connectHost(host) },
      ...(allowMultiple
        ? [{ label: "Connect in new window", onSelect: () => connectHost(host, true) }]
        : []),
      {
        label: "Edit…",
        onSelect: () => editHost(host),
      },
      {
        label: host.favorite ? "Remove from Favorites" : "Add to Favorites",
        onSelect: () => void saveHost({ ...host, favorite: !host.favorite }),
      },
      {
        label: "Duplicate",
        onSelect: () =>
          void saveHost({
            ...host,
            id: undefined,
            friendlyName: `${host.friendlyName} copy`,
            hasPassword: false,
          }),
      },
      {
        label: "Wake (Wake-on-LAN)",
        disabled: !host.wolMac,
        onSelect: () => {
          void wakeHost(host.id);
          push("info", `Magic packet sent to ${host.friendlyName}`);
        },
      },
      {
        // Thumbnails are captured by the SESSION window (capture_thumbnail
        // takes a raw RGBA body, not a host id), so from here we can only
        // re-read what the store already has.
        label: "Reload thumbnail",
        onSelect: () => refreshThumbnail(host.id),
      },
      {
        // A changed server key is a deliberate hard stop that cannot be
        // clicked through, so without this a legitimately rebuilt machine, // new TLS certificate or new RA2 key, would be permanently
        // unreachable. Forgetting returns it to first-contact state, where the
        // usual "Trust this computer" prompt applies.
        label: "Forget saved key…",
        onSelect: () => {
          void forgetCertificate(host.address, host.port).then(() =>
            push(
              "info",
              `Forgot the saved key for ${host.friendlyName}. You will be asked to verify it on the next connection.`,
            ),
          );
        },
      },
      {
        label: "Delete…",
        danger: true,
        separatorAbove: true,
        onSelect: () => {
          void deleteHost(host.id);
          push("info", `Deleted ${host.friendlyName}`, {
            label: "Undo",
            run: () => void saveHost({ ...host }),
          });
        },
      },
    ],
    [allowMultiple, connectHost, editHost, saveHost, deleteHost, wakeHost, refreshThumbnail, push],
  );

  // ------------------------------------------------------------ render

  const nothingSaved = !loading && hosts.length === 0;
  const gridClass = classNames("host-grid", settings.compact && "is-compact");

  return (
    <div className="flex h-full flex-col bg-canvas">
      {/* Top bar */}
      <header className="flex items-center gap-3 border-b border-subtle bg-surface/80 px-4 py-2.5">
        <h1 className="mr-1 text-sm font-semibold tracking-tight text-primary">DeskVNCViewer</h1>
        <div className="relative max-w-md flex-1">
          <IconSearch size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-tertiary" />
          <input
            ref={searchRef}
            className="field !pl-8"
            placeholder={`Search or press ${modKeyLabel}K`}
            aria-label="Search hosts"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setSearch("");
            }}
          />
        </div>
        <label className="flex shrink-0 items-center gap-1.5 text-xs text-secondary">
          Sort
          <Select
            wrapperClassName="!inline-block"
            className="!w-auto !py-1 text-xs"
            aria-label="Sort hosts"
            value={settings.sortKey}
            onChange={(e) => update({ sortKey: e.target.value as SortKey })}
          >
            <option value="name">Name</option>
            <option value="last-connected">Last connected</option>
            <option value="frequency">Most used</option>
            <option value="group">Group</option>
          </Select>
        </label>
        <div className="flex overflow-hidden rounded-sm border border-subtle" role="group" aria-label="View mode">
          <button
            type="button"
            aria-label="Grid view"
            aria-pressed={settings.libraryView === "grid"}
            className={classNames("p-1.5", settings.libraryView === "grid" ? "bg-accent text-accent-fg" : "text-secondary hover:bg-inset")}
            onClick={() => update({ libraryView: "grid" })}
          >
            <IconGrid size={15} />
          </button>
          <button
            type="button"
            aria-label="List view"
            aria-pressed={settings.libraryView === "list"}
            className={classNames("p-1.5", settings.libraryView === "list" ? "bg-accent text-accent-fg" : "text-secondary hover:bg-inset")}
            onClick={() => update({ libraryView: "list" })}
          >
            <IconList size={15} />
          </button>
        </div>
        <button
          type="button"
          aria-pressed={livePreviews}
          aria-label="Live previews"
          title="Live previews, tiles with an active session show a live picture instead of the saved thumbnail"
          className={classNames(
            "overflow-hidden rounded-sm border border-subtle p-1.5",
            livePreviews ? "bg-accent text-accent-fg" : "text-secondary hover:bg-inset",
          )}
          onClick={() => setLivePreviews(!livePreviews)}
        >
          <IconActivity size={15} />
        </button>
        <button type="button" className="btn-secondary relative overflow-hidden" onClick={() => void startScan()}>
          {scan.running ? (
            <span className="absolute inset-x-0 bottom-0 h-0.5 bg-inset">
              <span
                className={classNames("block h-full bg-accent", scan.total === 0 && "indeterminate-bar w-1/3")}
                style={scan.total > 0 ? { width: `${(scan.done / scan.total) * 100}%` } : undefined}
              />
            </span>
          ) : null}
          <IconZap size={14} />
          {scan.running ? "Scanning…" : "Scan network"}
        </button>
        <button type="button" className="btn-primary" onClick={() => setHostDialog(draftFromHost(null))}>
          <IconPlus size={14} /> New Host
        </button>
      </header>

      <QuickConnect
        hosts={hosts}
        discovered={discovered}
        recents={settings.quickConnectHistory}
        inputRef={quickConnectRef}
        onConnectHost={connectHost}
        onConnectAddress={connectAdHoc}
        onRemember={rememberQuickConnect}
      />

      <div className="flex min-h-0 flex-1">
        <Sidebar
          hosts={hosts}
          groups={groups}
          tags={tags}
          nearbyCount={unsavedDiscovered.length}
          selection={selection}
          onSelect={setSelection}
          activeTagIds={activeTagIds}
          tagMode={tagMode}
          onToggleTag={(id) =>
            setActiveTagIds((prev) => {
              const next = new Set(prev);
              if (next.has(id)) next.delete(id);
              else next.add(id);
              return next;
            })
          }
          onToggleTagMode={() => setTagMode((m) => (m === "and" ? "or" : "and"))}
          onNewGroup={() => setNamePrompt("group")}
          onNewTag={() => setNamePrompt("tag")}
          onOpenPreferences={onOpenPreferences}
        />

        <main className="min-w-0 flex-1 overflow-y-auto p-4" aria-label="Hosts">
          {loading ? (
            <div className={gridClass} style={gridCap(8, settings.compact)}>
              {Array.from({ length: 8 }, (_, i) => (
                <TileSkeleton key={i} />
              ))}
            </div>
          ) : nothingSaved && unsavedDiscovered.length === 0 ? (
            <EmptyState
              icon={<IconMonitor size={56} />}
              title="Let's find your computers"
              body="DeskVNCViewer can discover VNC servers on your local network automatically, or you can add one by address."
              primary={{ label: "Find computers on my network", onClick: () => void startScan() }}
              secondary={{ label: "Add a computer manually", onClick: () => setHostDialog(draftFromHost(null)) }}
            />
          ) : (
            <>
              {selection.kind !== "nearby" ? (
                visibleHosts.length === 0 && search.trim() ? (
                  <EmptyState
                    title={`No computers match “${search.trim()}”`}
                    primary={{
                      label: `Add “${search.trim()}” as a new host`,
                      onClick: () =>
                        setHostDialog(draftFromHost(null, { address: search.trim(), friendlyName: search.trim() })),
                    }}
                  />
                ) : settings.libraryView === "grid" ? (
                  <div className={gridClass} style={gridCap(visibleHosts.length, settings.compact)}>
                    {visibleHosts.map((h) => (
                      <HostTile
                        key={h.id}
                        host={h}
                        selected={selectedId === h.id}
                        onSelect={() => setSelectedId(h.id)}
                        onConnect={() => connectHost(h)}
                        onEdit={() => editHost(h)}
                        onWake={() => void wakeHost(h.id)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          openCtxMenu(e, h);
                        }}
                      />
                    ))}
                  </div>
                ) : (
                  <HostListView
                    hosts={visibleHosts}
                    groups={groups}
                    tags={tags}
                    selectedId={selectedId}
                    onSelect={setSelectedId}
                    onConnect={connectHost}
                    onContextMenu={(e, h) => {
                      e.preventDefault();
                      openCtxMenu(e, h);
                    }}
                  />
                )
              ) : null}

              {showNearbyBand ? (
                <section className="mt-6" aria-label="Nearby, not yet saved">
                  <h2 className="mb-3 text-2xs font-semibold uppercase tracking-wider text-tertiary">
                    Nearby, not yet saved
                  </h2>
                  <div className={gridClass} style={gridCap(unsavedDiscovered.length, settings.compact)}>
                    {unsavedDiscovered.map((d) => (
                      <DiscoveredTile
                        key={d.id}
                        host={d}
                        onAdd={() => addDiscovered(d)}
                        onConnect={() => connectAdHoc(d.address, d.port)}
                      />
                    ))}
                  </div>
                </section>
              ) : selection.kind === "nearby" && unsavedDiscovered.length === 0 ? (
                <EmptyState
                  icon={<IconZap size={48} />}
                  title="Nothing discovered yet"
                  body="Some VNC servers don't advertise themselves on the network. You can actively scan this subnet, or add a computer by address."
                  primary={{ label: "Scan this network", onClick: () => void startScan() }}
                  secondary={{ label: "Add manually", onClick: () => setHostDialog(draftFromHost(null)) }}
                />
              ) : null}
            </>
          )}
        </main>
      </div>

      {/* Overlays */}
      {ctxMenu ? (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} items={menuItemsFor(ctxMenu.host)} onClose={() => setCtxMenu(null)} />
      ) : null}
      {paletteOpen ? (
        <CommandPalette
          hosts={hosts}
          actions={paletteActions}
          onConnect={connectHost}
          onClose={() => setPaletteOpen(false)}
        />
      ) : null}
      {hostDialog ? (
        <HostDialog
          draft={hostDialog}
          groups={groups}
          tags={tags}
          onSave={(d) => void saveDraft(d)}
          onClose={() => setHostDialog(null)}
        />
      ) : null}
      {namePrompt ? (
        <NamePromptDialog
          kind={namePrompt}
          onSubmit={(name, color) => {
            if (namePrompt === "group") void saveGroup({ name });
            else void saveTag({ name, color });
            setNamePrompt(null);
          }}
          onClose={() => setNamePrompt(null)}
        />
      ) : null}
    </div>
  );
}

// ------------------------------------------------------------------ list view

function HostListView({
  hosts,
  groups,
  tags,
  selectedId,
  onSelect,
  onConnect,
  onContextMenu,
}: {
  hosts: HostProfile[];
  groups: { id: string; name: string }[];
  tags: { id: string; name: string; color: string }[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onConnect: (h: HostProfile) => void;
  onContextMenu: (e: React.MouseEvent, h: HostProfile) => void;
}): ReactNode {
  const { forKey } = useSessions();
  return (
    <div className="overflow-x-auto rounded-md border border-subtle bg-surface">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-subtle text-left text-xs text-tertiary">
            <th className="px-3 py-2 font-medium">Name</th>
            <th className="px-3 py-2 font-medium">Address</th>
            <th className="px-3 py-2 font-medium">Group</th>
            <th className="px-3 py-2 font-medium">Tags</th>
            <th className="px-3 py-2 font-medium">OS</th>
            <th className="px-3 py-2 font-medium">Last connected</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr
              key={h.id}
              tabIndex={0}
              aria-selected={selectedId === h.id}
              className={classNames(
                "cursor-default border-b border-subtle last:border-b-0",
                selectedId === h.id ? "bg-accent/12" : "hover:bg-inset/60",
              )}
              onClick={() => onSelect(h.id)}
              onDoubleClick={() => onConnect(h)}
              onContextMenu={(e) => onContextMenu(e, h)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onConnect(h);
              }}
            >
              <td className="px-3 py-2">
                <span className="flex items-center gap-2">
                  <span
                    className={classNames("h-2 w-2 rounded-full", h.online ? "bg-success" : "bg-tertiary/60")}
                    role="img"
                    aria-label={h.online ? "Online" : "Offline or unknown"}
                  />
                  <span className="font-medium text-primary">{h.friendlyName}</span>
                </span>
              </td>
              <td className="mono px-3 py-2 text-secondary">
                {h.address}
                {h.port !== 5900 ? `:${h.port}` : ""}
                <RowBandwidth bandwidth={forKey(h.id).bandwidth} />
              </td>
              <td className="px-3 py-2 text-secondary">
                {groups.find((g) => g.id === h.groupId)?.name ?? "-"}
              </td>
              <td className="px-3 py-2">
                <span className="flex gap-1">
                  {h.tags.map((tid) => {
                    const t = tags.find((x) => x.id === tid);
                    return t ? (
                      <span
                        key={tid}
                        className="rounded-pill px-1.5 py-px text-2xs font-medium text-white"
                        style={{ background: t.color }}
                      >
                        {t.name}
                      </span>
                    ) : null;
                  })}
                </span>
              </td>
              <td className="px-3 py-2 text-secondary">{osLabel(h.osHint)}</td>
              <td className="px-3 py-2 text-secondary">{timeAgo(h.lastConnected)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Compact `↓/↑` for a row with fresh session stats (no sparkline in the table). */
function RowBandwidth({
  bandwidth,
}: {
  bandwidth: { rx: number; tx: number } | null;
}): ReactNode {
  if (!bandwidth) return null;
  return (
    <span className="ml-2 whitespace-nowrap text-2xs text-tertiary [font-variant-numeric:tabular-nums]">
      ↓ {formatBps(bandwidth.rx)} ↑ {formatBps(bandwidth.tx)}
    </span>
  );
}

// ------------------------------------------------------------- name prompt

const TAG_COLORS = ["#e5544b", "#e5a53a", "#34c26b", "#4f8ef7", "#8a63e8", "#e560a8"];

function NamePromptDialog({
  kind,
  onSubmit,
  onClose,
}: {
  kind: "group" | "tag";
  onSubmit: (name: string, color: string) => void;
  onClose: () => void;
}): ReactNode {
  const [name, setName] = useState("");
  const [color, setColor] = useState(TAG_COLORS[3]);
  return (
    <Dialog title={kind === "group" ? "New Group" : "New Tag"} onClose={onClose} width={400}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) onSubmit(name.trim(), color);
        }}
      >
        <input
          data-autofocus
          className="field"
          placeholder={kind === "group" ? "Office" : "prod"}
          aria-label={`${kind} name`}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {kind === "tag" ? (
          <div className="flex gap-2" role="radiogroup" aria-label="Tag color">
            {TAG_COLORS.map((c) => (
              <button
                key={c}
                type="button"
                role="radio"
                aria-checked={color === c}
                aria-label={`Color ${c}`}
                className={classNames(
                  "h-6 w-6 rounded-full border-2",
                  color === c ? "border-primary" : "border-transparent",
                )}
                style={{ background: c }}
                onClick={() => setColor(c)}
              />
            ))}
          </div>
        ) : null}
        <div className="flex justify-end gap-2.5">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={!name.trim()}>
            Create
          </button>
        </div>
      </form>
    </Dialog>
  );
}
