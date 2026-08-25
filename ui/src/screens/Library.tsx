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
import type { DiscoveredHost, HostProfile, ProtocolKind } from "../lib/types";
import { serializeRdpSettings } from "../lib/rdp";
import { serializeSshSettings } from "../lib/ssh";
import { loadSshDefaults } from "../lib/sshDefaults";
import {
  hostMac,
  hostProtocol,
  protocolLabel,
  resolvedOsHint,
  serializeSshTunnel,
} from "../lib/types";
import {
  allowsMultipleSessions,
  inTauri,
  openSessionWindow,
  safeInvoke,
  safeListen,
  forgetCertificate,
  type OpenSessionOptions,
} from "../lib/tauri";
import { seedMockThumbnails, useMockData } from "../lib/mock";
import { useSessions } from "../state/SessionsContext";
import { useTabs } from "../state/TabsContext";
import { classNames, formatBps, fuzzyMatch, modKeyLabel, timeAgo } from "../lib/util";
import { Sidebar, type SidebarSelection } from "../components/Sidebar";
import { useHostDragSelect, type DropTarget } from "../hooks/useHostDragSelect";
import { HostTile, DiscoveredTile, addressLabel, osLabel } from "../components/HostTile";
import { CommandPalette, type PaletteAction } from "../components/CommandPalette";
import { HostDialog, draftFromHost, type HostDraft } from "../components/HostDialog";
import { loadRdpDefaults } from "../lib/rdpDefaults";
import { QuickConnect } from "../components/QuickConnect";
import { ContextMenu, Dialog, EmptyState, Select, TileSkeleton, type MenuItem } from "../components/primitives";
import {
  IconActivity,
  IconGrid,
  IconHelp,
  IconList,
  IconMonitor,
  IconPlus,
  IconSearch,
  IconTabs,
  IconWindows,
  IconZap,
} from "../components/icons";
import { emit, listen } from "@tauri-apps/api/event";
import { EDIT_HOST_EVENT, type EditHostRequest } from "../lib/editHost";

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

/**
 * A session id for the browser-dev mock, where there is no shell to mint one.
 * Unique per tab, or two mock sessions would collide on one tab.
 */
function devSessionId(): string {
  return `dev-${Math.random().toString(36).slice(2, 10)}`;
}

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
  const { hosts, groups, tags, loading, saveHost, deleteHost, saveGroup, saveTag, setHostTags, setHostsGroup, addTagToHosts, removeTagFromHosts, savePassword, saveSshPassphrase, saveRdpCredentials, wakeHost, refresh, refreshThumbnail } = useHosts();
  const { discovered, scan, startScan } = useDiscovery();
  const { settings, update } = useSettings();
  const { livePreviews, setLivePreviews } = useSessions();
  const { tabs, open: openTab, select: selectTab, has: hasTab, activeId: activeTabId } = useTabs();
  /** Is the library the pane on screen, or is a session tab in front of it? */
  const inFront = activeTabId === null;
  const { push } = useToasts();

  const [selection, setSelection] = useState<SidebarSelection>({ kind: "all" });
  const [search, setSearch] = useState("");
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

  const tabbed = settings.windowMode === "tabs";

  /**
   * Every connect gesture, in one place.
   *
   * The shell still decides everything that matters, we only act on what it
   * reports back. `reused` means an already-open session was brought forward
   * and nothing new was connected, so the history counter must not be bumped
   * either. `target` says where that session actually lives: a machine opened
   * in its own window before the preference was switched to tabs is still
   * found, and is still raised as a window rather than duplicated into a tab.
   */
  const openSession = useCallback(
    async (
      options: OpenSessionOptions,
      label: string,
      onConnected?: () => void,
    ): Promise<void> => {
      let outcome = await openSessionWindow({ ...options, asTab: tabbed });
      if (!outcome) return;
      // A tab the shell believes is still open, but which is not on the strip,
      // is a session on its way out: `disconnect_session` only ASKS the session
      // to stop, and the shell's liveness test for a tab is whether the library
      // window still exists, which it always does. Closing a tab and
      // reconnecting straight away would otherwise be answered with "already
      // open" and connect nothing at all. Ask once more, saying outright that a
      // new one is wanted.
      if (outcome.reused && outcome.target === "tab" && !hasTab(outcome.sessionId)) {
        outcome = await openSessionWindow({ ...options, asTab: tabbed, forceNew: true });
        if (!outcome) return;
      }
      if (outcome.reused) {
        if (outcome.target === "tab") selectTab(outcome.sessionId);
        push("info", `${label} is already open, brought it to the front`);
        return;
      }
      if (outcome.target === "tab" && outcome.params) {
        // A tab has no URL to read its parameters out of, so the shell hands
        // them back and we mount the viewer with them.
        openTab(outcome.sessionId, {
          sessionId: outcome.sessionId,
          profileId: outcome.params.profileId,
          address: outcome.params.address,
          port: outcome.params.port,
          name: outcome.params.name,
          protocol: outcome.params.protocol,
        });
      }
      onConnected?.();
    },
    [tabbed, selectTab, openTab, hasTab, push],
  );

  const connectHost = useCallback(
    (host: HostProfile, forceNew = false): void => {
      const protocol = hostProtocol(host);
      if (inTauri()) {
        void openSession({ profileId: host.id, forceNew }, host.friendlyName, () => {
          void safeInvoke("touch_connected", { hostId: host.id }, null);
        });
        return;
      }
      // Browser dev: no shell to resolve anything, so mount the mock session
      // directly. `profileId` rides along exactly as the shell would set it,
      // so the mock session's thumbnail capture attaches to this host.
      if (tabbed) {
        const id = devSessionId();
        openTab(id, {
          sessionId: id,
          profileId: host.id,
          address: host.address,
          port: host.port,
          name: host.friendlyName,
          protocol,
        });
        return;
      }
      window.location.search =
        `?sessionId=dev&profileId=${encodeURIComponent(host.id)}` +
        `&name=${encodeURIComponent(host.friendlyName)}` +
        (protocol === "vnc" ? "" : `&protocol=${protocol}`);
    },
    [openSession, tabbed, openTab],
  );

  const connectAdHoc = useCallback(
    (protocol: ProtocolKind, address: string, port: number): void => {
      if (inTauri()) {
        void openSession({ address, port, protocol }, address);
        return;
      }
      // Endpoint rides along exactly as the shell sets it: an ad-hoc session
      // is keyed by `discovered:<address>:<port>`, so without it the browser
      // dev session has nothing to attach its capture to.
      if (tabbed) {
        const id = devSessionId();
        openTab(id, {
          sessionId: id,
          profileId: null,
          address,
          port,
          name: address,
          protocol,
        });
        return;
      }
      window.location.search =
        `?sessionId=dev&address=${encodeURIComponent(address)}&port=${port}` +
        `&name=${encodeURIComponent(address)}` +
        (protocol === "vnc" ? "" : `&protocol=${protocol}`);
    },
    [openSession, tabbed, openTab],
  );

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

  // Browser dev only: stand in for "this machine was connected to once
  // already" so a Nearby tile can be seen with a real picture (see mock.ts).
  const mock = useMockData();
  // The Preferences defaults a new Remote Desktop or SSH host starts with,
  // cached once so building a draft stays synchronous. See `lib/rdpDefaults.ts`
  // and `lib/sshDefaults.ts`. A default with no reader here is worse than no
  // default at all, since Preferences would look like it works while a new
  // SSH host quietly never sees the multiplexer the user picked.
  useEffect(() => {
    void loadRdpDefaults();
    void loadSshDefaults();
  }, []);

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

  /**
   * Badge every tile, or none.
   *
   * A library that speaks one protocol has nothing to disambiguate, and it is
   * the majority case today; the moment a second one appears every tile needs
   * to say which it is, because a badge on some tiles leaves the user
   * guessing what the unbadged ones are.
   */
  const showProtocol = useMemo(
    () => new Set(hosts.map((h) => h.protocol)).size > 1,
    [hosts],
  );

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

  // --------------------------------------------------- selection and drag

  /** Display order, which is what a shift-click range and a marquee follow. */
  const visibleOrder = useMemo(() => visibleHosts.map((h) => h.id), [visibleHosts]);
  /** Id lookup: a Cmd+A selection turns every `hosts.find` into a full scan. */
  const hostById = useMemo(() => new Map(hosts.map((h) => [h.id, h] as const)), [hosts]);
  const hostName = useCallback(
    (id: string): string => hostById.get(id)?.friendlyName ?? "host",
    [hostById],
  );

  /** "3 hosts" / "Studio", for toasts about a dropped selection. */
  const describe = useCallback(
    (ids: string[]): string => (ids.length === 1 ? hostName(ids[0]) : `${ids.length} hosts`),
    [hostName],
  );

  /**
   * A selection was dropped on a group or a tag in the sidebar.
   *
   * Every branch is undoable, because a drag is the easiest gesture in the app
   * to make by accident: the previous group of each host, and which of them
   * did not already carry the tag, are captured BEFORE the write so Undo can
   * put things back exactly, rather than blanket-clearing.
   */
  const dropOnTarget = useCallback(
    (ids: string[], target: DropTarget): void => {
      const previousGroup = new Map(
        ids.map((id) => [id, hostById.get(id)?.groupId ?? null] as const),
      );
      /**
       * Put every host back in the group it came from.
       *
       * Sequential, not a fan-out: each write ends with its own `refresh()`,
       * and three unordered refreshes can settle on the snapshot taken before
       * the last write landed, leaving a correct database behind a stale grid.
       */
      const undoGroups = async (): Promise<void> => {
        const byGroup = new Map<string | null, string[]>();
        for (const [id, gid] of previousGroup) byGroup.set(gid, [...(byGroup.get(gid) ?? []), id]);
        for (const [gid, members] of byGroup) await setHostsGroup(members, gid);
      };
      // An undo that fails has to say so. Letting the promise reject into
      // nothing is the very bug this change exists to fix, and it is no more
      // acceptable on the way back than on the way there.
      const reportUndo = (run: () => Promise<void>) => (): void => {
        void run().catch((err: unknown) => push("danger", `Could not undo: ${String(err)}`));
      };

      if (target.kind === "ungroup") {
        // Nothing to do for hosts that are not in a group anyway.
        const grouped = ids.filter((id) => previousGroup.get(id) !== null);
        if (grouped.length === 0) {
          push("info", `${describe(ids)} ${ids.length === 1 ? "is" : "are"} not in a group`);
          return;
        }
        void setHostsGroup(grouped, null).then(
          () =>
            push("success", `Removed ${describe(grouped)} from their group`, {
              label: "Undo",
              run: reportUndo(undoGroups),
            }),
          (err: unknown) => push("danger", `Could not move those hosts: ${String(err)}`),
        );
        return;
      }

      if (target.kind === "group") {
        const group = groups.find((g) => g.id === target.id);
        if (!group) return;
        const moving = ids.filter((id) => previousGroup.get(id) !== target.id);
        // Silence here would be indistinguishable from a drop that missed.
        if (moving.length === 0) {
          push("info", `${describe(ids)} already in ${group.name}`);
          return;
        }
        void setHostsGroup(moving, target.id).then(
          () =>
            push("success", `Moved ${describe(moving)} to ${group.name}`, {
              label: "Undo",
              run: reportUndo(undoGroups),
            }),
          (err: unknown) => push("danger", `Could not move those hosts: ${String(err)}`),
        );
        return;
      }

      const tag = tags.find((t) => t.id === target.id);
      if (!tag) return;
      // Hosts that already carry the tag are left out of the Undo, or undoing
      // would strip a tag the user had put there earlier by hand.
      const tagging = ids.filter((id) => !(hostById.get(id)?.tags ?? []).includes(target.id));
      if (tagging.length === 0) {
        push("info", `${describe(ids)} already tagged ${tag.name}`);
        return;
      }
      void addTagToHosts(tagging, target.id).then(
        () =>
          push("success", `Tagged ${describe(tagging)} with ${tag.name}`, {
            label: "Undo",
            run: reportUndo(() => removeTagFromHosts(tagging, target.id)),
          }),
        (err: unknown) => push("danger", `Could not tag those hosts: ${String(err)}`),
      );
    },
    [hostById, groups, tags, setHostsGroup, addTagToHosts, removeTagFromHosts, describe, push],
  );

  const {
    selectedIds,
    selectOnly,
    selectAll,
    clear: clearSelection,
    containerRef,
    onPointerDown,
    isGesturing,
    cancelGesture,
    marquee,
    drag,
  } = useHostDragSelect({ order: visibleOrder, onDrop: dropOnTarget });

  /**
   * What the Escape / Select-all shortcuts need to know, in a ref.
   *
   * Through the state itself, the keydown effect below would tear down and
   * re-register its window listener every time the selection or a dialog
   * changed, which during a marquee sweep is once per pointer move.
   */
  const selectionKeys = useRef({ overlaid: false, hasSelection: false });
  selectionKeys.current = {
    overlaid: hostDialog !== null || paletteOpen || namePrompt !== null || ctxMenu !== null,
    hasSelection: selectedIds.size > 0,
  };

  const openCtxMenu = useCallback(
    (e: { clientX: number; clientY: number }, host: HostProfile): void => {
      refreshAllowMultiple();
      // Right-clicking outside the selection is a fresh start, exactly as it
      // is in a file manager; inside it, the selection is kept so the menu can
      // act on all of it.
      if (!selectedIds.has(host.id)) selectOnly(host.id);
      setCtxMenu({ x: e.clientX, y: e.clientY, host });
    },
    [refreshAllowMultiple, selectedIds, selectOnly],
  );

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
        // The discovery row already knows what answers on that port, so the
        // editor opens on the right side of the protocol selector rather
        // than making the user notice and switch it.
        protocol: d.protocol ?? "vnc",
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
  // Read inside the listener rather than captured, so the subscription is
  // not torn down and rebuilt every time a host list arrives.
  const hostsRef = useRef(hosts);
  hostsRef.current = hosts;

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

  /**
   * A session window asked for a host's security settings.
   *
   * The disconnect panel names a setting, and the editor lives here rather
   * than in the session window, so the request arrives as a broadcast. The
   * dialog opens with Advanced and Security already expanded, which
   * `HostDialog` does for itself whenever either of those switches is on and
   * which is exactly the state a user sent here needs.
   */
  useEffect(() => {
    if (!inTauri()) return;
    let stop: (() => void) | null = null;
    void listen<EditHostRequest>(EDIT_HOST_EVENT, (e) => {
      const host = hostsRef.current.find((h) => h.id === e.payload?.hostId);
      if (host) editHost(host);
    }).then((un) => {
      stop = un;
    });
    return () => stop?.();
  }, [editHost]);

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
        sshTunnel: serializeSshTunnel(draft.sshTunnel),
        wolMac: draft.wolMac,
        tags: draft.tagIds,
        hasPassword: draft.hasPassword,
        protocol: draft.protocol,
        // An untouched settings object stores null, so the column only fills
        // once the user actually changes something and the Rust side keeps
        // applying its own defaults.
        rdpSettings: draft.protocol === "rdp" ? serializeRdpSettings(draft.rdp) : null,
        sshSettings: draft.protocol === "ssh" ? serializeSshSettings(draft.ssh) : null,
      });
      const id = saved?.id ?? draft.id;
      if (id) {
        // An RDP password belongs with its user name and domain, which are
        // three fields of one credential rather than a password on its own.
        if (draft.protocol === "rdp") {
          await saveRdpCredentials(id, {
            user: draft.rdpUser,
            domain: draft.rdpDomain,
            password: draft.password,
          });
        } else if (draft.protocol === "ssh") {
          // `save_password` (Rust) already carries `sshUser` / `sshPassword`
          // fields alongside the existing `sshPassphrase` (see
          // `StoredCredentials` in crates/vnc-store/src/models.rs), and
          // `connect_session` reads exactly this pair for SSH account
          // password auth. There is no `saveSshCredentials` wrapper in
          // HostsContext yet, only `savePassword` (hardcoded to
          // `vncPassword`) and `saveSshPassphrase` (hardcoded to
          // `sshPassphrase`), and HostsContext.tsx is outside this change's
          // scope, so this calls the command directly with `safeInvoke`,
          // already imported here, rather than adding a new context method.
          // Only non-empty fields are sent, matching `saveRdpCredentials`'s
          // own rule: an empty box means "keep what is stored", not "erase
          // it", and a merge on the Rust side is what makes that true.
          const payload: Record<string, string> = {};
          if (draft.sshUser.trim()) payload.sshUser = draft.sshUser.trim();
          if (draft.password) payload.sshPassword = draft.password;
          if (Object.keys(payload).length > 0) {
            await safeInvoke("save_password", { hostId: id, creds: payload }, null);
            // `saveRdpCredentials` flips `hasPassword` in local state itself
            // after a write like this one, which needs `setHosts` and so
            // lives in HostsContext.tsx, outside this change's scope. A
            // refresh gets the library's key icon to the same correct end
            // state by re-reading it from the backend instead.
            if (payload.sshPassword) await refresh();
          }
        } else if (draft.password) {
          await savePassword(id, draft.password);
        }
        if (draft.sshPassphrase) await saveSshPassphrase(id, draft.sshPassphrase);
        await setHostTags(id, draft.tagIds);
      }
      setHostDialog(null);
      push("success", draft.id ? "Host updated" : `Added ${draft.friendlyName}`);
    },
    [saveHost, savePassword, saveSshPassphrase, saveRdpCredentials, setHostTags, refresh, push],
  );

  const paletteActions = useMemo((): PaletteAction[] => {
    return [
      // Sessions open in tabs are reachable from here as well as from the
      // strip, so a library with a long list of machines still has one keyboard
      // route back to the one you were working in.
      ...tabs.map((t, i) => ({
        id: `go-to-tab-${t.id}`,
        label: `Go to ${t.title}`,
        hint: i < 8 ? `${modKeyLabel}${i + 2}` : "",
        run: () => selectTab(t.id),
      })),
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
  }, [tabs, selectTab, settings.libraryView, update, startScan, focusQuickConnect, onOpenPreferences, onOpenAbout, refresh]);

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
      // These listen on `window`, and in tabbed view the library stays mounted
      // behind whichever session is in front. Without this, Cmd+F would move
      // the focus into a search box nobody can see.
      if (!inFront) return;
      const mod = e.metaKey || e.ctrlKey;
      // Typing in the search box or a dialog field: only the app-level
      // shortcuts below apply, "select all" belongs to the text there.
      // `instanceof` rather than a cast: a keydown delivered with no element
      // target (window) would otherwise throw on `.closest` and take the rest
      // of these shortcuts down with it.
      const el = e.target instanceof HTMLElement ? e.target : null;
      const typing = el?.closest("input, textarea, select") != null;
      // A dialog, the palette or a context menu is in front: Escape belongs to
      // whatever is on top, and selecting every tile behind a modal (then
      // popping the selection bar up underneath it) helps nobody.
      const { overlaid, hasSelection } = selectionKeys.current;
      if (mod && e.key.toLowerCase() === "a" && !typing && !overlaid) {
        e.preventDefault();
        selectAll();
        return;
      }
      // One owner for Escape. Mid-gesture it means "cancel this sweep", which
      // puts back the selection the sweep started from; otherwise it clears.
      if (e.key === "Escape" && !typing && !overlaid) {
        if (isGesturing()) cancelGesture();
        else if (hasSelection) clearSelection();
        else return;
        return;
      }
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
  }, [inFront, focusQuickConnect, selectAll, clearSelection, isGesturing, cancelGesture]);

  // The same two things off the native File menu. menu.rs routes them here
  // whichever window has focus, so they work from inside a session too, and in
  // tabbed view "from inside a session" means the library is behind a tab:
  // bring it forward first, or the dialog and the address bar would open on a
  // pane nobody is looking at.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      if (id !== "menu:quick-connect" && id !== "menu:new-host") return;
      selectTab(null);
      // Focus cannot land on an element that is still hidden, so let the pane
      // swap paint first.
      requestAnimationFrame(() => {
        if (id === "menu:quick-connect") focusQuickConnect();
        else setHostDialog(draftFromHost(null));
      });
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [focusQuickConnect, selectTab]);

  // ------------------------------------------------------------ context menu

  /**
   * Menu for a right-click inside a multi-selection. Connect and Edit are
   * deliberately absent: they are single-host gestures, and "connect to nine
   * machines at once" is not something to offer by accident.
   */
  const multiMenuItems = useCallback(
    (ids: string[]): MenuItem[] => {
      const grouped = ids.filter((id) => hosts.find((h) => h.id === id)?.groupId);
      return [
        {
          label: `Remove ${ids.length} hosts from their group`,
          disabled: grouped.length === 0,
          onSelect: () => dropOnTarget(ids, { kind: "ungroup" }),
        },
        ...groups.map((g) => ({
          label: `Move to ${g.name}`,
          onSelect: () => dropOnTarget(ids, { kind: "group", id: g.id }),
        })),
        ...tags.map((t) => ({
          label: `Tag with ${t.name}`,
          separatorAbove: t.id === tags[0]?.id,
          onSelect: () => dropOnTarget(ids, { kind: "tag", id: t.id }),
        })),
        {
          label: `Delete ${ids.length} hosts…`,
          danger: true,
          separatorAbove: true,
          onSelect: () => {
            const doomed = ids
              .map((id) => hostById.get(id))
              .filter((h): h is HostProfile => h !== undefined);
            clearSelection();
            // Awaited, and one at a time: each delete ends with its own
            // refresh, and the toast must not claim the work is done before
            // any of it has been attempted.
            void (async () => {
              for (const h of doomed) await deleteHost(h.id);
              // Undo restores the profiles and their tags. It cannot bring
              // back the saved passwords: `delete_host` drops the keychain
              // entry, the history rows and the thumbnail, and none of those
              // are recoverable from here. Say so rather than promise more
              // than the button delivers.
              push("info", `Deleted ${doomed.length} hosts. Saved passwords are gone.`, {
                label: "Undo",
                run: () => {
                  void (async () => {
                    for (const h of doomed) await saveHost({ ...h });
                  })().catch((err: unknown) =>
                    push("danger", `Could not restore those hosts: ${String(err)}`),
                  );
                },
              });
            })();
          },
        },
      ];
    },
    [hostById, groups, tags, dropOnTarget, deleteHost, saveHost, clearSelection, push],
  );

  const menuItemsFor = useCallback(
    (host: HostProfile): MenuItem[] => [
      { label: "Connect", onSelect: () => connectHost(host) },
      ...(allowMultiple
        ? [
            {
              label: tabbed ? "Connect in new tab" : "Connect in new window",
              onSelect: () => connectHost(host, true),
            },
          ]
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
    [allowMultiple, tabbed, connectHost, editHost, saveHost, deleteHost, wakeHost, refreshThumbnail, push],
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
        {/* The same preference as Connections > "Show sessions as tabs", within
            reach of the moment it matters: about to connect. It decides where
            the NEXT session goes, so sessions already running stay put. */}
        <div className="flex overflow-hidden rounded-sm border border-subtle" role="group" aria-label="Where sessions open">
          <button
            type="button"
            aria-label="Open sessions in their own windows"
            title="Open each session in its own window"
            aria-pressed={!tabbed}
            className={classNames("p-1.5", !tabbed ? "bg-accent text-accent-fg" : "text-secondary hover:bg-inset")}
            onClick={() => update({ windowMode: "windows" })}
          >
            <IconWindows size={15} />
          </button>
          <button
            type="button"
            aria-label="Open sessions as tabs in this window"
            title="Open sessions as tabs in this window"
            aria-pressed={tabbed}
            className={classNames("p-1.5", tabbed ? "bg-accent text-accent-fg" : "text-secondary hover:bg-inset")}
            onClick={() => update({ windowMode: "tabs" })}
          >
            <IconTabs size={15} />
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
        {/* Routed through the same event the native menu's About item emits,
            so one listener (App.tsx) owns opening the dialog everywhere. */}
        <button
          type="button"
          aria-label="About and help"
          title="About and help"
          className="overflow-hidden rounded-sm border border-subtle p-1.5 text-secondary hover:bg-inset"
          onClick={() => void emit("menu://action", { id: "menu:about" })}
        >
          <IconHelp size={15} />
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

      {/* `relative` anchors the floating selection bar: it must NOT be part of
          the flow, or appearing on the first click would push every tile down
          by its height and land the second click of a Shift-range on the wrong
          row. */}
      <div className="relative flex min-h-0 flex-1">
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
          dragging={drag !== null}
          dropOverKey={drag?.over ?? null}
        />

        <main
          ref={containerRef}
          onPointerDown={onPointerDown}
          // select-none on the whole pane, not just the tiles: a marquee that
          // starts on a heading or on the empty-state copy would otherwise
          // drag a text highlight along with the rectangle.
          className="min-w-0 flex-1 select-none overflow-y-auto p-4"
          aria-label="Hosts"
        >
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
              body="DeskVNCViewer can discover computers on your local network automatically, or you can add one by address."
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
                        selected={selectedIds.has(h.id)}
                        showProtocol={showProtocol}
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
                    selectedIds={selectedIds}
                    showProtocol={showProtocol}
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
                        onConnect={() => connectAdHoc(d.protocol ?? "vnc", d.address, d.port)}
                      />
                    ))}
                  </div>
                </section>
              ) : selection.kind === "nearby" && unsavedDiscovered.length === 0 ? (
                <EmptyState
                  icon={<IconZap size={48} />}
                  title="Nothing discovered yet"
                  body="Some computers don't advertise themselves on the network. You can actively scan this subnet, or add a computer by address."
                  primary={{ label: "Scan this network", onClick: () => void startScan() }}
                  secondary={{ label: "Add manually", onClick: () => setHostDialog(draftFromHost(null)) }}
                />
              ) : null}
            </>
          )}
        </main>

        {/* Two or more only: with a single host selected the bar is noise, and
            everything on it is already on that host's own tile or its
            right-click menu. */}
        {selectedIds.size > 1 ? (
          <SelectionBar
            count={selectedIds.size}
            groups={groups}
            tags={tags}
            onMoveToGroup={(gid) =>
              dropOnTarget([...selectedIds], gid === null ? { kind: "ungroup" } : { kind: "group", id: gid })
            }
            onAddTag={(tid) => dropOnTarget([...selectedIds], { kind: "tag", id: tid })}
            onClear={clearSelection}
          />
        ) : null}
      </div>

      {/* Overlays */}
      {marquee ? (
        <div
          className="pointer-events-none fixed z-40 rounded-xs border border-accent bg-accent/15"
          style={{
            left: marquee.left,
            top: marquee.top,
            width: marquee.right - marquee.left,
            height: marquee.bottom - marquee.top,
          }}
        />
      ) : null}
      {/* The dragged stack follows the pointer. `pointer-events: none` is not
          decoration: the drop target is found with elementFromPoint, and a
          ghost that could be hit would always be the answer. */}
      {drag ? (
        <div
          className="pointer-events-none fixed z-50 flex items-center gap-2 rounded-pill border border-subtle bg-raised px-2.5 py-1 text-xs font-medium text-primary shadow-(--shadow-pop)"
          style={{ left: drag.x + 14, top: drag.y + 14 }}
        >
          <IconMonitor size={13} className="text-tertiary" />
          {drag.ids.length === 1 ? hostName(drag.ids[0]) : `${drag.ids.length} hosts`}
        </div>
      ) : null}
      {ctxMenu ? (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          items={
            selectedIds.size > 1 && selectedIds.has(ctxMenu.host.id)
              ? multiMenuItems([...selectedIds])
              : menuItemsFor(ctxMenu.host)
          }
          onClose={() => setCtxMenu(null)}
        />
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
            const kind = namePrompt;
            const created = kind === "group" ? saveGroup({ name }) : saveTag({ name, color });
            // A failure here used to be invisible: the dialog closed, nothing
            // appeared in the sidebar, and the only trace was a console
            // warning nobody sees in a packaged app.
            void created.then(
              () => push("success", `Created the ${kind} ${name}`),
              (err: unknown) => push("danger", `Could not create the ${kind}: ${String(err)}`),
            );
            setNamePrompt(null);
          }}
          onClose={() => setNamePrompt(null)}
        />
      ) : null}
    </div>
  );
}

// -------------------------------------------------------------- selection bar

/**
 * What to do with the hosts that are selected, without dragging them anywhere.
 *
 * The drag onto the sidebar is the quick route, but it is invisible until you
 * try it, and it is awkward with a trackpad on a long list. This bar states
 * plainly what is selected and offers the same two writes.
 *
 * It floats over the bottom of the grid rather than sitting above it. In the
 * flow it would appear on the first click of a Shift-range and push every tile
 * down by its own height, so the second click would land on the wrong row.
 * Bottom RIGHT, because the toast shelf owns bottom centre.
 */
function SelectionBar({
  count,
  groups,
  tags,
  onMoveToGroup,
  onAddTag,
  onClear,
}: {
  count: number;
  groups: { id: string; name: string }[];
  tags: { id: string; name: string; color: string }[];
  onMoveToGroup: (groupId: string | null) => void;
  onAddTag: (tagId: string) => void;
  onClear: () => void;
}): ReactNode {
  return (
    <div
      className="fade-in absolute bottom-4 right-4 z-30 flex max-w-[calc(100%-2rem)] flex-wrap items-center gap-2 rounded-md border border-strong bg-raised/95 px-3 py-2 text-sm shadow-(--shadow-pop) backdrop-blur-sm"
    >
      {/* Only the count is a live region. Wrapping the selects in one would
          have a screen reader re-read every control each time the count
          changed, which during a marquee is constantly. */}
      <span className="font-medium text-primary" role="status">
        {count} hosts selected
      </span>
      <span className="hidden text-xs text-tertiary lg:inline">
        Drag onto a group or tag in the sidebar, or:
      </span>
      <label className="flex items-center gap-1.5 text-xs text-secondary">
        Group
        <Select
          wrapperClassName="!inline-block"
          className="!w-auto !py-1 text-xs"
          aria-label="Move selected hosts to a group"
          value=""
          onChange={(e) => {
            const v = e.target.value;
            if (v) onMoveToGroup(v === "__none__" ? null : v);
            e.target.value = "";
          }}
        >
          <option value="">Move to…</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
          <option value="__none__">No group</option>
        </Select>
      </label>
      <label className="flex items-center gap-1.5 text-xs text-secondary">
        Tag
        <Select
          wrapperClassName="!inline-block"
          className="!w-auto !py-1 text-xs"
          aria-label="Add a tag to the selected hosts"
          value=""
          onChange={(e) => {
            const v = e.target.value;
            if (v) onAddTag(v);
            e.target.value = "";
          }}
        >
          <option value="">Add tag…</option>
          {tags.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </Select>
      </label>
      <button type="button" className="btn-secondary ml-auto !py-1 !text-xs" onClick={onClear}>
        Clear selection
      </button>
    </div>
  );
}

// ------------------------------------------------------------------ list view

function HostListView({
  hosts,
  groups,
  tags,
  selectedIds,
  onConnect,
  onContextMenu,
  showProtocol,
}: {
  hosts: HostProfile[];
  groups: { id: string; name: string }[];
  tags: { id: string; name: string; color: string }[];
  selectedIds: ReadonlySet<string>;
  onConnect: (h: HostProfile) => void;
  onContextMenu: (e: React.MouseEvent, h: HostProfile) => void;
  /** The library holds more than one protocol, so the column earns its width. */
  showProtocol?: boolean;
}): ReactNode {
  const { forKey } = useSessions();
  return (
    <div className="select-none overflow-x-auto rounded-md border border-subtle bg-surface">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-subtle text-left text-xs text-tertiary">
            <th className="px-3 py-2 font-medium">Name</th>
            <th className="px-3 py-2 font-medium">Address</th>
            <th className="px-3 py-2 font-medium">Group</th>
            <th className="px-3 py-2 font-medium">Tags</th>
            {showProtocol ? <th className="px-3 py-2 font-medium">Protocol</th> : null}
            <th className="px-3 py-2 font-medium">OS</th>
            <th className="px-3 py-2 font-medium">Last connected</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr
              key={h.id}
              data-host-id={h.id}
              tabIndex={0}
              aria-selected={selectedIds.has(h.id)}
              className={classNames(
                "cursor-default border-b border-subtle last:border-b-0",
                selectedIds.has(h.id) ? "bg-accent/12" : "hover:bg-inset/60",
              )}
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
                {addressLabel(h)}
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
              {showProtocol ? (
                <td className="px-3 py-2 text-secondary">{protocolLabel(h.protocol)}</td>
              ) : null}
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
