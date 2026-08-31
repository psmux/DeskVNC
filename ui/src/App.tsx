import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { SettingsProvider, useSettings } from "./state/SettingsContext";
import { ToastProvider } from "./state/ToastContext";
import { HostsProvider } from "./state/HostsContext";
import { DiscoveryProvider } from "./state/DiscoveryContext";
import { SessionsProvider } from "./state/SessionsContext";
import { AgentActivityProvider, useAgentActivity } from "./state/AgentActivityContext";
import { TabsProvider, useTabs } from "./state/TabsContext";
import { Library } from "./screens/Library";
import { Session } from "./screens/Session";
import { Preferences } from "./screens/Preferences";
import { About } from "./screens/About";
import { Onboarding } from "./screens/Onboarding";
import { TabStrip, tabPanelId } from "./components/TabStrip";
import { Pane } from "./components/Pane";
import { SplitView } from "./components/SplitView";
import { AgentWall } from "./components/AgentWall";
import { ToastShelf } from "./components/primitives";
import { panes } from "./lib/layout";
import { inTauri, safeListen } from "./lib/tauri";
import { syncSessionMenu } from "./lib/menuSync";
import { PREF_HIDE_TOOLBAR, readBoolPref, writeBoolPref } from "./lib/prefs";
import { installContextMenuSuppressor } from "./lib/contextMenu";

/**
 * Tell the native menu that nothing is connected in the window in front.
 *
 * The toolbar preference is global and still applies, so it goes along; the
 * session half of the menu greys out.
 */
function syncMenuState(): void {
  syncSessionMenu(readBoolPref(PREF_HIDE_TOOLBAR, false), null);
}

/**
 * A session in a window of its own.
 *
 * It needs its own About dialog: the shell that renders one is only mounted
 * in the library window, so Help ▸ About from a session window opened the
 * dialog on the library window instead, behind the session the user was
 * looking at.
 */
function SessionWindow(): ReactNode {
  const [aboutOpen, setAboutOpen] = useState(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      if (id === "menu:about") setAboutOpen(true);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);
  return (
    <>
      <Session />
      {aboutOpen ? <About onClose={() => setAboutOpen(false)} /> : null}
    </>
  );
}

export default function App(): ReactNode {
  const isSession = useMemo(
    () => new URLSearchParams(window.location.search).has("sessionId"),
    [],
  );

  /**
   * A desktop app should not show a browser's context menu over its own
   * chrome. Installed here rather than per screen because the gesture is
   * global and so is the cause: a session keeps a focused, editable element
   * to own keyboard input, and a webview offers the editing menu for the
   * FOCUSED element rather than the clicked one, so a stray Ctrl+click or
   * two-finger tap anywhere produced a Paste menu over the tabs. Real text
   * fields keep theirs, see `lib/contextMenu.ts`.
   */
  useEffect(() => installContextMenuSuppressor(), []);

  return (
    <SettingsProvider>
      <ToastProvider>
        {isSession ? (
          <SessionWindow />
        ) : (
          <HostsProvider>
            <DiscoveryProvider>
              <SessionsProvider>
                {/*
                  Outside the tabs, because a lease is a fact about a machine
                  rather than about the pane it happens to be shown in, and the
                  plane may hold one for a limb this window has never mounted.
                */}
                <AgentActivityProvider>
                  <TabsProvider>
                    <MainShell />
                    <ToastShelf />
                  </TabsProvider>
                </AgentActivityProvider>
              </SessionsProvider>
            </DiscoveryProvider>
          </HostsProvider>
        )}
      </ToastProvider>
    </SettingsProvider>
  );
}

function MainShell(): ReactNode {
  const { settings } = useSettings();
  const [prefsOpen, setPrefsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [autoAddDiscoveredId, setAutoAddDiscoveredId] = useState<string | null>(null);
  const [skippedOnboarding, setSkippedOnboarding] = useState(false);
  const {
    tabs,
    summaries,
    activeId,
    activeTab,
    close,
    closePane,
    select,
    selectRelative,
    selectIndex,
    selectSession,
    closeActive,
    split,
    arrange,
    toggleZoom,
    moveFocus,
    cycleFocus,
    evenOut,
  } = useTabs();
  const { driving } = useAgentActivity();

  /**
   * Which tabs hold a machine an agent is driving.
   *
   * Worked out here rather than in `TabsContext` because a tab does not know
   * about leases and a lease does not know about tabs; this is the one place
   * that already has both. Empty, and free, until the plane is on.
   */
  const drivenTabIds = useMemo(
    () =>
      new Set(
        tabs
          .filter((t) => panes(t.root).some((p) => p.sessionId !== null && driving(p.sessionId)))
          .map((t) => t.id),
      ),
    [tabs, driving],
  );

  // `select` already refuses an id that is not open, so this only differs from
  // `activeId === null` for a tab closed in the same render. Belt and braces
  // for the one state with no way out: no pane in front, and no strip either.
  const libraryInFront = activeId === null || !tabs.some((t) => t.id === activeId);
  // Read inside the menu listener, which is registered once.
  const libraryInFrontRef = useRef(libraryInFront);
  libraryInFrontRef.current = libraryInFront;
  const activeTabRef = useRef(activeTab);
  activeTabRef.current = activeTab;

  // menu.rs emits `menu://action` for every custom item and expects the
  // frontend to route it. Items handled natively there (fullscreen, the Help
  // URL) never reach this listener.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      if (id === "menu:about") setAboutOpen(true);
      else if (id === "menu:settings") setPrefsOpen(true);
      else if (id === "menu:tab:next") selectRelative(1);
      else if (id === "menu:tab:prev") selectRelative(-1);
      else if (id === "menu:tab:close") closeActive();
      else if (id === "menu:tab:library") select(null);
      // The pane items belong to the shell rather than to a session, the same
      // way the tab items do: they act on the layout around a session, and the
      // session in front has no idea what shape it is being shown in.
      else if (id === "menu:pane:split-right") split("row");
      else if (id === "menu:pane:split-down") split("column");
      else if (id === "menu:pane:next") cycleFocus(1);
      else if (id === "menu:pane:prev") cycleFocus(-1);
      // The pane count rides in the id, so one branch covers every grid size.
      else if (id.startsWith("menu:pane:grid:")) {
        const count = Number(id.slice("menu:pane:grid:".length));
        if (Number.isFinite(count) && count > 0) arrange(count);
      }
      else if (id === "menu:pane:zoom") {
        const tab = activeTabRef.current;
        if (tab) toggleZoom(tab.id, tab.focusedPaneId);
      } else if (id === "menu:pane:even") {
        const tab = activeTabRef.current;
        if (tab) evenOut(tab.id);
      } else if (id === "menu:pane:close") {
        const tab = activeTabRef.current;
        if (tab) closePane(tab.id, tab.focusedPaneId);
      }
      else if (id === "menu:hide-toolbar" && libraryInFrontRef.current) {
        // A session mounted in a tab lives in THIS window and hears the same
        // event, so only one of us may act on it: with a session in front it
        // is that session's, and toggling here as well would land back on the
        // value it started from.
        writeBoolPref(PREF_HIDE_TOOLBAR, !readBoolPref(PREF_HIDE_TOOLBAR, false));
        syncMenuState();
      }
    }).then((fn) => {
      // `safeListen` resolves a turn later than the effect that started it, so
      // a cleanup that has already run left `unlisten` to be assigned after
      // the fact and the listener stayed registered for good. Every re-run
      // then added another, and each one acted on the same event: harmless
      // for "open the About dialog", but it made a toggle like
      // `menu:hide-toolbar` fire twice and land back where it started.
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [selectRelative, closeActive, select, split, cycleFocus, evenOut, closePane, arrange, toggleZoom]);

  /**
   * With the library in front there is no session for the View and Session
   * menus to act on, so they are greyed out rather than left showing the ticks
   * of whichever session was last looked at. A session pushes its own state
   * over this the moment it takes the focus.
   */
  useEffect(() => {
    if (!libraryInFront) return;
    syncMenuState();
    window.addEventListener("focus", syncMenuState);
    return () => window.removeEventListener("focus", syncMenuState);
  }, [libraryInFront]);

  /**
   * The shell's own keyboard: tabs, and the panes inside them.
   *
   * Handed to every mounted viewer as well as listened for here, because the
   * remote keyboard hook sits on `window` in the capture phase: once a session
   * is in front, this listener never sees the keystroke, and the viewer's
   * `onAppHotkey` is the only way through. It fires even with shortcut
   * pass-through switched on, deliberately, the same way the toolbar's own
   * recall shortcut does: leaving no way back out of a tab, or out of a pane,
   * would be a trap.
   *
   * The pane chords all carry Alt on top of the platform modifier. The
   * unadorned pairs are spoken for (Cmd/Ctrl+Shift+W closes a tab, Shift+D
   * disconnects), and a chord that closed a pane when the user meant to close
   * the tab is the kind of near miss that costs a connection.
   *
   * In the app itself the pane chords are NOT handled here: they are native
   * menu accelerators, and `menu.rs` explains why that is the only thing that
   * works while a session holds the keyboard. Handling them in both places
   * would run each command twice wherever the OS lets the keystroke through to
   * the page as well. The browser dev build has no native menu, so there it is
   * this listener or nothing.
   */
  const appHotkey = useCallback(
    (e: KeyboardEvent): boolean => {
      // This is reached twice for one keystroke: once through a focused
      // session's keyboard hook, which is where `onAppHotkey` leads, and once
      // through the listener below. Whichever gets there first calls
      // `preventDefault`, so this is how the other one knows to stand down.
      // The guard lives here rather than in the listener because the two do
      // not arrive in a fixed order: the hook sits on `window` in the capture
      // phase and wins for a real keystroke, but an event dispatched at
      // `window` itself is AT_TARGET for both, and then registration order
      // decides. Pane commands are not idempotent, so "usually first" is not
      // good enough.
      if (e.defaultPrevented) return false;
      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return false;

      if (!e.altKey) {
        if (e.key >= "1" && e.key <= "9") {
          selectIndex(Number(e.key) - 1);
          return true;
        }
        return false;
      }

      if (inTauri()) return false;

      // With the library in front there is no layout to act on. Returning
      // false rather than swallowing the chord matters: Cmd/Ctrl+Alt with an
      // arrow key means something on both macOS and Windows, and eating it to
      // do nothing is worse than not binding it at all.
      const tab = activeTabRef.current;
      if (!tab) return false;

      switch (e.code) {
        case "KeyD":
          // Alt+Shift+D goes down, Alt+D goes right: one chord for "divide",
          // and the shift says which way, rather than two to remember.
          split(e.shiftKey ? "column" : "row");
          return true;
        case "KeyW":
          closePane(tab.id, tab.focusedPaneId);
          return true;
        case "Equal":
          evenOut(tab.id);
          return true;
        case "KeyZ":
          toggleZoom(tab.id, tab.focusedPaneId);
          return true;
        case "ArrowLeft":
          moveFocus("left");
          return true;
        case "ArrowRight":
          moveFocus("right");
          return true;
        case "ArrowUp":
          moveFocus("up");
          return true;
        case "ArrowDown":
          moveFocus("down");
          return true;
        case "BracketRight":
          cycleFocus(1);
          return true;
        case "BracketLeft":
          cycleFocus(-1);
          return true;
        default:
          return false;
      }
    },
    [selectIndex, split, closePane, evenOut, moveFocus, cycleFocus, toggleZoom],
  );

  /**
   * The shell's own listener, for keystrokes no session is holding.
   *
   * With a session focused this is the second of two routes to the same
   * callback, and `appHotkey` refuses an event that has already been acted on,
   * so the command runs once however the two happen to be ordered.
   */
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (appHotkey(e)) e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [appHotkey]);

  // The session toolbar is positioned against the viewport, not against its
  // pane, so it has to be told how much of the top the tab strip is using or
  // it lands on the tabs and takes the clicks meant for them.
  const stripRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = stripRef.current;
    const root = document.documentElement;
    if (!el) {
      root.style.removeProperty("--session-inset-top");
      return;
    }
    const apply = (): void => {
      root.style.setProperty("--session-inset-top", `${el.offsetHeight}px`);
    };
    apply();
    // The strip grows a scrollbar, and wraps differently at narrow widths.
    const ro = new ResizeObserver(apply);
    ro.observe(el);
    return () => {
      ro.disconnect();
      root.style.removeProperty("--session-inset-top");
    };
  }, [tabs.length > 0]);

  // The window title follows whatever is in front, the way it would if that
  // session had a window of its own. In a split that is the focused pane's
  // machine, which is what the strip is labelled with too.
  useEffect(() => {
    const summary = summaries.find((t) => t.id === activeId);
    document.title = summary ? summary.title : "DeskVNCViewer";
  }, [summaries, activeId]);

  const showOnboarding = !settings.onboarded && !skippedOnboarding;

  if (showOnboarding) {
    return (
      <Onboarding
        onDone={() => setSkippedOnboarding(true)}
        onAddDiscovered={(id) => {
          setAutoAddDiscoveredId(id);
          setSkippedOnboarding(true);
        }}
      />
    );
  }

  return (
    <div className="flex h-full flex-col">
      {/*
        The strip appears as soon as anything is open in a tab, whatever the
        preference says now: switching back to separate windows must not strand
        the sessions already running in here with no way to reach them.
      */}
      {tabs.length > 0 ? (
        <div ref={stripRef}>
          <TabStrip
            tabs={summaries}
            activeId={activeId}
            onSelect={select}
            onClose={close}
            onSelectRelative={selectRelative}
            drivenTabIds={drivenTabIds}
          />
        </div>
      ) : null}

      {/*
        Two surfaces, not one per tab: the library, and the one the sessions
        are laid out on. `SplitView` mounts every session in every tab at once
        and positions each one from its tab's layout tree, which is what lets a
        session be dragged from one pane to another, or from one tab to
        another, without its connection noticing. See that file's header.
      */}
      <div className="relative min-h-0 flex-1">
        <Pane visible={libraryInFront} id={tabPanelId(null)} label="Library">
          <Library
            onOpenPreferences={() => setPrefsOpen(true)}
            onOpenAbout={() => setAboutOpen(true)}
            autoAddDiscoveredId={autoAddDiscoveredId}
            onAutoAddHandled={() => setAutoAddDiscoveredId(null)}
          />
        </Pane>
        <SplitView onAppHotkey={appHotkey} />
      </div>

      {/*
        Every machine an agent is driving, across every tab, in one row.

        Below the panes rather than over them: the grid only ever draws the tab
        in front, so anything painted on it can show a subset of the work at
        best, and the whole point of this strip is that eight machines being
        driven at once are visible at once. It takes no height at all until a
        lease is actually held, which is why it needs no toggle and cannot be
        put away, and why a person who never turns the plane on will never see
        it. See the file header of `AgentWall`.
      */}
      <AgentWall onShowSession={selectSession} />

      {prefsOpen ? <Preferences onClose={() => setPrefsOpen(false)} /> : null}
      {aboutOpen ? <About onClose={() => setAboutOpen(false)} /> : null}
    </div>
  );
}
