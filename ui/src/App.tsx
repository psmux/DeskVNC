import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { SettingsProvider, useSettings } from "./state/SettingsContext";
import { ToastProvider } from "./state/ToastContext";
import { HostsProvider } from "./state/HostsContext";
import { DiscoveryProvider } from "./state/DiscoveryContext";
import { SessionsProvider } from "./state/SessionsContext";
import { TabsProvider, useTabs } from "./state/TabsContext";
import { Library } from "./screens/Library";
import { Session } from "./screens/Session";
import { Preferences } from "./screens/Preferences";
import { About } from "./screens/About";
import { Onboarding } from "./screens/Onboarding";
import { TabStrip, tabPanelId } from "./components/TabStrip";
import { Pane } from "./components/Pane";
import { ToastShelf } from "./components/primitives";
import { safeListen } from "./lib/tauri";
import { syncSessionMenu } from "./lib/menuSync";
import { PREF_HIDE_TOOLBAR, readBoolPref, writeBoolPref } from "./lib/prefs";

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

  return (
    <SettingsProvider>
      <ToastProvider>
        {isSession ? (
          <SessionWindow />
        ) : (
          <HostsProvider>
            <DiscoveryProvider>
              <SessionsProvider>
                <TabsProvider>
                  <MainShell />
                  <ToastShelf />
                </TabsProvider>
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
    activeId,
    close,
    select,
    selectRelative,
    selectIndex,
    closeActive,
    setTitle,
    setState,
  } = useTabs();

  // `select` already refuses an id that is not open, so this only differs from
  // `activeId === null` for a tab closed in the same render. Belt and braces
  // for the one state with no way out: no pane in front, and no strip either.
  const libraryInFront = activeId === null || !tabs.some((t) => t.id === activeId);
  // Read inside the menu listener, which is registered once.
  const libraryInFrontRef = useRef(libraryInFront);
  libraryInFrontRef.current = libraryInFront;

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
  }, [selectRelative, closeActive, select]);

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
   * Cmd/Ctrl+1…9 selects a tab by position, 1 being the library.
   *
   * Handed to every mounted viewer as well as listened for here, because the
   * remote keyboard hook sits on `window` in the capture phase: once a session
   * is in front, this listener never sees the keystroke, and the viewer's
   * `onAppHotkey` is the only way through. It fires even with shortcut
   * pass-through switched on, deliberately, the same way the toolbar's own
   * recall shortcut does: leaving no way back out of a tab would be a trap.
   */
  const tabHotkey = useCallback(
    (e: KeyboardEvent): boolean => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return false;
      if (e.key < "1" || e.key > "9") return false;
      selectIndex(Number(e.key) - 1);
      return true;
    },
    [selectIndex],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (tabHotkey(e)) e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [tabHotkey]);

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
  // session had a window of its own.
  useEffect(() => {
    const tab = tabs.find((t) => t.id === activeId);
    document.title = tab ? tab.title : "DeskVNCViewer";
  }, [tabs, activeId]);

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
            tabs={tabs}
            activeId={activeId}
            onSelect={select}
            onClose={close}
            onSelectRelative={selectRelative}
          />
        </div>
      ) : null}

      {/*
        Every pane stays mounted and laid out; only the one in front is
        painted. `visibility` rather than `display: none` on purpose: a hidden
        pane still has to have a size, or its canvas would collapse to zero,
        take the WebGL viewport with it, and have to rebuild the whole
        framebuffer every time the user came back to that tab.
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
        {tabs.map((tab) => (
          <Pane
            key={tab.id}
            visible={tab.id === activeId}
            id={tabPanelId(tab.id)}
            label={tab.title}
          >
            <Session
              params={tab.params}
              embedded
              active={tab.id === activeId}
              onClose={() => close(tab.id)}
              onDesktopName={(name) => setTitle(tab.id, name)}
              onState={(state) => setState(tab.id, state)}
              onAppHotkey={tabHotkey}
            />
          </Pane>
        ))}
      </div>

      {prefsOpen ? <Preferences onClose={() => setPrefsOpen(false)} /> : null}
      {aboutOpen ? <About onClose={() => setAboutOpen(false)} /> : null}
    </div>
  );
}
