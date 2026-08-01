import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
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
import { TabStrip } from "./components/TabStrip";
import { ToastShelf } from "./components/primitives";
import { safeListen } from "./lib/tauri";

export default function App(): ReactNode {
  const isSession = useMemo(
    () => new URLSearchParams(window.location.search).has("sessionId"),
    [],
  );

  return (
    <SettingsProvider>
      <ToastProvider>
        {isSession ? (
          <Session />
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

  // menu.rs emits `menu://action` for every custom item and expects the
  // frontend to route it. Items handled natively there (fullscreen, the Help
  // URL) never reach this listener.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      if (id === "menu:about") setAboutOpen(true);
      else if (id === "menu:settings") setPrefsOpen(true);
      else if (id === "menu:tab:next") selectRelative(1);
      else if (id === "menu:tab:prev") selectRelative(-1);
      else if (id === "menu:tab:close") closeActive();
      else if (id === "menu:tab:library") select(null);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [selectRelative, closeActive, select]);

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

  const libraryInFront = activeId === null;

  return (
    <div className="flex h-full flex-col">
      {/*
        The strip appears as soon as anything is open in a tab, whatever the
        preference says now: switching back to separate windows must not strand
        the sessions already running in here with no way to reach them.
      */}
      {tabs.length > 0 ? (
        <TabStrip
          tabs={tabs}
          activeId={activeId}
          onSelect={select}
          onClose={close}
          onSelectRelative={selectRelative}
        />
      ) : null}

      {/*
        Every pane stays mounted and laid out; only the one in front is
        painted. `visibility` rather than `display: none` on purpose: a hidden
        pane still has to have a size, or its canvas would collapse to zero,
        take the WebGL viewport with it, and have to rebuild the whole
        framebuffer every time the user came back to that tab.
      */}
      <div className="relative min-h-0 flex-1">
        <Pane visible={libraryInFront}>
          <Library
            onOpenPreferences={() => setPrefsOpen(true)}
            onOpenAbout={() => setAboutOpen(true)}
            autoAddDiscoveredId={autoAddDiscoveredId}
            onAutoAddHandled={() => setAutoAddDiscoveredId(null)}
          />
        </Pane>
        {tabs.map((tab) => (
          <Pane key={tab.id} visible={tab.id === activeId}>
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

function Pane({ visible, children }: { visible: boolean; children: ReactNode }): ReactNode {
  return (
    <div
      className="absolute inset-0"
      style={{ visibility: visible ? "visible" : "hidden" }}
      aria-hidden={visible ? undefined : true}
      inert={visible ? undefined : true}
    >
      {children}
    </div>
  );
}
