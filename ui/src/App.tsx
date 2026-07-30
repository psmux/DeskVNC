import { useEffect, useMemo, useState, type ReactNode } from "react";
import { SettingsProvider, useSettings } from "./state/SettingsContext";
import { ToastProvider } from "./state/ToastContext";
import { HostsProvider } from "./state/HostsContext";
import { DiscoveryProvider } from "./state/DiscoveryContext";
import { SessionsProvider } from "./state/SessionsContext";
import { Library } from "./screens/Library";
import { Session } from "./screens/Session";
import { Preferences } from "./screens/Preferences";
import { About } from "./screens/About";
import { Onboarding } from "./screens/Onboarding";
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
                <MainShell />
                <ToastShelf />
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

  // menu.rs emits `menu://action` for every custom item and expects the
  // frontend to route it. Items handled natively there (fullscreen, the Help
  // URL) never reach this listener.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      if (id === "menu:about") setAboutOpen(true);
      else if (id === "menu:settings") setPrefsOpen(true);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, []);

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
    <>
      <Library
        onOpenPreferences={() => setPrefsOpen(true)}
        onOpenAbout={() => setAboutOpen(true)}
        autoAddDiscoveredId={autoAddDiscoveredId}
        onAutoAddHandled={() => setAutoAddDiscoveredId(null)}
      />
      {prefsOpen ? <Preferences onClose={() => setPrefsOpen(false)} /> : null}
      {aboutOpen ? <About onClose={() => setAboutOpen(false)} /> : null}
    </>
  );
}
