import { AnimatePresence, motion, MotionConfig } from "motion/react";
import { useEffect, useState } from "react";
import { usingMock } from "./api";
import { SideRail, TabBar } from "./components/TabBar";
import { setPrefs, usePrefs } from "./lib/prefs";
import { AddComputer } from "./screens/AddComputer";
import { Computers } from "./screens/Computers";
import { Help } from "./screens/Help";
import { Nearby } from "./screens/Nearby";
import { SessionRoute } from "./screens/SessionRoute";
import { Settings } from "./screens/Settings";
import { Welcome } from "./screens/Welcome";
import { AppProvider, useApp } from "./state/app";

function Shell() {
  const app = useApp();
  const prefs = usePrefs();
  const [welcome, setWelcome] = useState(!prefs.onboarded);

  // Deep links for screenshots and testing in the browser: ?tab=nearby
  useEffect(() => {
    if (!usingMock) return;
    const tab = new URLSearchParams(window.location.search).get("tab");
    if (tab === "computers" || tab === "nearby" || tab === "help" || tab === "settings") app.setTab(tab);
    // Once, at start.
  }, []);

  return (
    <div className="flex h-full">
      <SideRail tab={app.tab} onTab={app.setTab} />
      <main className="pl-safe pr-safe relative h-full min-w-0 flex-1 md:pl-0">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={app.tab}
            className="h-full"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.16 }}
          >
            {app.tab === "computers" && <Computers />}
            {app.tab === "nearby" && <Nearby />}
            {app.tab === "help" && <Help />}
            {app.tab === "settings" && <Settings onShowWelcome={() => setWelcome(true)} />}
          </motion.div>
        </AnimatePresence>
      </main>
      <TabBar tab={app.tab} onTab={app.setTab} />

      <AnimatePresence>{app.wizard && <AddComputer key="wizard" initial={app.wizard} />}</AnimatePresence>
      <SessionRoute />

      <AnimatePresence>
        {app.toast && (
          <motion.div
            className="pointer-events-none fixed inset-x-0 bottom-[calc(5.5rem+env(safe-area-inset-bottom))] z-[60] flex justify-center px-6 md:bottom-8"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
          >
            <p className="rounded-full bg-ink px-5 py-3 text-center font-semibold text-bg shadow-lift">{app.toast}</p>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {welcome && (
          <Welcome
            onDone={() => {
              setPrefs({ onboarded: true });
              setWelcome(false);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

export function App() {
  return (
    <MotionConfig reducedMotion="user">
      <AppProvider>
        <Shell />
      </AppProvider>
    </MotionConfig>
  );
}
