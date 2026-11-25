import { invoke } from "@tauri-apps/api/core";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { insideTauri } from "./api";
import "./index.css";
import { installKeyboardRoom } from "./lib/keyboard";
import { applyTheme, DEFAULT_PREFS, readPrefs, setPrefs, subscribePrefs } from "./lib/prefs";
import { installSafeArea } from "./lib/safeArea";
import { type BarsWindow, installSystemBars } from "./lib/systemBars";

// Browser switches for screenshots: ?reset=1 starts fresh, ?theme=dark forces a theme,
// ?onboarded=1 skips the welcome.
const q = new URLSearchParams(window.location.search);
if (q.get("reset") === "1") setPrefs({ ...DEFAULT_PREFS });
if (q.get("onboarded") === "1") setPrefs({ onboarded: true });
const theme = q.get("theme");
if (theme === "dark" || theme === "light") setPrefs({ theme });
applyTheme(readPrefs().theme);
installSafeArea();
installSystemBars({
  win: window as unknown as BarsWindow,
  readTheme: () => readPrefs().theme,
  onThemeChange: subscribePrefs,
  // Android has MainActivity's bridge; iOS takes it as a command.
  fallback: insideTauri() ? (icons) => void invoke("system_bars", { icons }).catch(() => {}) : undefined,
});
installKeyboardRoom();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
