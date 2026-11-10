import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";
import { applyTheme, DEFAULT_PREFS, readPrefs, setPrefs } from "./lib/prefs";

// Browser switches for screenshots: ?reset=1 starts fresh, ?theme=dark forces a theme,
// ?onboarded=1 skips the welcome.
const q = new URLSearchParams(window.location.search);
if (q.get("reset") === "1") setPrefs({ ...DEFAULT_PREFS });
if (q.get("onboarded") === "1") setPrefs({ onboarded: true });
const theme = q.get("theme");
if (theme === "dark" || theme === "light") setPrefs({ theme });
applyTheme(readPrefs().theme);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
