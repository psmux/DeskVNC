import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { initLanguage } from "./i18n/preference";
import "./styles/index.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("#root missing");

// The language is read before the first render, so a window never shows a
// frame of English before switching to the language that was chosen. It is
// one quick call to the shell; if it fails, the window opens in English.
void initLanguage()
  .catch(() => undefined)
  .then(() => {
    createRoot(rootEl).render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
  });
