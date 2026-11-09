/**
 * Dev harness for the session screen: `npx vite mobile/ui/src/session/dev`.
 * Runs SessionScreen against the fake Api in fakeApi.ts. See that file for
 * the query string scenarios.
 */
import { StrictMode, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { SessionScreen } from "../SessionScreen";
import { makeFakeApi } from "./fakeApi";

function App() {
  const api = useMemo(() => makeFakeApi(), []);
  const target = useMemo(() => ({ kind: "saved" as const, hostId: "h1" }), []);
  const [open, setOpen] = useState(true);
  if (!open) {
    return (
      <div style={{ color: "#fff", font: "18px system-ui", padding: 40 }}>
        Left the session. <button onClick={() => setOpen(true)}>Connect again</button>
      </div>
    );
  }
  return <SessionScreen api={api} target={target} title="Office PC" onExit={() => setOpen(false)} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
