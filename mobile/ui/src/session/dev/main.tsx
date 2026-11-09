/**
 * Dev page for the session screen: `npx vite mobile/ui/src/session/dev`.
 * Runs SessionScreen against the fake Api in fakeApi.ts. See that file for
 * the query string scenarios. With `?demo=1` it runs against the app's own
 * mock Api (src/api) and the built in demo computer instead.
 */
import { StrictMode, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { SessionScreen } from "../SessionScreen";
import { makeFakeApi } from "./fakeApi";
import { createMockApi } from "../../api/mock";
import { withDemo } from "../../api";
import type { ConnectTarget } from "../../api/contract";

const demo = new URLSearchParams(location.search).get("demo") === "1";

function App() {
  const api = useMemo(() => (demo ? withDemo(createMockApi()) : makeFakeApi()), []);
  const target = useMemo<ConnectTarget>(() => (demo ? { kind: "demo" } : { kind: "saved", hostId: "h1" }), []);
  const [open, setOpen] = useState(true);
  if (!open) {
    return (
      <div style={{ color: "#fff", font: "18px system-ui", padding: 40 }}>
        Left the session. <button onClick={() => setOpen(true)}>Connect again</button>
      </div>
    );
  }
  return <SessionScreen api={api} target={target} title={demo ? "Demo computer" : "Office PC"} onExit={() => setOpen(false)} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
