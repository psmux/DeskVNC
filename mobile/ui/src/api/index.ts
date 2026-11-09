/**
 * Which Api the app talks to.
 *
 * Inside Tauri it is the real one, unless the page was opened with `?mock=1`.
 * In a plain browser it is the mock. Either way the built in demo computer
 * (`{ kind: "demo" }`) is wrapped around it: its session runs in JS from
 * mock.ts, and every later call for that session id stays in JS too, so a
 * store reviewer can try everything with no network.
 */
import type { Api } from "./contract";
import { createMockApi, createMockSessions, type MockSessions } from "./mock";
import { tauriApi } from "./tauri";

export function insideTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function wantsMock(): boolean {
  try {
    return new URLSearchParams(window.location.search).get("mock") === "1";
  } catch {
    return false;
  }
}

/** Route the demo computer to the JS session and everything else to `inner`. */
export function withDemo(inner: Api, demo: MockSessions = createMockSessions(() => null)): Api {
  const pick = (sessionId: string): Api => (demo.has(sessionId) ? (demo as unknown as Api) : inner);
  return {
    ...inner,
    sessionConnect: (target, onFrame, onEvent) =>
      target.kind === "demo" ? demo.sessionConnect(target, onFrame, onEvent) : inner.sessionConnect(target, onFrame, onEvent),
    sessionInput: (id, seq, body) => pick(id).sessionInput(id, seq, body),
    sessionText: (id, text) => pick(id).sessionText(id, text),
    sessionKeyCombo: (id, combo) => pick(id).sessionKeyCombo(id, combo),
    sessionCredentials: (id, u, p, save) => pick(id).sessionCredentials(id, u, p, save),
    sessionTrust: (id, fp, scheme, accept) => pick(id).sessionTrust(id, fp, scheme, accept),
    sessionQuality: (id, q) => pick(id).sessionQuality(id, q),
    sessionClipboard: (id, text) => pick(id).sessionClipboard(id, text),
    // A demo screen is never saved as a card picture.
    sessionSnapshot: (id, rgba, w, h) => (demo.has(id) ? Promise.resolve() : inner.sessionSnapshot(id, rgba, w, h)),
    sessionDisconnect: (id) => pick(id).sessionDisconnect(id),
  };
}

export const usingMock = !insideTauri() || wantsMock();

export const api: Api = withDemo(usingMock ? createMockApi() : tauriApi);

export type { Api } from "./contract";
