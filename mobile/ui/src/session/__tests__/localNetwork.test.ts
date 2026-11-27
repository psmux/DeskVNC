// @vitest-environment jsdom
/**
 * Android 17's local network permission (issue #56).
 *
 * 0.36.5 asked for it once, at launch, and never looked again. A phone where
 * that prompt was missed or refused sat on "Finding the computer" for every
 * computer on its Wi-Fi until the connect timed out, with nothing saying why.
 * Now Rust refuses at once when the permission is missing and the computer
 * is on this network, the session asks with Android's own prompt right after
 * Connect, dials again on a yes, and on a no says how to allow it.
 */
import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Api, ConnectTarget, LocalNetwork, SessionEvent } from "../../api/contract";
import { LOCAL_NETWORK_REFUSED } from "../../api/contract";
import { LOCAL_NETWORK_WORDS, friendlyError, isLocalNetworkRefusal } from "../status";
import { useRemoteSession, type RemoteSession } from "../useRemoteSession";

vi.mock("../render/WebGLRenderer", () => ({
  WebGLRenderer: class {
    onNotice: ((m: string) => void) | null = null;
    start(): void {}
    stop(): void {}
    dispose(): void {}
    markDirty(): void {}
    setRemoteSize(): void {}
    hasFrame(): boolean {
      return false;
    }
  },
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const TIMEOUT = "The computer did not respond. It may be asleep or unreachable.";
const TARGET: ConnectTarget = { kind: "adhoc", protocol: "vnc", address: "192.168.1.20", port: 5900 };

/**
 * A phone where the permission starts as `held`, and the prompt answers with
 * each of `answers` in turn. Rust's check is played by sessionConnect: it
 * refuses while the permission is missing, and `unreachable` makes a connect
 * that gets through time out instead.
 */
function phone(held: LocalNetwork, answers: LocalNetwork[], unreachable = false) {
  let state = held;
  const calls = { connect: 0, ask: 0, settings: 0 };
  const api = {
    sessionConnect: vi.fn(async (_t: ConnectTarget, _f: unknown, onEvent: (e: SessionEvent) => void) => {
      calls.connect += 1;
      if (state === "denied" && !unreachable) throw LOCAL_NETWORK_REFUSED;
      const id = `s${calls.connect}`;
      queueMicrotask(() => {
        if (unreachable) {
          onEvent({ sessionId: id, type: "state-changed", state: { state: "disconnected", reason: TIMEOUT, can_retry: true } });
        } else {
          onEvent({ sessionId: id, type: "state-changed", state: { state: "connected" } });
        }
      });
      return { sessionId: id };
    }),
    localNetworkState: vi.fn(async () => state),
    localNetworkAsk: vi.fn(async () => {
      calls.ask += 1;
      if (state === "denied") state = answers.shift() ?? "denied";
      return state;
    }),
    openAppSettings: vi.fn(async () => {
      calls.settings += 1;
    }),
    sessionDisconnect: vi.fn(async () => {}),
    sessionQuality: vi.fn(async () => {}),
    sessionInput: vi.fn(async () => {}),
    sessionSnapshot: vi.fn(async () => {}),
    hostsSetSecret: vi.fn(async () => {}),
    hostsSetSshSecret: vi.fn(async () => {}),
  } as unknown as Api;
  return { api, calls, allow: () => (state = "granted") };
}

let root: Root | null = null;
let host: HTMLDivElement | null = null;

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

async function mount(api: Api): Promise<{ current: RemoteSession }> {
  const out = {} as { current: RemoteSession };
  function Probe() {
    out.current = useRemoteSession(api, TARGET);
    return null;
  }
  root = createRoot(host!);
  await act(async () => root!.render(createElement(Probe)));
  await act(async () => out.current.attachCanvas(document.createElement("canvas")));
  await settle();
  return out;
}

async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await act(async () => {});
}

describe("the local network refusal", () => {
  it("is told apart from a computer that is off or a refused password", () => {
    expect(isLocalNetworkRefusal(LOCAL_NETWORK_REFUSED)).toBe(true);
    expect(isLocalNetworkRefusal(TIMEOUT)).toBe(false);
    expect(isLocalNetworkRefusal("The password was not accepted.")).toBe(false);
    expect(friendlyError(LOCAL_NETWORK_REFUSED)).toEqual(LOCAL_NETWORK_WORDS);
    expect(LOCAL_NETWORK_WORDS.detail).toContain("Nearby devices");
  });
});

describe("connecting to a computer on this network", () => {
  it("asks with Android's prompt right after Connect and dials again on a yes", async () => {
    const { api, calls } = phone("denied", ["granted"]);
    const s = await mount(api);
    expect(calls.ask).toBe(1);
    expect(calls.connect).toBe(2);
    expect(s.current.phase).toBe("connected");
    expect(s.current.lanBlocked).toBe(false);
  });

  it("says how to allow it on a no, instead of waiting for a timeout", async () => {
    const { api, calls } = phone("denied", ["denied"]);
    const s = await mount(api);
    expect(calls.connect).toBe(1);
    expect(calls.ask).toBe(1);
    expect(s.current.phase).toBe("error");
    expect(s.current.lanBlocked).toBe(true);
    expect(s.current.error).toBe(LOCAL_NETWORK_REFUSED);
    await act(async () => s.current.openSettings());
    expect(calls.settings).toBe(1);
  });

  it("connects on Try again once Nearby devices was allowed in settings", async () => {
    const { api, calls, allow } = phone("denied", ["denied"]);
    const s = await mount(api);
    expect(s.current.lanBlocked).toBe(true);
    allow();
    await act(async () => s.current.reconnect());
    await settle();
    expect(calls.connect).toBe(2);
    expect(s.current.phase).toBe("connected");
    expect(s.current.lanBlocked).toBe(false);
  });

  it("asks again on Try again while the permission is still missing, and never loops", async () => {
    const { api, calls } = phone("denied", ["denied", "denied"]);
    const s = await mount(api);
    await act(async () => s.current.reconnect());
    await settle();
    expect(calls.ask).toBe(2);
    expect(calls.connect).toBe(2);
    expect(s.current.phase).toBe("error");
  });

  it("does not ask when the permission is already held", async () => {
    const { api, calls } = phone("granted", []);
    const s = await mount(api);
    expect(calls.ask).toBe(0);
    expect(s.current.phase).toBe("connected");
  });

  it("names the permission when a connect timed out and the permission is missing", async () => {
    // An address Rust could not place on this network, dropped by Android.
    const { api } = phone("denied", [], true);
    const s = await mount(api);
    expect(s.current.phase).toBe("error");
    expect(s.current.lanBlocked).toBe(true);
  });

  it("leaves a plain timeout alone when the permission is held", async () => {
    const { api } = phone("granted", [], true);
    const s = await mount(api);
    expect(s.current.phase).toBe("error");
    expect(s.current.lanBlocked).toBe(false);
  });
});
