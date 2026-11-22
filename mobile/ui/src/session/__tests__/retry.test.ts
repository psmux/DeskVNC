// @vitest-environment jsdom
/**
 * Try again after the computer refused a name or password.
 *
 * A remembered password the server turned down used to go out again on every
 * Try again, with no prompt in between: a server log showed four refusals in
 * a row. Now the refusal forgets the saved password, so the next attempt
 * reaches the computer with none, the computer asks, and the sign in sheet
 * opens with the user name filled in.
 */
import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Api, ConnectTarget, CredentialRequest, SessionEvent } from "../../api/contract";
import { isSignInRefusal } from "../status";
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

const REFUSED_VNC = "The password was not accepted.";
const REFUSED_RDP = "authentication failed: The user name or password is incorrect.";
const NO_ROUTE = "Connection refused by 192.0.2.10:5900. The VNC server may not be running on that port.";

const ASK: CredentialRequest = {
  method: "Network Level Authentication (NTLM)",
  kind: "username-and-password",
  attempt: 1,
  error: null,
  truncatesPassword: false,
  usernameHint: "alice",
};

/** What each connect does, in order: end with a reason, or ask for a password. */
type Script = ({ refuse: string } | { ask: CredentialRequest })[];

function fakeApi(script: Script) {
  const calls: { connect: ConnectTarget[]; secret: unknown[][]; creds: unknown[][]; order: string[] } = {
    connect: [],
    secret: [],
    creds: [],
    order: [],
  };
  let n = 0;
  let releaseSecret: () => void = () => {};
  const api = {
    sessionConnect: vi.fn(async (target: ConnectTarget, _f: unknown, onEvent: (e: SessionEvent) => void) => {
      const step = script[n];
      const id = `s${++n}`;
      calls.connect.push(target);
      calls.order.push("connect");
      queueMicrotask(() => {
        if (!step) return;
        if ("refuse" in step) {
          onEvent({ sessionId: id, type: "state-changed", state: { state: "disconnected", reason: step.refuse, can_retry: false } });
        } else {
          onEvent({ sessionId: id, type: "credentials-required", request: step.ask });
        }
      });
      return { sessionId: id };
    }),
    hostsSetSecret: vi.fn((...args: unknown[]) => {
      calls.secret.push(args);
      calls.order.push("forget");
      // Held until the test lets it finish, to prove Try again waits for it.
      return new Promise<void>((resolve) => {
        releaseSecret = () => {
          calls.order.push("forgotten");
          resolve();
        };
      });
    }),
    sessionCredentials: vi.fn(async (...args: unknown[]) => {
      calls.creds.push(args);
    }),
    sessionDisconnect: vi.fn(async () => {}),
    sessionQuality: vi.fn(async () => {}),
    sessionInput: vi.fn(async () => {}),
    sessionSnapshot: vi.fn(async () => {}),
    sessionTrust: vi.fn(async () => {}),
    localNetworkState: vi.fn(async () => "granted"),
  } as unknown as Api;
  return { api, calls, releaseSecret: () => releaseSecret() };
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

async function mount(api: Api, target: ConnectTarget): Promise<{ current: RemoteSession }> {
  const out = {} as { current: RemoteSession };
  function Probe() {
    out.current = useRemoteSession(api, target);
    return null;
  }
  root = createRoot(host!);
  await act(async () => root!.render(createElement(Probe)));
  await act(async () => out.current.attachCanvas(document.createElement("canvas")));
  await settle();
  return out;
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await act(async () => {});
}

describe("which errors are a refused sign in", () => {
  it("counts a wrong password or user name, from VNC and from RDP", () => {
    expect(isSignInRefusal(REFUSED_VNC)).toBe(true);
    expect(isSignInRefusal(REFUSED_RDP)).toBe(true);
    expect(isSignInRefusal("authentication failed: The remote computer refused the sign in (0xc000006a).")).toBe(true);
  });

  it("does not count a network failure or a declined key", () => {
    expect(isSignInRefusal(NO_ROUTE)).toBe(false);
    expect(isSignInRefusal("The computer did not respond. It may be asleep or unreachable.")).toBe(false);
    expect(isSignInRefusal("This computer's identity was not trusted, so no name or password was sent to it.")).toBe(false);
    expect(isSignInRefusal(null)).toBe(false);
    // The password was right; the Mac would not let that account share.
    expect(isSignInRefusal("The Mac accepted the password but did not let this account share its screen.")).toBe(false);
  });
});

describe("Try again after a refused sign in", () => {
  it("forgets the saved password, then asks with the user name filled in", async () => {
    const { api, calls, releaseSecret } = fakeApi([{ refuse: REFUSED_RDP }, { ask: ASK }]);
    const s = await mount(api, { kind: "saved", hostId: "h1" });

    expect(s.current.phase).toBe("error");
    // Password cleared, user name left as it is.
    expect(calls.secret).toEqual([["h1", null, ""]]);

    await act(async () => s.current.reconnect());
    await settle();
    // The next attempt waits for the vault, or it would read the old password.
    expect(calls.connect).toHaveLength(1);
    releaseSecret();
    await settle();
    expect(calls.order).toEqual(["connect", "forget", "forgotten", "connect"]);

    expect(s.current.credentials?.usernameHint).toBe("alice");
    await act(async () => s.current.answerCredentials("alice", "new password", true));
    expect(calls.creds).toEqual([["s2", "alice", "new password", true]]);
  });

  it("leaves Remember off when the person turns it off", async () => {
    const { api, calls, releaseSecret } = fakeApi([{ refuse: REFUSED_VNC }, { ask: { ...ASK, kind: "password-only", usernameHint: null } }]);
    const s = await mount(api, { kind: "saved", hostId: "h1" });
    await act(async () => s.current.reconnect());
    releaseSecret();
    await settle();
    await act(async () => s.current.answerCredentials(null, "new password", false));
    expect(calls.creds).toEqual([["s2", null, "new password", false]]);
  });

  it("does not send a typed in password again on a connection that was not saved", async () => {
    const { api, calls } = fakeApi([{ refuse: REFUSED_VNC }, { ask: ASK }]);
    const target: ConnectTarget = { kind: "adhoc", protocol: "rdp", address: "192.0.2.10", port: 3389, username: "alice", password: "old" };
    const s = await mount(api, target);
    await act(async () => s.current.reconnect());
    await settle();
    expect(calls.secret).toEqual([]);
    expect(calls.connect[1]).toEqual({ ...target, password: undefined });
    expect(s.current.credentials?.usernameHint).toBe("alice");
  });

  it("keeps the saved password after a network failure", async () => {
    const { api, calls } = fakeApi([{ refuse: NO_ROUTE }, { refuse: NO_ROUTE }]);
    const s = await mount(api, { kind: "saved", hostId: "h1" });
    expect(s.current.phase).toBe("error");
    await act(async () => s.current.reconnect());
    await settle();
    expect(calls.secret).toEqual([]);
    expect(calls.connect).toEqual([
      { kind: "saved", hostId: "h1" },
      { kind: "saved", hostId: "h1" },
    ]);
  });
});
