import { act, createElement, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The shell, faked at the IPC boundary.
const calls: { cmd: string; args: Record<string, unknown> }[] = [];

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    calls.push({ cmd, args: args ?? {} });
    if (cmd === "connect_session") return { status: "connected", sessionId: "s1" };
    return null;
  },
  Channel: class {
    onmessage: ((data: unknown) => void) | null = null;
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: async () => () => {},
  emit: async () => {},
}));

const { useSession } = await import("./useSession");
type Params = Parameters<typeof useSession>[0];
type Api = ReturnType<typeof useSession>;

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const bridge = {
  onFrame: () => {},
  onDesktopResize: () => {},
  onCursorShape: () => {},
  onCursorPosition: () => {},
  onPty: () => {},
};

let api: Api;
function Viewer({ params }: { params: Params }): ReactNode {
  api = useSession(params, bridge);
  return null;
}

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  calls.length = 0;
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

async function flush(): Promise<void> {
  for (let i = 0; i < 8; i++) await act(async () => await Promise.resolve());
}

const adHoc: Params = {
  sessionId: "s1",
  profileId: null,
  address: "192.0.2.10",
  port: 5900,
  name: "192.0.2.10",
  protocol: "vnc",
};

const connects = (): Record<string, unknown>[] =>
  calls.filter((c) => c.cmd === "connect_session").map((c) => c.args);

describe("a session saved as a host while it is connected", () => {
  it("keeps its connection, and reconnects as the saved host", async () => {
    act(() => root.render(createElement(Viewer, { params: adHoc })));
    await flush();
    expect(connects()).toHaveLength(1);
    expect(connects()[0].profileId).toBeNull();

    // What "Add to saved hosts" does to the tab's params.
    act(() => root.render(createElement(Viewer, { params: { ...adHoc, profileId: "h1", name: "Studio" } })));
    await flush();
    expect(connects()).toHaveLength(1);
    expect(calls.some((c) => c.cmd === "disconnect_session")).toBe(false);

    // The next connect is the saved host's, so it reads its stored password.
    act(() => api.retryConnect());
    await flush();
    expect(connects()).toHaveLength(2);
    expect(connects()[1].profileId).toBe("h1");
  });
});
