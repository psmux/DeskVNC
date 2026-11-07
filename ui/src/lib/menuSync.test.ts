import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";

const invoked: { cmd: string; args: unknown }[] = [];
vi.mock("./tauri", () => ({
  safeInvoke: (cmd: string, args: unknown) => {
    invoked.push({ cmd, args });
    return Promise.resolve(null);
  },
}));

import { useTerminalMenu } from "./menuSync";

interface Pushed {
  update: { hideToolbar: boolean; session: { filesAvailable: boolean; terminal?: boolean } | null };
}

function pushes(): Pushed[] {
  return invoked.filter((c) => c.cmd === "sync_session_menu").map((c) => c.args as Pushed);
}

function Probe({ owns }: { owns: boolean }): null {
  useTerminalMenu(owns);
  return null;
}

// An SSH tab never told the native menu it was in front, so the menu kept the
// last desktop tab's state and offered File Transfer, which then did nothing.
describe("useTerminalMenu", () => {
  let root: Root | null = null;
  let host: HTMLDivElement | null = null;
  beforeEach(() => {
    invoked.length = 0;
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
  });
  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
  });

  it("tells the menu an SSH tab in front has no file transfer", () => {
    act(() => root!.render(createElement(Probe, { owns: true })));
    const sent = pushes();
    expect(sent).toHaveLength(1);
    expect(sent[0].update.session).not.toBeNull();
    expect(sent[0].update.session!.filesAvailable).toBe(false);
    expect(sent[0].update.session!.terminal).toBe(true);
  });

  it("says it again when the window takes the focus back", () => {
    act(() => root!.render(createElement(Probe, { owns: true })));
    window.dispatchEvent(new Event("focus"));
    expect(pushes()).toHaveLength(2);
  });

  it("stays quiet from a pane that is not in front", () => {
    act(() => root!.render(createElement(Probe, { owns: false })));
    window.dispatchEvent(new Event("focus"));
    expect(pushes()).toHaveLength(0);
  });

  it("speaks up when the tab is brought to the front", () => {
    act(() => root!.render(createElement(Probe, { owns: false })));
    act(() => root!.render(createElement(Probe, { owns: true })));
    expect(pushes()).toHaveLength(1);
  });
});
