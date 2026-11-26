import { act, createElement, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { TabsProvider, useTabs } from "./TabsContext";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let root: Root;
let tabs: ReturnType<typeof useTabs>;

function Probe(): ReactNode {
  tabs = useTabs();
  return null;
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  act(() => root.render(createElement(TabsProvider, null, createElement(Probe))));
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

describe("saving a tab's session as a host", () => {
  it("makes the session the saved host's and names the tab after it", () => {
    act(() =>
      tabs.open("s1", {
        sessionId: "s1",
        profileId: null,
        address: "192.0.2.10",
        port: 5900,
        name: "192.0.2.10",
        protocol: "vnc",
      }),
    );
    expect(tabs.summaries[0]).toMatchObject({ title: "192.0.2.10", sessionId: "s1" });

    act(() => tabs.bindHost("s1", "h1", "Studio"));

    const session = tabs.sessions.s1;
    expect(session.params).toMatchObject({
      sessionId: "s1",
      profileId: "h1",
      name: "Studio",
      address: "192.0.2.10",
      port: 5900,
      protocol: "vnc",
    });
    expect(tabs.summaries[0].title).toBe("Studio");
  });

  it("keeps the tab's title when the shell adopted the session without a name", () => {
    act(() =>
      tabs.open("s2", {
        sessionId: "s2",
        profileId: null,
        address: "192.0.2.11",
        port: 5900,
        name: "192.0.2.11",
        protocol: "vnc",
      }),
    );
    act(() => tabs.setTitle("s2", "Front desk"));
    act(() => tabs.bindHost("s2", "h2"));
    expect(tabs.sessions.s2.params.profileId).toBe("h2");
    expect(tabs.summaries[0].title).toBe("Front desk");
  });

  it("does nothing for a session that is not open", () => {
    const before = tabs.sessions;
    act(() => tabs.bindHost("gone", "h1", "Studio"));
    expect(tabs.sessions).toBe(before);
  });
});
