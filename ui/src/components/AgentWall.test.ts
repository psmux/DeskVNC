/**
 * Issue #52: the agent strip and the pane header must keep one height whether
 * or not an agent is driving.
 *
 * Both take their height out of the session's area, and with "resize remote to
 * fit" a change in that area resizes the remote desktop. An agent that took a
 * screenshot, started driving, and then clicked, clicked a desktop of a
 * different size from the one it had looked at.
 *
 * jsdom lays nothing out, so this holds the strip to the height it pins on
 * itself. The dev build measured in a headless browser is the other half of
 * the evidence (see the pull request).
 */
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PLANE_OFF, type AgentActivity, type PlaneView } from "../lib/agentActivity";
import { PREF_COMPACT_AGENT_ROW, PREF_HIDE_AGENT_STATUS, prefStorageKey } from "../lib/prefs";
import { paneHeaderShown } from "./PaneHeader";

const activity = vi.hoisted(() => ({
  current: null as unknown,
}));

vi.mock("../state/AgentActivityContext", () => ({
  useAgentActivity: () => activity.current,
}));

// Imported after the mock is declared; vitest hoists `vi.mock` above it.
import { AgentWall } from "./AgentWall";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const DRIVEN: AgentActivity = {
  sessionId: "s1",
  machine: { label: "build-01", address: "10.0.0.4", port: 5900, protocol: "vnc" },
  holder: { kind: "agent", name: "agent-a", since: Date.now() - 4000 },
  intent: {
    id: "i1",
    kind: "pointer.click",
    summary: "(612, 448)",
    outcome: "in-flight",
    remote: { surface: "terminal", text: "a line the far side printed" },
  },
  preempted: null,
  firstSeen: 1,
} as unknown as AgentActivity;

const ON: PlaneView = { ...PLANE_OFF, on: true, agents: 1 };

function setActivity(wall: AgentActivity[]): void {
  activity.current = {
    wall,
    count: wall.length,
    plane: { ...ON, driving: wall.length },
    stopAgent: () => {},
    stopAll: () => {},
  };
}

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  localStorage.clear();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  localStorage.clear();
});

/** The strip's own height, as it pins it, or null when there is no strip. */
function stripHeight(wall: AgentActivity[]): string | null {
  setActivity(wall);
  act(() => root.render(createElement(AgentWall, { onShowSession: () => {} })));
  const strip = host.querySelector<HTMLElement>('[role="region"][aria-label="Agent activity"]');
  return strip ? strip.style.height : null;
}

describe("the agent strip keeps one height (issue #52)", () => {
  const cases: Array<[string, Record<string, string>]> = [
    ["with the cards", {}],
    ["with the counts hidden", { [PREF_HIDE_AGENT_STATUS]: "1" }],
    ["kept to one line", { [PREF_COMPACT_AGENT_ROW]: "1" }],
  ];

  for (const [name, prefs] of cases) {
    it(`is the same height idle and driving, ${name}`, () => {
      for (const [k, v] of Object.entries(prefs)) localStorage.setItem(prefStorageKey(k), v);
      const idle = stripHeight([]);
      const driving = stripHeight([DRIVEN]);
      expect(idle).toMatch(/^\d+px$/);
      expect(driving).toBe(idle);
    });
  }

  it("is shorter kept to one line than with the cards", () => {
    const full = parseInt(stripHeight([DRIVEN]) ?? "0", 10);
    localStorage.setItem(prefStorageKey(PREF_COMPACT_AGENT_ROW), "1");
    act(() => root.unmount());
    root = createRoot(host);
    const compact = parseInt(stripHeight([DRIVEN]) ?? "0", 10);
    expect(compact).toBeGreaterThan(0);
    expect(compact).toBeLessThan(full);
  });

  it("still takes no room at all with the plane off", () => {
    activity.current = {
      wall: [],
      count: 0,
      plane: PLANE_OFF,
      stopAgent: () => {},
      stopAll: () => {},
    };
    act(() => root.render(createElement(AgentWall, { onShowSession: () => {} })));
    expect(host.querySelector('[role="region"]')).toBeNull();
  });
});

describe("a lone pane's header (issue #52)", () => {
  it("is there idle and driving while the plane is on", () => {
    expect(paneHeaderShown(false, true, null)).toBe(true);
    expect(paneHeaderShown(false, true, DRIVEN)).toBe(true);
  });

  it("stays away with the plane off and nobody driving", () => {
    expect(paneHeaderShown(false, false, null)).toBe(false);
  });

  it("is always there in a split", () => {
    expect(paneHeaderShown(true, false, null)).toBe(true);
  });
});
