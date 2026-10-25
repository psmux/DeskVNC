import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  TEXT,
  parseRequestsEvent,
  type RequestsState,
} from "../lib/agentRequests";
import { AgentRequestPanel, type AgentRequestPanelProps } from "./AgentRequestPanel";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const NOW = 1_700_000_100_000;

function event(rows: Array<Record<string, unknown>>, muted: unknown = null): RequestsState {
  const parsed = parseRequestsEvent({ type: "requests", requests: rows, muted, personIdleMs: 20_000 });
  if (!parsed) throw new Error("not a requests event");
  return parsed;
}

const claude = {
  sessionId: "s1",
  attachmentId: "att_1",
  agent: "claude-code pid 7 (att_1)",
  reason: "run the nightly build",
  address: "10.0.0.5:5900",
  askedAt: NOW - 12_000,
  freesAt: NOW + 14_000,
};
const codex = {
  sessionId: "s2",
  attachmentId: "att_2",
  agent: "codex pid 9 (att_2)",
  reason: null,
  address: "10.0.0.6:3389",
  askedAt: NOW - 3_000,
  freesAt: NOW + 18_000,
};

let host: HTMLDivElement;
let root: Root;
let props: AgentRequestPanelProps;

function render(state: RequestsState, now = NOW): void {
  props = { ...props, state, now };
  act(() => root.render(createElement(AgentRequestPanel, props)));
}

function button(label: string): HTMLButtonElement {
  const found = [...host.querySelectorAll("button")].filter((b) => b.textContent === label);
  if (found.length === 0) throw new Error(`no button ${label}: ${host.textContent}`);
  return found[0] as HTMLButtonElement;
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  props = {
    state: event([]),
    now: NOW,
    titleOf: (id) => (id === "s1" ? "Build box" : null),
    onAllow: vi.fn(),
    onNotNow: vi.fn(),
    onMute: vi.fn(),
    onUnmute: vi.fn(),
  };
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

describe("the request panel", () => {
  it("is nothing at all while nobody is asking", () => {
    render(event([]));
    expect(host.innerHTML).toBe("");
  });

  it("is one panel listing every agent, with machine, reason, wait and countdown", () => {
    render(event([claude, codex]));
    expect(host.querySelectorAll("[data-agent-requests]")).toHaveLength(1);
    expect(host.querySelectorAll("[data-request]")).toHaveLength(2);
    const text = host.textContent ?? "";
    expect(text).toContain(TEXT.heading(2));
    expect(text).toContain("claude-code pid 7 (att_1)");
    expect(text).toContain("on Build box");
    expect(text).toContain("on 10.0.0.6:3389");
    expect(text).toContain("“run the nightly build”");
    expect(text).toContain("waiting 12 s");
    expect(text).toContain("gets it in 14 s if you stop typing");
  });

  it("follows the list live: a third agent is a row, not a second panel", () => {
    render(event([claude]));
    render(
      event([claude, codex, { ...codex, attachmentId: "att_3", agent: "pi pid 3 (att_3)" }]),
      NOW + 2_000,
    );
    expect(host.querySelectorAll("[data-agent-requests]")).toHaveLength(1);
    expect(host.querySelectorAll("[data-request]")).toHaveLength(3);
    expect(host.textContent).toContain("waiting 14 s");
    expect(host.textContent).toContain("gets it in 12 s");
    // One left, one got the machine: the panel shrinks, then goes.
    render(event([codex]), NOW + 3_000);
    expect(host.querySelectorAll("[data-request]")).toHaveLength(1);
    render(event([]), NOW + 4_000);
    expect(host.innerHTML).toBe("");
  });

  it("answers one request, or all of them", () => {
    render(event([claude, codex]));
    act(() => button(TEXT.allow).click());
    expect(props.onAllow).toHaveBeenCalledWith("s1", "att_1");
    act(() => [...host.querySelectorAll("button")].filter((b) => b.textContent === TEXT.notNow)[1]?.click());
    expect(props.onNotNow).toHaveBeenCalledWith("s2", "att_2");
    act(() => button(TEXT.allowAll).click());
    expect(props.onAllow).toHaveBeenLastCalledWith();
    act(() => button(TEXT.notNowAll).click());
    expect(props.onNotNow).toHaveBeenLastCalledWith();
  });

  it("offers the mute lengths and sends the one chosen", () => {
    render(event([claude]));
    act(() => button(TEXT.mute).click());
    for (const choice of TEXT.muteChoices) button(choice.label);
    act(() => button("15 minutes").click());
    expect(props.onMute).toHaveBeenCalledWith(15);
    act(() => button(TEXT.mute).click());
    act(() => button("Until I take my hands off").click());
    expect(props.onMute).toHaveBeenLastCalledWith(null);
  });

  it("while muted is a small badge with the count and an unmute", () => {
    const until = new Date(2026, 9, 25, 14, 32).getTime();
    render(event([], { until, untilIdle: false, waiting: 2 }));
    const badge = host.querySelector('[data-agent-requests="muted"]');
    expect(badge).not.toBeNull();
    expect(badge?.textContent).toContain("Agent requests muted until 14:32");
    expect(badge?.textContent).toContain("2 asked");
    expect(host.querySelectorAll("[data-request]")).toHaveLength(0);
    act(() => button(TEXT.unmute).click());
    expect(props.onUnmute).toHaveBeenCalled();
  });

  it("does not take keyboard focus from the session being typed in", () => {
    const typing = document.createElement("input");
    document.body.append(typing);
    typing.focus();
    render(event([claude]));
    expect(document.activeElement).toBe(typing);
    const allow = button(TEXT.allow);
    const down = new PointerEvent("pointerdown", { bubbles: true, cancelable: true });
    act(() => {
      allow.dispatchEvent(down);
    });
    expect(down.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(typing);
    expect(host.querySelector('[role="dialog"]')).toBeNull();
    typing.remove();
  });
});
