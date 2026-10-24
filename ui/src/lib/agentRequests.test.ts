import { describe, expect, it } from "vitest";
import { parseActivityEvent } from "./agentActivity";
import {
  AGENT_TEXT_MAX,
  agentText,
  machineName,
  parseRequestsEvent,
  secondsUntil,
  waitedFor,
} from "./agentRequests";

describe("the requests event", () => {
  it("reads every row and the mute", () => {
    const state = parseRequestsEvent({
      type: "requests",
      requests: [
        { sessionId: "s1", attachmentId: "att_1", agent: "codex pid 9", reason: "check mail", askedAt: 5, freesAt: 20 },
        { sessionId: "", attachmentId: "att_2" },
      ],
      muted: { until: 99, untilIdle: false, waiting: 1 },
      personIdleMs: 20_000,
    });
    expect(state?.requests).toHaveLength(1);
    expect(state?.requests[0]?.reason).toBe("check mail");
    expect(state?.muted).toEqual({ until: 99, untilIdle: false, waiting: 1 });
  });

  it("is not mistaken for a lease event, and a lease event is not one", () => {
    expect(parseRequestsEvent({ type: "lease", sessionId: "s1", held: true })).toBeNull();
    expect(parseActivityEvent({ type: "requests", requests: [] })).toBeNull();
  });

  it("keeps agent text plain and short", () => {
    expect(agentText("a\u0007b\nc")).toBe("a b c");
    expect(agentText("x".repeat(500))).toHaveLength(AGENT_TEXT_MAX);
  });

  it("words times plainly", () => {
    expect(waitedFor(0, 8_400)).toBe("8 s");
    expect(waitedFor(0, 150_000)).toBe("2 min");
    expect(secondsUntil(10_000, 1_500)).toBe(9);
    expect(secondsUntil(1_000, 5_000)).toBe(0);
  });

  it("names a machine by its tab, then its address", () => {
    const row = { sessionId: "s1", attachmentId: "a", agent: "x", reason: null, address: "10.0.0.5:5900", askedAt: 0, freesAt: null };
    expect(machineName(row, () => "Build box")).toBe("Build box");
    expect(machineName(row, () => null)).toBe("10.0.0.5:5900");
  });
});
