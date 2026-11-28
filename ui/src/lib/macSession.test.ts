import { describe, expect, it } from "vitest";
import {
  macChoiceTitle,
  macShareWithdrawn,
  macUserLabel,
  macWaitingText,
  parseMacSessionPref,
  storeMacSessionPref,
} from "./macSession";

describe("the per host Mac session default", () => {
  it("reads what it stores and treats anything else as ask", () => {
    expect(parseMacSessionPref("share")).toBe("share");
    expect(parseMacSessionPref("separate")).toBe("separate");
    expect(parseMacSessionPref(null)).toBe("ask");
    expect(parseMacSessionPref(undefined)).toBe("ask");
    expect(parseMacSessionPref("take-over")).toBe("ask");
  });

  it("stores ask as no choice at all", () => {
    expect(storeMacSessionPref("ask")).toBeNull();
    expect(storeMacSessionPref("share")).toBe("share");
    expect(storeMacSessionPref("separate")).toBe("separate");
  });
});

describe("the words for a Mac with someone at it", () => {
  it("names the person the Mac reported", () => {
    expect(macChoiceTitle("anna")).toBe("anna is using this Mac");
    expect(macWaitingText("anna")).toBe(
      "Waiting for anna to accept the request to share their screen.",
    );
    expect(macShareWithdrawn("anna")).toBe("The request to share anna's screen was withdrawn.");
    expect(macShareWithdrawn("james")).toBe("The request to share james' screen was withdrawn.");
  });

  it("still reads when the Mac sent no name", () => {
    expect(macUserLabel("  ")).toBe("The person at the Mac");
    expect(macChoiceTitle("")).toBe("Someone is using this Mac");
    expect(macShareWithdrawn("")).toBe("The request to share the Mac user's screen was withdrawn.");
  });
});
