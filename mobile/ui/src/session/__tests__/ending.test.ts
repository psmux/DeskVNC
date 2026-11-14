import { describe, expect, it } from "vitest";
import { endKind, endWords, mergeEnd } from "../status";

// The reasons below are the strings the Rust side really sends:
// boundary-driver's clean end, boundary-session's ended_by_host, RDP's
// server end, and lifecycle::REASON.
const BACKGROUND = "DeskVNC was in the background for more than 30 seconds";

describe("why a session ended", () => {
  it("calls DeskVNC Support pressing End the other side ending it, not a pause", () => {
    expect(endKind("Support session ended", false)).toBe("remote");
    expect(endKind("That computer ended the session: Screen Recording was turned off", false)).toBe("remote");
    expect(endKind("the server ended the session", false)).toBe("remote");
  });

  it("keeps the paused wording for the background timeout", () => {
    expect(endKind(BACKGROUND, false)).toBe("paused");
    // While hidden, a clean end is the phone's own background stop.
    expect(endKind("Support session ended", true)).toBe("paused");
  });

  it("treats anything else as a dropped link", () => {
    expect(endKind("The connection to that computer was lost: timed out", false)).toBe("lost");
    expect(endKind(null, false)).toBe("lost");
  });

  it("lets the later background reason win over the driver's clean end", () => {
    const first = endKind("Support session ended", false);
    expect(mergeEnd(first, endKind(BACKGROUND, false))).toBe("paused");
    expect(mergeEnd("remote", "lost")).toBe("remote");
    expect(mergeEnd(null, "lost")).toBe("lost");
  });

  it("says who ended it, with their reason when they gave one", () => {
    expect(endWords("remote", "Support session ended")).toEqual({
      title: "They ended the session",
      lead: "The other side closed the connection.",
    });
    expect(endWords("remote", "That computer ended the session: Screen Recording was turned off").lead).toBe(
      "The other side closed the connection: Screen Recording was turned off",
    );
    expect(endWords("paused", BACKGROUND).lead).toMatch(/background/);
    expect(endWords("lost", null).title).toBe("The connection dropped");
  });
});
