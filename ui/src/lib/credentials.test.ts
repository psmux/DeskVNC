import { describe, expect, it } from "vitest";
import { joinDomainUser, promptStart, splitDomainUser } from "./credentials";

describe("splitDomainUser", () => {
  it("splits a down-level name", () => {
    expect(splitDomainUser("CORP\\alice")).toEqual({ domain: "CORP", user: "alice" });
    expect(splitDomainUser("corp.local\\alice")).toEqual({ domain: "corp.local", user: "alice" });
  });

  it("leaves a UPN alone", () => {
    // THE row that matters. An RDP server accepts a UPN as the user name
    // with an empty domain; splitting it at the `@` and sending
    // "corp.com\alice" fails against Entra ID and against any forest whose
    // NetBIOS name is not the DNS label.
    expect(splitDomainUser("alice@corp.com")).toEqual({ domain: null, user: "alice@corp.com" });
  });

  it("takes the last backslash, because a name may contain one", () => {
    expect(splitDomainUser("A\\B\\c")).toEqual({ domain: "A\\B", user: "c" });
  });

  it("treats a bare name and a leading backslash as no domain", () => {
    expect(splitDomainUser("alice")).toEqual({ domain: null, user: "alice" });
    expect(splitDomainUser("")).toEqual({ domain: null, user: "" });
    expect(splitDomainUser("\\alice")).toEqual({ domain: null, user: "alice" });
  });
});

describe("joinDomainUser", () => {
  it("qualifies a bare name", () => {
    expect(joinDomainUser("CORP", "alice")).toBe("CORP\\alice");
  });

  it("leaves a UPN and an already-qualified name alone", () => {
    expect(joinDomainUser("CORP", "alice@corp.com")).toBe("alice@corp.com");
    expect(joinDomainUser("CORP", "OTHER\\alice")).toBe("OTHER\\alice");
  });

  it("does nothing without a domain", () => {
    expect(joinDomainUser(null, "alice")).toBe("alice");
    expect(joinDomainUser("  ", "alice")).toBe("alice");
  });
});

describe("promptStart", () => {
  it("starts with Remember ticked when the host already has a saved password", () => {
    expect(promptStart("tester", null, true).save).toBe(true);
    expect(promptStart("tester", null, false).save).toBe(false);
    // An explicit untick in this window still wins.
    const previous = { username: "tester", domain: "", save: false };
    expect(promptStart("tester", previous, true).save).toBe(false);
  });

  it("opens the first prompt from the hint, with Remember off", () => {
    expect(promptStart("godwin", null)).toEqual({ username: "godwin", domain: "", save: false });
    expect(promptStart(null, undefined)).toEqual({ username: "", domain: "", save: false });
  });

  // Issue #9. The dialog unmounts when answered, so the next prompt used to
  // open with Remember unticked. Ticking it, mistyping once and then typing
  // the right password saved nothing.
  it("keeps Remember ticked for the next prompt in the same window", () => {
    const previous = { username: "mac-user", domain: null, save: true };
    expect(promptStart("mac-user", previous).save).toBe(true);
  });

  it("keeps the user name and domain typed last ahead of the hint", () => {
    const previous = { username: "alice", domain: "CORP", save: false };
    expect(promptStart("Administrator", previous)).toEqual({
      username: "alice",
      domain: "CORP",
      save: false,
    });
  });

  it("falls back to the hint when the last answer had no user name", () => {
    // A password only prompt (VNC Authentication) answers with no user name.
    const previous = { username: null, domain: null, save: true };
    expect(promptStart("godwin", previous)).toEqual({ username: "godwin", domain: "", save: true });
    expect(promptStart("godwin", { ...previous, username: "  " }).username).toBe("godwin");
  });
});
