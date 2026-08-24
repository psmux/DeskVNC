import { describe, expect, it } from "vitest";
import { joinDomainUser, splitDomainUser } from "./credentials";

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
