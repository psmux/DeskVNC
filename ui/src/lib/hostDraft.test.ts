import { describe, expect, it } from "vitest";
import { portOnProtocolChange, portWasTouched, vncCredentialPayload } from "./hostDraft";
import { blankHostProfile } from "./types";

describe("portOnProtocolChange", () => {
  it("moves a default port to the other protocol's default", () => {
    expect(portOnProtocolChange("vnc", "rdp", 5900, false)).toBe(3389);
    expect(portOnProtocolChange("rdp", "vnc", 3389, false)).toBe(5900);
  });

  it("leaves a port the user chose alone", () => {
    // 5901 is not the outgoing default, so somebody chose it.
    expect(portOnProtocolChange("vnc", "rdp", 5901, false)).toBe(5901);
    // And a typed 5900 is still a typed 5900.
    expect(portOnProtocolChange("vnc", "rdp", 5900, true)).toBe(5900);
  });

  it("does nothing when the protocol has not changed", () => {
    expect(portOnProtocolChange("vnc", "vnc", 5900, false)).toBe(5900);
  });
});

describe("blankHostProfile", () => {
  it("still produces exactly what it produced before, with no argument", () => {
    const h = blankHostProfile();
    expect(h.protocol).toBe("vnc");
    expect(h.port).toBe(5900);
    expect(h.rdpSettings).toBeNull();
  });

  it("carries the protocol's own default port", () => {
    const h = blankHostProfile("rdp");
    expect(h.protocol).toBe("rdp");
    expect(h.port).toBe(3389);
    // Deliberately null even for RDP: an untouched settings object stores
    // NULL and the Rust side applies its own defaults.
    expect(h.rdpSettings).toBeNull();
  });
});

describe("portWasTouched", () => {
  // The seeding rule most likely to be got wrong, which is why it is one
  // function with a test rather than a condition inside a handler.
  it("reads a non-default port as deliberate", () => {
    expect(portWasTouched({ ...blankHostProfile(), port: 5900 })).toBe(false);
    expect(portWasTouched({ ...blankHostProfile(), port: 5901 })).toBe(true);
    expect(portWasTouched({ ...blankHostProfile("rdp"), port: 3389 })).toBe(false);
    expect(portWasTouched({ ...blankHostProfile("rdp"), port: 3390 })).toBe(true);
    expect(portWasTouched(null)).toBe(false);
  });
});

describe("vncCredentialPayload", () => {
  // Issue #9. A Mac with Screen Sharing needs a user name as well as a
  // password, and the editor had no field for it, so what was typed here
  // could never be used without the prompt asking for both again.
  it("stores the user name a Mac asks for beside the password", () => {
    expect(vncCredentialPayload(" godwin ", "secret")).toEqual({
      vencryptUser: "godwin",
      vencryptPass: "secret",
      vncPassword: "secret",
    });
  });

  it("writes both password fields so an older prompt answer cannot shadow this one", () => {
    expect(vncCredentialPayload("", "secret")).toEqual({
      vencryptPass: "secret",
      vncPassword: "secret",
    });
  });

  it("leaves what is stored alone for an empty box", () => {
    expect(vncCredentialPayload("godwin", "")).toEqual({ vencryptUser: "godwin" });
    expect(vncCredentialPayload("  ", "")).toEqual({});
  });
});
