import { describe, expect, it } from "vitest";
import {
  portOnProtocolChange,
  portWasTouched,
  vncCredentialPayload,
  vncTakesUsername,
} from "./hostDraft";
import { blankHostProfile, type HostProfile } from "./types";
import { draftFromHost } from "../components/HostDialog";

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

describe("vncTakesUsername", () => {
  it("asks for an account with Apple Screen Sharing, whatever the OS hint says", () => {
    expect(vncTakesUsername("apple-dh", "macos")).toBe(true);
    expect(vncTakesUsername("apple-dh", "unknown")).toBe(true);
  });

  it("asks for one with the VeNCrypt and RA2 types that may sign in with a name", () => {
    expect(vncTakesUsername("vencrypt-x509", "linux")).toBe(true);
    expect(vncTakesUsername("ra2", "unknown")).toBe(true);
  });

  it("asks for one on Auto only when the host is a Mac", () => {
    // Auto against macOS negotiates Apple auth, so the account is needed.
    expect(vncTakesUsername(null, "macos")).toBe(true);
    expect(vncTakesUsername("auto", "macos")).toBe(true);
    expect(vncTakesUsername(null, "unknown")).toBe(false);
    expect(vncTakesUsername(null, "windows")).toBe(false);
    expect(vncTakesUsername(null, "linux")).toBe(false);
  });

  it("does not ask for one with a password only or open type", () => {
    expect(vncTakesUsername("vncauth", "macos")).toBe(false);
    expect(vncTakesUsername("none", "macos")).toBe(false);
  });
});

describe("vncCredentialPayload", () => {
  it("sends the user name and password as one pair for an account method", () => {
    expect(vncCredentialPayload("  alice ", "pw", true)).toEqual({
      vencryptUser: "alice",
      vencryptPass: "pw",
    });
  });

  it("sends only what was typed, so a blank box keeps what is stored", () => {
    expect(vncCredentialPayload("alice", "", true)).toEqual({ vencryptUser: "alice" });
    expect(vncCredentialPayload("", "pw", true)).toEqual({ vencryptPass: "pw" });
    expect(vncCredentialPayload("   ", "", true)).toBeNull();
  });

  it("keeps a password only host on the plain VNC password, as before", () => {
    expect(vncCredentialPayload("", "pw", false)).toEqual({ vncPassword: "pw" });
    // A name left in the box from an earlier security type is not saved.
    expect(vncCredentialPayload("alice", "pw", false)).toEqual({ vncPassword: "pw" });
    expect(vncCredentialPayload("", "", false)).toBeNull();
  });
});

describe("the VNC user name through the host draft", () => {
  // The host from issue #9: a Mac with Apple Screen Sharing pinned.
  const mac: HostProfile = {
    ...blankHostProfile(),
    id: "mac-1",
    address: "192.168.1.3",
    osHint: "macos",
    securityPref: "apple-dh",
    hasPassword: false,
  };

  it("starts blank and shows the field for the reporter's Mac", () => {
    const d = draftFromHost(mac);
    expect(d.vncUser).toBe("");
    expect(vncTakesUsername(d.securityPref, d.osHint)).toBe(true);
  });

  it("saves what was typed and reopens without reading it back", () => {
    const typed = { ...draftFromHost(mac), vncUser: "godwin", password: "secret" };
    expect(
      vncCredentialPayload(
        typed.vncUser,
        typed.password,
        vncTakesUsername(typed.securityPref, typed.osHint),
      ),
    ).toEqual({ vencryptUser: "godwin", vencryptPass: "secret" });

    // Reopened after the save: the field is still there and still blank (no
    // secret or account crosses back into the webview), and since a
    // credential now exists a blank box means "keep the saved one".
    const reopened = draftFromHost({ ...mac, hasPassword: true });
    expect(reopened.vncUser).toBe("");
    expect(reopened.hasPassword).toBe(true);
    expect(reopened.securityPref).toBe("apple-dh");
    expect(
      vncCredentialPayload(
        reopened.vncUser,
        reopened.password,
        vncTakesUsername(reopened.securityPref, reopened.osHint),
      ),
    ).toBeNull();
  });

  it("hides the field once the host is switched to a password only type", () => {
    const d = { ...draftFromHost(mac), securityPref: "vncauth" };
    expect(vncTakesUsername(d.securityPref, d.osHint)).toBe(false);
  });
});
