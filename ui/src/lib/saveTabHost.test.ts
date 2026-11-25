import { describe, expect, it } from "vitest";
import type { SessionParams } from "../hooks/useSession";
import { blankHostProfile, type DiscoveredHost, type HostProfile } from "./types";
import {
  canSaveAsHost,
  credentialsLabel,
  existingHostFor,
  newHostForSession,
  parseCredentialState,
  saveCredentialsByDefault,
  saveTargetOf,
  suggestedName,
  updatedHost,
} from "./saveTabHost";

function params(over: Partial<SessionParams> = {}): SessionParams {
  return {
    sessionId: "s1",
    profileId: null,
    address: "192.0.2.10",
    port: 5900,
    name: "192.0.2.10",
    protocol: "vnc",
    ...over,
  };
}

function saved(over: Partial<HostProfile>): HostProfile {
  return { ...blankHostProfile(), id: "h1", friendlyName: "Studio", address: "192.0.2.10", port: 5900, ...over };
}

describe("which tabs offer Add to saved hosts", () => {
  it("offers it for a session opened by address", () => {
    expect(canSaveAsHost(params())).toBe(true);
    expect(canSaveAsHost(params({ protocol: "rdp", port: 3389 }))).toBe(true);
    expect(canSaveAsHost(params({ protocol: "ssh", port: 22 }))).toBe(true);
  });

  it("does not offer it for a session that already belongs to a saved host", () => {
    expect(canSaveAsHost(params({ profileId: "h1" }))).toBe(false);
  });

  it("leaves Boundary out, as the automatic save does", () => {
    expect(canSaveAsHost(params({ protocol: "boundary", address: "123456789", port: 0 }))).toBe(false);
  });

  it("needs an address to save", () => {
    expect(canSaveAsHost(params({ address: null }))).toBe(false);
    expect(canSaveAsHost(params({ address: "  " }))).toBe(false);
  });

  it("acts on the focused pane's session, and only an unsaved one", () => {
    const sessions = {
      a: { params: params({ sessionId: "a" }) },
      b: { params: params({ sessionId: "b", profileId: "h1" }) },
    };
    expect(saveTargetOf("a", sessions)).toBe(sessions.a);
    expect(saveTargetOf("b", sessions)).toBeNull();
    expect(saveTargetOf(null, sessions)).toBeNull();
    expect(saveTargetOf("gone", sessions)).toBeNull();
  });
});

describe("the name the dialog starts with", () => {
  it("is the desktop name the server reported", () => {
    expect(suggestedName("  Studio iMac  ", "192.0.2.10")).toBe("Studio iMac");
  });

  it("is the address when the tab shows nothing better", () => {
    expect(suggestedName("192.0.2.10", "192.0.2.10")).toBe("192.0.2.10");
    expect(suggestedName("", "192.0.2.10 ")).toBe("192.0.2.10");
    expect(suggestedName("New pane", "192.0.2.10")).toBe("192.0.2.10");
  });
});

describe("a host already saved for the same machine", () => {
  const hosts = [saved({}), saved({ id: "h2", address: "192.0.2.11", port: 3389, protocol: "rdp" })];

  it("is found by address and port", () => {
    expect(existingHostFor(hosts, params())?.id).toBe("h1");
    expect(existingHostFor(hosts, params({ address: "192.0.2.11", port: 3389 }))?.id).toBe("h2");
  });

  it("is not a host on another port of that machine", () => {
    expect(existingHostFor(hosts, params({ port: 5901 }))).toBeNull();
  });

  it("is found whatever protocol it was saved under, so no duplicate is made", () => {
    expect(existingHostFor(hosts, params({ protocol: "ssh" }))?.id).toBe("h1");
  });

  it("keeps its own settings when updated, and only takes the new name", () => {
    const existing = saved({ viewOnly: true, qualityPref: "low" });
    const next = updatedHost(existing, " Front desk ");
    expect(next).toEqual({ ...existing, friendlyName: "Front desk" });
    expect(updatedHost(existing, "Studio")).toBe(existing);
    expect(updatedHost(existing, "   ")).toBe(existing);
  });
});

describe("the new host", () => {
  it("has the session's protocol, address and port, and the default settings it connected with", () => {
    const host = newHostForSession({
      params: params({ protocol: "rdp", address: " 192.0.2.20 ", port: 3390 }),
      name: " Office PC ",
      discovered: null,
    });
    expect(host).toMatchObject({
      friendlyName: "Office PC",
      address: "192.0.2.20",
      port: 3390,
      protocol: "rdp",
      rdpSettings: null,
      sshSettings: null,
      securityPref: null,
      viewOnly: false,
      hasPassword: false,
    });
  });

  it("takes discovery's hints when discovery saw the machine", () => {
    const found: DiscoveredHost = {
      id: "192.0.2.10:5900",
      name: "studio",
      address: "192.0.2.10",
      port: 5900,
      osHint: "macos",
      serverHint: "Apple Screen Sharing",
      securityHint: null,
      security: "unknown",
      securityTypes: [],
      source: "scan",
      savedHostId: null,
    };
    const host = newHostForSession({ params: params(), name: "Studio", discovered: found });
    expect(host.friendlyName).toBe("Studio");
    expect(host.serverHint).toBe("Apple Screen Sharing");
  });

  it("falls back to the address for an empty name", () => {
    expect(newHostForSession({ params: params(), name: "  ", discovered: null }).friendlyName).toBe(
      "192.0.2.10",
    );
  });
});

describe("saving the credentials too", () => {
  it("offers nothing when the shell reports nothing, or is too old to report", () => {
    expect(parseCredentialState(null)).toEqual({ used: false, hasUsername: false, remembered: false });
    expect(parseCredentialState("nope")).toEqual({ used: false, hasUsername: false, remembered: false });
    expect(parseCredentialState({ used: false, remembered: true }).remembered).toBe(false);
  });

  it("starts unticked unless Remember was ticked at the prompt", () => {
    expect(saveCredentialsByDefault(parseCredentialState({ used: true, remembered: false }))).toBe(false);
    expect(saveCredentialsByDefault(parseCredentialState({ used: true, remembered: true }))).toBe(true);
  });

  it("says what will be kept", () => {
    expect(credentialsLabel(parseCredentialState({ used: true }))).toBe(
      "Also save the password used for this session",
    );
    expect(credentialsLabel(parseCredentialState({ used: true, hasUsername: true }))).toBe(
      "Also save the user name and password used for this session",
    );
  });
});
