import { describe, expect, it } from "vitest";
import type { SessionParams } from "../hooks/useSession";
import { blankHostProfile, type DiscoveredHost, type HostProfile } from "./types";
import {
  credentialsLabel,
  existingHostFor,
  newHostForSession,
  parseCredentialState,
  saveCredentialsByDefault,
  suggestedName,
  tabHostAction,
  tabHostLabel,
  tabHostTargetOf,
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

describe("what a tab's menu offers for keeping its machine", () => {
  const ADD = { kind: "add" };

  it("offers Add to saved hosts for a session opened by address", () => {
    expect(tabHostAction(params(), [])).toEqual(ADD);
    expect(tabHostAction(params({ protocol: "rdp", port: 3389 }), [])).toEqual(ADD);
    expect(tabHostAction(params({ protocol: "ssh", port: 22 }), [])).toEqual(ADD);
    expect(tabHostLabel({ kind: "add" })).toBe("Add to saved hosts");
  });

  it("offers Edit saved host for a session of a saved host, auto saved or not", () => {
    // The automatic save names a host after the server's desktop. Opening it
    // again from the Library, or by an agent asking for it by name, gives the
    // session that host's id. The tab used to offer nothing at all then.
    const auto = saved({ id: "h1", friendlyName: "test desktop" });
    const action = tabHostAction(params({ profileId: "h1" }), [auto]);
    expect(action).toEqual({ kind: "edit", host: auto });
    expect(tabHostLabel({ kind: "edit", host: auto })).toBe("Edit saved host");
  });

  it("offers Add when the session's host is not in the list, so the tab is never left with nothing", () => {
    expect(tabHostAction(params({ profileId: "deleted" }), [saved({ id: "h1" })])).toEqual(ADD);
  });

  it("leaves Boundary out, as the automatic save does", () => {
    const boundary = params({ protocol: "boundary", address: "123456789", port: 0 });
    expect(tabHostAction(boundary, [])).toBeNull();
    expect(tabHostAction({ ...boundary, profileId: "h1" }, [saved({ id: "h1", protocol: "boundary" })])).toBeNull();
  });

  it("needs an address", () => {
    expect(tabHostAction(params({ address: null }), [])).toBeNull();
    expect(tabHostAction(params({ address: "  " }), [])).toBeNull();
  });

  it("acts on the focused pane's session, saved or not", () => {
    const host = saved({ id: "h1" });
    const sessions = {
      a: { params: params({ sessionId: "a" }) },
      b: { params: params({ sessionId: "b", profileId: "h1" }) },
    };
    expect(tabHostTargetOf("a", sessions, [host])).toEqual({ session: sessions.a, action: ADD });
    expect(tabHostTargetOf("b", sessions, [host])).toEqual({
      session: sessions.b,
      action: { kind: "edit", host },
    });
    expect(tabHostTargetOf(null, sessions, [host])).toBeNull();
    expect(tabHostTargetOf("gone", sessions, [host])).toBeNull();
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
