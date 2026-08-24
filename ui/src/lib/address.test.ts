/**
 * The highest risk change in the interface, because this decides where a
 * connection goes.
 *
 * Existing behaviour is regression tested first and nothing in that block may
 * change: a parser that quietly moves an existing form connects somewhere the
 * user never went.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_RDP_PORT,
  DEFAULT_VNC_PORT,
  formatTarget,
  parseConnectTarget,
  presetProtocol,
} from "./address";
import type { ProtocolKind } from "./types";

function ok(input: string, assume?: ProtocolKind) {
  const r = parseConnectTarget(input, assume);
  if (!r.ok) throw new Error(`expected ${input} to parse, got: ${r.error}`);
  return r.target;
}

function err(input: string): string {
  const r = parseConnectTarget(input);
  if (r.ok) throw new Error(`expected ${input} to fail`);
  return r.error;
}

describe("existing behaviour, unchanged", () => {
  it("keeps the VNC forms exactly as they were", () => {
    expect(ok("office")).toMatchObject({ address: "office", port: 5900, explicitPort: false });
    expect(ok("office:1")).toMatchObject({ port: 5901, explicitPort: true });
    expect(ok("office:5901")).toMatchObject({ port: 5901 });
    expect(ok("office::5901")).toMatchObject({ port: 5901 });
    expect(ok("office::42")).toMatchObject({ port: 42 });
    expect(ok("[fe80::1%en0]:5901")).toMatchObject({ address: "fe80::1%en0", port: 5901 });
    expect(ok("fe80::1")).toMatchObject({ address: "fe80::1", port: 5900 });
    expect(ok("[::1]:1")).toMatchObject({ address: "::1", port: 1 });
    expect(ok("vnc://office:5901/")).toMatchObject({ protocol: "vnc", port: 5901 });
  });

  it("still discards VNC userinfo rather than capturing it", () => {
    expect(ok("vnc://bob@office")).toMatchObject({
      protocol: "vnc",
      address: "office",
      port: 5900,
      username: null,
    });
  });

  it("keeps the error strings", () => {
    expect(err("1::2::3")).toMatch(/IPv6/);
    expect(err("::1]:5901")).toBeTruthy();
    expect(err("office 2")).toMatch(/spaces/);
  });

  it("reports no protocol when the input named none", () => {
    expect(ok("office").protocol).toBeNull();
  });
});

describe("the rdp:// grammar", () => {
  it("parses every form", () => {
    expect(ok("rdp://box")).toMatchObject({
      protocol: "rdp", address: "box", port: 3389, explicitPort: false, username: null,
    });
    expect(ok("rdp://box:3389")).toMatchObject({ port: 3389, explicitPort: true });
    expect(ok("rdp://box:3390")).toMatchObject({ port: 3390, explicitPort: true });
    expect(ok("rdps://box")).toMatchObject({ protocol: "rdp", port: 3389 });
    expect(ok("rdp://alice@box")).toMatchObject({ address: "box", username: "alice" });
    expect(ok("rdp://[fe80::1]:3390")).toMatchObject({ address: "fe80::1", port: 3390 });
  });

  it("reads a low port as a port, not a display number", () => {
    // `rdp://box:1` is port 1. The display-number convention is an RFB one
    // and does not exist for RDP, so 3390 would be an invented answer.
    expect(ok("rdp://box:1")).toMatchObject({ port: 1, explicitPort: true });
  });

  it("splits userinfo at the LAST @, so a UPN survives", () => {
    // Splitting at the first would yield user "alice" and host
    // "corp.example@box", which is neither of the two things it could mean.
    expect(ok("rdp://alice@corp.example@box")).toMatchObject({
      address: "box", username: "alice@corp.example",
    });
    expect(ok("rdp://CORP\\alice@box")).toMatchObject({ username: "CORP\\alice" });
  });

  it("reads a bare user@host as RDP", () => {
    expect(ok("alice@box")).toMatchObject({
      protocol: "rdp", address: "box", port: 3389, username: "alice",
    });
  });

  it("still refuses what it always refused", () => {
    expect(err("rdp://")).toMatch(/Enter an address/);
    expect(err("rdp://box:0")).toMatch(/between 1 and 65535/);
  });
});

describe("what the parser must not guess", () => {
  it("leaves host:3389 with no protocol at all", () => {
    // The parser reports what the input NAMED and nothing more. Resolving
    // this is QuickConnect's job, where the answer is visible on the chip
    // before Enter and one click flips it.
    expect(ok("box:3389")).toMatchObject({
      protocol: null, address: "box", port: 3389, explicitPort: true,
    });
  });

  it("presets RDP for 3389 and VNC for everything else", () => {
    expect(presetProtocol({ port: DEFAULT_RDP_PORT })).toBe("rdp");
    expect(presetProtocol({ port: 5901 })).toBe("vnc");
    expect(presetProtocol({ port: DEFAULT_VNC_PORT })).toBe("vnc");
  });

  it("parses as the protocol the caller assumes when the input named none", () => {
    // The host dialog passes the draft's protocol, so `box:1` in an RDP
    // host's address field is port 1 rather than display 1.
    expect(ok("box:1", "rdp")).toMatchObject({ port: 1 });
    expect(ok("box:1", "vnc")).toMatchObject({ port: 5901 });
    expect(ok("box", "rdp")).toMatchObject({ port: 3389 });
  });
});

describe("round trips", () => {
  // A recent that does not re-parse to itself connects somewhere the user
  // never went, which is the whole reason `formatTarget` exists.
  const cases: [ProtocolKind, string, number, string?][] = [
    ["vnc", "office", 5900],
    ["vnc", "office", 5901],
    ["vnc", "office", 42],
    ["vnc", "fe80::1", 5900],
    ["rdp", "box", 3389],
    ["rdp", "box", 3390],
    ["rdp", "box", 3389, "alice"],
    ["rdp", "::1", 3389],
  ];
  for (const [protocol, address, port, username] of cases) {
    it(`${protocol} ${address}:${port}${username ? ` as ${username}` : ""}`, () => {
      const text = formatTarget(protocol, address, port, username);
      const back = ok(text);
      expect(back.address).toBe(address);
      expect(back.port).toBe(port);
      // A VNC target names no protocol when it does not have to, so the
      // round trip preserves "unspecified" rather than inventing "vnc".
      expect(back.protocol ?? "vnc").toBe(protocol);
      if (username) expect(back.username).toBe(username);
    });
  }

  it("always writes the scheme for an RDP target, even on 3389", () => {
    // A bare `box` reads back as VNC, so the scheme is not optional here.
    expect(formatTarget("rdp", "box", 3389)).toBe("rdp://box");
    expect(formatTarget("vnc", "box", 5900)).toBe("box");
  });
});
