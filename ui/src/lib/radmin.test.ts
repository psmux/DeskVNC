import { describe, expect, it } from "vitest";
import { parseConnectTarget, formatTarget, presetProtocol } from "./address";
import { blankHostProfile, hostProtocol, PROTOCOLS } from "./types";
import { portOnProtocolChange } from "./hostDraft";

describe("Radmin connection routing", () => {
  it("preserves the protocol, account and literal port", () => {
    expect(parseConnectTarget("radmin://operator@server:1")).toMatchObject({
      ok: true, target: { protocol: "radmin", username: "operator", address: "server", port: 1 },
    });
    expect(parseConnectTarget("server", "radmin")).toMatchObject({ ok: true, target: { port: 4899 } });
    expect(parseConnectTarget("radmin://[::1]:14899")).toMatchObject({ ok: true, target: { address: "::1", port: 14899 } });
  });
  it("round-trips a saved endpoint without becoming VNC", () => {
    const text = formatTarget("radmin", "::1", 4899, "operator");
    expect(parseConnectTarget(text)).toMatchObject({ ok: true, target: { protocol: "radmin", port: 4899, username: "operator" } });
    expect(hostProtocol(blankHostProfile("radmin"))).toBe("radmin");
    expect(PROTOCOLS).toContain("radmin");
    expect(presetProtocol({ port: 4899 })).toBe("radmin");
    expect(portOnProtocolChange("vnc", "radmin", 5900, false)).toBe(4899);
    expect(portOnProtocolChange("vnc", "radmin", 14899, true)).toBe(14899);
  });
});
