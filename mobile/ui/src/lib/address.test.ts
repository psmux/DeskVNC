import { describe, expect, it } from "vitest";
import { looksLikeLink, parseConnectTarget, parsePhoneTarget } from "./address";

function ok(input: string, assume?: "vnc" | "rdp" | "boundary") {
  const r = parsePhoneTarget(input, assume);
  if (!r.ok) throw new Error(`expected ${input} to parse, got: ${r.error}`);
  return r.target;
}

describe("the shared parser, as the desktop reads it", () => {
  it("keeps the VNC forms", () => {
    expect(parseConnectTarget("office")).toMatchObject({ ok: true, target: { address: "office", port: 5900 } });
    expect(parseConnectTarget("office:1")).toMatchObject({ ok: true, target: { port: 5901 } });
    expect(parseConnectTarget("office::42")).toMatchObject({ ok: true, target: { port: 42 } });
    expect(parseConnectTarget("[fe80::1]:5901")).toMatchObject({ ok: true, target: { address: "fe80::1", port: 5901 } });
  });

  it("refuses spaces and empty input in words a person understands", () => {
    expect(parseConnectTarget("")).toEqual({ ok: false, error: "Enter an address" });
    expect(parseConnectTarget("my pc")).toMatchObject({ ok: false, error: expect.stringMatching(/spaces/) });
  });
});

describe("parsePhoneTarget", () => {
  it("reads rdp links with their user name", () => {
    expect(ok("rdp://alice@192.0.2.20")).toMatchObject({
      protocol: "rdp",
      address: "192.0.2.20",
      port: 3389,
      username: "alice",
    });
    expect(ok("rdp://box.example.com:3390")).toMatchObject({ protocol: "rdp", port: 3390, explicitPort: true });
  });

  it("reads vnc links and display numbers", () => {
    expect(ok("vnc://studio.example.com:1")).toMatchObject({ protocol: "vnc", port: 5901 });
    expect(ok("10.0.0.5:5902")).toMatchObject({ protocol: "vnc", port: 5902 });
  });

  it("presets Remote Desktop for port 3389 when nothing named a protocol", () => {
    expect(ok("10.0.0.7:3389")).toMatchObject({ protocol: "rdp", port: 3389 });
  });

  it("leaves the protocol open for a bare host", () => {
    expect(ok("office-pc.local")).toMatchObject({ protocol: null, port: 5900, explicitPort: false });
  });

  it("reads a low port as a port when the wizard already picked Remote Desktop", () => {
    expect(ok("box:1", "rdp")).toMatchObject({ port: 1 });
  });

  it("turns away terminal links", () => {
    const r = parsePhoneTarget("ssh://pi@10.0.0.9");
    expect(r.ok).toBe(false);
  });
});

describe("looksLikeLink", () => {
  it("spots links and host:port", () => {
    expect(looksLikeLink("rdp://box")).toBe(true);
    expect(looksLikeLink("vnc://box:5901")).toBe(true);
    expect(looksLikeLink("192.0.2.4:5900")).toBe(true);
    expect(looksLikeLink("[::1]:5901")).toBe(true);
  });
  it("ignores plain names", () => {
    expect(looksLikeLink("office")).toBe(false);
    expect(looksLikeLink("office pc")).toBe(false);
  });
});
