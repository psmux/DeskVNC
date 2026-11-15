import { describe, expect, it } from "vitest";
import type { FoundComputer, Host } from "../api/contract";
import { chooseService, choiceKey, orderServices, readQuickInput } from "./quick";

const ID = "3ae432ab7fd87dbd85b26c69e3d00be3f1ad47688df3e79e650ea9c8f0440723";

function host(over: Partial<Host>): Host {
  return {
    id: "h1",
    name: "Studio PC",
    protocol: "rdp",
    address: "192.0.2.20",
    port: 3389,
    username: null,
    hasPassword: false,
    os: "windows",
    color: "blue",
    favorite: false,
    lastConnectedAt: null,
    hasThumbnail: false,
    ...over,
  };
}

function found(protocol: FoundComputer["protocol"], port: number, os: FoundComputer["os"] = "unknown"): FoundComputer {
  return { address: "192.0.2.7", port, protocol, name: null, os };
}

describe("readQuickInput", () => {
  it("is empty for blank input", () => {
    expect(readQuickInput("   ", [])).toEqual({ kind: "empty" });
  });

  it("asks what is there for a bare name or address", () => {
    expect(readQuickInput("studio", [])).toEqual({ kind: "identify", address: "studio", port: null, username: null });
    expect(readQuickInput(" 192.0.2.7 ", [])).toEqual({ kind: "identify", address: "192.0.2.7", port: null, username: null });
    expect(readQuickInput("fe80::1", [])).toMatchObject({ kind: "identify", address: "fe80::1", port: null });
  });

  it("keeps a typed port and asks only that port", () => {
    expect(readQuickInput("192.0.2.7:5902", [])).toEqual({ kind: "identify", address: "192.0.2.7", port: 5902, username: null });
    expect(readQuickInput("box:3389", [])).toMatchObject({ kind: "identify", address: "box", port: 3389 });
    expect(readQuickInput("[fe80::1]:5901", [])).toMatchObject({ kind: "identify", address: "fe80::1", port: 5901 });
    // A display number is a VNC habit, and still a port to try.
    expect(readQuickInput("box:1", [])).toMatchObject({ kind: "identify", address: "box", port: 5901 });
  });

  it("connects straight away when a link names the protocol", () => {
    expect(readQuickInput("vnc://studio.example.com:1", [])).toEqual({
      kind: "direct",
      protocol: "vnc",
      address: "studio.example.com",
      port: 5901,
      username: null,
    });
    expect(readQuickInput("rdp://alice@192.0.2.20", [])).toEqual({
      kind: "direct",
      protocol: "rdp",
      address: "192.0.2.20",
      port: 3389,
      username: "alice",
    });
  });

  it("reads a Boundary computer by ID or boundary link", () => {
    expect(readQuickInput(ID, [])).toMatchObject({ kind: "direct", protocol: "boundary", address: ID, port: 0 });
    expect(readQuickInput(`boundary://${ID}@192.0.2.7`, [])).toMatchObject({
      kind: "direct",
      protocol: "boundary",
      address: `${ID}@192.0.2.7`,
    });
  });

  it("sends a help code or an invitation to Help someone", () => {
    expect(readQuickInput("1234 5678 9012", [])).toEqual({ kind: "help", text: "1234 5678 9012" });
    expect(readQuickInput("123456789012", [])).toEqual({ kind: "help", text: "123456789012" });
    expect(readQuickInput("boundary1:abcDEF", [])).toEqual({ kind: "help", text: "boundary1:abcDEF" });
  });

  it("turns away what it cannot use, in plain words", () => {
    expect(readQuickInput("ssh://box", [])).toMatchObject({ kind: "error" });
    expect(readQuickInput("my pc", [])).toMatchObject({ kind: "error", error: expect.stringMatching(/spaces/) });
  });

  it("finds a known computer by its name or its address", () => {
    const studio = host({});
    const pi = host({ id: "pi", name: "Raspberry Pi", protocol: "vnc", address: "10.0.0.31", port: 5901, os: "raspberry" });
    expect(readQuickInput("studio pc", [studio, pi])).toEqual({ kind: "saved", host: studio });
    expect(readQuickInput("192.0.2.20", [studio, pi])).toEqual({ kind: "saved", host: studio });
    expect(readQuickInput("10.0.0.31:5901", [studio, pi])).toEqual({ kind: "saved", host: pi });
    expect(readQuickInput("rdp://192.0.2.20", [studio, pi])).toEqual({ kind: "saved", host: studio });
  });

  it("does not take a saved computer on another port or protocol", () => {
    const studio = host({});
    expect(readQuickInput("192.0.2.20:5900", [studio])).toMatchObject({ kind: "identify", port: 5900 });
    expect(readQuickInput("vnc://192.0.2.20", [studio])).toMatchObject({ kind: "direct", protocol: "vnc" });
  });

  it("prefers the most recent of two saved entries at one address", () => {
    const old = host({ id: "a", lastConnectedAt: 1 });
    const recent = host({ id: "b", protocol: "vnc", port: 5900, lastConnectedAt: 9 });
    expect(readQuickInput("192.0.2.20", [old, recent])).toEqual({ kind: "saved", host: recent });
  });
});

describe("orderServices", () => {
  it("puts Remote Desktop first on Windows", () => {
    const list = orderServices([found("vnc", 5900, "windows"), found("rdp", 3389, "windows")]);
    expect(list.map((f) => f.protocol)).toEqual(["rdp", "vnc"]);
  });

  it("puts screen sharing first elsewhere, and Boundary last", () => {
    const list = orderServices([found("boundary", 5940, "mac"), found("rdp", 3389, "mac"), found("vnc", 5900, "mac")]);
    expect(list.map((f) => f.protocol)).toEqual(["vnc", "rdp", "boundary"]);
  });

  it("orders two VNC servers by port", () => {
    const list = orderServices([found("vnc", 5901), found("vnc", 5900)]);
    expect(list.map((f) => f.port)).toEqual([5900, 5901]);
  });
});

describe("chooseService", () => {
  it("connects straight away to the only one", () => {
    const only = found("vnc", 5900);
    expect(chooseService([only], {})).toEqual({ kind: "connect", item: only });
  });

  it("says when nothing answered", () => {
    expect(chooseService([], {})).toEqual({ kind: "none" });
  });

  it("asks when there are several", () => {
    const list = [found("vnc", 5900, "windows"), found("rdp", 3389, "windows")];
    expect(chooseService(list, {})).toEqual({ kind: "pick", items: orderServices(list) });
  });

  it("uses the choice made last time", () => {
    const list = [found("boundary", 5940, "mac"), found("vnc", 5900, "mac")];
    const remembered = { [choiceKey("192.0.2.7")]: "boundary:5940" };
    expect(chooseService(list, remembered)).toEqual({ kind: "connect", item: list[0] });
  });

  it("asks again when the remembered one did not answer", () => {
    const list = [found("rdp", 3389, "windows"), found("vnc", 5900, "windows")];
    const remembered = { [choiceKey("192.0.2.7")]: "vnc:5901" };
    expect(chooseService(list, remembered)).toMatchObject({ kind: "pick" });
  });

  it("matches a Boundary row by its address after the ID", () => {
    const row = { ...found("boundary", 5940), address: `${ID}@192.0.2.7` };
    const remembered = { [choiceKey("192.0.2.7")]: "boundary:5940" };
    expect(chooseService([found("vnc", 5900), row], remembered)).toEqual({ kind: "connect", item: row });
  });
});
