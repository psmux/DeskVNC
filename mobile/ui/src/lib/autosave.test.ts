import { describe, expect, it } from "vitest";
import type { Host } from "../api/contract";
import { autoSaveDraft, autoSaveName, autoSaveOs, certCommonName, isSaved, type AutoSave } from "./autosave";

const base: AutoSave = {
  protocol: "vnc",
  address: "192.0.2.7",
  port: 5900,
  username: null,
  foundName: null,
  identifiedName: null,
  os: "unknown",
};

describe("autoSaveName", () => {
  it("takes the Nearby name first", () => {
    expect(
      autoSaveName({ ...base, foundName: "Spare room Mac", identifiedName: "spare-room" }, { desktopName: "Godwin's Mac", certName: null }),
    ).toBe("Spare room Mac");
  });

  it("then the name identify found", () => {
    expect(autoSaveName({ ...base, identifiedName: "STUDIO-PC" }, { desktopName: "Desktop", certName: null })).toBe("STUDIO-PC");
  });

  it("then the name the computer gave itself, then its certificate", () => {
    expect(autoSaveName(base, { desktopName: "Workshop Pi", certName: "PI" })).toBe("Workshop Pi");
    expect(autoSaveName({ ...base, protocol: "rdp", port: 3389 }, { desktopName: null, certName: "STUDIO-PC" })).toBe("STUDIO-PC");
  });

  it("falls back to the address, made friendly when it is a name", () => {
    expect(autoSaveName(base, { desktopName: null, certName: null })).toBe("192.0.2.7");
    expect(autoSaveName({ ...base, address: "studio-pc.local" }, { desktopName: null, certName: null })).toBe("Studio pc");
  });

  it("skips names that are blank or only an address", () => {
    expect(autoSaveName({ ...base, foundName: "  ", identifiedName: "192.0.2.7" }, { desktopName: "10.0.0.5", certName: null })).toBe("192.0.2.7");
  });

  it("keeps a long desktop name to something a card can show", () => {
    const long = "x".repeat(200);
    expect(autoSaveName(base, { desktopName: long, certName: null }).length).toBeLessThanOrEqual(60);
  });

  it("never shows a Boundary machine ID as the name", () => {
    const id = "ab".repeat(32);
    expect(autoSaveName({ ...base, protocol: "boundary", address: `${id}@192.0.2.7`, port: 5940 }, { desktopName: null, certName: null })).toBe("192.0.2.7");
    expect(autoSaveName({ ...base, protocol: "boundary", address: id, port: 0 }, { desktopName: null, certName: null })).toBe("Boundary computer");
  });
});

describe("autoSaveOs", () => {
  it("uses the hint when there is one", () => {
    expect(autoSaveOs({ ...base, os: "mac" })).toBe("mac");
  });
  it("reads Remote Desktop as Windows when nothing else is known", () => {
    expect(autoSaveOs({ ...base, protocol: "rdp" })).toBe("windows");
    expect(autoSaveOs(base)).toBe("unknown");
  });
});

describe("certCommonName", () => {
  it("takes the CN out of a subject", () => {
    expect(certCommonName("CN=STUDIO-PC")).toBe("STUDIO-PC");
    expect(certCommonName("O=xrdp, CN=www.xrdp.org")).toBe("www.xrdp.org");
    expect(certCommonName("STUDIO-PC")).toBe("STUDIO-PC");
    expect(certCommonName("")).toBeNull();
    expect(certCommonName(null)).toBeNull();
  });
});

describe("isSaved", () => {
  const host = (over: Partial<Host>): Host => ({
    id: "h",
    name: "Studio",
    protocol: "vnc",
    address: "192.0.2.7",
    port: 5900,
    username: null,
    hasPassword: false,
    os: "mac",
    color: "teal",
    favorite: false,
    lastConnectedAt: null,
    hasThumbnail: false,
    ...over,
  });

  it("matches protocol, address and port", () => {
    expect(isSaved([host({})], base)).toBe(true);
    expect(isSaved([host({ address: "192.0.2.7".toUpperCase() })], base)).toBe(true);
    expect(isSaved([host({ port: 5901 })], base)).toBe(false);
    expect(isSaved([host({ protocol: "rdp", port: 5900 })], base)).toBe(false);
  });

  it("matches a Boundary computer with or without its ID", () => {
    const id = "ab".repeat(32);
    const b: AutoSave = { ...base, protocol: "boundary", address: `${id}@192.0.2.7`, port: 5940 };
    expect(isSaved([host({ protocol: "boundary", address: "192.0.2.7", port: 5940 })], b)).toBe(true);
  });
});

describe("autoSaveDraft", () => {
  it("makes a card with the protocol's colour and the user name", () => {
    expect(
      autoSaveDraft({ ...base, protocol: "rdp", port: 3389, username: "alice", identifiedName: "STUDIO-PC", os: "windows" }, { desktopName: null, certName: null }),
    ).toEqual({
      name: "STUDIO-PC",
      protocol: "rdp",
      address: "192.0.2.7",
      port: 3389,
      username: "alice",
      os: "windows",
      color: "blue",
      favorite: false,
      domain: null,
      boundaryInvitation: null,
    });
  });
});
