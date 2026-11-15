import { describe, expect, it } from "vitest";
import { blankHostProfile, type DiscoveredHost, type HostProfile, type ProtocolKind } from "./types";
import {
  autoSaveName,
  autoSaveProfile,
  canAutoSave,
  discoveredFor,
  findSavedHost,
  renameAdopted,
  sameAddress,
} from "./autoSave";

function host(protocol: ProtocolKind, address: string, port: number, name = address): HostProfile {
  return { ...blankHostProfile(protocol), id: `${protocol}-${address}-${port}`, friendlyName: name, address, port };
}

function found(over: Partial<DiscoveredHost>): DiscoveredHost {
  return {
    id: `${over.address ?? "10.0.0.5"}:${over.port ?? 5900}`,
    name: "",
    address: "10.0.0.5",
    port: 5900,
    osHint: "unknown",
    serverHint: "",
    securityHint: null,
    security: "unknown",
    securityTypes: [],
    source: "scan",
    savedHostId: null,
    ...over,
  };
}

describe("sameAddress", () => {
  it("ignores case, spaces and a trailing dot", () => {
    expect(sameAddress(" Studio.Local. ", "studio.local")).toBe(true);
  });

  it("tells two machines apart", () => {
    expect(sameAddress("10.0.0.5", "10.0.0.50")).toBe(false);
  });
});

describe("findSavedHost", () => {
  const hosts = [host("vnc", "10.0.0.5", 5900), host("rdp", "office.example.com", 3389)];

  it("finds a host saved at the same address, port and protocol", () => {
    expect(findSavedHost(hosts, { address: "10.0.0.5", port: 5900, protocol: "vnc" })?.id).toBe("vnc-10.0.0.5-5900");
  });

  it("matches the address without regard to case", () => {
    expect(
      findSavedHost(hosts, { address: "OFFICE.example.com", port: 3389, protocol: "rdp" })?.id,
    ).toBe("rdp-office.example.com-3389");
  });

  it("does not count a host saved on another port", () => {
    expect(findSavedHost(hosts, { address: "10.0.0.5", port: 5901, protocol: "vnc" })).toBeNull();
  });

  it("does not count a host saved under another protocol", () => {
    expect(findSavedHost(hosts, { address: "10.0.0.5", port: 5900, protocol: "rdp" })).toBeNull();
  });

  it("lets a typed bare address find a host on a non default port", () => {
    const onDisplay1 = [host("vnc", "box", 5901)];
    expect(
      findSavedHost(onDisplay1, { address: "box", port: 5900, protocol: null, explicitPort: false })?.id,
    ).toBe("vnc-box-5901");
  });

  it("reads a host with no protocol column as VNC", () => {
    const old = [{ ...host("vnc", "10.0.0.9", 5900), protocol: "" }];
    expect(findSavedHost(old, { address: "10.0.0.9", port: 5900, protocol: "vnc" })).not.toBeNull();
  });
});

describe("autoSaveName", () => {
  it("prefers the name discovery found", () => {
    expect(autoSaveName({ discoveredName: "Studio Mac", desktopName: "admin's desktop", address: "10.0.0.5" })).toBe(
      "Studio Mac",
    );
  });

  it("falls back to the name the server gave", () => {
    expect(autoSaveName({ discoveredName: null, desktopName: "FRONTDESK", address: "10.0.0.5" })).toBe("FRONTDESK");
  });

  it("skips a discovered name that is only the address", () => {
    expect(autoSaveName({ discoveredName: "10.0.0.5", desktopName: "FRONTDESK", address: "10.0.0.5" })).toBe(
      "FRONTDESK",
    );
  });

  it("skips a desktop name that is only the address", () => {
    expect(autoSaveName({ discoveredName: "", desktopName: "10.0.0.5", address: "10.0.0.5" })).toBe("10.0.0.5");
  });

  it("uses the address when nothing better is known", () => {
    expect(autoSaveName({ discoveredName: "  ", desktopName: "", address: "10.0.0.5" })).toBe("10.0.0.5");
  });

  it("trims what it keeps", () => {
    expect(autoSaveName({ discoveredName: " Studio Mac ", desktopName: null, address: "10.0.0.5" })).toBe("Studio Mac");
  });
});

describe("discoveredFor", () => {
  const list = [
    found({ name: "Studio Mac", address: "10.0.0.5", port: 5900, protocol: "vnc" }),
    found({ name: "FRONTDESK", address: "10.0.0.5", port: 3389, protocol: "rdp" }),
  ];

  it("finds the row for the endpoint that was dialled", () => {
    expect(discoveredFor(list, "rdp", "10.0.0.5", 3389)?.name).toBe("FRONTDESK");
  });

  it("finds nothing for an endpoint discovery never saw", () => {
    expect(discoveredFor(list, "ssh", "10.0.0.5", 22)).toBeNull();
  });
});

describe("canAutoSave", () => {
  it("covers the protocols quick connect speaks", () => {
    expect(canAutoSave("vnc")).toBe(true);
    expect(canAutoSave("rdp")).toBe(true);
    expect(canAutoSave("ssh")).toBe(true);
  });

  it("leaves Boundary support sessions alone", () => {
    expect(canAutoSave("boundary")).toBe(false);
  });
});

describe("autoSaveProfile", () => {
  it("builds a host for the endpoint with the best name and discovery hints", () => {
    const d = found({
      name: "FRONTDESK",
      address: "10.0.0.5",
      port: 3389,
      protocol: "rdp",
      osHint: "unknown",
      nameSource: "netbios",
      serverHint: "Windows RDP",
      mac: "00:11:22:33:44:55",
    });
    const p = autoSaveProfile({ protocol: "rdp", address: "10.0.0.5", port: 3389, desktopName: null, discovered: d });
    expect(p.friendlyName).toBe("FRONTDESK");
    expect(p.address).toBe("10.0.0.5");
    expect(p.port).toBe(3389);
    expect(p.protocol).toBe("rdp");
    expect(p.osHint).toBe("windows");
    expect(p.serverHint).toBe("Windows RDP");
    expect(p.wolMac).toBe("00:11:22:33:44:55");
    expect(p.hasPassword).toBe(false);
  });

  it("works with nothing from discovery", () => {
    const p = autoSaveProfile({ protocol: "ssh", address: "build.example.com", port: 22, desktopName: "", discovered: null });
    expect(p.friendlyName).toBe("build.example.com");
    expect(p.osHint).toBe("unknown");
    expect(p.serverHint).toBeNull();
    expect(p.wolMac).toBeNull();
    expect(p.protocol).toBe("ssh");
  });
});

describe("renameAdopted", () => {
  const better = { ...host("vnc", "10.0.0.5", 5900, "Studio Box"), osHint: "linux" as const };

  it("gives a host saved under its bare address the better name and hints", () => {
    const adopted = host("vnc", "10.0.0.5", 5900);
    const out = renameAdopted(adopted, better);
    expect(out?.friendlyName).toBe("Studio Box");
    expect(out?.osHint).toBe("linux");
    expect(out?.id).toBe(adopted.id);
  });

  it("leaves a host someone named alone", () => {
    expect(renameAdopted(host("vnc", "10.0.0.5", 5900, "Kitchen PC"), better)).toBeNull();
  });

  it("does nothing when there is no better name", () => {
    expect(renameAdopted(host("vnc", "10.0.0.5", 5900), host("vnc", "10.0.0.5", 5900))).toBeNull();
  });
});
