import { describe, expect, it } from "vitest";
import { draftFromRdpImport, splitRdpUser } from "./rdpImport";
import { blankHostProfile } from "./types";
import { serializeRdpSettings } from "./rdp";
import type { RdpImport } from "./tauri";

/** What `import_rdp_file` returns for the mstsc fixture in
 *  `crates/vnc-store/tests/fixtures`, cut down to what the editor reads. */
function imported(): RdpImport {
  return {
    profile: {
      ...blankHostProfile("rdp"),
      id: "from-the-shell",
      friendlyName: "mstsc-gateway-utf16le",
      address: "192.0.2.10",
      port: 3390,
      scalingMode: "aspect-fit",
      qualityPref: "high",
      rdpSettings: JSON.stringify({
        v: 1,
        clipboard: true,
        fullscreen: true,
        domain: "EXAMPLE",
        audio: "play-locally",
        resolution: { mode: "fixed", width: 1920, height: 1080 },
        gateway: { host: "gw.example.net", port: 443, separateCredentials: false },
      }),
    },
    username: "EXAMPLE\\operator",
    mapped: ["full address", "screen mode id"],
    ignored: ["password 51"],
    unparseable: 0,
    warnings: [
      "the file contains a saved password, which cannot be imported: it is encrypted for the Windows account that wrote it",
      "the file uses an RD Gateway. The setting is kept, and connecting through a gateway is not supported yet, so this profile will refuse to connect rather than reaching the server directly",
    ],
    desktopSize: [1920, 1080],
  };
}

describe("draftFromRdpImport", () => {
  it("is a new RDP host with the file's address, port and name", () => {
    const d = draftFromRdpImport(imported());
    expect(d.id).toBeUndefined();
    expect(d.protocol).toBe("rdp");
    expect(d.address).toBe("192.0.2.10");
    expect(d.port).toBe(3390);
    expect(d.portTouched).toBe(true);
    expect(d.friendlyName).toBe("mstsc-gateway-utf16le");
    expect(d.scalingMode).toBe("aspect-fit");
    expect(d.qualityPref).toBe("high");
  });

  it("keeps the file's settings, gateway included, through a save", () => {
    const d = draftFromRdpImport(imported());
    expect(d.rdp?.fullscreen).toBe(true);
    expect(d.rdp?.resolution).toEqual({ mode: "fixed", width: 1920, height: 1080 });
    const saved = JSON.parse(serializeRdpSettings(d.rdp) ?? "{}");
    expect(saved.fullscreen).toBe(true);
    // Saved, so the connection goes through the gateway rather than straight
    // to the server, with every field the editor shows filled in.
    expect(saved.gateway).toEqual({
      host: "gw.example.net",
      port: 443,
      separateCredentials: false,
      username: null,
      transport: "auto",
      accessToken: null,
    });
  });

  it("fills the account but never a password", () => {
    const d = draftFromRdpImport(imported());
    expect(d.rdpUser).toBe("operator");
    expect(d.rdpDomain).toBe("EXAMPLE");
    expect(d.password).toBe("");
    expect(d.hasPassword).toBe(false);
  });

  it("carries the warnings to the editor", () => {
    const notes = draftFromRdpImport(imported()).importNotes ?? [];
    expect(notes.some((n) => n.includes("not supported yet"))).toBe(true);
    const quiet = draftFromRdpImport({ ...imported(), warnings: [] });
    expect(quiet.importNotes).toBeUndefined();
  });
});

describe("splitRdpUser", () => {
  it("splits DOMAIN\\user when the domain agrees or is missing", () => {
    expect(splitRdpUser("EXAMPLE\\operator", "example")).toEqual({ user: "operator", domain: "example" });
    expect(splitRdpUser("LAB\\operator", null)).toEqual({ user: "operator", domain: "LAB" });
  });

  it("keeps anything else whole", () => {
    expect(splitRdpUser("OTHER\\operator", "EXAMPLE")).toEqual({ user: "OTHER\\operator", domain: "EXAMPLE" });
    expect(splitRdpUser("operator@example.com", null)).toEqual({ user: "operator@example.com", domain: "" });
    const broker = "secureaccess /i operator@example.com /s example /d local";
    expect(splitRdpUser(broker, null)).toEqual({ user: broker, domain: "" });
    expect(splitRdpUser(null, null)).toEqual({ user: "", domain: "" });
  });
});
