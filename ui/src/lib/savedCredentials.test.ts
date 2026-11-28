import { describe, expect, it } from "vitest";
import { blankHostProfile, type HostProfile } from "./types";
import {
  credentialFits,
  credentialsFor,
  deleteSummary,
  hostHasSavedSecret,
  hostsUsing,
  linkedCredential,
  type SavedCredential,
} from "./savedCredentials";

function cred(id: string, kind: string, name = id, hasSecret = true): SavedCredential {
  return { id, name, kind, username: "u", domain: null, keyPath: null, hasSecret, createdAt: 1, updatedAt: 1 };
}

function host(name: string, protocol: string, credentialId: string | null, hasPassword = false): HostProfile {
  return { ...blankHostProfile(), id: name, friendlyName: name, protocol, credentialId, hasPassword };
}

describe("saved credentials", () => {
  it("fit the protocols Rust says they fit", () => {
    expect(credentialFits({ kind: "password" }, "vnc")).toBe(true);
    expect(credentialFits({ kind: "password" }, "rdp")).toBe(true);
    expect(credentialFits({ kind: "password" }, "ssh")).toBe(true);
    expect(credentialFits({ kind: "password" }, "boundary")).toBe(false);
    expect(credentialFits({ kind: "ssh-key" }, "ssh")).toBe(true);
    expect(credentialFits({ kind: "ssh-key" }, "rdp")).toBe(false);
    expect(credentialFits({ kind: "smartcard" }, "ssh")).toBe(false);
  });

  it("are offered by name, and only the ones that fit", () => {
    const all = [cred("b", "password", "beta"), cred("k", "ssh-key", "Key"), cred("a", "password", "Alpha")];
    expect(credentialsFor(all, "rdp").map((c) => c.name)).toEqual(["Alpha", "beta"]);
    expect(credentialsFor(all, "ssh").map((c) => c.name)).toEqual(["Alpha", "beta", "Key"]);
  });

  it("light the key icon for a linked host only when the credential has a secret", () => {
    const all = [cred("p", "password"), cred("empty", "password", "e", false), cred("k", "ssh-key")];
    expect(hostHasSavedSecret(host("a", "rdp", "p"), all)).toBe(true);
    expect(hostHasSavedSecret(host("b", "rdp", "empty"), all)).toBe(false);
    expect(hostHasSavedSecret(host("c", "rdp", "k"), all)).toBe(false);
    expect(hostHasSavedSecret(host("d", "rdp", "gone"), all)).toBe(false);
    expect(hostHasSavedSecret(host("e", "rdp", null, true), all)).toBe(true);
    expect(linkedCredential(host("f", "vnc", "k"), all)).toBeNull();
  });

  it("name every host a delete affects", () => {
    const c = cred("p", "password", "Office");
    const hosts = [host("Zeta", "rdp", "p"), host("alpha", "ssh", "p"), host("Other", "rdp", null)];
    const using = hostsUsing("p", hosts);
    expect(using.map((h) => h.friendlyName)).toEqual(["alpha", "Zeta"]);
    const text = deleteSummary(c, using);
    expect(text).toContain("2 hosts use it: alpha, Zeta.");
    expect(text).toContain("ask for a user name and password on their next connect");
    expect(deleteSummary(c, [])).toContain("No host uses Office");
    const many = Array.from({ length: 7 }, (_, i) => host(`h${i}`, "rdp", "p"));
    expect(deleteSummary(c, many)).toContain("and 2 more");
  });
});
