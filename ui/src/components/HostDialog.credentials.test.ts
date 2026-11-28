import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createElement, act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { HostDialog, draftFromHost, type HostDraft } from "./HostDialog";
import { blankHostProfile, type ProtocolKind } from "../lib/types";
import type { SavedCredential } from "../lib/savedCredentials";

const ADMIN: SavedCredential = {
  id: "cred-admin",
  name: "Office admin",
  kind: "password",
  username: "admin",
  domain: "CORP",
  keyPath: null,
  hasSecret: true,
  createdAt: 1,
  updatedAt: 1,
};
const LAB_KEY: SavedCredential = {
  id: "cred-key",
  name: "Lab key",
  kind: "ssh-key",
  username: "ops",
  domain: null,
  keyPath: "/home/you/.ssh/id_ed25519",
  hasSecret: false,
  createdAt: 1,
  updatedAt: 1,
};

vi.mock("../lib/tauri", async (orig) => ({
  ...(await orig<typeof import("../lib/tauri")>()),
  savedUserNames: vi.fn(async () => null),
  hasSavedPassword: vi.fn(async () => false),
}));

const saveSavedCredential = vi.fn(async (c: SavedCredential, secret: string) => ({
  saved: { ...c, hasSecret: Boolean(secret), createdAt: 5, updatedAt: 5 },
  outcome: "saved" as const,
}));

vi.mock("../lib/savedCredentials", async (orig) => ({
  ...(await orig<typeof import("../lib/savedCredentials")>()),
  listSavedCredentials: vi.fn(async () => [ADMIN, LAB_KEY]),
  saveSavedCredential: (c: SavedCredential, s: string) => saveSavedCredential(c, s),
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root;
let host: HTMLDivElement;

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  saveSavedCredential.mockClear();
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

function draft(protocol: ProtocolKind, credentialId: string | null = null): HostDraft {
  return draftFromHost({
    ...blankHostProfile(protocol),
    id: `host-${protocol}`,
    friendlyName: "Box",
    address: "192.0.2.20",
    credentialId,
  });
}

async function open(d: HostDraft, onSave: (d: HostDraft) => void): Promise<void> {
  await act(async () => {
    root.render(createElement(HostDialog, { draft: d, groups: [], tags: [], onSave, onClose: () => {} }));
  });
  await act(async () => {
    await Promise.resolve();
  });
}

function picker(): HTMLSelectElement {
  const s = document.querySelector('select[aria-label="Credential"]');
  if (!s) throw new Error("no credential picker");
  return s as HTMLSelectElement;
}

function choose(select: HTMLSelectElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!;
  act(() => {
    setter.call(select, value);
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

function type(input: HTMLInputElement, text: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  act(() => {
    setter.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function button(text: string): HTMLButtonElement {
  const b = [...document.querySelectorAll("button")].find((x) => x.textContent?.trim() === text);
  if (!b) throw new Error(`no button ${text}`);
  return b as HTMLButtonElement;
}

function hasLabel(text: string): boolean {
  return [...document.querySelectorAll("label")].some((l) => l.textContent?.startsWith(text));
}

function options(): string[] {
  return [...picker().options].map((o) => o.textContent ?? "");
}

describe("picking a saved credential in the host editor", () => {
  it("offers a password credential for Remote Desktop but not a key", async () => {
    await open(draft("rdp"), () => {});
    expect(options()).toEqual(["Enter for this host only", "Office admin", "New saved credential…"]);
  });

  it("offers both a password and a key for SSH", async () => {
    await open(draft("ssh"), () => {});
    expect(options()).toEqual(["Enter for this host only", "Lab key", "Office admin", "New saved credential…"]);
  });

  it("hides the host's own login once one is picked, and saves the link", async () => {
    const saved: HostDraft[] = [];
    await open(draft("rdp"), (d) => saved.push(d));
    expect(hasLabel("Password")).toBe(true);
    choose(picker(), ADMIN.id);
    expect(hasLabel("Password")).toBe(false);
    expect(hasLabel("User name")).toBe(false);
    expect(document.body.textContent).toContain("Signs in as CORP\\admin");
    await act(async () => {
      button("Save Changes").click();
    });
    expect(saved[0].credentialId).toBe(ADMIN.id);
  });

  it("goes back to the host's own login with Enter for this host only", async () => {
    const saved: HostDraft[] = [];
    await open(draft("ssh", LAB_KEY.id), (d) => saved.push(d));
    expect(picker().value).toBe(LAB_KEY.id);
    expect(hasLabel("Sign in with")).toBe(false);
    choose(picker(), "");
    expect(hasLabel("Sign in with")).toBe(true);
    await act(async () => {
      button("Save Changes").click();
    });
    expect(saved[0].credentialId).toBeNull();
  });

  it("says so when the saved credential is gone, and drops the dead link on save", async () => {
    const saved: HostDraft[] = [];
    await open(draft("rdp", "deleted-one"), (d) => saved.push(d));
    expect(picker().value).toBe("");
    expect(document.body.textContent).toContain("is gone or does not work with this protocol");
    expect(hasLabel("Password")).toBe(true);
    await act(async () => {
      button("Save Changes").click();
    });
    expect(saved[0].credentialId).toBeNull();
  });

  it("treats a key credential on a VNC host as not usable", async () => {
    await open(draft("vnc", LAB_KEY.id), () => {});
    expect(options()).not.toContain("Lab key");
    expect(document.body.textContent).toContain("is gone or does not work with this protocol");
  });

  it("makes a new saved credential from the editor and picks it", async () => {
    const saved: HostDraft[] = [];
    await open(draft("vnc"), (d) => saved.push(d));
    choose(picker(), "__new__");
    const dialog = document.querySelector('[role="dialog"][aria-label="New Saved Credential"]');
    expect(dialog).not.toBeNull();
    const inputs = [...dialog!.querySelectorAll("input")] as HTMLInputElement[];
    // Name, User name, Domain, Password
    type(inputs[0], "Pi login");
    type(inputs[1], "pi");
    type(inputs[3], "raspberry");
    await act(async () => {
      button("Add Credential").click();
    });
    expect(saveSavedCredential).toHaveBeenCalledTimes(1);
    const [sent, secret] = saveSavedCredential.mock.calls[0];
    expect(sent.name).toBe("Pi login");
    expect(sent.username).toBe("pi");
    expect(sent.kind).toBe("password");
    expect(secret).toBe("raspberry");
    expect(document.querySelector('[aria-label="New Saved Credential"]')).toBeNull();
    expect(picker().value).toBe(sent.id);
    await act(async () => {
      button("Save Changes").click();
    });
    expect(saved[0].credentialId).toBe(sent.id);
    // The password went to the saved credential, never into the host draft.
    expect(saved[0].password).toBe("");
  });

  it("has no picker for a Boundary computer", async () => {
    await open(draft("boundary"), () => {});
    expect(document.querySelector('select[aria-label="Credential"]')).toBeNull();
  });
});
