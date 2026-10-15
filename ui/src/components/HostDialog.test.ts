import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { HostDialog, draftFromHost, type HostDraft } from "./HostDialog";
import { blankHostProfile } from "../lib/types";
import { vncCredentialPayload, vncTakesUsername } from "../lib/hostDraft";

// The editor asks the keychain for saved names and whether a password is
// there. Those answers are what a host saved by 0.29.0 would give.
vi.mock("../lib/tauri", async (orig) => ({
  ...(await orig<typeof import("../lib/tauri")>()),
  savedUserNames: vi.fn(async () => ({ vncUser: "alice", rdpUser: null, rdpDomain: null, sshUser: null })),
  hasSavedPassword: vi.fn(async () => true),
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root;
let host: HTMLDivElement;

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

/** A Mac saved with Apple Screen Sharing whose library row says "no password". */
function savedMac(): HostDraft {
  return draftFromHost({
    ...blankHostProfile(),
    id: "mac-1",
    friendlyName: "Office Mac",
    address: "192.168.1.3",
    port: 5900,
    osHint: "macos",
    securityPref: "apple-dh",
    hasPassword: false,
  });
}

function field(label: string): HTMLInputElement {
  const labels = [...document.querySelectorAll("label")];
  const found = labels.find((l) => l.textContent?.startsWith(label));
  const input = found?.querySelector("input") ?? found?.parentElement?.querySelector("input");
  if (!input) throw new Error(`no field ${label}`);
  return input as HTMLInputElement;
}

/** Type the way a person does: React only hears a native input event. */
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

async function open(onSave: (d: HostDraft) => void): Promise<void> {
  await act(async () => {
    root.render(
      createElement(HostDialog, { draft: savedMac(), groups: [], tags: [], onSave, onClose: () => {} }),
    );
  });
  // let the keychain answers land
  await act(async () => {
    await Promise.resolve();
  });
}

describe("editing a saved Mac", () => {
  it("shows the saved user name and says a password is kept", async () => {
    await open(() => {});
    expect(field("User name").value).toBe("alice");
    expect(field("Password").placeholder).toContain("unchanged");
  });

  it("saves a new user name and password typed over the old ones", async () => {
    const saved: HostDraft[] = [];
    await open((d) => saved.push(d));
    type(field("User name"), "bob");
    type(field("Password"), "new-secret");
    await act(async () => {
      button("Save Changes").click();
    });
    expect(saved).toHaveLength(1);
    const d = saved[0];
    // The exact payload Library sends to `save_password` for this draft.
    expect(vncCredentialPayload(d.vncUser, d.password, vncTakesUsername(d.securityPref, d.osHint))).toEqual({
      vencryptUser: "bob",
      vencryptPass: "new-secret",
    });
  });

  it("keeps the saved login when the boxes are left alone", async () => {
    const saved: HostDraft[] = [];
    await open((d) => saved.push(d));
    await act(async () => {
      button("Save Changes").click();
    });
    const d = saved[0];
    expect(d.password).toBe("");
    // Only the name goes back, and the Rust merge keeps the stored password.
    expect(vncCredentialPayload(d.vncUser, d.password, true)).toEqual({ vencryptUser: "alice" });
  });
});
