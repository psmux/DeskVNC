import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";

// The shell, faked at the IPC boundary: `invoke` answers per command and
// `listen` hands the test the handler so it can fire shell events.
const calls: { cmd: string; args: unknown }[] = [];
const answers: Record<string, (args: unknown) => unknown> = {};
const listeners: Record<string, (e: { payload: unknown }) => void> = {};

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: async (cmd: string, args?: unknown) => {
    calls.push({ cmd, args });
    const answer = answers[cmd];
    if (!answer) throw new Error(`no fake for ${cmd}`);
    return answer(args);
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: async (event: string, handler: (e: { payload: unknown }) => void) => {
    listeners[event] = handler;
    return () => delete listeners[event];
  },
}));

const { saveCredentials, describeCredentialStore } = await import("../lib/credentialStore");
const { CredentialUnlockHost } = await import("./CredentialUnlock");
const { ToastProvider } = await import("../state/ToastContext");

const LOCKED = "credential store is locked; unlock it with the master password first";

let root: Root | null = null;
let host: HTMLDivElement | null = null;

beforeEach(() => {
  calls.length = 0;
  for (const k of Object.keys(answers)) delete answers[k];
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  root = null;
});

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await act(async () => await Promise.resolve());
}

function type(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

describe("saveCredentials", () => {
  it("does not swallow a failed save", async () => {
    answers.save_password = () => {
      throw new Error("Couldn't access platform storage");
    };
    await expect(saveCredentials("h", { vncPassword: "x" })).rejects.toThrow(/platform storage/);
  });

  it("treats a locked store as waiting for the unlock, not as saved", async () => {
    answers.save_password = () => {
      throw LOCKED;
    };
    await expect(saveCredentials("h", { vncPassword: "x" })).resolves.toBe("waiting-for-unlock");
  });

  it("reports a save that worked", async () => {
    answers.save_password = () => null;
    await expect(saveCredentials("h", { vncPassword: "x" })).resolves.toBe("saved");
  });
});

describe("describeCredentialStore", () => {
  it("explains a locked encrypted file instead of printing the enum", () => {
    const line = describeCredentialStore({ backend: "Locked", vaultExists: true, parkedSaves: 0 });
    expect(line).not.toMatch(/^Passwords are stored in: Locked$/);
    expect(line).toMatch(/no usable keychain/i);
    expect(line).toMatch(/master password/i);
  });
});

describe("CredentialUnlockHost", () => {
  function mount(): void {
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    act(() =>
      root!.render(createElement(ToastProvider, null, createElement(CredentialUnlockHost))),
    );
  }

  it("asks for a new master password when a save waits for it, and unlocks with it", async () => {
    let unlocked = false;
    answers.credential_status = () => ({
      backend: unlocked ? "EncryptedFile" : "Locked",
      vaultExists: unlocked,
      parkedSaves: unlocked ? 0 : 1,
    });
    answers.unlock_credentials = () => {
      unlocked = true;
      return ["host-1"];
    };
    mount();
    await flush();
    // No file yet: nothing is asked at start.
    expect(document.body.textContent).not.toMatch(/master password/i);

    act(() => listeners["credential-store-locked"]?.({ payload: { hostId: "host-1" } }));
    await flush();
    expect(document.body.textContent).toMatch(/Choose a master password/);
    expect(document.body.textContent).toMatch(/One password you asked to remember is waiting/);

    const [pw, again] = [
      ...document.querySelectorAll<HTMLInputElement>("input[type=password]"),
    ];
    type(pw, "long enough secret");
    type(again, "long enough secret");
    const create = [...document.querySelectorAll("button")].find((b) => b.textContent === "Create")!;
    expect(create.disabled).toBe(false);
    await act(async () => create.click());
    await flush();

    const unlock = calls.find((c) => c.cmd === "unlock_credentials");
    expect(unlock?.args).toEqual({ masterPassword: "long enough secret" });
    expect(document.body.textContent).not.toMatch(/Choose a master password/);
  });

  it("asks once at start for a file from an earlier run, and says when the password is wrong", async () => {
    answers.credential_status = () => ({ backend: "Locked", vaultExists: true, parkedSaves: 0 });
    answers.unlock_credentials = () => {
      throw "invalid master password";
    };
    mount();
    await flush();
    expect(document.body.textContent).toMatch(/Unlock saved passwords/);
    const [pw] = [...document.querySelectorAll<HTMLInputElement>("input[type=password]")];
    type(pw, "not it");
    const unlock = [...document.querySelectorAll("button")].find((b) => b.textContent === "Unlock")!;
    await act(async () => unlock.click());
    await flush();
    expect(document.body.textContent).toMatch(/not the one this file was locked with/);
  });

  it("does not reopen after Not now, and says the password is waiting instead", async () => {
    answers.credential_status = () => ({ backend: "Locked", vaultExists: false, parkedSaves: 1 });
    mount();
    await flush();
    act(() => listeners["credential-store-locked"]?.({ payload: { hostId: "h" } }));
    await flush();
    const notNow = [...document.querySelectorAll("button")].find((b) => b.textContent === "Not now")!;
    act(() => notNow.click());
    await flush();
    expect(document.body.textContent).not.toMatch(/Choose a master password/);

    act(() => listeners["credential-store-locked"]?.({ payload: { hostId: "h" } }));
    await flush();
    expect(document.body.textContent).not.toMatch(/Choose a master password/);
  });
});
