import { beforeEach, describe, expect, it, vi } from "vitest";
import { Terminal } from "@xterm/xterm";
import { installTerminalClipboard } from "./terminalClipboard";
import { readClipboard, writeClipboard } from "./tauri";

vi.mock("./tauri", () => ({ readClipboard: vi.fn(), writeClipboard: vi.fn() }));

function setup() {
  let handler: (event: KeyboardEvent) => boolean = () => true;
  const term = {
    attachCustomKeyEventHandler: (fn: typeof handler) => { handler = fn; },
    getSelection: vi.fn(() => "selected text"),
    paste: vi.fn(),
  };
  const container = document.createElement("div");
  const stop = installTerminalClipboard(term, container);
  return { term, container, stop, key: (key: string, init: KeyboardEventInit) => {
    const event = new KeyboardEvent("keydown", { key, cancelable: true, ...init });
    return { handled: !handler(event), prevented: event.defaultPrevented };
  } };
}

beforeEach(() => { vi.resetAllMocks(); });

describe("SSH clipboard", () => {
  it.each([{ metaKey: true }, { ctrlKey: true, shiftKey: true }])(
    "copies the terminal selection with %j", async (modifiers) => {
      const s = setup();
      expect(s.key("c", modifiers)).toEqual({ handled: true, prevented: true });
      expect(writeClipboard).toHaveBeenCalledWith("selected text");
      s.stop();
    },
  );

  it("leaves Ctrl+C and Ctrl+V available to the remote terminal", () => {
    const s = setup();
    expect(s.key("c", { ctrlKey: true }).handled).toBe(false);
    expect(s.key("v", { ctrlKey: true }).handled).toBe(false);
    expect(writeClipboard).not.toHaveBeenCalled();
    s.stop();
  });

  it.each([{ metaKey: true }, { ctrlKey: true, shiftKey: true }])(
    "pastes through xterm with %j", async (modifiers) => {
      vi.mocked(readClipboard).mockResolvedValue("first\nsecond");
      const s = setup();
      expect(s.key("v", modifiers).prevented).toBe(true);
      await Promise.resolve();
      expect(s.term.paste).toHaveBeenCalledExactlyOnceWith("first\nsecond");
      s.stop();
    },
  );

  it("does not paste after disposal or when the clipboard cannot be read", async () => {
    vi.mocked(readClipboard).mockResolvedValue("late");
    const s = setup();
    s.key("v", { metaKey: true });
    s.stop();
    await Promise.resolve();
    expect(s.term.paste).not.toHaveBeenCalled();
    vi.mocked(readClipboard).mockResolvedValue(null);
    const next = setup();
    next.key("v", { metaKey: true });
    await Promise.resolve();
    expect(next.term.paste).not.toHaveBeenCalled();
    next.stop();
  });

  it("handles a DOM paste once and removes its listener on disposal", () => {
    const s = setup();
    const event = new Event("paste", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "clipboardData", { value: { getData: () => "text" } });
    s.container.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    expect(s.term.paste).toHaveBeenCalledExactlyOnceWith("text");
    s.stop();
    s.container.dispatchEvent(event);
    expect(s.term.paste).toHaveBeenCalledTimes(1);
  });

  it("preserves xterm newline conversion and bracketed paste", async () => {
    const term = new Terminal();
    const container = document.createElement("div");
    document.body.append(container);
    vi.stubGlobal("matchMedia", () => ({ matches: false, addListener() {}, removeListener() {} }));
    term.open(container);
    const data: string[] = [];
    term.onData((text) => data.push(text));
    term.paste("one\ntwo");
    expect(data).toEqual(["one\rtwo"]);
    await new Promise<void>((resolve) => term.write("\x1b[?2004h", resolve));
    term.paste("one\ntwo");
    expect(data[1]).toBe("\x1b[200~one\rtwo\x1b[201~");
    term.dispose();
    container.remove();
    vi.unstubAllGlobals();
  });
});
