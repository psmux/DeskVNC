import { describe, expect, it } from "vitest";
import { ClipboardEcho, nextRemoteClipboard } from "./clipboardEcho";

describe("nextRemoteClipboard", () => {
  // Copy X on the remote, copy something else locally, copy X on the remote
  // again: the second X has to be a new state value, or React drops it as
  // unchanged and the local clipboard keeps the local text.
  it("makes a repeat of the same remote text a new value", () => {
    const first = nextRemoteClipboard(null, "same text");
    const again = nextRemoteClipboard(first, "same text");
    expect(again.text).toBe("same text");
    expect(Object.is(again, first)).toBe(false);
    expect(again).not.toEqual(first);
  });
});

describe("ClipboardEcho", () => {
  it("does not push back what it just moved", () => {
    const echo = new ClipboardEcho();
    expect(echo.shouldPush("copied", false)).toBe(true);
    echo.moved("copied");
    expect(echo.shouldPush("copied", false)).toBe(false);
    expect(echo.shouldPush("something else", false)).toBe(true);
  });

  it("pushes on request even when nothing changed", () => {
    const echo = new ClipboardEcho();
    echo.moved("copied");
    expect(echo.shouldPush("copied", true)).toBe(true);
  });

  it("never pushes empty text", () => {
    const echo = new ClipboardEcho();
    expect(echo.shouldPush("", false)).toBe(false);
    expect(echo.shouldPush("", true)).toBe(false);
  });

  // Issue #9: the new connection's clipboard channel starts empty, so the
  // text pushed before the drop has to be offered again.
  it("pushes the same text again after a reconnect", () => {
    const echo = new ClipboardEcho();
    echo.moved("copied before the drop");
    echo.connected();
    expect(echo.shouldPush("copied before the drop", false)).toBe(true);
  });
});
