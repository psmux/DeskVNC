import { describe, expect, it } from "vitest";
import { ClipboardEcho } from "./clipboardEcho";

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
