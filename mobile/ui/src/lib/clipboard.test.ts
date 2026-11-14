import { describe, expect, it } from "vitest";
import { ClipboardError, READ_FAILED, WRITE_FAILED, clipboardMessage, readClipboard, writeClipboard, type ClipboardBackend } from "./clipboard";

function backend(over: Partial<ClipboardBackend>): ClipboardBackend {
  return { read: async () => "", write: async () => {}, ...over };
}

describe("the phone clipboard", () => {
  it("reads and writes through the backend", async () => {
    let held = "";
    const b = backend({ read: async () => held, write: async (t) => void (held = t) });
    await writeClipboard("boundary1:abc", b);
    expect(await readClipboard(b)).toBe("boundary1:abc");
  });

  it("reads an empty clipboard as nothing, not as a failure", async () => {
    const b = backend({
      read: () => Promise.reject("Clipboard is empty"),
    });
    expect(await readClipboard(b)).toBe("");
  });

  it("turns a refusal into a message the person can act on", async () => {
    // What the Android WebView's navigator.clipboard did.
    const refused = backend({
      read: () => Promise.reject(new DOMException("Read permission denied.", "NotAllowedError")),
      write: () => Promise.reject(new DOMException("Write permission denied.", "NotAllowedError")),
    });
    await expect(readClipboard(refused)).rejects.toBeInstanceOf(ClipboardError);
    await expect(readClipboard(refused)).rejects.toThrow(READ_FAILED);
    await expect(writeClipboard("x", refused)).rejects.toThrow(WRITE_FAILED);
  });

  it("falls back to a stock sentence for errors from elsewhere", () => {
    expect(clipboardMessage(new ClipboardError("specific"))).toBe("specific");
    expect(clipboardMessage(new Error("odd"), WRITE_FAILED)).toBe(WRITE_FAILED);
  });
});
