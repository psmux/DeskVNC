/**
 * The phone's clipboard.
 *
 * Inside the app it goes through the Tauri clipboard manager plugin, because
 * the Android WebView refuses navigator.clipboard with NotAllowedError even
 * while the app is in front. In a plain browser (the mock, screenshots) it
 * falls back to navigator.clipboard.
 *
 * Both calls throw a ClipboardError with a sentence the person can act on, so
 * every caller can show it rather than fail without a word.
 */
import { invoke } from "@tauri-apps/api/core";
import { insideTauri } from "../api";

export class ClipboardError extends Error {}

export const READ_FAILED = "This phone did not let DeskVNC read the clipboard. Long press the box and choose Paste instead.";
export const WRITE_FAILED = "This phone did not let DeskVNC copy. Long press the text to select and copy it.";

export interface ClipboardBackend {
  read(): Promise<string>;
  write(text: string): Promise<void>;
}

const tauriBackend: ClipboardBackend = {
  read: () => invoke<string>("plugin:clipboard-manager|read_text"),
  write: (text) => invoke<void>("plugin:clipboard-manager|write_text", { text }),
};

const browserBackend: ClipboardBackend = {
  read: async () => (await navigator.clipboard.readText()) ?? "",
  write: (text) => navigator.clipboard.writeText(text),
};

/** The plugin says this when there is simply nothing to paste. */
function isEmptyClipboard(e: unknown): boolean {
  const text = e instanceof Error ? e.message : String(e);
  return /clipboard is empty|no text|empty/i.test(text);
}

function pick(): ClipboardBackend {
  return insideTauri() ? tauriBackend : browserBackend;
}

/** The text on the clipboard, "" when it holds none. */
export async function readClipboard(backend: ClipboardBackend = pick()): Promise<string> {
  try {
    return (await backend.read()) ?? "";
  } catch (e) {
    if (isEmptyClipboard(e)) return "";
    throw new ClipboardError(READ_FAILED);
  }
}

export async function writeClipboard(text: string, backend: ClipboardBackend = pick()): Promise<void> {
  try {
    await backend.write(text);
  } catch {
    throw new ClipboardError(WRITE_FAILED);
  }
}

/** The message to show for a failed clipboard call. */
export function clipboardMessage(e: unknown, fallback = READ_FAILED): string {
  return e instanceof ClipboardError ? e.message : fallback;
}
