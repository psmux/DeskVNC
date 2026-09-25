import type { Terminal } from "@xterm/xterm";
import { readClipboard, writeClipboard } from "./tauri";

/** Use the native clipboard in both SSH views while preserving terminal paste modes. */
export function installTerminalClipboard(
  term: Pick<Terminal, "attachCustomKeyEventHandler" | "getSelection" | "paste">,
  container: HTMLElement,
): () => void {
  let disposed = false;
  term.attachCustomKeyEventHandler((event) => {
    const key = event.key.toLowerCase();
    const modifier = !event.altKey && (
      (event.metaKey && !event.ctrlKey) ||
      (event.ctrlKey && event.shiftKey && !event.metaKey)
    );
    const copy = modifier && key === "c";
    const paste = modifier && key === "v";
    if (!copy && !paste) return true;
    const selection = copy ? term.getSelection() : "";
    if (copy && !selection) return true;
    event.preventDefault();
    if (event.type === "keydown") {
      if (copy) void writeClipboard(selection);
      else void readClipboard().then((text) => {
        if (!disposed && text !== null) term.paste(text);
      });
    }
    return false;
  });

  const onPaste = (event: ClipboardEvent): void => {
    const text = event.clipboardData?.getData("text/plain");
    if (text == null) return;
    event.preventDefault();
    event.stopPropagation();
    // xterm normalizes newlines and adds bracketed paste delimiters when the
    // remote application requests them. Sending bytes directly skips both.
    term.paste(text);
  };
  container.addEventListener("paste", onPaste, true);
  return () => {
    disposed = true;
    container.removeEventListener("paste", onPaste, true);
  };
}
