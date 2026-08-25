/**
 * Library thumbnail for an SSH session: renders the terminal's own visible
 * buffer onto an offscreen canvas and reads it back as RGBA, the same shape
 * `capture_thumbnail` expects from the WebGL path (see
 * `WebGLRenderer.readFramebufferRGBA`).
 *
 * An SSH session has no framebuffer to read pixels from. The renderer xterm
 * picked underneath (canvas or WebGL) is an implementation detail this
 * should not depend on, `preserveDrawingBuffer` is not set on either, and
 * screenshotting the live DOM would pull in a dependency for something the
 * terminal's own buffer API already answers directly. Walking
 * `buffer.active` and drawing plain text is deterministic, dependency-free,
 * and legible at tile size, which is the only bar this has to clear.
 */
import type { Terminal } from "@xterm/xterm";
import { buildTheme } from "../components/SshTerminal";

/**
 * Plain cell-grid text at the terminal's own font: no cursor, no selection,
 * no per-cell colour. A mini-terminal that is legible beats a pixel-accurate
 * one nobody can read at tile size.
 *
 * Sized from the terminal's live grid (`cols`/`rows`) and its own font
 * metrics rather than a fixed thumbnail resolution, the same way the VNC/RDP
 * path hands over the full framebuffer and lets `vnc_store::save_thumbnail`
 * do the one downscale (`MAX_THUMB_WIDTH`, `crates/vnc-store/src/thumbs.rs`).
 *
 * Returns `null` when the terminal has not been measured yet (`cols`/`rows`
 * still 0, before the first `fit()`) or a canvas context could not be
 * obtained: there is nothing to draw a thumbnail of either way.
 */
export function captureTerminalThumbnail(
  term: Terminal,
): { width: number; height: number; pixels: Uint8Array } | null {
  const cols = term.cols;
  const rows = term.rows;
  if (cols <= 0 || rows <= 0) return null;

  const fontFamily = term.options.fontFamily ?? "monospace";
  const fontSize = term.options.fontSize ?? 13;
  const lineHeight = term.options.lineHeight ?? 1.35;
  const font = `${fontSize}px ${fontFamily}`;

  // A throwaway context just to measure a glyph: xterm's own cell width is a
  // private implementation detail, and this runs at most twice per session,
  // so it is not worth caching.
  const probe = document.createElement("canvas").getContext("2d");
  if (!probe) return null;
  probe.font = font;
  const cellWidth = probe.measureText("M").width;
  const cellHeight = fontSize * lineHeight;

  const width = Math.max(1, Math.round(cols * cellWidth));
  const height = Math.max(1, Math.round(rows * cellHeight));

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;

  const theme = buildTheme();
  ctx.fillStyle = theme.background ?? "#1a1d24";
  ctx.fillRect(0, 0, width, height);
  ctx.fillStyle = theme.foreground ?? "#e9ebef";
  ctx.font = font;
  ctx.textBaseline = "top";

  // `buffer.active` is absolute (scrollback included); `viewportY` is the
  // row currently scrolled to the top of the screen, so this reads exactly
  // what the user is looking at, not the start of history.
  const buffer = term.buffer.active;
  for (let y = 0; y < rows; y++) {
    const line = buffer.getLine(buffer.viewportY + y);
    if (!line) continue;
    // `true` trims trailing whitespace: a blank line drawn in full would
    // still be blank, this only saves the `fillText` call.
    const text = line.translateToString(true);
    if (text.length === 0) continue;
    ctx.fillText(text, 0, y * cellHeight);
  }

  const { data } = ctx.getImageData(0, 0, width, height);
  // `ImageData.data` is a `Uint8ClampedArray` view over the same bytes
  // `capture_thumbnail` wants as a `Uint8Array`; wrap rather than copy.
  const pixels = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return { width, height, pixels };
}
