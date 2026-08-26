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
 * `buffer.active` is deterministic and dependency-free, and reading each
 * cell's own attributes rather than just its text puts a shell tile in the
 * Library on the same footing as the VNC and RDP tiles beside it, which are
 * literal framebuffer pixels.
 */
import type { IBufferCell, IBufferLine, ITheme, Terminal } from "@xterm/xterm";
import { buildTheme } from "../components/SshTerminal";

/**
 * How much the dim attribute (CSI 2 m) knocks back the foreground. xterm's
 * own renderers use half alpha; matching it keeps a dimmed prompt looking
 * dimmed in the tile rather than turning it into a second bold.
 */
const DIM_ALPHA = 0.5;

/** ITheme's 16 ANSI slots, in palette-index order. */
const ANSI_KEYS = [
  "black",
  "red",
  "green",
  "yellow",
  "blue",
  "magenta",
  "cyan",
  "white",
  "brightBlack",
  "brightRed",
  "brightGreen",
  "brightYellow",
  "brightBlue",
  "brightMagenta",
  "brightCyan",
  "brightWhite",
] as const satisfies readonly (keyof ITheme)[];

/**
 * Plain VGA colors, used only for a slot the theme left unset. `buildTheme`
 * fills all sixteen, but every field on `ITheme` is optional and a thumbnail
 * is not worth a crash over a missing one.
 */
const ANSI_FALLBACK = [
  "#000000",
  "#cd0000",
  "#00cd00",
  "#cdcd00",
  "#0000ee",
  "#cd00cd",
  "#00cdcd",
  "#e5e5e5",
  "#7f7f7f",
  "#ff0000",
  "#00ff00",
  "#ffff00",
  "#5c5cff",
  "#ff00ff",
  "#00ffff",
  "#ffffff",
] as const;

/** The six channel levels of the 6x6x6 cube at palette indices 16 to 231. */
const CUBE_LEVELS = [0, 95, 135, 175, 215, 255] as const;

function rgbCss(r: number, g: number, b: number): string {
  return `rgb(${r}, ${g}, ${b})`;
}

/** A cell's 24-bit true colour (`CSI 38 ; 2 ; …`) as a canvas fill style. */
function trueColorCss(value: number): string {
  return `#${(value & 0xffffff).toString(16).padStart(6, "0")}`;
}

/**
 * The 256 colour palette a cell's index refers to: the theme's own sixteen
 * first, so an `ls` in the shell picks up the same red and blue as the rest
 * of the window, then the standard xterm cube and greyscale ramp, which are
 * fixed by the protocol and nothing to theme.
 */
export function buildPalette(theme: ITheme): string[] {
  const palette: string[] = [];
  for (let i = 0; i < 16; i++) palette.push(theme[ANSI_KEYS[i]] ?? ANSI_FALLBACK[i]);
  for (let i = 0; i < 216; i++) {
    palette.push(
      rgbCss(
        CUBE_LEVELS[Math.floor(i / 36) % 6],
        CUBE_LEVELS[Math.floor(i / 6) % 6],
        CUBE_LEVELS[i % 6],
      ),
    );
  }
  for (let i = 0; i < 24; i++) {
    const level = 8 + i * 10;
    palette.push(rgbCss(level, level, level));
  }
  return palette;
}

/** What one cell paints with. `bg` is null when the cell keeps the default
 *  background, which the canvas was already cleared to. */
export interface CellColors {
  fg: string;
  bg: string | null;
}

/**
 * Resolve a cell's two colours through the three modes xterm reports
 * (default, 256-colour palette, 24-bit true colour), then apply inverse.
 *
 * Inverse is settled here rather than at the paint sites because it is what
 * makes a status line or a selected menu entry recognisable at tile size,
 * and it turns a default background into something that has to be filled.
 */
export function cellColors(
  cell: IBufferCell,
  palette: string[],
  defaultFg: string,
  defaultBg: string,
): CellColors {
  let fg = cell.isFgDefault()
    ? defaultFg
    : cell.isFgPalette()
      ? (palette[cell.getFgColor()] ?? defaultFg)
      : trueColorCss(cell.getFgColor());
  let bg = cell.isBgDefault()
    ? null
    : cell.isBgPalette()
      ? (palette[cell.getBgColor()] ?? defaultBg)
      : trueColorCss(cell.getBgColor());

  if (cell.isInverse()) {
    const swapped = fg;
    fg = bg ?? defaultBg;
    bg = swapped;
  }
  return { fg, bg };
}

/** Everything the row painters need that does not change between rows. */
interface RowContext {
  ctx: CanvasRenderingContext2D;
  cell: IBufferCell;
  palette: string[];
  defaultFg: string;
  defaultBg: string;
  cols: number;
  cellWidth: number;
  cellHeight: number;
  fontSize: number;
  fontFamily: string;
}

/** A stretch of one row sharing a foreground colour and a set of attributes,
 *  drawn with a single `fillText` rather than a call per cell. */
interface TextRun {
  x: number;
  cells: number;
  text: string;
  fg: string;
  bold: boolean;
  italic: boolean;
  dim: boolean;
  underline: boolean;
  strike: boolean;
}

function sameStyle(run: TextRun, other: Omit<TextRun, "x" | "cells" | "text">): boolean {
  return (
    run.fg === other.fg &&
    run.bold === other.bold &&
    run.italic === other.italic &&
    run.dim === other.dim &&
    run.underline === other.underline &&
    run.strike === other.strike
  );
}

/**
 * Backgrounds for one row, batched into runs of the same colour.
 *
 * Run edges are rounded to whole pixels: `cellWidth` comes off `measureText`
 * and is almost never an integer, and two adjacent `fillRect`s at fractional
 * edges leave an antialiased seam between them that shows up as a grid of
 * hairlines behind a coloured block.
 */
function paintRowBackgrounds(rc: RowContext, line: IBufferLine, row: number): void {
  const { ctx, cell, palette, defaultFg, defaultBg, cols, cellWidth, cellHeight } = rc;
  const top = Math.round(row * cellHeight);
  const bottom = Math.round((row + 1) * cellHeight);

  let runColor: string | null = null;
  let runStart = 0;
  const flush = (end: number): void => {
    if (runColor !== null) {
      const left = Math.round(runStart * cellWidth);
      ctx.fillStyle = runColor;
      ctx.fillRect(left, top, Math.round(end * cellWidth) - left, bottom - top);
    }
    runColor = null;
  };

  for (let x = 0; x < cols; x++) {
    const bg = line.getCell(x, cell) ? cellColors(cell, palette, defaultFg, defaultBg).bg : null;
    if (bg === runColor) continue;
    flush(x);
    runColor = bg;
    runStart = x;
  }
  flush(cols);
}

function drawTextRun(rc: RowContext, run: TextRun, row: number): void {
  const { ctx, cellWidth, cellHeight, fontSize, fontFamily } = rc;
  const left = Math.round(run.x * cellWidth);
  const top = row * cellHeight;
  // The cell is taller than the font (xterm's `lineHeight`), so the glyph is
  // centred in it the way xterm centres its own rather than pinned to the
  // top of the cell.
  const textTop = top + (cellHeight - fontSize) / 2;

  ctx.globalAlpha = run.dim ? DIM_ALPHA : 1;
  ctx.fillStyle = run.fg;

  if (run.underline || run.strike) {
    const thickness = Math.max(1, Math.round(fontSize / 12));
    const span = Math.round((run.x + run.cells) * cellWidth) - left;
    if (run.underline) {
      // Under the glyph, not on the floor of the cell: with a line height of
      // 1.35 the two are three pixels apart, which is the difference between
      // an underline and a rule between rows. The bottom of the em box
      // clears descenders; the clamp keeps it inside its own cell for a
      // font tall enough to overflow.
      const y = Math.min(Math.round(textTop + fontSize), Math.round(top + cellHeight) - thickness);
      ctx.fillRect(left, y, span, thickness);
    }
    if (run.strike) ctx.fillRect(left, Math.round(textTop + fontSize / 2), span, thickness);
  }

  if (run.text.trim() !== "") {
    ctx.font = `${run.italic ? "italic " : ""}${run.bold ? "bold " : ""}${fontSize}px ${fontFamily}`;
    ctx.fillText(run.text, left, textTop);
  }

  ctx.globalAlpha = 1;
}

/** Text for one row, batched into runs that share a foreground and a style. */
function paintRowText(rc: RowContext, line: IBufferLine, row: number): void {
  const { cell, palette, defaultFg, defaultBg, cols } = rc;
  let run: TextRun | null = null;
  const flush = (): void => {
    if (run) drawTextRun(rc, run, row);
    run = null;
  };

  for (let x = 0; x < cols; x++) {
    if (!line.getCell(x, cell)) {
      flush();
      continue;
    }
    // 0 is the trailing half of a wide glyph, drawn whole with its leading
    // half; it has no character of its own to add.
    const span = cell.getWidth();
    if (span === 0) continue;

    const style = {
      fg: cellColors(cell, palette, defaultFg, defaultBg).fg,
      bold: cell.isBold() !== 0,
      italic: cell.isItalic() !== 0,
      dim: cell.isDim() !== 0,
      underline: cell.isUnderline() !== 0,
      strike: cell.isStrikethrough() !== 0,
    };
    if (run && !sameStyle(run, style)) flush();
    if (!run) run = { ...style, x, cells: 0, text: "" };

    // An invisible cell (CSI 8 m) still holds its width open, and a null
    // cell reports no characters at all; both advance as blanks so the rest
    // of the run stays on its own columns.
    const chars = cell.getChars();
    run.text += chars === "" || cell.isInvisible() ? " ".repeat(span) : chars;
    run.cells += span;

    // A monospace font advances one cell per character, which is the whole
    // reason a run can be drawn as one string. A CJK glyph is the exception:
    // it occupies two cells but its advance is whatever the font says, so
    // the run ends here and the next one starts at its own column instead of
    // letting the error accumulate across the row.
    if (span !== 1) flush();
  }
  flush();
}

/**
 * A mini-terminal: the visible grid at the terminal's own font, in the
 * colours and attributes the cells actually carry, with no cursor and no
 * selection.
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
  const defaultBg = theme.background ?? "#1a1d24";
  const defaultFg = theme.foreground ?? "#e9ebef";
  ctx.fillStyle = defaultBg;
  ctx.fillRect(0, 0, width, height);
  ctx.textBaseline = "top";

  // `buffer.active` is absolute (scrollback included); `viewportY` is the
  // row currently scrolled to the top of the screen, so this reads exactly
  // what the user is looking at, not the start of history.
  const buffer = term.buffer.active;
  const rc: RowContext = {
    ctx,
    // One reusable cell for the whole capture, which is what `getNullCell`
    // is for: a fresh object per cell would be tens of thousands of them.
    cell: buffer.getNullCell(),
    palette: buildPalette(theme),
    defaultFg,
    defaultBg,
    cols,
    cellWidth,
    cellHeight,
    fontSize,
    fontFamily,
  };

  for (let y = 0; y < rows; y++) {
    const line = buffer.getLine(buffer.viewportY + y);
    if (!line) continue;
    // Backgrounds for the whole row first: a later cell's block would
    // otherwise paint over the overhang of an italic glyph beside it.
    paintRowBackgrounds(rc, line, y);
    paintRowText(rc, line, y);
  }

  const { data } = ctx.getImageData(0, 0, width, height);
  // `ImageData.data` is a `Uint8ClampedArray` view over the same bytes
  // `capture_thumbnail` wants as a `Uint8Array`; wrap rather than copy.
  const pixels = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return { width, height, pixels };
}
