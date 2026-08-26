/**
 * The thumbnail is written into a canvas the user never sees and read back
 * as raw bytes, so the only way to check it draws what the cells say is to
 * record the drawing calls. jsdom has no canvas implementation at all
 * (`getContext` returns null), so the fake below is not a workaround for a
 * missing feature, it is the whole test surface.
 */
import { beforeEach, afterEach, describe, expect, it } from "vitest";
import type { IBufferCell, Terminal } from "@xterm/xterm";
import { buildPalette, captureTerminalThumbnail, cellColors } from "./TerminalThumbnail";

// ------------------------------------------------------------- recording canvas

type Op =
  | { op: "rect"; x: number; y: number; w: number; h: number; fill: string; alpha: number }
  | { op: "text"; text: string; x: number; y: number; fill: string; font: string; alpha: number };

/** One cell wide in the fake font, so a column index and a pixel x differ by
 *  exactly this factor and the expectations below stay readable. */
const CELL_PX = 8;

class FakeContext {
  fillStyle = "";
  font = "";
  globalAlpha = 1;
  textBaseline = "";
  ops: Op[] = [];

  fillRect(x: number, y: number, w: number, h: number): void {
    this.ops.push({ op: "rect", x, y, w, h, fill: this.fillStyle, alpha: this.globalAlpha });
  }

  fillText(text: string, x: number, y: number): void {
    this.ops.push({
      op: "text",
      text,
      x,
      y,
      fill: this.fillStyle,
      font: this.font,
      alpha: this.globalAlpha,
    });
  }

  measureText(): { width: number } {
    return { width: CELL_PX };
  }

  getImageData(_x: number, _y: number, w: number, h: number): { data: Uint8ClampedArray } {
    return { data: new Uint8ClampedArray(w * h * 4) };
  }
}

let contexts: FakeContext[] = [];
let realGetContext: typeof HTMLCanvasElement.prototype.getContext;

beforeEach(() => {
  contexts = [];
  // `buildTheme` asks the OS for its colour scheme, which jsdom does not
  // answer. Light is the "no explicit choice" branch, and the assertions
  // below only depend on it being one branch or the other consistently.
  window.matchMedia = ((query: string) =>
    ({
      matches: false,
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }) as unknown as MediaQueryList) as typeof window.matchMedia;
  realGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function fake(): unknown {
    const ctx = new FakeContext();
    contexts.push(ctx);
    return ctx;
  } as typeof HTMLCanvasElement.prototype.getContext;
});

afterEach(() => {
  HTMLCanvasElement.prototype.getContext = realGetContext;
});

/** The capture makes two canvases: a throwaway one to measure a glyph, then
 *  the one it actually paints. Only the second one's calls are the output. */
function paintedOps(): Op[] {
  expect(contexts.length).toBe(2);
  return contexts[1].ops;
}

// ------------------------------------------------------------------ fake buffer

interface Color {
  mode: "default" | "palette" | "rgb";
  value?: number;
}

interface CellSpec {
  chars: string;
  width?: number;
  fg?: Color;
  bg?: Color;
  bold?: boolean;
  italic?: boolean;
  dim?: boolean;
  inverse?: boolean;
  invisible?: boolean;
  underline?: boolean;
  strike?: boolean;
}

const BLANK: CellSpec = { chars: "" };

/**
 * Mirrors the contract `getNullCell` + `line.getCell(x, cell)` has: one cell
 * object is reused for the whole capture and each read overwrites it, so a
 * fake that handed back independent objects would let a bug that retains a
 * cell pass here and fail against the real terminal.
 */
class FakeCell {
  spec: CellSpec = BLANK;

  getWidth(): number {
    return this.spec.width ?? (this.spec.chars === "" ? 1 : 1);
  }
  getChars(): string {
    return this.spec.chars;
  }
  getCode(): number {
    return this.spec.chars.codePointAt(0) ?? 0;
  }
  getFgColorMode(): number {
    return 0;
  }
  getBgColorMode(): number {
    return 0;
  }
  getFgColor(): number {
    return this.spec.fg?.value ?? 0;
  }
  getBgColor(): number {
    return this.spec.bg?.value ?? 0;
  }
  isFgDefault(): boolean {
    return (this.spec.fg?.mode ?? "default") === "default";
  }
  isBgDefault(): boolean {
    return (this.spec.bg?.mode ?? "default") === "default";
  }
  isFgPalette(): boolean {
    return this.spec.fg?.mode === "palette";
  }
  isBgPalette(): boolean {
    return this.spec.bg?.mode === "palette";
  }
  isFgRGB(): boolean {
    return this.spec.fg?.mode === "rgb";
  }
  isBgRGB(): boolean {
    return this.spec.bg?.mode === "rgb";
  }
  isBold(): number {
    return this.spec.bold ? 1 : 0;
  }
  isItalic(): number {
    return this.spec.italic ? 1 : 0;
  }
  isDim(): number {
    return this.spec.dim ? 1 : 0;
  }
  isInverse(): number {
    return this.spec.inverse ? 1 : 0;
  }
  isInvisible(): number {
    return this.spec.invisible ? 1 : 0;
  }
  isUnderline(): number {
    return this.spec.underline ? 1 : 0;
  }
  isBlink(): number {
    return 0;
  }
  isStrikethrough(): number {
    return this.spec.strike ? 1 : 0;
  }
  isOverline(): number {
    return 0;
  }
  isAttributeDefault(): boolean {
    return this.spec === BLANK;
  }
}

const FONT_SIZE = 10;
const LINE_HEIGHT = 2; // cellHeight of 20, so row edges are whole pixels.

/** A terminal showing exactly `rows`, with no scrollback above it. */
function fakeTerminal(rows: CellSpec[][], cols: number): Terminal {
  const shared = new FakeCell();
  const buffer = {
    viewportY: 0,
    getNullCell: () => shared as unknown as IBufferCell,
    getLine: (y: number) => {
      const row = rows[y];
      if (!row) return undefined;
      return {
        length: cols,
        getCell: (x: number, cell?: IBufferCell) => {
          if (x >= cols) return undefined;
          const target = (cell ?? shared) as unknown as FakeCell;
          target.spec = row[x] ?? BLANK;
          return target as unknown as IBufferCell;
        },
      };
    },
  };
  return {
    cols,
    rows: rows.length,
    options: { fontFamily: "TestMono", fontSize: FONT_SIZE, lineHeight: LINE_HEIGHT },
    buffer: { active: buffer },
  } as unknown as Terminal;
}

/** What `buildTheme` resolves to under jsdom, where no CSS variable is set
 *  and every token falls through to its hard-coded default. */
const DEFAULT_BG = "#1a1d24";
const DEFAULT_FG = "#e9ebef";

// ----------------------------------------------------------------------- tests

describe("buildPalette", () => {
  it("takes the first sixteen slots from the theme", () => {
    const palette = buildPalette({ red: "#ff0000", brightWhite: "#ffffff" });
    expect(palette[1]).toBe("#ff0000");
    expect(palette[15]).toBe("#ffffff");
  });

  it("falls back to plain VGA for a slot the theme leaves unset", () => {
    expect(buildPalette({})[2]).toBe("#00cd00");
  });

  it("lays out the xterm cube and greyscale ramp", () => {
    const palette = buildPalette({});
    expect(palette).toHaveLength(256);
    expect(palette[16]).toBe("rgb(0, 0, 0)");
    expect(palette[196]).toBe("rgb(255, 0, 0)"); // 16 + 5*36
    expect(palette[231]).toBe("rgb(255, 255, 255)");
    expect(palette[232]).toBe("rgb(8, 8, 8)");
    expect(palette[255]).toBe("rgb(238, 238, 238)");
  });
});

describe("cellColors", () => {
  const palette = buildPalette({ red: "#ee6055" });
  const resolve = (spec: CellSpec): { fg: string; bg: string | null } => {
    const cell = new FakeCell();
    cell.spec = spec;
    return cellColors(cell as unknown as IBufferCell, palette, DEFAULT_FG, DEFAULT_BG);
  };

  it("leaves a default cell on the theme foreground and no background", () => {
    expect(resolve({ chars: "x" })).toEqual({ fg: DEFAULT_FG, bg: null });
  });

  it("reads a palette index through the theme", () => {
    expect(resolve({ chars: "x", fg: { mode: "palette", value: 1 } }).fg).toBe("#ee6055");
  });

  it("reads a true colour as a hex fill", () => {
    expect(resolve({ chars: "x", bg: { mode: "rgb", value: 0x0a1b2c } }).bg).toBe("#0a1b2c");
  });

  it("pads a true colour that needs leading zeroes", () => {
    expect(resolve({ chars: "x", fg: { mode: "rgb", value: 0x00ff01 } }).fg).toBe("#00ff01");
  });

  it("swaps the two colours under inverse", () => {
    expect(resolve({ chars: "x", fg: { mode: "rgb", value: 0x112233 }, inverse: true })).toEqual({
      fg: DEFAULT_BG,
      bg: "#112233",
    });
  });

  it("gives an inverted default cell a background to fill", () => {
    expect(resolve({ chars: "x", inverse: true })).toEqual({ fg: DEFAULT_BG, bg: DEFAULT_FG });
  });
});

describe("captureTerminalThumbnail", () => {
  it("returns null before the terminal has been measured", () => {
    expect(captureTerminalThumbnail(fakeTerminal([], 0))).toBeNull();
  });

  it("sizes the canvas from the grid and its font metrics", () => {
    const frame = captureTerminalThumbnail(fakeTerminal([[{ chars: "a" }]], 10));
    expect(frame).not.toBeNull();
    expect(frame?.width).toBe(10 * CELL_PX);
    expect(frame?.height).toBe(FONT_SIZE * LINE_HEIGHT);
    expect(frame?.pixels).toHaveLength(10 * CELL_PX * FONT_SIZE * LINE_HEIGHT * 4);
  });

  it("clears to the theme background before anything else", () => {
    captureTerminalThumbnail(fakeTerminal([[{ chars: "a" }]], 4));
    expect(paintedOps()[0]).toMatchObject({ op: "rect", x: 0, y: 0, fill: DEFAULT_BG });
  });

  it("paints a cell's own colours", () => {
    const row: CellSpec[] = [
      { chars: "e", fg: { mode: "rgb", value: 0xff0000 }, bg: { mode: "rgb", value: 0x000080 } },
    ];
    captureTerminalThumbnail(fakeTerminal([row], 1));
    const ops = paintedOps();
    expect(ops).toContainEqual(
      expect.objectContaining({ op: "rect", x: 0, w: CELL_PX, fill: "#000080" }),
    );
    expect(ops).toContainEqual(expect.objectContaining({ op: "text", text: "e", fill: "#ff0000" }));
  });

  it("batches a stretch of one colour into a single background fill", () => {
    const green: Color = { mode: "rgb", value: 0x00ff00 };
    const row: CellSpec[] = [
      { chars: "a", bg: green },
      { chars: "b", bg: green },
      { chars: "c", bg: green },
      { chars: "d" },
    ];
    captureTerminalThumbnail(fakeTerminal([row], 4));
    const fills = paintedOps().filter((o) => o.op === "rect" && o.fill === "#00ff00");
    expect(fills).toHaveLength(1);
    expect(fills[0]).toMatchObject({ x: 0, w: 3 * CELL_PX });
  });

  it("batches same-styled text into one draw and breaks the run on a colour change", () => {
    const row: CellSpec[] = [
      { chars: "h", fg: { mode: "palette", value: 2 } },
      { chars: "i", fg: { mode: "palette", value: 2 } },
      { chars: "!", fg: { mode: "palette", value: 1 } },
    ];
    captureTerminalThumbnail(fakeTerminal([row], 3));
    const texts = paintedOps().filter((o) => o.op === "text");
    expect(texts.map((t) => t.text)).toEqual(["hi", "!"]);
    expect(texts[1].x).toBe(2 * CELL_PX);
  });

  it("breaks the run when only an attribute changes", () => {
    const row: CellSpec[] = [{ chars: "a", bold: true }, { chars: "b" }];
    captureTerminalThumbnail(fakeTerminal([row], 2));
    const texts = paintedOps().filter((o) => o.op === "text");
    expect(texts.map((t) => t.text)).toEqual(["a", "b"]);
    expect(texts[0].font).toBe(`bold ${FONT_SIZE}px TestMono`);
    expect(texts[1].font).toBe(`${FONT_SIZE}px TestMono`);
  });

  it("writes italic into the font string", () => {
    captureTerminalThumbnail(fakeTerminal([[{ chars: "a", italic: true, bold: true }]], 1));
    const text = paintedOps().find((o) => o.op === "text");
    expect(text?.font).toBe(`italic bold ${FONT_SIZE}px TestMono`);
  });

  it("draws a dim cell at half alpha", () => {
    captureTerminalThumbnail(fakeTerminal([[{ chars: "a", dim: true }]], 1));
    expect(paintedOps().find((o) => o.op === "text")?.alpha).toBe(0.5);
  });

  it("fills the background of an inverted default cell", () => {
    captureTerminalThumbnail(fakeTerminal([[{ chars: "a", inverse: true }]], 1));
    const ops = paintedOps();
    expect(ops).toContainEqual(expect.objectContaining({ op: "rect", x: 0, fill: DEFAULT_FG }));
    expect(ops).toContainEqual(expect.objectContaining({ op: "text", fill: DEFAULT_BG }));
  });

  it("holds an invisible cell's columns open without drawing it", () => {
    const row: CellSpec[] = [{ chars: "s", invisible: true }, { chars: "x" }];
    captureTerminalThumbnail(fakeTerminal([row], 2));
    const texts = paintedOps().filter((o) => o.op === "text");
    expect(texts.map((t) => t.text)).toEqual([" x"]);
  });

  it("rules an underline across the run, under the glyph rather than the cell", () => {
    const row: CellSpec[] = [
      { chars: "a", underline: true },
      { chars: "b", underline: true },
    ];
    captureTerminalThumbnail(fakeTerminal([row], 2));
    const rules = paintedOps().filter((o) => o.op === "rect" && o.h === 1);
    expect(rules).toHaveLength(1);
    // The glyph is centred in a cell twice its height, so the rule sits at
    // the bottom of the em box (5 + 10), well clear of the row below it.
    expect(rules[0]).toMatchObject({ x: 0, w: 2 * CELL_PX, y: 15 });
  });

  it("strikes through the middle of the glyph", () => {
    captureTerminalThumbnail(fakeTerminal([[{ chars: "a", strike: true }]], 1));
    const rules = paintedOps().filter((o) => o.op === "rect" && o.h === 1);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({ y: 10 });
  });

  it("ends a run after a wide glyph and skips its trailing half", () => {
    const row: CellSpec[] = [
      { chars: "漢", width: 2 },
      { chars: "", width: 0 },
      { chars: "a" },
    ];
    captureTerminalThumbnail(fakeTerminal([row], 3));
    const texts = paintedOps().filter((o) => o.op === "text");
    expect(texts.map((t) => t.text)).toEqual(["漢", "a"]);
    expect(texts[1].x).toBe(2 * CELL_PX);
  });

  it("puts each row at its own offset and skips rows the buffer does not have", () => {
    const rows: CellSpec[][] = [[{ chars: "a" }], [{ chars: "b" }]];
    captureTerminalThumbnail(fakeTerminal(rows, 1));
    const texts = paintedOps().filter((o) => o.op === "text");
    expect(texts.map((t) => t.text)).toEqual(["a", "b"]);
    expect(texts[1].y - texts[0].y).toBe(FONT_SIZE * LINE_HEIGHT);
  });

  it("does not draw a run that is only blanks", () => {
    captureTerminalThumbnail(fakeTerminal([[BLANK, BLANK]], 2));
    expect(paintedOps().filter((o) => o.op === "text")).toHaveLength(0);
  });
});
