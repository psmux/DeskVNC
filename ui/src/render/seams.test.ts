import { describe, expect, it } from "vitest";
import { candidateSeams, detectVerticalSeam } from "./seams";

/** Build `rows` RGBA rows, `width` wide, colouring each column via `col`. */
function band(width: number, rows: number, col: (x: number, row: number) => [number, number, number]): Uint8Array {
  const px = new Uint8Array(width * rows * 4);
  for (let r = 0; r < rows; r++) {
    for (let x = 0; x < width; x++) {
      const [cr, cg, cb] = col(x, r);
      const i = (r * width + x) * 4;
      px[i] = cr;
      px[i + 1] = cg;
      px[i + 2] = cb;
      px[i + 3] = 255;
    }
  }
  return px;
}

describe("candidateSeams", () => {
  it("offers the midpoint and common widths from both edges", () => {
    const c = candidateSeams(2720);
    expect(c).toContain(1360); // half
    expect(c).toContain(1920); // common width from the left
    expect(c).toContain(800); // 2720 - 1920: the same pair, other way round
  });

  it("never offers a sliver that could not be a monitor", () => {
    for (const x of candidateSeams(2720)) {
      expect(x).toBeGreaterThanOrEqual(320);
      expect(2720 - x).toBeGreaterThanOrEqual(320);
    }
  });
});

describe("detectVerticalSeam", () => {
  it("finds two different wallpapers meeting at a candidate column", () => {
    const px = band(2720, 32, (x) => (x < 1920 ? [30, 60, 120] : [200, 180, 90]));
    const seam = detectVerticalSeam(px, 2720, 32);
    expect(seam?.x).toBe(1920);
  });

  it("finds an equal-halves boundary", () => {
    const px = band(2560, 32, (x) => (x < 1280 ? [10, 10, 10] : [240, 240, 240]));
    expect(detectVerticalSeam(px, 2560, 32)?.x).toBe(1280);
  });

  it("reports nothing on a uniform desktop", () => {
    const px = band(2720, 32, () => [80, 90, 100]);
    expect(detectVerticalSeam(px, 2720, 32)).toBeNull();
  });

  it("ignores a hard edge that sits where no monitor could", () => {
    // A maximized dark window ending at x=700 against a light desktop:
    // 700 is not a candidate for w=2720, so it must not be reported.
    const px = band(2720, 32, (x) => (x < 700 ? [10, 10, 10] : [230, 230, 230]));
    expect(detectVerticalSeam(px, 2720, 32)).toBeNull();
  });

  it("is not fooled by a noisy desktop with no seam", () => {
    // Deterministic per-column hash noise: plenty of column-to-column
    // difference everywhere, so the noise floor rises and nothing stands out.
    const px = band(2720, 32, (x, r) => {
      const v = ((x * 2654435761 + r * 40503) >>> 16) & 0xff;
      return [v, (v * 3) & 0xff, (v * 7) & 0xff];
    });
    expect(detectVerticalSeam(px, 2720, 32)).toBeNull();
  });

  it("prefers the strong seam when a weaker candidate also differs", () => {
    const px = band(2720, 32, (x) => {
      if (x < 1360) return [100, 100, 100];
      if (x < 1920) return [110, 110, 110]; // mild shift at the half-way point
      return [240, 30, 30]; // hard seam at 1920
    });
    expect(detectVerticalSeam(px, 2720, 32)?.x).toBe(1920);
  });
});
