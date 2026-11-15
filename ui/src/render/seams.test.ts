import { describe, expect, it } from "vitest";
import { candidateSeams, detectMonitors, detectVerticalSeam } from "./seams";

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

/** A whole top-down RGBA frame, `w` by `h`, coloured per pixel by `px`. */
function frame(
  w: number,
  h: number,
  px: (x: number, y: number) => [number, number, number],
): { width: number; height: number; pixels: Uint8Array } {
  const pixels = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const [r, g, b] = px(x, y);
      const i = (y * w + x) * 4;
      pixels[i] = r;
      pixels[i + 1] = g;
      pixels[i + 2] = b;
      pixels[i + 3] = 255;
    }
  }
  return { width: w, height: h, pixels };
}

/** A wallpaper with some texture and a dark grey taskbar along its bottom. */
function wallpaper(seed: number, h: number) {
  return (x: number, y: number): [number, number, number] => {
    if (y >= h - 48) return [32, 32, 36]; // taskbar, dark but not black
    const v = ((x * 7 + y * 13 + seed * 101) % 64) + 40;
    return seed === 1 ? [v, v + 60, 40] : [60, 40, v + 100];
  };
}

/** Two monitors side by side, top aligned, black under the shorter one. */
function twoMonitors(
  a: { w: number; h: number },
  b: { w: number; h: number },
  extra?: (x: number, y: number) => [number, number, number] | null,
) {
  const left = wallpaper(1, a.h);
  const right = wallpaper(2, b.h);
  return frame(a.w + b.w, Math.max(a.h, b.h), (x, y) => {
    const e = extra?.(x, y);
    if (e) return e;
    if (x < a.w) return y < a.h ? left(x, y) : [0, 0, 0];
    return y < b.h ? right(x - a.w, y) : [0, 0, 0];
  });
}

describe("detectMonitors", () => {
  it("finds a 1920x1080 monitor beside a larger one, without the black under it", () => {
    const f = twoMonitors({ w: 1920, h: 1080 }, { w: 2880, h: 1620 });
    expect(detectMonitors(f)).toEqual([
      { x: 0, y: 0, width: 1920, height: 1080 },
      { x: 1920, y: 0, width: 2880, height: 1620 },
    ]);
  });

  it("finds the layout seen on a real two monitor PC: 1280x720 beside 1920x1080", () => {
    // A bright window inside the right monitor has its own hard vertical edge
    // at x = 1920, a common monitor width. Reading only the seam, that edge
    // won and the menu offered 1920x1080 and 1280x1080.
    const f = twoMonitors({ w: 1280, h: 720 }, { w: 1920, h: 1080 }, (x, y) =>
      x >= 1920 && x < 3000 && y >= 40 && y < 1000 ? [250, 250, 250] : null,
    );
    expect(detectMonitors(f)).toEqual([
      { x: 0, y: 0, width: 1280, height: 720 },
      { x: 1280, y: 0, width: 1920, height: 1080 },
    ]);
  });

  it("finds a shorter monitor on the right too", () => {
    const f = twoMonitors({ w: 2560, h: 1440 }, { w: 1920, h: 1080 });
    expect(detectMonitors(f)).toEqual([
      { x: 0, y: 0, width: 2560, height: 1440 },
      { x: 2560, y: 0, width: 1920, height: 1080 },
    ]);
  });

  it("finds a bottom aligned shorter monitor, with the black above it", () => {
    const left = wallpaper(1, 1080);
    const right = wallpaper(2, 1440);
    const f = frame(1920 + 2560, 1440, (x, y) => {
      if (x < 1920) return y >= 360 ? left(x, y - 360) : [0, 0, 0];
      return right(x - 1920, y);
    });
    expect(detectMonitors(f)).toEqual([
      { x: 0, y: 360, width: 1920, height: 1080 },
      { x: 1920, y: 0, width: 2560, height: 1440 },
    ]);
  });

  it("still finds two equal height monitors by their seam", () => {
    const f = twoMonitors({ w: 1920, h: 1080 }, { w: 1920, h: 1080 });
    expect(detectMonitors(f)).toEqual([
      { x: 0, y: 0, width: 1920, height: 1080 },
      { x: 1920, y: 0, width: 1920, height: 1080 },
    ]);
  });

  it("reports nothing for one plain desktop", () => {
    expect(detectMonitors(frame(1920, 1080, wallpaper(1, 1080)))).toBeNull();
  });

  it("does not take a black window for the empty area under a monitor", () => {
    // A black terminal across the bottom left of one monitor, above its
    // taskbar, is still part of that monitor.
    const f = twoMonitors({ w: 1920, h: 1080 }, { w: 1920, h: 1080 }, (x, y) =>
      x < 1200 && y >= 600 && y < 1032 ? [0, 0, 0] : null,
    );
    expect(detectMonitors(f)).toEqual([
      { x: 0, y: 0, width: 1920, height: 1080 },
      { x: 1920, y: 0, width: 1920, height: 1080 },
    ]);
  });
});
