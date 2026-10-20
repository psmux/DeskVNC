// Review-only probes asserting desired behaviour against unchanged production
// modules. These are expected to be RED at 6933f0d. No GUI or Mac is touched.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { WebGLRenderer } from '../../../ui/src/render/WebGLRenderer';
import { readAppleGeometry, writeAppleGeometry } from '../../../ui/src/lib/appleGeometry';

interface Picture {
  displayWidth: number;
  displayHeight: number;
  timestamp: number;
  close: ReturnType<typeof vi.fn>;
}

interface Context {
  w: number;
  h: number;
  stretch: boolean;
}

interface Harness {
  setRemoteSize(w: number, h: number): void;
  getRemoteSize(): { width: number; height: number };
  createH264(rect: { x: number; y: number; w: number; h: number }, id: number, bytes: Uint8Array): Context;
  latestVideo: { frame: Picture; ctx: Context } | null;
}

beforeEach(() => localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

function harness() {
  let output: (frame: Picture) => void = () => {};
  vi.stubGlobal('VideoDecoder', class {
    state = 'configured';
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = 'closed'; }
  });
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null,
    fbWidth: 3600, fbHeight: 2338, sawFrame: true,
    mediaPictureWidth: 3600, mediaPictureHeight: 2338, mediaDecoded: 0,
    frameTex: {}, scratchTex: {},
    h264Failed: false, h264Unsupported: false, h264Failures: 0,
    h264Acceleration: 'prefer-hardware', notices: new Set(), notice: vi.fn(),
    gl: {
      bindTexture: vi.fn(), texImage2D: vi.fn(),
      TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4,
    },
    clearViewRect: vi.fn(), markDirty: vi.fn(),
  }) as Harness;
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  return { renderer, output: (frame: Picture) => output(frame) };
}

function picture(w: number, h: number, timestamp = 1): Picture {
  return { displayWidth: w, displayHeight: h, timestamp, close: vi.fn() };
}

it('can commit a newly confirmed layout when its matching decoded picture arrives', () => {
  const { renderer, output } = harness();
  renderer.setRemoteSize(2700, 1754);
  // Preserve the old frame until new output, but do not lose the new target.
  output(picture(2700, 1754));
  expect(renderer.getRemoteSize()).toEqual({ width: 2700, height: 1754 });
});

it('does not silently stretch an unrelated 4:3 fallback into the Retina desktop', () => {
  const { renderer, output } = harness();
  const good = picture(3600, 2338);
  output(good);
  output(picture(1600, 1200, 2));
  // Keep the last valid presentation and surface/request recovery for the
  // mismatch. Stretching cannot restore the remote desktop's point geometry.
  expect(renderer.latestVideo?.frame).toBe(good);
  expect(good.close).not.toHaveBeenCalled();
});

it('does not let a reduced-stream layout redefine the cached native pixel baseline', () => {
  writeAppleGeometry('review-host', {
    pixelWidth: 3600, pixelHeight: 2338, pointWidth: 1800, pointHeight: 1169,
  });
  writeAppleGeometry('review-host', {
    pixelWidth: 1800, pixelHeight: 1169, pointWidth: 1800, pointHeight: 1169,
  });
  expect(readAppleGeometry('review-host')?.pixelWidth).toBe(3600);
});
