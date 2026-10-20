// Review characterization: passing confirms observed defects; see README.md.
import { afterEach, expect, it, vi } from 'vitest';
import { WebGLRenderer } from '../../../ui/src/render/WebGLRenderer';

afterEach(() => vi.unstubAllGlobals());
function harness(extra: Record<string, unknown> = {}) {
  return Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null, notices: new Set(),
    h264Failed: false, h264Unsupported: false, h264Failures: 0,
    h264Acceleration: 'prefer-hardware', h264Behind: false,
    behindAskedAt: -Infinity, mediaSubmitted: 0, mediaDecoded: 0,
    fbWidth: 1920, fbHeight: 1080, pendingLayout: null,
    notice: vi.fn(), ...extra,
  });
}
function chunks() {
  vi.stubGlobal('EncodedVideoChunk', class { constructor(init: unknown) { Object.assign(this, init); } });
}
const independent = { x: 0, y: 0, w: 1920, h: 1080, h264Context: 0, h264Key: true, h264Reset: false, payload: new Uint8Array([0,0,0,1,0x61,0xb0]) };

it('reproduces lost non-IDR independent recovery after standards-compliant reset', async () => {
  chunks();
  vi.stubGlobal('VideoDecoder', class {});
  const decoder = {
    state: 'configured', decodeQueueSize: 4, configure: vi.fn(), close: vi.fn(),
    reset: vi.fn(function(this: any) { this.state='unconfigured'; this.decodeQueueSize=0; }),
    decode: vi.fn(function(this: any) { if (this.state !== 'configured') throw new Error('InvalidStateError'); }),
  };
  const ctx = { decoder, avc: false, timestamp: 0, generation: 1, waiters: new Map(), submitted: new Map() };
  const recovery = vi.fn();
  const r = harness({ h264: new Map([[0, ctx]]), onDecoderBehind: recovery });
  await r.decodeH264({ ...independent, h264Key: false });
  await r.decodeH264(independent);
  expect(decoder.reset).toHaveBeenCalledOnce();
  expect(decoder.configure).not.toHaveBeenCalled();
  expect(decoder.decode.mock.results[0].type).toBe('throw');
  expect(r.h264.size).toBe(0);
  expect(recovery).toHaveBeenCalledOnce();
});

it('reproduces lifetime accumulation of errors separated by successful frames', () => {
  const callbacks: any[]=[];
  vi.stubGlobal('VideoDecoder', class {
    state='configured';
    constructor(c: any) { callbacks.push(c); }
    configure() {}
    close() { this.state='closed'; }
  });
  const r=harness();
  for(let i=0;i<3;i++) {
    r.createH264(independent, 0, independent.payload);
    callbacks[i].output({ displayWidth:1920,displayHeight:1080,timestamp:1,close:vi.fn() });
    callbacks[i].error(new Error('transient failure after healthy output'));
  }
  expect(r.mediaDecoded).toBe(3);
  expect(r.h264Failed).toBe(true);
  r.setRemoteSize(1920,1080);
  expect(r.h264Failed).toBe(true);
});

it('reproduces no backend recovery request on async decoder error', () => {
  let error: any;
  vi.stubGlobal('VideoDecoder', class {
    state='configured';
    constructor(c: any) { error=c.error; }
    configure() {}
    close() { this.state='closed'; }
  });
  const recovery=vi.fn(); const r=harness({onDecoderBehind:recovery});
  r.createH264(independent, 0, independent.payload);
  error(new Error('decoder failed'));
  expect(r.h264.size).toBe(0);
  expect(recovery).not.toHaveBeenCalled();
});

it('reproduces unbounded continuous-video timestamp retention with swallowed output', async () => {
  chunks();
  vi.stubGlobal('VideoDecoder',class {});
  const ctx={decoder:{state:'configured',decodeQueueSize:0,decode:vi.fn()},avc:false,timestamp:0,generation:1,waiters:new Map(),submitted:new Map()};
  const r=harness({h264:new Map([[0,ctx]])});
  for(let i=0;i<10000;i++) await r.decodeH264({...independent,h264Key:false});
  expect(ctx.submitted.size).toBe(10000);
});

it('reproduces leaked decoder when both configure calls throw', () => {
  const close=vi.fn();
  vi.stubGlobal('VideoDecoder',class {
    state='unconfigured';
    configure(){throw new Error('unsupported');}
    close=close;
  });
  const r=harness();
  expect(r.createH264(independent,0,independent.payload)).toBeNull();
  expect(close).not.toHaveBeenCalled();
});
