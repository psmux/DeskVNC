/**
 * WebGL2 framebuffer renderer.
 *
 * - One TEXTURE_2D at remote-desktop size; dirty rects land via texSubImage2D.
 * - One full-screen quad drawn at most once per requestAnimationFrame, and only
 *   when something is dirty.
 * - Scaling (fit / aspect-fit / actual / custom zoom + pan) happens in the
 *   vertex transform, the canvas backing store is always at device pixels.
 * - Grayscale/B&W quantization path lives in the fragment shader (levels
 *   256/16/8/4/2, plus 1-bit with 4x4 ordered Bayer dithering).
 * - Client-side cursor sprite composited as a second small quad, updated
 *   independently of frame delivery.
 *
 * This class is deliberately outside React: no state, no allocation per frame
 * on the hot path.
 */
import {
  H264_RESET_ALL_CONTEXTS,
  H264_RESET_CONTEXT,
  RectFormat,
  type FrameMessage,
  type WireRect,
} from "./frameProtocol";

export type RendererScalingMode = "fit" | "aspect-fit" | "actual" | "custom";

export interface ContentTransform {
  /** top-left of the content in device pixels */
  x: number;
  y: number;
  /** device pixels per framebuffer pixel */
  scaleX: number;
  scaleY: number;
}

const VS = `#version 300 es
layout(location = 0) in vec2 a_pos;      // unit quad [0,1]^2
uniform vec4 u_rect;                     // x, y, w, h in NDC (y = top, h negative-down handled here)
out vec2 v_uv;
void main() {
  v_uv = a_pos;
  vec2 p = u_rect.xy + a_pos * u_rect.zw;
  gl_Position = vec4(p.x * 2.0 - 1.0, 1.0 - p.y * 2.0, 0.0, 1.0);
}`;

const FS = `#version 300 es
precision mediump float;
uniform sampler2D u_tex;
uniform float u_levels;   // 0 = passthrough color; 1 = 1-bit dithered; N>=2 = N gray levels
// 0 = force opaque (the framebuffer quad), 1 = honour the texture's alpha.
// The cursor sprite is masked, so forcing alpha to 1 for it paints a black
// square around the pointer.
uniform float u_texAlpha;
in vec2 v_uv;
out vec4 outColor;

const mat4 bayer = mat4(
   0.0,  8.0,  2.0, 10.0,
  12.0,  4.0, 14.0,  6.0,
   3.0, 11.0,  1.0,  9.0,
  15.0,  7.0, 13.0,  5.0
);

void main() {
  vec4 c = texture(u_tex, v_uv);
  if (u_levels < 0.5) {
    outColor = vec4(c.rgb, mix(1.0, c.a, u_texAlpha));
    return;
  }
  float g = dot(c.rgb, vec3(0.2126, 0.7152, 0.0722));
  if (u_levels < 1.5) {
    // 1-bit with ordered dithering
    ivec2 p = ivec2(mod(gl_FragCoord.xy, 4.0));
    float threshold = (bayer[p.x][p.y] + 0.5) / 16.0;
    float v = g > threshold ? 1.0 : 0.0;
    outColor = vec4(vec3(v), 1.0);
  } else {
    float n = u_levels - 1.0;
    float v = floor(g * n + 0.5) / n;
    outColor = vec4(vec3(v), 1.0);
  }
}`;

/** One live `VideoDecoder` plus the rect geometry it decodes into. */
interface H264Context {
  decoder: VideoDecoder;
  x: number;
  y: number;
  w: number;
  h: number;
  /** Renderer generation this decoder belongs to (dropped on resize). */
  generation: number;
  /** Monotonic presentation timestamps, in microseconds. */
  timestamp: number;
}

/** Maximum simultaneous decoder contexts, mirrors the backend's cap. */
const H264_MAX_CONTEXTS = 64;

function compile(gl: WebGL2RenderingContext, type: number, src: string): WebGLShader {
  const sh = gl.createShader(type);
  if (!sh) throw new Error("createShader failed");
  gl.shaderSource(sh, src);
  gl.compileShader(sh);
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(sh) ?? "unknown";
    gl.deleteShader(sh);
    throw new Error(`shader compile failed: ${log}`);
  }
  return sh;
}

export class WebGLRenderer {
  private gl: WebGL2RenderingContext;
  private canvas: HTMLCanvasElement;
  private program: WebGLProgram;
  private uRect: WebGLUniformLocation;
  private uLevels: WebGLUniformLocation;
  private uTexAlpha: WebGLUniformLocation;
  private frameTex: WebGLTexture;
  private scratchTex: WebGLTexture;
  private cursorTex: WebGLTexture;
  private readFbo: WebGLFramebuffer;

  private fbWidth = 0;
  private fbHeight = 0;
  private scratchW = 0;
  private scratchH = 0;

  private dirty = false;
  private running = false;
  private rafId = 0;
  private disposed = false;
  /** bumped on resize/reconnect so stale async JPEG uploads are dropped */
  private generation = 0;
  /** Serialises frame application so updates can never be reordered. */
  private applyChain: Promise<void> = Promise.resolve();

  // view transform
  private mode: RendererScalingMode = "aspect-fit";
  private zoom = 1;
  private panX = 0;
  private panY = 0;

  // cursor
  /** User preference: draw the remote pointer at all (Preferences ▸ Input). */
  private cursorEnabled = true;
  /** A cursor shape has actually been received from the server. */
  private cursorHasShape = false;
  private cursorX = 0;
  private cursorY = 0;
  private cursorW = 0;
  private cursorH = 0;
  private cursorHotX = 0;
  private cursorHotY = 0;

  // grayscale
  private grayLevels = 0; // 0 = color

  // H.264 (WebCodecs): one decoder per server-side context, keyed by the
  // context id the backend assigns per rect geometry (0..63).
  private h264 = new Map<number, H264Context>();
  private h264Failed = false;

  onFirstFrame: (() => void) | null = null;

  /**
   * Whether any real framebuffer data has been applied.
   *
   * Guards thumbnail capture: a session that never got past authentication has
   * a blank texture, and storing that would replace a good tile picture with a
   * black rectangle.
   */
  hasFrame(): boolean {
    return this.sawFrame;
  }
  /**
   * Non-fatal renderer notices worth surfacing to the user (e.g. "this webview
   * has no H.264 decoder"). Each distinct message is reported at most once per
   * renderer; when nothing is listening it goes to the console instead.
   */
  onNotice: ((message: string) => void) | null = null;
  private notices = new Set<string>();
  private sawFrame = false;

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas;
    const gl = canvas.getContext("webgl2", {
      alpha: false,
      antialias: false,
      depth: false,
      stencil: false,
      preserveDrawingBuffer: false,
      powerPreference: "high-performance",
      desynchronized: true,
    });
    if (!gl) throw new Error("WebGL2 is not available in this webview");
    this.gl = gl;

    const vs = compile(gl, gl.VERTEX_SHADER, VS);
    const fs = compile(gl, gl.FRAGMENT_SHADER, FS);
    const program = gl.createProgram();
    if (!program) throw new Error("createProgram failed");
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    gl.deleteShader(vs);
    gl.deleteShader(fs);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      throw new Error(`program link failed: ${gl.getProgramInfoLog(program) ?? ""}`);
    }
    this.program = program;
    gl.useProgram(program);
    const uRect = gl.getUniformLocation(program, "u_rect");
    const uLevels = gl.getUniformLocation(program, "u_levels");
    const uTexAlpha = gl.getUniformLocation(program, "u_texAlpha");
    if (!uRect || !uLevels || !uTexAlpha) throw new Error("uniform lookup failed");
    this.uRect = uRect;
    this.uLevels = uLevels;
    this.uTexAlpha = uTexAlpha;
    gl.uniform1i(gl.getUniformLocation(program, "u_tex"), 0);

    // unit quad
    const vbo = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([0, 0, 1, 0, 0, 1, 1, 1]),
      gl.STATIC_DRAW,
    );
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

    this.frameTex = this.makeTexture();
    this.scratchTex = this.makeTexture();
    this.cursorTex = this.makeTexture();
    const fbo = gl.createFramebuffer();
    if (!fbo) throw new Error("createFramebuffer failed");
    this.readFbo = fbo;

    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
    gl.clearColor(0, 0, 0, 0);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
  }

  private makeTexture(): WebGLTexture {
    const gl = this.gl;
    const tex = gl.createTexture();
    if (!tex) throw new Error("createTexture failed");
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    return tex;
  }

  // ------------------------------------------------------------------ sizing

  /** Set remote framebuffer size (on connect and DesktopResize). */
  setRemoteSize(width: number, height: number): void {
    if (width === this.fbWidth && height === this.fbHeight) return;
    const gl = this.gl;
    this.fbWidth = width;
    this.fbHeight = height;
    this.generation++;
    this.sawFrame = false;
    // Every decoder's target geometry just became meaningless.
    this.closeAllH264();
    gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    this.markDirty();
  }

  getRemoteSize(): { width: number; height: number } {
    return { width: this.fbWidth, height: this.fbHeight };
  }

  /** Canvas backing-store size in DEVICE pixels (caller derives from ResizeObserver + DPR). */
  setCanvasSize(deviceW: number, deviceH: number): void {
    if (this.canvas.width !== deviceW || this.canvas.height !== deviceH) {
      this.canvas.width = Math.max(1, deviceW);
      this.canvas.height = Math.max(1, deviceH);
    }
    this.markDirty();
  }

  // ------------------------------------------------------------------ frames

  /**
   * Apply one parsed channel message.
   *
   * ORDER IS LOAD-BEARING. RGBA and CopyRect apply synchronously, but JPEG has
   * to go through `createImageBitmap`, which is async. Applying each bitmap
   * whenever its promise happened to settle let a JPEG rect from an older
   * update land *on top of* newer content, visible as patches of stale pixels
   * during window drags and minimise/maximise animations, which then "healed"
   * whenever something else repainted that region.
   *
   * So: kick every decode off immediately (they still run in parallel), then
   * apply everything strictly in protocol order, and chain updates so update
   * N is fully applied before N+1 starts.
   */
  applyFrame(msg: FrameMessage): void {
    // Start decodes now, parallelism is preserved, ordering is not sacrificed.
    const pending: (Promise<ImageBitmap> | null)[] = msg.rects.map((r) =>
      r.format === RectFormat.Jpeg ? this.decodeJpeg(r.payload) : null,
    );
    const gen = this.generation;
    this.applyChain = this.applyChain
      .then(() => this.applyFrameOrdered(msg, pending, gen))
      .catch(() => undefined);
  }

  private async applyFrameOrdered(
    msg: FrameMessage,
    pending: (Promise<ImageBitmap> | null)[],
    gen: number,
  ): Promise<void> {
    const gl = this.gl;
    for (let i = 0; i < msg.rects.length; i++) {
      const r = msg.rects[i];
      if (this.disposed) return;
      switch (r.format) {
        case RectFormat.Rgba:
          if (r.payload.byteLength >= r.w * r.h * 4) {
            gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
            gl.texSubImage2D(gl.TEXTURE_2D, 0, r.x, r.y, r.w, r.h, gl.RGBA, gl.UNSIGNED_BYTE, r.payload);
          }
          break;
        case RectFormat.Jpeg: {
          const p = pending[i];
          if (!p) break;
          let bmp: ImageBitmap | null = null;
          try {
            bmp = await p;
          } catch (err) {
            // A corrupt rect must not stall the rest of the update, but a
            // SILENT skip leaves a permanently stale region: a full-screen
            // refresh re-sends the same bytes, which fail the same way, so
            // no amount of refreshing ever heals it. Say so, loudly, with
            // enough detail to reproduce the decode failure offline.
            console.warn(
              `[render] jpeg decode failed at ${r.x},${r.y} ${r.w}x${r.h} (${r.payload.byteLength}B):`,
              err,
            );
            break;
          }
          // A resize (new generation) invalidated the texture this was for.
          if (this.disposed || gen !== this.generation) {
            bmp.close();
            return;
          }
          gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
          gl.texSubImage2D(gl.TEXTURE_2D, 0, r.x, r.y, gl.RGBA, gl.UNSIGNED_BYTE, bmp);
          bmp.close();
          break;
        }
        case RectFormat.CopyRect:
          this.copyRect(r.srcX, r.srcY, r.x, r.y, r.w, r.h);
          break;
        case RectFormat.H264:
          this.decodeH264(r);
          break;
        default:
          break; // unknown format: skip gracefully
      }
    }
    if (!this.sawFrame) {
      this.sawFrame = true;
      this.onFirstFrame?.();
    }
    this.markDirty();
  }

  /** Start a JPEG decode. The buffer is reused downstream, so copy it first. */
  private decodeJpeg(bytes: Uint8Array): Promise<ImageBitmap> {
    const blob = new Blob([bytes.slice().buffer as ArrayBuffer], { type: "image/jpeg" });
    return createImageBitmap(blob);
  }

  /** Texture-to-itself copy via a scratch texture (self-copy is undefined when overlapping). */
  private copyRect(srcX: number, srcY: number, dstX: number, dstY: number, w: number, h: number): void {
    const gl = this.gl;
    if (this.scratchW < w || this.scratchH < h) {
      this.scratchW = Math.max(this.scratchW, w);
      this.scratchH = Math.max(this.scratchH, h);
      gl.bindTexture(gl.TEXTURE_2D, this.scratchTex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, this.scratchW, this.scratchH, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    }
    gl.bindFramebuffer(gl.FRAMEBUFFER, this.readFbo);
    // 1) frame -> scratch
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.frameTex, 0);
    gl.bindTexture(gl.TEXTURE_2D, this.scratchTex);
    gl.copyTexSubImage2D(gl.TEXTURE_2D, 0, 0, 0, srcX, srcY, w, h);
    // 2) scratch -> frame
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.scratchTex, 0);
    gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
    gl.copyTexSubImage2D(gl.TEXTURE_2D, 0, dstX, dstY, 0, 0, w, h);
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
  }

  /**
   * Apply one H.264 rect (PRD/02 §2.3).
   *
   * The backend has already done the context bookkeeping: `h264Context` is a
   * decoder slot keyed by rect geometry, `h264Reset` says the decoder must be
   * rebuilt (new context, server reset, or still waiting for an IDR), and
   * `h264Key` says this payload can start a decoder. An empty payload is a
   * control message: apply the flags and decode nothing.
   */
  private decodeH264(r: WireRect): void {
    if (this.h264Failed) return;
    if (typeof VideoDecoder === "undefined" || typeof EncodedVideoChunk === "undefined") {
      this.h264Failed = true;
      this.notice(
        "This webview has no WebCodecs H.264 decoder; video-coded regions will not render. " +
          "Switch the connection's quality preset to High to force a non-H.264 encoding.",
      );
      return;
    }

    const id = r.h264Context ?? 0;
    const flags = r.h264Flags ?? 0;
    const isKey = r.h264Key === true;
    if (flags & H264_RESET_ALL_CONTEXTS) this.closeAllH264();
    if (flags & H264_RESET_CONTEXT) this.closeH264(id);
    if (r.payload.byteLength === 0) return; // control message: nothing to decode

    let ctx = this.h264.get(id);
    if (r.h264Reset || !ctx) {
      if (ctx) this.closeH264(id);
      // A decoder can only start on an IDR; anything else is undecodable.
      if (!isKey) return;
      ctx = this.createH264(r, id) ?? undefined;
      if (!ctx) return;
    }
    if (ctx.decoder.state === "closed") {
      this.h264.delete(id);
      return;
    }

    try {
      ctx.timestamp += 1000; // 1 ms apart: monotonic is all the decoder needs
      ctx.decoder.decode(
        new EncodedVideoChunk({
          type: isKey ? "key" : "delta",
          timestamp: ctx.timestamp,
          // Copy: the parse buffer is recycled long before decode completes.
          data: r.payload.slice(),
        }),
      );
    } catch {
      this.closeH264(id);
    }
  }

  /** Build a decoder for one context, or `null` if WebCodecs refuses. */
  private createH264(r: WireRect, id: number): H264Context | null {
    if (this.h264.size >= H264_MAX_CONTEXTS) {
      // The backend caps contexts at 64 and recycles slots, so this only
      // happens if the two sides disagree. Start clean rather than leak.
      this.closeAllH264();
    }
    const generation = this.generation;
    const ctx: H264Context = {
      decoder: null as unknown as VideoDecoder,
      x: r.x,
      y: r.y,
      w: r.w,
      h: r.h,
      generation,
      timestamp: 0,
    };
    try {
      ctx.decoder = new VideoDecoder({
        output: (frame: VideoFrame) => {
          if (this.disposed || generation !== this.generation) {
            frame.close();
            return;
          }
          this.uploadVideoFrame(frame, ctx);
        },
        error: () => {
          this.closeH264(id);
        },
      });
      ctx.decoder.configure({
        // Baseline profile per the PRD; the decoder reads the real profile
        // from the in-band SPS, this is only the initial hint.
        codec: "avc1.42E01E",
        optimizeForLatency: true,
      } as VideoDecoderConfig);
    } catch {
      this.h264Failed = true;
      this.notice("H.264 decoding is unavailable in this webview; those regions will not render.");
      return null;
    }
    this.h264.set(id, ctx);
    return ctx;
  }

  /**
   * Upload one decoded frame at its context's origin, cropping bottom/right:
   * the encoder pads to macroblock boundaries, so frames are routinely larger
   * than the rect and the excess must not bleed into neighbouring pixels.
   */
  private uploadVideoFrame(frame: VideoFrame, ctx: H264Context): void {
    const gl = this.gl;
    const frameW = frame.displayWidth || frame.codedWidth;
    const frameH = frame.displayHeight || frame.codedHeight;
    const w = Math.min(frameW, ctx.w);
    const h = Math.min(frameH, ctx.h);
    let cropped: VideoFrame | null = null;
    try {
      if (frameW > w || frameH > h) {
        cropped = new VideoFrame(frame, { visibleRect: { x: 0, y: 0, width: w, height: h } });
      }
      gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
      gl.texSubImage2D(
        gl.TEXTURE_2D, 0, ctx.x, ctx.y,
        gl.RGBA, gl.UNSIGNED_BYTE, cropped ?? frame,
      );
      this.markDirty();
    } catch {
      // VideoFrame cropping is not universally supported: fall back to a 2D
      // canvas copy, which is slower but always available.
      this.uploadVideoFrameViaCanvas(frame, ctx, w, h);
    } finally {
      cropped?.close();
      frame.close();
    }
  }

  private uploadVideoFrameViaCanvas(frame: VideoFrame, ctx: H264Context, w: number, h: number): void {
    try {
      const off = new OffscreenCanvas(w, h);
      const c2d = off.getContext("2d");
      if (!c2d) return;
      c2d.drawImage(frame, 0, 0, w, h, 0, 0, w, h);
      const gl = this.gl;
      gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
      gl.texSubImage2D(gl.TEXTURE_2D, 0, ctx.x, ctx.y, gl.RGBA, gl.UNSIGNED_BYTE, off);
      this.markDirty();
    } catch {
      this.notice("Failed to present an H.264 frame; falling back to other encodings.");
      this.h264Failed = true;
    }
  }

  private closeH264(id: number): void {
    const ctx = this.h264.get(id);
    if (!ctx) return;
    this.h264.delete(id);
    try {
      if (ctx.decoder.state !== "closed") ctx.decoder.close();
    } catch {
      /* already gone */
    }
  }

  private closeAllH264(): void {
    for (const id of Array.from(this.h264.keys())) this.closeH264(id);
  }

  /** Report a non-fatal renderer condition at most once. */
  private notice(message: string): void {
    if (this.notices.has(message)) return;
    this.notices.add(message);
    if (this.onNotice) this.onNotice(message);
    else console.warn(`[renderer] ${message}`);
  }

  // ------------------------------------------------------------------ cursor

  setCursorShape(width: number, height: number, hotX: number, hotY: number, rgba: Uint8Array): void {
    const gl = this.gl;
    this.cursorW = width;
    this.cursorH = height;
    this.cursorHotX = hotX;
    this.cursorHotY = hotY;
    this.cursorHasShape = width > 0 && height > 0;
    if (this.cursorHasShape) {
      gl.bindTexture(gl.TEXTURE_2D, this.cursorTex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, rgba);
    }
    this.markDirty();
  }

  /** Move the cursor sprite (framebuffer coordinates), independent of frame delivery. */
  setCursorPosition(x: number, y: number): void {
    if (x === this.cursorX && y === this.cursorY) return;
    this.cursorX = x;
    this.cursorY = y;
    if (this.cursorEnabled && this.cursorHasShape) this.markDirty();
  }

  setCursorVisible(v: boolean): void {
    if (this.cursorEnabled !== v) {
      // Deliberately independent of whether a shape has arrived: a later
      // setCursorShape must not silently re-enable a pointer the user hid.
      this.cursorEnabled = v;
      this.markDirty();
    }
  }

  // --------------------------------------------------------------- transform

  setScalingMode(mode: RendererScalingMode): void {
    this.mode = mode;
    if (mode !== "custom") {
      this.panX = 0;
      this.panY = 0;
    }
    this.markDirty();
  }

  getScalingMode(): RendererScalingMode {
    return this.mode;
  }

  setZoom(zoom: number): void {
    this.zoom = Math.min(4, Math.max(0.25, zoom));
    this.markDirty();
  }

  getZoom(): number {
    return this.zoom;
  }

  panBy(dxDevice: number, dyDevice: number): void {
    this.panX += dxDevice;
    this.panY += dyDevice;
    this.clampPan();
    this.markDirty();
  }

  private clampPan(): void {
    const t = this.contentTransform();
    const cw = this.fbWidth * t.scaleX;
    const ch = this.fbHeight * t.scaleY;
    const W = this.canvas.width;
    const H = this.canvas.height;
    const maxX = Math.max(0, (cw - W) / 2);
    const maxY = Math.max(0, (ch - H) / 2);
    this.panX = Math.min(maxX, Math.max(-maxX, this.panX));
    this.panY = Math.min(maxY, Math.max(-maxY, this.panY));
  }

  /** Content placement in device pixels for the current mode/zoom/pan. */
  contentTransform(): ContentTransform {
    const W = this.canvas.width;
    const H = this.canvas.height;
    const fw = Math.max(1, this.fbWidth);
    const fh = Math.max(1, this.fbHeight);
    let sx: number;
    let sy: number;
    switch (this.mode) {
      case "fit":
        sx = W / fw;
        sy = H / fh;
        break;
      case "aspect-fit": {
        const s = Math.min(W / fw, H / fh);
        sx = s;
        sy = s;
        break;
      }
      case "actual":
        sx = 1;
        sy = 1;
        break;
      case "custom":
        sx = this.zoom;
        sy = this.zoom;
        break;
    }
    const cw = fw * sx;
    const ch = fh * sy;
    return {
      x: (W - cw) / 2 - this.panX,
      y: (H - ch) / 2 - this.panY,
      scaleX: sx,
      scaleY: sy,
    };
  }

  /**
   * Map a point in canvas CSS pixels to framebuffer pixels.
   * `rect` is the canvas getBoundingClientRect; clamped to the framebuffer.
   */
  cssPointToFramebuffer(
    cssX: number,
    cssY: number,
    rect: { left: number; top: number; width: number; height: number },
  ): { x: number; y: number } {
    const dprX = this.canvas.width / Math.max(1, rect.width);
    const dprY = this.canvas.height / Math.max(1, rect.height);
    const dx = (cssX - rect.left) * dprX;
    const dy = (cssY - rect.top) * dprY;
    const t = this.contentTransform();
    const fx = (dx - t.x) / t.scaleX;
    const fy = (dy - t.y) / t.scaleY;
    return {
      x: Math.max(0, Math.min(this.fbWidth - 1, Math.round(fx))),
      y: Math.max(0, Math.min(this.fbHeight - 1, Math.round(fy))),
    };
  }

  // ------------------------------------------------------------------ B&W

  /** 0 = full color. Otherwise gray levels: 256/16/8/4/2, or 1 for 1-bit dithered. */
  setGrayLevels(levels: number): void {
    this.grayLevels = levels;
    this.markDirty();
  }

  // ------------------------------------------------------------------ loop

  start(): void {
    if (this.running || this.disposed) return;
    this.running = true;
    const loop = (): void => {
      if (!this.running) return;
      if (this.dirty) {
        this.dirty = false;
        this.draw();
      }
      this.rafId = requestAnimationFrame(loop);
    };
    this.rafId = requestAnimationFrame(loop);
  }

  stop(): void {
    this.running = false;
    cancelAnimationFrame(this.rafId);
  }

  markDirty(): void {
    this.dirty = true;
  }

  private draw(): void {
    const gl = this.gl;
    const W = this.canvas.width;
    const H = this.canvas.height;
    gl.viewport(0, 0, W, H);
    gl.clear(gl.COLOR_BUFFER_BIT);
    if (this.fbWidth === 0 || W === 0) return;

    const t = this.contentTransform();
    gl.useProgram(this.program);

    // main frame quad
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
    gl.uniform1f(this.uLevels, this.grayLevels);
    gl.uniform1f(this.uTexAlpha, 0); // framebuffer is opaque
    gl.uniform4f(
      this.uRect,
      t.x / W,
      t.y / H,
      (this.fbWidth * t.scaleX) / W,
      (this.fbHeight * t.scaleY) / H,
    );
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

    // cursor sprite, scaled with content
    if (this.cursorEnabled && this.cursorHasShape && this.cursorW > 0) {
      const cx = t.x + (this.cursorX - this.cursorHotX) * t.scaleX;
      const cy = t.y + (this.cursorY - this.cursorHotY) * t.scaleY;
      gl.bindTexture(gl.TEXTURE_2D, this.cursorTex);
      gl.uniform1f(this.uLevels, 0);
      gl.uniform1f(this.uTexAlpha, 1); // masked sprite, keep transparency
      gl.uniform4f(
        this.uRect,
        cx / W,
        cy / H,
        (this.cursorW * t.scaleX) / W,
        (this.cursorH * t.scaleY) / H,
      );
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }
  }

  /**
   * Current framebuffer as tightly packed, top-down RGBA8888, exactly the
   * body `capture_thumbnail` expects (`width * height * 4` bytes).
   *
   * Texture row 0 is the top scanline and the read FBO is the texture itself,
   * so `readPixels` already yields rows top-down; no vertical flip needed.
   */
  readFramebufferRGBA(): { width: number; height: number; pixels: Uint8Array } | null {
    if (this.fbWidth === 0 || this.fbHeight === 0) return null;
    const gl = this.gl;
    const width = this.fbWidth;
    const height = this.fbHeight;
    const pixels = new Uint8Array(width * height * 4);
    gl.bindFramebuffer(gl.FRAMEBUFFER, this.readFbo);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.frameTex, 0);
    gl.readPixels(0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    return { width, height, pixels };
  }

  /** Current frame as a PNG blob (screenshots). */
  async screenshot(): Promise<Blob | null> {
    const frame = this.readFramebufferRGBA();
    if (!frame) return null;
    const off = new OffscreenCanvas(frame.width, frame.height);
    const ctx = off.getContext("2d");
    if (!ctx) return null;
    // Copy into a fresh ArrayBuffer-backed view: ImageData rejects the
    // ArrayBufferLike typing of a view over a possibly-shared buffer.
    const img = new ImageData(new Uint8ClampedArray(frame.pixels), frame.width, frame.height);
    ctx.putImageData(img, 0, 0);
    return off.convertToBlob({ type: "image/png" });
  }

  dispose(): void {
    this.disposed = true;
    this.stop();
    this.closeAllH264();
    const gl = this.gl;
    gl.deleteTexture(this.frameTex);
    gl.deleteTexture(this.scratchTex);
    gl.deleteTexture(this.cursorTex);
    gl.deleteFramebuffer(this.readFbo);
    gl.deleteProgram(this.program);
  }
}
