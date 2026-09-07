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
 * - Incoming updates queue in a pending list and are coverage-pruned before
 *   they are applied, so a backlog that builds up during video playback
 *   collapses to what is still visible instead of playing out seconds late.
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
uniform vec4 u_uv;                       // texture subrect: offset xy, scale zw (0,0,1,1 = whole texture)
out vec2 v_uv;
void main() {
  v_uv = u_uv.xy + a_pos * u_uv.zw;
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
  /**
   * Uploads still waiting on the decoder, keyed by the timestamp of the chunk
   * that will produce them. Insertion order is submission order, which is
   * also ascending timestamp order; see `decodeH264` for what that buys.
   */
  waiters: Map<number, (frame: VideoFrame | null) => void>;
}

/** Maximum simultaneous decoder contexts, mirrors the backend's cap. */
const H264_MAX_CONTEXTS = 64;

/**
 * How long one H.264 rect waits for its decoded frame before giving up on it.
 *
 * A `decode()` normally produces exactly one `output` callback, but a decoder
 * that quietly swallows a chunk (a corrupt slice, a driver hiccup) would
 * otherwise leave the apply loop waiting forever, and every later update
 * queued behind it: the whole viewer freezes, which is far worse than one
 * missing frame. A real decode is tens of milliseconds, so half a second only
 * ever fires when something has genuinely gone wrong, and the picture heals on
 * the next key frame.
 */
const H264_FRAME_TIMEOUT_MS = 500;

/**
 * Hard cap on queued updates before the drain loop stops being polite.
 *
 * Below this, only rects that are provably invisible get dropped (see
 * `pruneUpdates`). At or above it the queue sheds every droppable rect in
 * every update but the newest, which CAN leave a region stale until the
 * server repaints it. That trade only makes sense as a last resort, so the cap
 * sits well above any backlog normal operation produces: the pruning below
 * collapses video and animation on its own, and a queue that still grows past
 * sixteen updates means the machine cannot keep up at all, where seconds of
 * input lag is the worse failure.
 */
export const MAX_PENDING_UPDATES = 16;

/**
 * The same cap expressed in payload bytes. Queued rects hold views into their
 * IPC message buffers, so a backlog pins that memory until it is applied; a
 * few full-screen RGBA updates on a 4K desktop are 30 MB each.
 */
export const MAX_PENDING_BYTES = 64 * 1024 * 1024;

/** Upper bound on the covered-region set, see `addCover`. */
const MAX_COVER_RECTS = 32;
/** Upper bound on the pieces one coverage test may split a rect into. */
const MAX_COVER_FRAGMENTS = 64;

/**
 * The rect metadata pruning looks at, and nothing else.
 *
 * Deliberately not `WireRect`: the pruner never touches a payload, never
 * touches GL, and is therefore testable on plain objects without standing up a
 * WebGL context.
 */
export interface PruneRect {
  x: number;
  y: number;
  w: number;
  h: number;
  format: number;
}

export interface PruneResult<T extends PruneRect> {
  /** Surviving rects per update, in protocol order. Inner arrays may be empty. */
  kept: T[][];
  /** How many rects were dropped, for the drop counters. */
  dropped: number;
}

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Whether `b` lies entirely inside `a`. */
function contains(a: Box, b: Box): boolean {
  return b.x >= a.x && b.y >= a.y && b.x + b.w <= a.x + a.w && b.y + b.h <= a.y + a.h;
}

/** The parts of `a` that `b` does not cover, appended to `out`. */
function subtractBox(a: Box, b: Box, out: Box[]): void {
  const ix0 = Math.max(a.x, b.x);
  const iy0 = Math.max(a.y, b.y);
  const ix1 = Math.min(a.x + a.w, b.x + b.w);
  const iy1 = Math.min(a.y + a.h, b.y + b.h);
  if (ix0 >= ix1 || iy0 >= iy1) {
    out.push(a); // no overlap at all
    return;
  }
  if (a.y < iy0) out.push({ x: a.x, y: a.y, w: a.w, h: iy0 - a.y });
  if (iy1 < a.y + a.h) out.push({ x: a.x, y: iy1, w: a.w, h: a.y + a.h - iy1 });
  if (a.x < ix0) out.push({ x: a.x, y: iy0, w: ix0 - a.x, h: iy1 - iy0 });
  if (ix1 < a.x + a.w) out.push({ x: ix1, y: iy0, w: a.x + a.w - ix1, h: iy1 - iy0 });
}

/**
 * Whether the union of `covers` hides every pixel of `r`.
 *
 * Chip the rect away one cover at a time and see whether anything is left. A
 * single later full-screen rect answers this on the first iteration, which is
 * the case that matters; the general union test is here so that a desktop
 * repainted as a grid of tiles also collapses instead of only the single-rect
 * case. If a rect shatters into more pieces than the fragment cap, give up and
 * say "not covered": keeping a rect is always safe, dropping one is not.
 */
function isCovered(r: Box, covers: readonly Box[]): boolean {
  let frags: Box[] = [r];
  for (const c of covers) {
    const next: Box[] = [];
    for (const f of frags) subtractBox(f, c, next);
    if (next.length === 0) return true;
    if (next.length > MAX_COVER_FRAGMENTS) return false;
    frags = next;
  }
  return false;
}

/**
 * Record `r` as covered, keeping the set small.
 *
 * A rect already inside a recorded one adds nothing, and a rect that swallows
 * recorded ones replaces them. Without that, a minute of video would leave
 * hundreds of identical full-screen rects in the set and every coverage test
 * would walk all of them. Once the set is full, later rects are simply not
 * recorded: that prunes less, never wrongly.
 */
function addCover(covers: Box[], r: Box): void {
  for (const c of covers) {
    if (contains(c, r)) return;
  }
  let n = 0;
  for (const c of covers) {
    if (!contains(r, c)) covers[n++] = c;
  }
  covers.length = n;
  if (covers.length < MAX_COVER_RECTS) covers.push(r);
}

/** A damage rectangle: the bounding box of one update's changed region. */
export interface DamageBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** One update as `coalesceByDamage` sees it: its rects and its damage box. */
export interface DamagedUpdate<T extends PruneRect> {
  rects: readonly T[];
  damage: DamageBox;
}

/** Is `r` wholly inside `b`? */
function within(r: PruneRect, b: DamageBox): boolean {
  return r.x >= b.x && r.y >= b.y && r.x + r.w <= b.x + b.w && r.y + r.h <= b.y + b.h;
}

/**
 * Drop the rects a newer update's DAMAGE BOX already supersedes.
 *
 * This is the coarse partner to `pruneUpdates`, and it exists because that one
 * cannot collapse a real video. A video arrives as thousands of small dirty
 * rectangles a second whose edges shift frame to frame, so they never nest
 * exactly and the per-tile coverage set (capped at `MAX_COVERAGE_RECTS` for
 * cost) is blown long before it can prove an old tile invisible. Measured on a
 * real playing video, the renderer queue still sat ~29 updates deep because of
 * this, and a right-click menu waited behind all of them.
 *
 * A whole update carries one damage box, the union of its rects. There are as
 * many boxes as updates in the queue, tens, not thousands, so using THOSE as
 * the cover set is cheap. Walking newest to oldest, a droppable rect wholly
 * inside a newer update's damage box is stale: a newer frame has already
 * repainted that region, so drawing the old one would be overwritten at once.
 * Video frames share a damage box and collapse to the newest; a right-click
 * menu, whose damage box is elsewhere, is inside no video box and is kept.
 *
 * The barriers are `pruneUpdates`' barriers, for the same reasons: a CopyRect
 * reads the framebuffer and an H264 rect carries decoder state, so the walk
 * stops at the first update that holds one and keeps it and everything older.
 * Survivors come back in arrival order, oldest first, ready to apply as one
 * batch.
 */
export function coalesceByDamage<T extends PruneRect>(
  updates: readonly DamagedUpdate<T>[],
): { kept: T[][]; dropped: number } {
  const newest = updates.length - 1;
  const keep = updates.map((u) => u.rects.map(() => true));
  const covers: DamageBox[] = [];
  let dropped = 0;
  scan: for (let u = newest; u >= 0; u--) {
    const rects = updates[u].rects;
    for (const r of rects) {
      if (r.format === RectFormat.CopyRect || r.format === RectFormat.H264) break scan;
    }
    for (let i = 0; i < rects.length; i++) {
      const r = rects[i];
      const droppable =
        (r.format === RectFormat.Rgba || r.format === RectFormat.Jpeg) && r.w > 0 && r.h > 0;
      if (droppable && covers.some((b) => within(r, b))) {
        keep[u][i] = false;
        dropped++;
      }
    }
    covers.push(updates[u].damage);
  }
  return {
    kept: updates.map((u, i) => u.rects.filter((_, j) => keep[i][j])),
    dropped,
  };
}


/**
 * Decide which queued rects are still worth applying.
 *
 * `pending` is the queue oldest-first, each entry one update's rects in
 * protocol order. The walk goes NEWEST to OLDEST carrying the union of the
 * regions later rects will paint. Any rect entirely inside that union is
 * redundant: applying it would be overwritten before a single frame is drawn,
 * so all it costs is a JPEG decode and a texture upload the user never sees.
 * That is what makes video cheap here, consecutive full-screen updates fully
 * cover their predecessors, so a backlog of thirty video frames collapses to
 * roughly the newest one and display latency stops growing.
 *
 * SAFETY, the part that must not be got wrong:
 *
 * - `CopyRect` READS the framebuffer it is applied to. Its source pixels are
 *   whatever earlier rects put there, so dropping or reordering anything
 *   ahead of it copies the wrong region onto the screen, and the server will
 *   not repaint what it believes the client already has. So a CopyRect is a
 *   hard barrier: the walk stops dead at it and everything older is kept.
 * - `H264` rects carry inter-frame dependencies and are fed to a decoder that
 *   has state. Dropping one corrupts every frame until the next IDR. They are
 *   barriers for the same reason.
 * - Only `Rgba` and `Jpeg` rects are self-contained, so only those are ever
 *   dropped, and only when fully covered.
 * - Survivors stay in protocol order. Pruning removes, it never reorders.
 *
 * With `collapse` set (the queue has blown past its cap, see
 * `MAX_PENDING_UPDATES`) every droppable rect outside the newest update is
 * treated as covered whether it is or not. That can leave a region showing
 * stale pixels until something repaints it, which is why it is reserved for a
 * queue that is already failing.
 *
 * One accepted trade in the ordinary path: an older rect dropped as covered
 * leaves its region stale if the newer rect that covered it then fails to
 * decode. A failing JPEG already leaves a permanently stale region on its own
 * (see the decode error path in `applyFrameOrdered`), so this widens an
 * existing hole rather than opening a new one.
 */
export function pruneUpdates<T extends PruneRect>(
  pending: readonly (readonly T[])[],
  collapse = false,
): PruneResult<T> {
  const newest = pending.length - 1;
  const keep = pending.map((rects) => rects.map(() => true));
  const covers: Box[] = [];
  let dropped = 0;
  scan: for (let u = newest; u >= 0; u--) {
    const rects = pending[u];
    for (let i = rects.length - 1; i >= 0; i--) {
      const r = rects[i];
      if (r.format === RectFormat.CopyRect || r.format === RectFormat.H264) break scan;
      // Anything else unknown to the apply switch paints nothing, so it
      // neither covers a rect below it nor is worth dropping.
      const paints =
        (r.format === RectFormat.Rgba || r.format === RectFormat.Jpeg) && r.w > 0 && r.h > 0;
      if (!paints) continue;
      if ((collapse && u !== newest) || isCovered(r, covers)) {
        keep[u][i] = false;
        dropped++;
        continue;
      }
      addCover(covers, r);
    }
  }
  return {
    kept: pending.map((rects, u) => rects.filter((_, i) => keep[u][i])),
    dropped,
  };
}

/** One update waiting its turn in the pending queue. */
interface PendingUpdate {
  rects: WireRect[];
  /** This update's damage box, used by `coalesceByDamage` to supersede it. */
  damage: DamageBox;
  /** Renderer generation the message was parsed against (see `generation`). */
  generation: number;
  /**
   * Payload bytes this update pins. Fixed at arrival rather than recomputed
   * after pruning: the rects are views into one IPC message buffer, and that
   * buffer stays alive while any rect of it is still queued.
   */
  bytes: number;
}

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
  private uUv: WebGLUniformLocation;
  private uLevels: WebGLUniformLocation;
  private uTexAlpha: WebGLUniformLocation;
  private frameTex: WebGLTexture;
  private scratchTex: WebGLTexture;
  private cursorTex: WebGLTexture;
  /** Small downscaled render target for readPreviewRGBA (Library live previews). */
  private previewTex: WebGLTexture;
  private readFbo: WebGLFramebuffer;

  private fbWidth = 0;
  private fbHeight = 0;
  private scratchW = 0;
  private scratchH = 0;
  private previewW = 0;
  private previewH = 0;

  private dirty = false;
  private running = false;
  private rafId = 0;
  private disposed = false;
  /** bumped on resize/reconnect so stale async JPEG uploads are dropped */
  private generation = 0;
  /** Updates waiting to be applied, oldest first. See `applyFrame`. */
  private pending: PendingUpdate[] = [];
  /** True while `drain` is running, so only ever one drain loop exists. */
  private draining = false;
  /** Payload bytes the pending queue currently pins. */
  private pendingBytes = 0;
  /** Rects pruning has thrown away this session, for `getQueueStats`. */
  private droppedRects = 0;
  /** Updates that left the queue without being applied at all. */
  private droppedUpdates = 0;

  // view transform
  private mode: RendererScalingMode = "aspect-fit";
  private zoom = 1;
  private panX = 0;
  private panY = 0;
  /**
   * Per-monitor view: the framebuffer subrect on display, in framebuffer
   * pixels. Zero width/height means "the whole desktop", which is also the
   * state on every resize (the geometry the rect was cut from is gone; the
   * session view re-applies its selection against the new layout).
   */
  private viewX = 0;
  private viewY = 0;
  private viewW = 0;
  private viewH = 0;

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
    const uUv = gl.getUniformLocation(program, "u_uv");
    const uLevels = gl.getUniformLocation(program, "u_levels");
    const uTexAlpha = gl.getUniformLocation(program, "u_texAlpha");
    if (!uRect || !uUv || !uLevels || !uTexAlpha) throw new Error("uniform lookup failed");
    this.uRect = uRect;
    this.uUv = uUv;
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
    this.previewTex = this.makeTexture();
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
    // A monitor rect cut from the old geometry means nothing in the new one.
    this.clearViewRect();
    // Every decoder's target geometry just became meaningless.
    this.closeAllH264();
    gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    // A CopyRect scratch texture sized for the old (possibly much larger)
    // desktop must not survive a resize; drop it and let the next CopyRect
    // reallocate to whatever it actually needs.
    this.scratchW = 0;
    this.scratchH = 0;
    gl.bindTexture(gl.TEXTURE_2D, this.scratchTex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
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
   * Queue one parsed channel message for application.
   *
   * ORDER IS LOAD-BEARING. RGBA and CopyRect apply synchronously, but JPEG has
   * to go through `createImageBitmap`, and H.264 through a `VideoDecoder`,
   * both async. Applying each decode whenever it happened to settle let a
   * rect from an older update land *on top of* newer content, visible as
   * patches of stale pixels during window drags and minimise/maximise
   * animations, which then "healed" whenever something else repainted that
   * region. So everything below applies strictly in protocol order, and
   * update N is fully applied (including every H.264 rect's frame actually
   * uploaded) before N+1 starts.
   *
   * What that ordering guarantee used to cost: this was an unbounded promise
   * chain, one link appended per arriving message, and every message's JPEG
   * decodes were started the moment it arrived. When updates arrive faster
   * than they apply, which is exactly what video playback and window
   * animations do, the chain grew without limit. The server saw the clicks
   * immediately but the picture on screen was seconds behind, so the session
   * felt like it had stopped responding altogether.
   *
   * Now the message joins a queue that `drain` prunes before each update it
   * applies, so work that is about to be overwritten is never paid for at
   * all: no decode is started for it and nothing is uploaded. Ordering is
   * unchanged, the queue is drained strictly front to back.
   */
  applyFrame(msg: FrameMessage): void {
    if (this.disposed) return;
    let bytes = 0;
    for (const r of msg.rects) bytes += r.payload.byteLength;
    this.pending.push({
      rects: msg.rects,
      damage: { x: msg.damageX, y: msg.damageY, w: msg.damageW, h: msg.damageH },
      generation: this.generation,
      bytes,
    });
    this.pendingBytes += bytes;
    if (this.draining) return;
    this.draining = true;
    void this.drain();
  }

  /**
   * Apply queued updates until the queue is empty.
   *
   * Pruning happens once per iteration rather than once per drain, because
   * messages keep arriving while we await a decode: by the time an update
   * reaches the front of the queue, updates behind it may already have made
   * most of it invisible.
   */
  private async drain(): Promise<void> {
    try {
      while (this.pending.length > 0 && !this.disposed) {
        // Coalesce the WHOLE queue into one apply, not one apply per update.
        //
        // Measured under a video playing on the remote: the server sends 16 to
        // 20 updates a second, the webview receives every one, and this queue
        // sat 21 updates deep, about 1.3 s. A right-click menu, a fresh update,
        // went to the BACK of that queue and waited for all 20 ahead of it to
        // be applied one await at a time, so the menu took two seconds to
        // appear. Pruning already dropped the covered video tiles of the older
        // updates, but an update pruned to a handful of rects still cost a full
        // async apply cycle, and twenty of those is the delay.
        //
        // So prune the queue, then apply everything still standing in ONE pass.
        // A backlog of video frames plus a menu becomes: the newest video tiles
        // (older ones pruned as covered) and the menu, drawn together, next
        // frame. Order is preserved by concatenation, which is exactly what the
        // per-update loop did in sequence; the CopyRect and H264 barriers the
        // pruner stops at are carried in that same order.
        // Supersede by damage box first, which is what actually collapses a
        // video (see `coalesceByDamage`), then fall back to the exact per-tile
        // pruner for the rest. Over the byte cap, the per-tile pass also
        // collapses to the newest update as a last resort.
        const coalesced = coalesceByDamage(
          this.pending.map((u) => ({ rects: u.rects, damage: u.damage })),
        );
        for (let i = 0; i < this.pending.length; i++) this.pending[i].rects = coalesced.kept[i];
        const overCap = this.pendingBytes > MAX_PENDING_BYTES;
        const pruned = pruneUpdates(
          this.pending.map((u) => u.rects),
          overCap,
        );
        this.droppedRects += coalesced.dropped + pruned.dropped;

        const batch: WireRect[] = [];
        const gen = this.generation;
        for (let u = 0; u < this.pending.length; u++) {
          const update = this.pending[u];
          // A resize replaced the texture an older update was parsed for; its
          // coordinates address a framebuffer that no longer exists, so it is
          // dropped rather than mixed into the current generation's batch.
          if (update.generation !== gen) {
            this.droppedRects += pruned.kept[u].length;
            this.droppedUpdates++;
            continue;
          }
          for (const r of pruned.kept[u]) batch.push(r);
        }
        this.pending = [];
        this.pendingBytes = 0;
        if (batch.length === 0) continue;

        // Decodes for the whole batch start together and run in parallel; the
        // ordered apply below awaits them in place so uploads still land in
        // protocol order.
        const decodes: (Promise<ImageBitmap> | null)[] = batch.map((r) => {
          if (r.format !== RectFormat.Jpeg) return null;
          const d = this.decodeJpeg(r.payload);
          // Caught here so a later rect's decode failure is not an unhandled
          // rejection while an earlier one is still being awaited; the await in
          // the apply loop still throws and is handled there.
          d.catch(() => undefined);
          return d;
        });
        try {
          await this.applyFrameOrdered(batch, decodes, gen);
        } catch {
          // One malformed rect must not kill the drain loop and strand every
          // update queued behind it.
        }
        // Whatever arrived while that batch was applying is picked up on the
        // next pass, coalesced with the same economy.
      }
    } finally {
      this.draining = false;
    }
  }

  /**
   * Queue depth and the shed-work counters, so the drop behaviour can be
   * observed from a debug overlay or a test without instrumenting the hot
   * path itself.
   */
  getQueueStats(): {
    depth: number;
    bytes: number;
    droppedRects: number;
    droppedUpdates: number;
  } {
    return {
      depth: this.pending.length,
      bytes: this.pendingBytes,
      droppedRects: this.droppedRects,
      droppedUpdates: this.droppedUpdates,
    };
  }

  private async applyFrameOrdered(
    rects: WireRect[],
    pending: (Promise<ImageBitmap> | null)[],
    gen: number,
  ): Promise<void> {
    const gl = this.gl;
    for (let i = 0; i < rects.length; i++) {
      const r = rects[i];
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
          await this.decodeH264(r);
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

  /**
   * Start a JPEG decode. `bytes` is a view into the IPC buffer (recycled as
   * soon as this call returns), but that's safe without an explicit copy:
   * the Blob constructor copies the bytes it's given synchronously, and it
   * respects the view's offset/length rather than the whole backing buffer.
   *
   * `colorSpaceConversion`/`premultiplyAlpha: "none"` skip the browser's
   * default colour management pass, which is both slower and can shift JPEG
   * rect colours slightly versus the untouched RGBA rects next to them.
   */
  private decodeJpeg(bytes: Uint8Array): Promise<ImageBitmap> {
    // The view is always backed by a plain ArrayBuffer (the IPC message
    // buffer); only the TS lib's generic ArrayBufferLike typing needs telling.
    const blob = new Blob([bytes as Uint8Array<ArrayBuffer>], { type: "image/jpeg" });
    return createImageBitmap(blob, { colorSpaceConversion: "none", premultiplyAlpha: "none" });
  }

  /** Texture-to-itself copy via a scratch texture (self-copy is undefined when overlapping). */
  private copyRect(srcX: number, srcY: number, dstX: number, dstY: number, w: number, h: number): void {
    const gl = this.gl;
    const tooSmall = this.scratchW < w || this.scratchH < h;
    // A single big CopyRect (e.g. a full-screen scroll on a 4K desktop)
    // otherwise pins its scratch allocation for the rest of the session even
    // once every later copy is tiny. Shrink back down once the live need
    // drops under a quarter of what's allocated, instead of only ever
    // growing to the largest CopyRect ever seen.
    const wastefullyBig = this.scratchW > 0 && w * 4 <= this.scratchW && h * 4 <= this.scratchH;
    if (tooSmall || wastefullyBig) {
      this.scratchW = w;
      this.scratchH = h;
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
   *
   * ORDERING: `decoder.decode()` is fire-and-forget; the frame comes back
   * later in the decoder's `output` callback (see `createH264`), OUTSIDE this
   * function's turn. Left alone, that let a slow decode from update N land on
   * top of update N+1's (synchronous) rects.
   *
   * This used to be closed by awaiting `decoder.flush()` after every single
   * `decode()`, which does guarantee the output callback has run, but flush
   * means "drain everything you are holding and reset your pipeline". Paying
   * that per rect on a video stream is exactly the workload it hurts most:
   * the decoder never gets to keep more than one frame in flight, and the
   * cost lands on the main thread, feeding the backlog this queue exists to
   * shed.
   *
   * Instead the chunk is tagged with a monotonic timestamp that identifies
   * its position, and `output` hands the decoded frame to whoever is waiting
   * on that timestamp rather than uploading it itself (see
   * `deliverH264Frame`). The upload then happens right here, at the rect's
   * own position in the ordered loop, so ordering is enforced by where the
   * pixels are written rather than by draining the decoder. The wait is
   * bounded by `H264_FRAME_TIMEOUT_MS` and released early whenever the
   * decoder is closed, so a decoder that never answers cannot stall the
   * queue.
   */
  private async decodeH264(r: WireRect): Promise<void> {
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

    ctx.timestamp += 1000; // 1 ms apart: monotonic is all the decoder needs
    const ts = ctx.timestamp;
    const wait = this.awaitH264Frame(ctx, ts);
    try {
      ctx.decoder.decode(
        new EncodedVideoChunk({
          type: isKey ? "key" : "delta",
          timestamp: ts,
          // Copy: the parse buffer is recycled long before decode completes.
          data: r.payload.slice(),
        }),
      );
    } catch {
      // Decode error, or the decoder was reset/closed (e.g. a resize raced
      // this update). Closing settles the waiter above, so the await below
      // returns immediately rather than sitting out the timeout.
      this.closeH264(id);
    }
    const frame = await wait;
    if (!frame) return;
    if (this.disposed || ctx.generation !== this.generation) {
      frame.close();
      return;
    }
    this.uploadVideoFrame(frame, ctx);
  }

  /**
   * Wait for the frame a chunk will decode into, identified by its timestamp.
   *
   * The waiter is registered before `decode()` is called so that an output
   * callback can never arrive before there is anything to hand it to, and it
   * is settled exactly once: whichever of delivery, decoder close, or the
   * timeout comes first wins, and the losers close the frame they were handed
   * rather than leaking a `VideoFrame`.
   */
  private awaitH264Frame(ctx: H264Context, ts: number): Promise<VideoFrame | null> {
    return new Promise((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const settle = (frame: VideoFrame | null): void => {
        if (ctx.waiters.get(ts) !== settle) {
          frame?.close();
          return;
        }
        ctx.waiters.delete(ts);
        if (timer !== undefined) clearTimeout(timer);
        resolve(frame);
      };
      ctx.waiters.set(ts, settle);
      timer = setTimeout(() => settle(null), H264_FRAME_TIMEOUT_MS);
    });
  }

  /**
   * Route one decoded frame to the rect that asked for it.
   *
   * Chunks go in one at a time in protocol order and this path has no
   * B-frames, so output comes back in the same order. That means anything
   * still outstanding with an OLDER timestamp than the frame just delivered
   * is never coming (a corrupt slice the decoder discarded, say), and holding
   * those waiters open would stall every update queued behind them until they
   * timed out. Release them as soon as a newer frame proves them lost.
   *
   * Matching is on the exact timestamp, which WebCodecs requires the decoder
   * to carry through from the chunk. A frame nobody is waiting for is dropped
   * rather than given to the next waiter in line: that frame's rect already
   * gave up on it, and handing it over would paint frame N where frame N+1
   * belongs and leave every frame after it one behind for good.
   */
  private deliverH264Frame(ctx: H264Context, frame: VideoFrame): void {
    const ts = frame.timestamp;
    for (const key of Array.from(ctx.waiters.keys())) {
      if (key < ts) ctx.waiters.get(key)?.(null);
    }
    const waiter = ctx.waiters.get(ts);
    if (waiter) waiter(frame);
    else frame.close();
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
      waiters: new Map(),
    };
    try {
      ctx.decoder = new VideoDecoder({
        output: (frame: VideoFrame) => {
          if (this.disposed || generation !== this.generation) {
            frame.close();
            return;
          }
          // Not uploaded here: `decodeH264` uploads it at the rect's own
          // position in the ordered apply loop.
          this.deliverH264Frame(ctx, frame);
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
    // Anything still waiting on this decoder is waiting on a frame that will
    // never be produced now. Settle those waiters so the apply loop moves on
    // instead of holding every later update behind a decoder that is gone.
    for (const settle of Array.from(ctx.waiters.values())) settle(null);
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

  /**
   * Show only this framebuffer subrect (one monitor of a multi-head
   * desktop), in framebuffer pixels. Everything downstream, scaling, edge
   * pan, pointer mapping, the cursor sprite, works against the subrect, so
   * callers do not change. The pan resets: a position held over from another
   * monitor points at nothing.
   */
  setViewRect(x: number, y: number, w: number, h: number): void {
    this.viewX = x;
    this.viewY = y;
    this.viewW = w;
    this.viewH = h;
    this.panX = 0;
    this.panY = 0;
    this.markDirty();
  }

  /** Back to the whole desktop. */
  clearViewRect(): void {
    if (this.viewW === 0 && this.viewH === 0) return;
    this.viewW = 0;
    this.viewH = 0;
    this.panX = 0;
    this.panY = 0;
    this.markDirty();
  }

  /**
   * The framebuffer subrect actually on display, clamped inside the current
   * framebuffer: the stored rect may predate a resize by a beat (the layout
   * event follows the resize event), and a stale rect must degrade to a
   * clipped view, never to sampling outside the texture.
   */
  private viewRect(): { x: number; y: number; w: number; h: number } {
    const fw = Math.max(1, this.fbWidth);
    const fh = Math.max(1, this.fbHeight);
    if (this.viewW <= 0 || this.viewH <= 0) return { x: 0, y: 0, w: fw, h: fh };
    const x = Math.max(0, Math.min(this.viewX, fw - 1));
    const y = Math.max(0, Math.min(this.viewY, fh - 1));
    return {
      x,
      y,
      w: Math.max(1, Math.min(this.viewW, fw - x)),
      h: Math.max(1, Math.min(this.viewH, fh - y)),
    };
  }

  /**
   * How far the view can still be panned in each direction, in device
   * pixels: 0 means the content fits and there is nothing to reach.
   *
   * Used by the edge auto-scroll to know whether moving toward an edge can
   * actually reveal anything, so it stays inert at "fit" and only comes
   * alive when part of the desktop is genuinely off-screen.
   */
  panRoom(): { left: number; right: number; up: number; down: number } {
    const t = this.contentTransform();
    const v = this.viewRect();
    const maxX = Math.max(0, (v.w * t.scaleX - this.canvas.width) / 2);
    const maxY = Math.max(0, (v.h * t.scaleY - this.canvas.height) / 2);
    return {
      left: maxX + this.panX,
      right: maxX - this.panX,
      up: maxY + this.panY,
      down: maxY - this.panY,
    };
  }

  panBy(dxDevice: number, dyDevice: number): void {
    this.panX += dxDevice;
    this.panY += dyDevice;
    this.clampPan();
    this.markDirty();
  }

  private clampPan(): void {
    const t = this.contentTransform();
    const v = this.viewRect();
    const cw = v.w * t.scaleX;
    const ch = v.h * t.scaleY;
    const W = this.canvas.width;
    const H = this.canvas.height;
    const maxX = Math.max(0, (cw - W) / 2);
    const maxY = Math.max(0, (ch - H) / 2);
    this.panX = Math.min(maxX, Math.max(-maxX, this.panX));
    this.panY = Math.min(maxY, Math.max(-maxY, this.panY));
  }

  /**
   * Content placement in device pixels for the current mode/zoom/pan.
   * `x`/`y` locate the top-left of the VISIBLE subrect (the whole desktop
   * unless a monitor view is set).
   */
  contentTransform(): ContentTransform {
    const W = this.canvas.width;
    const H = this.canvas.height;
    const v = this.viewRect();
    let sx: number;
    let sy: number;
    switch (this.mode) {
      case "fit":
        sx = W / v.w;
        sy = H / v.h;
        break;
      case "aspect-fit": {
        const s = Math.min(W / v.w, H / v.h);
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
    const cw = v.w * sx;
    const ch = v.h * sy;
    return {
      x: (W - cw) / 2 - this.panX,
      y: (H - ch) / 2 - this.panY,
      scaleX: sx,
      scaleY: sy,
    };
  }

  /**
   * Map a point in canvas CSS pixels to framebuffer pixels.
   * `rect` is the canvas getBoundingClientRect; clamped to the visible
   * subrect, so with a monitor view up the pointer cannot leave that monitor.
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
    const v = this.viewRect();
    const fx = v.x + (dx - t.x) / t.scaleX;
    const fy = v.y + (dy - t.y) / t.scaleY;
    return {
      x: Math.max(v.x, Math.min(v.x + v.w - 1, Math.round(fx))),
      y: Math.max(v.y, Math.min(v.y + v.h - 1, Math.round(fy))),
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
    const v = this.viewRect();
    const fw = Math.max(1, this.fbWidth);
    const fh = Math.max(1, this.fbHeight);
    gl.useProgram(this.program);

    // main frame quad: only the visible subrect of the texture (the whole
    // texture unless a monitor view is set)
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
    gl.uniform1f(this.uLevels, this.grayLevels);
    gl.uniform1f(this.uTexAlpha, 0); // framebuffer is opaque
    gl.uniform4f(this.uUv, v.x / fw, v.y / fh, v.w / fw, v.h / fh);
    gl.uniform4f(
      this.uRect,
      t.x / W,
      t.y / H,
      (v.w * t.scaleX) / W,
      (v.h * t.scaleY) / H,
    );
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

    // cursor sprite, scaled with content
    if (this.cursorEnabled && this.cursorHasShape && this.cursorW > 0) {
      // With a monitor view up, a pointer parked on ANOTHER monitor must not
      // float over the letterbox: clip the sprite to the content area.
      // (scissor origin is bottom-left, hence the H flip)
      const cropped = v.w < fw || v.h < fh;
      if (cropped) {
        gl.enable(gl.SCISSOR_TEST);
        gl.scissor(
          Math.max(0, Math.floor(t.x)),
          Math.max(0, Math.floor(H - (t.y + v.h * t.scaleY))),
          Math.max(0, Math.ceil(v.w * t.scaleX)),
          Math.max(0, Math.ceil(v.h * t.scaleY)),
        );
      }
      const cx = t.x + (this.cursorX - v.x - this.cursorHotX) * t.scaleX;
      const cy = t.y + (this.cursorY - v.y - this.cursorHotY) * t.scaleY;
      gl.bindTexture(gl.TEXTURE_2D, this.cursorTex);
      gl.uniform1f(this.uLevels, 0);
      gl.uniform1f(this.uTexAlpha, 1); // masked sprite, keep transparency
      gl.uniform4f(this.uUv, 0, 0, 1, 1);
      gl.uniform4f(
        this.uRect,
        cx / W,
        cy / H,
        (this.cursorW * t.scaleX) / W,
        (this.cursorH * t.scaleY) / H,
      );
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      if (cropped) gl.disable(gl.SCISSOR_TEST);
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

  /**
   * `rowCount` evenly spaced full-width RGBA rows of the framebuffer at full
   * resolution, packed row-major. For the monitor-seam detector: a seam is
   * one column wide, so the preview path's downscale would smear it away,
   * while reading the whole frame costs tens of MB for rows it never looks
   * at. Row reads only sync the pipeline once, so this stays cheap enough
   * to run on demand.
   */
  readSampledRowsRGBA(rowCount: number): { width: number; rows: number; pixels: Uint8Array } | null {
    if (this.fbWidth === 0 || this.fbHeight === 0 || rowCount <= 0) return null;
    const gl = this.gl;
    const w = this.fbWidth;
    const n = Math.min(rowCount, this.fbHeight);
    const pixels = new Uint8Array(w * n * 4);
    gl.bindFramebuffer(gl.FRAMEBUFFER, this.readFbo);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.frameTex, 0);
    for (let i = 0; i < n; i++) {
      const y = Math.floor(((i + 0.5) / n) * this.fbHeight);
      gl.readPixels(0, y, w, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixels.subarray(i * w * 4, (i + 1) * w * 4));
    }
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    return { width: w, rows: n, pixels };
  }

  /**
   * Downscaled, top-down RGBA8888 snapshot of the framebuffer, for the
   * Library live preview poll (every 500 ms while previews are enabled).
   * Same row order as `readFramebufferRGBA`, though it takes a different
   * route to it; see the `u_uv` comment below. A full-res
   * `readFramebufferRGBA` is 33 MB at 4K and runs on the main thread; instead,
   * render `frameTex` through the existing quad program into a small FBO
   * (preserving aspect, capped to `maxWidth`) and read pixels from that,
   * which is a few hundred KB regardless of desktop size.
   *
   * Use `readFramebufferRGBA` instead where full resolution actually matters
   * (e.g. disconnect thumbnail capture).
   */
  readPreviewRGBA(maxWidth: number): { width: number; height: number; pixels: Uint8Array } | null {
    if (this.fbWidth === 0 || this.fbHeight === 0) return null;
    const gl = this.gl;
    const width = Math.max(1, Math.min(maxWidth, this.fbWidth));
    const height = Math.max(1, Math.round((this.fbHeight * width) / this.fbWidth));

    if (this.previewW !== width || this.previewH !== height) {
      this.previewW = width;
      this.previewH = height;
      gl.bindTexture(gl.TEXTURE_2D, this.previewTex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    }

    gl.bindFramebuffer(gl.FRAMEBUFFER, this.readFbo);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.previewTex, 0);
    gl.viewport(0, 0, width, height);
    gl.useProgram(this.program);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.frameTex);
    gl.uniform1f(this.uLevels, 0); // preview is always full color, independent of the on-screen B&W mode
    gl.uniform1f(this.uTexAlpha, 0);
    // The whole desktop, whatever monitor view is up, sampled BOTTOM-UP.
    //
    // Unlike `readFramebufferRGBA`, which reads the texture with no draw and
    // therefore gets rows back in upload order, this path renders first. The
    // vertex shader maps the top of the source to NDC +1 (`1.0 - p.y * 2.0`),
    // which is correct on screen but is the LAST row `readPixels` returns,
    // because GL reads from the lower-left. Sampling v from 1 down to 0
    // cancels that on the way in, so the pixels come out top-down like every
    // other path. The alternative, reversing rows after the read, costs a
    // full copy for something the sampler does for nothing.
    gl.uniform4f(this.uUv, 0, 1, 1, -1);
    gl.uniform4f(this.uRect, 0, 0, 1, 1);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

    const pixels = new Uint8Array(width * height * 4);
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
    // Drop the queue before the decoders: an update still holding views into
    // its IPC buffer keeps that buffer alive for as long as the queue does,
    // and nothing left in it will ever be applied now.
    this.pending.length = 0;
    this.pendingBytes = 0;
    this.closeAllH264();
    const gl = this.gl;
    gl.deleteTexture(this.frameTex);
    gl.deleteTexture(this.scratchTex);
    gl.deleteTexture(this.cursorTex);
    gl.deleteTexture(this.previewTex);
    gl.deleteFramebuffer(this.readFbo);
    gl.deleteProgram(this.program);
  }
}
