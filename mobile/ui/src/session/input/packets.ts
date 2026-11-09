/**
 * Input bodies for `api.sessionInput`, in the desktop `send_input` layout
 * (src-tauri/FRAME_FORMAT.md, "Input events"). Little endian, no padding:
 *
 *   pointer      [u8 0][u16 x][u16 y][u16 mask]          7 bytes
 *   key          [u8 1][u8 down][u32 keysym][u32 keycode] 10 bytes
 *   release all  [u8 2]                                    1 byte
 *
 * `InputSender` batches events into one body per animation frame, keeps
 * pointer moves down to the newest one per frame, and numbers every body with
 * the per session `x-input-seq` counter, which starts at 1.
 */

export const KIND_POINTER = 0;
export const KIND_KEY = 1;
export const KIND_RELEASE_ALL = 2;

/** RFB button mask bits. */
export const BUTTON = {
  left: 1,
  middle: 2,
  right: 4,
  wheelUp: 8,
  wheelDown: 16,
  wheelLeft: 32,
  wheelRight: 64,
} as const;

const clamp16 = (n: number): number => Math.max(0, Math.min(0xffff, Math.round(n)));

export function encodePointer(x: number, y: number, mask: number): Uint8Array {
  const out = new Uint8Array(7);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, KIND_POINTER);
  dv.setUint16(1, clamp16(x), true);
  dv.setUint16(3, clamp16(y), true);
  dv.setUint16(5, mask & 0xffff, true);
  return out;
}

export function encodeKey(down: boolean, keysym: number, keycode: number): Uint8Array {
  const out = new Uint8Array(10);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, KIND_KEY);
  dv.setUint8(1, down ? 1 : 0);
  dv.setUint32(2, keysym >>> 0, true);
  dv.setUint32(6, keycode >>> 0, true);
  return out;
}

export function encodeReleaseAll(): Uint8Array {
  return new Uint8Array([KIND_RELEASE_ALL]);
}

export function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export interface SenderDeps {
  send(seq: number, body: Uint8Array): void;
  /** Schedules one flush. Defaults to requestAnimationFrame. */
  schedule?(cb: () => void): void;
}

/**
 * One per session. Events keep their order; consecutive pointer moves with
 * the same button mask collapse into the newest, so dragging a finger costs
 * at most one pointer event per frame however fast touchmove fires.
 */
export class InputSender {
  private queue: Uint8Array[] = [];
  /** Index in `queue` of a move that a newer move may replace, or -1. */
  private lastMove = -1;
  private lastMask = 0;
  private scheduled = false;
  private seq = 1;
  private readonly schedule: (cb: () => void) => void;

  constructor(private readonly deps: SenderDeps) {
    this.schedule =
      deps.schedule ?? ((cb) => (typeof requestAnimationFrame === "function" ? requestAnimationFrame(() => cb()) : setTimeout(cb, 16)));
  }

  /** The seq the next body will carry. */
  nextSeq(): number {
    return this.seq;
  }

  pointer(x: number, y: number, mask: number): void {
    const ev = encodePointer(x, y, mask);
    if (mask !== this.lastMask) {
      // A button change is never replaced by a later move.
      this.queue.push(ev);
      this.lastMask = mask;
      this.lastMove = -1;
    } else if (this.lastMove >= 0) {
      this.queue[this.lastMove] = ev;
    } else {
      this.queue.push(ev);
      this.lastMove = this.queue.length - 1;
    }
    this.kick();
  }

  key(down: boolean, keysym: number, keycode: number): void {
    this.queue.push(encodeKey(down, keysym, keycode));
    this.lastMove = -1;
    this.kick();
  }

  releaseAll(): void {
    this.queue.push(encodeReleaseAll());
    this.lastMove = -1;
    this.lastMask = 0;
    this.flush();
  }

  /** Send everything queued now, as one body. */
  flush(): void {
    this.scheduled = false;
    if (this.queue.length === 0) return;
    const body = concat(this.queue);
    this.queue = [];
    this.lastMove = -1;
    this.deps.send(this.seq++, body);
  }

  private kick(): void {
    if (this.scheduled) return;
    this.scheduled = true;
    this.schedule(() => {
      if (this.scheduled) this.flush();
    });
  }
}
