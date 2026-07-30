/**
 * Binary framing for the framebuffer Channel (little-endian throughout).
 * Byte-exact contract: src-tauri/FRAME_FORMAT.md, encoder src-tauri/src/framing.rs.
 *
 * Every message starts with a 1-byte msg_type; unknown types are ignored.
 *
 * msg_type = 1, framebuffer update:
 *   header:   u8 msg_type(=1) | u8 reserved | u16 rect_count
 *             u16 damage_x | u16 damage_y | u16 damage_w | u16 damage_h
 *   per rect: u16 x | u16 y | u16 w | u16 h | u8 format | u8 reserved
 *             u32 payload_len | payload
 *
 *   format: 0 = RGBA raw | 1 = JPEG | 2 = CopyRect (payload u16 src_x,u16 src_y)
 *           3 = H264 (payload u32 flags, u32 context_id, u32 ctx_flags,
 *                     then the Annex-B bytes, which may be empty, meaning
 *                     "control message: apply the flags, decode nothing")
 *             flags     bit0 ResetContext, bit1 ResetAllContexts (server's own)
 *             ctx_flags bit0 = rebuild this context's decoder first
 *                       bit1 = the data contains an IDR (can start a decoder)
 *
 * msg_type = 2, cursor shape:
 *   u8 msg_type(=2) | u8 reserved | u16 w | u16 h | u16 hotspot_x | u16 hotspot_y
 *   | w*h*4 bytes RGBA8888        (a 0x0 cursor means "hide the local cursor")
 *
 * The parser hands out subarray views into the incoming buffer, zero copies.
 */

export const MSG_FRAMEBUFFER = 1;
export const MSG_CURSOR = 2;

export const enum RectFormat {
  Rgba = 0,
  Jpeg = 1,
  CopyRect = 2,
  H264 = 3,
}

/** H.264 `flags`: drop this rect's decoder context. */
export const H264_RESET_CONTEXT = 1;
/** H.264 `flags`: drop every decoder context. */
export const H264_RESET_ALL_CONTEXTS = 2;

export interface WireRect {
  x: number;
  y: number;
  w: number;
  h: number;
  format: number;
  /**
   * View into the message buffer. Empty for CopyRect (use srcX/srcY); for
   * H264 this is the Annex-B data only, with the 12-byte header stripped, * and legitimately empty for a control message.
   */
  payload: Uint8Array;
  srcX: number;
  srcY: number;
  // H264 only; always set by the parser, optional so non-H264 producers
  // (the no-backend demo path) can keep constructing plain rects.
  /** Server flags (ResetContext / ResetAllContexts). */
  h264Flags?: number;
  /** Decoder context slot (0..63), keyed server-side by rect geometry. */
  h264Context?: number;
  /** Rebuild this context's decoder before decoding. */
  h264Reset?: boolean;
  /** The payload contains an IDR, so it can start a decoder. */
  h264Key?: boolean;
}

export interface FrameMessage {
  damageX: number;
  damageY: number;
  damageW: number;
  damageH: number;
  rects: WireRect[];
}

export interface CursorMessage {
  width: number;
  height: number;
  hotspotX: number;
  hotspotY: number;
  /** RGBA8888, exactly width*height*4 bytes. Empty when width/height are 0. */
  pixels: Uint8Array;
}

const HEADER_LEN = 12;
const RECT_HEADER_LEN = 14;
/** `[u32 flags][u32 context_id][u32 ctx_flags]` ahead of the Annex-B data. */
const H264_HEADER_LEN = 12;
const CURSOR_HEADER_LEN = 10;

/** The msg_type byte of a channel message, or -1 if the buffer is empty. */
export function messageType(buffer: ArrayBuffer): number {
  return buffer.byteLength > 0 ? new DataView(buffer).getUint8(0) : -1;
}

/**
 * Parse a cursor-shape message (msg_type 2). Returns null when the message is
 * not a cursor or the pixel payload is truncated.
 */
export function parseCursorMessage(buffer: ArrayBuffer): CursorMessage | null {
  if (buffer.byteLength < CURSOR_HEADER_LEN) return null;
  const dv = new DataView(buffer);
  if (dv.getUint8(0) !== MSG_CURSOR) return null;
  const width = dv.getUint16(2, true);
  const height = dv.getUint16(4, true);
  const hotspotX = dv.getUint16(6, true);
  const hotspotY = dv.getUint16(8, true);
  const expected = width * height * 4;
  if (buffer.byteLength < CURSOR_HEADER_LEN + expected) return null;
  return {
    width,
    height,
    hotspotX,
    hotspotY,
    pixels: expected > 0 ? new Uint8Array(buffer, CURSOR_HEADER_LEN, expected) : EMPTY,
  };
}

/** Parse one channel message. Returns null for non-framebuffer or malformed messages. */
export function parseFrameMessage(buffer: ArrayBuffer): FrameMessage | null {
  if (buffer.byteLength < HEADER_LEN) return null;
  const dv = new DataView(buffer);
  if (dv.getUint8(0) !== MSG_FRAMEBUFFER) return null;
  const rectCount = dv.getUint16(2, true);
  const msg: FrameMessage = {
    damageX: dv.getUint16(4, true),
    damageY: dv.getUint16(6, true),
    damageW: dv.getUint16(8, true),
    damageH: dv.getUint16(10, true),
    rects: [],
  };
  let off = HEADER_LEN;
  for (let i = 0; i < rectCount; i++) {
    if (off + RECT_HEADER_LEN > buffer.byteLength) return msg; // truncated: keep what we have
    const x = dv.getUint16(off, true);
    const y = dv.getUint16(off + 2, true);
    const w = dv.getUint16(off + 4, true);
    const h = dv.getUint16(off + 6, true);
    const format = dv.getUint8(off + 8);
    const payloadLen = dv.getUint32(off + 10, true);
    off += RECT_HEADER_LEN;
    if (off + payloadLen > buffer.byteLength) return msg;
    let srcX = 0;
    let srcY = 0;
    let h264Flags = 0;
    let h264Context = 0;
    let h264Reset = false;
    let h264Key = false;
    let payload: Uint8Array;
    if (format === RectFormat.CopyRect) {
      if (payloadLen >= 4) {
        srcX = dv.getUint16(off, true);
        srcY = dv.getUint16(off + 2, true);
      }
      payload = EMPTY;
    } else if (format === RectFormat.H264) {
      if (payloadLen < H264_HEADER_LEN) {
        payload = EMPTY; // malformed: drop the rect's data, keep parsing
      } else {
        h264Flags = dv.getUint32(off, true);
        h264Context = dv.getUint32(off + 4, true);
        const ctxFlags = dv.getUint32(off + 8, true);
        h264Reset = (ctxFlags & 1) !== 0;
        h264Key = (ctxFlags & 2) !== 0;
        const dataLen = payloadLen - H264_HEADER_LEN;
        payload = dataLen > 0 ? new Uint8Array(buffer, off + H264_HEADER_LEN, dataLen) : EMPTY;
      }
    } else {
      payload = new Uint8Array(buffer, off, payloadLen);
    }
    msg.rects.push({
      x,
      y,
      w,
      h,
      format,
      payload,
      srcX,
      srcY,
      h264Flags,
      h264Context,
      h264Reset,
      h264Key,
    });
    off += payloadLen;
  }
  return msg;
}

const EMPTY = new Uint8Array(0);
