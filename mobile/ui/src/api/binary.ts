/**
 * Binary bodies for `invoke`. iOS posts an ArrayBuffer over Tauri's custom
 * protocol as raw bytes. Android has no custom protocol IPC, so Tauri sends
 * the call as JSON and turns the ArrayBuffer into an array of numbers, one
 * JSON number per byte. Rust accepts raw bytes, that array and base64 text;
 * large bodies go as base64 on Android because it is a third the size.
 */

/** Copy the bytes so a view over a larger buffer never sends its neighbours. */
export function exactBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? (bytes.buffer as ArrayBuffer)
    : (bytes.slice().buffer as ArrayBuffer);
}

/** Standard base64 with padding, the form Rust's base64 STANDARD decodes. */
export function toBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  let text = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    text += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(text);
}

export function isAndroid(userAgent: string = typeof navigator === "undefined" ? "" : navigator.userAgent): boolean {
  return /\bAndroid\b/i.test(userAgent);
}

/** A large binary body: raw where the custom protocol carries it, base64 on Android. */
export function largeBody(bytes: Uint8Array, android: boolean = isAndroid()): ArrayBuffer | string {
  return android ? toBase64(bytes) : exactBuffer(bytes);
}
