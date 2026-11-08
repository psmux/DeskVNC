/**
 * H.264 as WebKitGTK's decoder takes it.
 *
 * Every server sends H.264 as Annex B: each NAL unit after a start code, the
 * parameter sets in band before each keyframe. WebCodecs says a decoder
 * configured without a `description` takes exactly that. WebView2's and
 * Safari's do. WebKitGTK's does not: on Ubuntu 26.04 (WebKitGTK 2.52) it
 * answered the first keyframe of every Boundary session with an
 * EncodingError, on an AMD card (vah264dec) and an NVIDIA one (nvh264dec)
 * alike, and the same stream decoded once it went in the other form WebCodecs
 * knows: each NAL unit after its length, with the parameter sets handed over
 * as an avcC record when the decoder is configured. These turn the one into
 * the other.
 */

/** NAL unit types this file cares about. */
const NAL_SPS = 7;
const NAL_PPS = 8;

/** The NAL units of an Annex B buffer, start codes removed. */
export function annexBUnits(data: Uint8Array): Uint8Array[] {
  const units: Uint8Array[] = [];
  let start = -1;
  let i = 0;
  while (i + 2 < data.length) {
    if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1) {
      if (start >= 0) units.push(trimZeros(data, start, i));
      i += 3;
      start = i;
    } else {
      i++;
    }
  }
  if (start >= 0 && start < data.length) units.push(data.subarray(start));
  return units.filter((u) => u.length > 0);
}

/** A unit ends before the zero that a four byte start code puts in front of the next. */
function trimZeros(data: Uint8Array, from: number, to: number): Uint8Array {
  let end = to;
  while (end > from && data[end - 1] === 0) end--;
  return data.subarray(from, end);
}

/** The same units, each after its length in four bytes, big endian. */
export function toLengthPrefixed(units: Uint8Array[]): Uint8Array {
  let size = 0;
  for (const u of units) size += 4 + u.length;
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let at = 0;
  for (const u of units) {
    view.setUint32(at, u.length);
    out.set(u, at + 4);
    at += 4 + u.length;
  }
  return out;
}

/**
 * What a decoder needs to be configured for a stream in length prefixed
 * form: its codec string and avcC record, read from the parameter sets in
 * front of a keyframe. `null` when the keyframe carries none.
 */
export function avcConfig(units: Uint8Array[]): { codec: string; description: Uint8Array } | null {
  const sps = units.filter((u) => (u[0] & 0x1f) === NAL_SPS && u.length >= 4);
  const pps = units.filter((u) => (u[0] & 0x1f) === NAL_PPS);
  if (sps.length === 0 || pps.length === 0) return null;
  const [profile, compat, level] = [sps[0][1], sps[0][2], sps[0][3]];
  let size = 7;
  for (const u of [...sps, ...pps]) size += 2 + u.length;
  const record = new Uint8Array(size);
  const view = new DataView(record.buffer);
  record.set([1, profile, compat, level, 0xff, 0xe0 | sps.length]);
  let at = 6;
  for (const u of sps) {
    view.setUint16(at, u.length);
    record.set(u, at + 2);
    at += 2 + u.length;
  }
  record[at++] = pps.length;
  for (const u of pps) {
    view.setUint16(at, u.length);
    record.set(u, at + 2);
    at += 2 + u.length;
  }
  const hex = (n: number) => n.toString(16).padStart(2, "0").toUpperCase();
  return { codec: `avc1.${hex(profile)}${hex(compat)}${hex(level)}`, description: record };
}
