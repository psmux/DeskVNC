import { describe, expect, it } from "vitest";
import { annexBUnits, avcConfig, toLengthPrefixed } from "./avc";

const sps = [0x67, 0x42, 0xc0, 0x1f, 0xda];
const pps = [0x68, 0xce, 0x3c, 0x80];
const idr = [0x65, 0x88, 0x84, 0x21];
// Four and three byte start codes, as encoders mix them.
const key = new Uint8Array([0, 0, 0, 1, ...sps, 0, 0, 0, 1, ...pps, 0, 0, 1, ...idr]);

describe("avc", () => {
  it("splits Annex B on both kinds of start code", () => {
    expect(annexBUnits(key).map((u) => Array.from(u))).toEqual([sps, pps, idr]);
  });

  it("puts each unit after its length", () => {
    const out = toLengthPrefixed(annexBUnits(key));
    expect(Array.from(out)).toEqual([0, 0, 0, 5, ...sps, 0, 0, 0, 4, ...pps, 0, 0, 0, 4, ...idr]);
  });

  it("builds the codec string and avcC record from the parameter sets", () => {
    const config = avcConfig(annexBUnits(key));
    expect(config?.codec).toBe("avc1.42C01F");
    expect(Array.from(config!.description)).toEqual([1, 0x42, 0xc0, 0x1f, 0xff, 0xe1, 0, 5, ...sps, 1, 0, 4, ...pps]);
  });

  it("has no configuration for a picture without parameter sets", () => {
    expect(avcConfig(annexBUnits(new Uint8Array([0, 0, 1, ...idr])))).toBeNull();
  });
});
