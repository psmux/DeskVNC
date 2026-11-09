import { describe, expect, it } from "vitest";
import { friendlyError, qualityLevel, stepOf } from "../status";
import { wireQuality } from "../useRemoteSession";

describe("status words", () => {
  it("maps session states to the four friendly steps", () => {
    expect(stepOf({ state: "connecting" })).toBe(0);
    expect(stepOf({ state: "negotiating" })).toBe(1);
    expect(stepOf({ state: "authenticating", method: "VncAuth" })).toBe(2);
    expect(stepOf({ state: "connected" })).toBe(3);
  });

  it("colours the badge from round trip time and frame rate", () => {
    expect(qualityLevel({ rtt_ms: 30, fps: 30, throughput_bps: 1 })).toBe("good");
    expect(qualityLevel({ rtt_ms: 150, fps: 30, throughput_bps: 1 })).toBe("fair");
    expect(qualityLevel({ rtt_ms: 400, fps: 30, throughput_bps: 1 })).toBe("poor");
    expect(qualityLevel({ rtt_ms: 90, fps: 2, throughput_bps: 1 })).toBe("fair");
    expect(qualityLevel({ rtt_ms: 30, fps: 0, throughput_bps: 1 })).toBe("good");
  });

  it("explains errors in plain words", () => {
    expect(friendlyError("Connection refused (os error 61)").title).toBe("We could not reach the computer");
    expect(friendlyError("Authentication failed").title).toBe("That sign in did not work");
    expect(friendlyError("weird thing").detail).toBe("weird thing");
  });

  it("asks for still pictures when the phone has no video decoder", () => {
    expect(wireQuality("auto", false)).toBe("quality");
    expect(wireQuality("auto", true)).toBe("auto");
    expect(wireQuality("speed", false)).toBe("speed");
  });
});
