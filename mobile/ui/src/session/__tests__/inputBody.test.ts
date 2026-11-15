import { describe, expect, it } from "vitest";
import { exactBuffer, isAndroid, largeBody, toBase64 } from "../../api/binary";
import { InputFailures } from "../input/failures";

/** What Tauri's postMessage path does to a payload on Android (process-ipc-message-fn.js). */
function androidPayload(payload: unknown): unknown {
  return JSON.parse(
    JSON.stringify(payload, (_k, val) => {
      if (val instanceof Uint8Array) return Array.from(val);
      if (val instanceof ArrayBuffer) return Array.from(new Uint8Array(val));
      return val;
    }),
  );
}

describe("binary invoke bodies", () => {
  it("sends only the viewed bytes", () => {
    const big = new Uint8Array([9, 9, 0, 1, 0, 1, 0, 0, 0, 9]);
    const view = big.subarray(2, 9);
    expect(Array.from(new Uint8Array(exactBuffer(view)))).toEqual([0, 1, 0, 1, 0, 0, 0]);
  });

  it("an input body reaches Rust on Android as an array of numbers", () => {
    const body = exactBuffer(new Uint8Array([0, 1, 0, 1, 0, 0, 0]));
    expect(androidPayload(body)).toEqual([0, 1, 0, 1, 0, 0, 0]);
  });

  it("encodes standard padded base64 across chunk boundaries", () => {
    expect(toBase64(new Uint8Array([0, 1, 0, 1, 0, 0, 0]))).toBe("AAEAAQAAAA==");
    const big = new Uint8Array(70_000).map((_, i) => i & 0xff);
    const back = Uint8Array.from(atob(toBase64(big)), (c) => c.charCodeAt(0));
    expect(back).toEqual(big);
  });

  it("sends large bodies as base64 only on Android", () => {
    const rgba = new Uint8Array([1, 2, 3, 4]);
    expect(largeBody(rgba, true)).toBe("AQIDBA==");
    expect(largeBody(rgba, false)).toBeInstanceOf(ArrayBuffer);
  });

  it("recognises Android webviews", () => {
    expect(isAndroid("Mozilla/5.0 (Linux; Android 14; sdk_gphone64_x86_64) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36")).toBe(true);
    expect(isAndroid("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15")).toBe(false);
  });
});

describe("InputFailures", () => {
  const bench = (threshold = 3, repeatMs = 1000) => {
    const logs: string[] = [];
    const reports: string[] = [];
    let t = 0;
    const f = new InputFailures({
      threshold,
      repeatMs,
      onPersistent: (m) => reports.push(m),
      log: (m) => logs.push(m),
      now: () => t,
    });
    return { f, logs, reports, advance: (ms: number) => (t += ms) };
  };

  it("logs the first error once", () => {
    const { f, logs } = bench();
    f.fail("session_input expects a raw binary body");
    f.fail(new Error("again"));
    expect(logs).toEqual(["session input failed: session_input expects a raw binary body"]);
  });

  it("reports only when failures keep coming", () => {
    const { f, reports } = bench();
    f.fail("a");
    f.fail("b");
    expect(reports).toEqual([]);
    f.fail("c");
    expect(reports).toEqual(["c"]);
  });

  it("a success clears the streak", () => {
    const { f, reports } = bench();
    f.fail("a");
    f.fail("b");
    f.ok();
    f.fail("c");
    f.fail("d");
    expect(reports).toEqual([]);
  });

  it("repeats the report no more than once per interval", () => {
    const { f, reports, advance } = bench(1, 1000);
    f.fail("a");
    advance(500);
    f.fail("b");
    expect(reports).toEqual(["a"]);
    advance(600);
    f.fail("c");
    expect(reports).toEqual(["a", "c"]);
  });
});
