/**
 * Order of input calls. Rust runs each invoke on its own task, so the fake
 * computer below applies a call when its delay runs out, not when it was
 * made. Letters typed while Gboard composes go out one `session_text` call
 * each, and Enter goes in a `session_input` body after them.
 */
import { describe, expect, it } from "vitest";
import { InputSender, SendLane } from "../input/packets";

const RETURN = 0xff0d;

function computer(delays: number[]) {
  const got: string[] = [];
  let i = 0;
  const later = (apply: () => void): Promise<void> =>
    new Promise((resolve) =>
      setTimeout(() => {
        apply();
        resolve();
      }, delays[i++ % delays.length]),
    );
  return {
    got,
    text: (t: string) => later(() => got.push(t)),
    input: (_seq: number, body: Uint8Array) =>
      later(() => {
        // Key events are [u8 1][u8 down][u32 keysym][u32 keycode].
        const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
        for (let at = 0; at + 10 <= body.length; at += 10) {
          if (dv.getUint8(at) === 1 && dv.getUint8(at + 1) === 1 && dv.getUint32(at + 2, true) === RETURN) got.push("<Return>");
        }
      }),
  };
}

/** Types "line2" then Enter, the way useRemoteSession wires the calls. */
async function typeLine(serial: boolean, delays: number[]): Promise<string> {
  const pc = computer(delays);
  const lane = new SendLane();
  const pending: Promise<void>[] = [];
  const call = (fn: () => Promise<void>): void => {
    pending.push(serial ? lane.run(fn) : fn());
  };
  const flushes: (() => void)[] = [];
  const sender = new InputSender({
    send: (seq, body) => call(() => pc.input(seq, body)),
    schedule: (cb) => flushes.push(cb),
  });
  for (const ch of "line2") {
    sender.flush();
    call(() => pc.text(ch));
  }
  sender.key(true, RETURN, 0x1c);
  sender.key(false, RETURN, 0x1c);
  for (const f of flushes.splice(0)) f();
  await Promise.all(pending);
  return pc.got.join("");
}

describe("input order", () => {
  const delays = [6, 1, 3, 0, 2, 4];

  it("keeps letters and Enter in the order typed", async () => {
    expect(await typeLine(true, delays)).toBe("line2<Return>");
  });

  it("shows why: calls in flight together land out of order", async () => {
    expect(await typeLine(false, delays)).not.toBe("line2<Return>");
  });

  it("keeps going after a call fails", async () => {
    const lane = new SendLane();
    const seen: number[] = [];
    const a = lane.run(async () => {
      seen.push(1);
      throw new Error("no");
    });
    const b = lane.run(async () => {
      seen.push(2);
    });
    await expect(a).rejects.toThrow("no");
    await b;
    expect(seen).toEqual([1, 2]);
  });
});
