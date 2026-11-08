import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_LAG, STEP, VideoPacer, type LearnedLag } from "./videoPacer";

const picture = (ts: number) => ({ timestamp: ts, close: vi.fn() });

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

function pacer(area = 100) {
  const learned: LearnedLag = { chunks: 0 };
  const shown: number[] = [];
  const p = new VideoPacer(learned, (pic: { timestamp: number }) => shown.push(pic.timestamp / STEP), area);
  return { p, learned, shown };
}

describe("VideoPacer", () => {
  it("waits for a chunk's own picture while the decoder has held nothing back", async () => {
    const { p, learned, shown } = pacer();
    const ts = p.feed();
    let settled = false;
    void p.settle(500).then(() => (settled = true));
    await vi.advanceTimersByTimeAsync(10);
    expect(settled).toBe(false);
    p.output(picture(ts));
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(true);
    expect(shown).toEqual([1]);
    expect(learned.chunks).toBe(0);
  });

  it("learns how far behind the decoder runs from the first late picture", async () => {
    const { p, learned, shown } = pacer();
    p.feed();
    p.feed();
    p.feed();
    let settled = false;
    void p.settle(500).then(() => (settled = true));
    p.output(picture(1 * STEP));
    await vi.advanceTimersByTimeAsync(0);
    expect(learned.chunks).toBe(2);
    expect(settled).toBe(true);
    expect(shown).toEqual([1]);
    // The next chunk is owed only the picture two behind it.
    p.feed();
    let next = false;
    void p.settle(500).then(() => (next = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(next).toBe(false);
    p.output(picture(2 * STEP));
    await vi.advanceTimersByTimeAsync(0);
    expect(next).toBe(true);
    expect(shown).toEqual([1, 2]);
  });

  it("caps the lag it believes", () => {
    const { p, learned } = pacer();
    for (let i = 0; i < 40; i++) p.feed();
    p.output(picture(STEP));
    expect(learned.chunks).toBe(MAX_LAG);
  });

  it("gives up after the timeout when nothing comes back", async () => {
    const { p } = pacer();
    p.feed();
    let settled = false;
    void p.settle(500).then(() => (settled = true));
    await vi.advanceTimersByTimeAsync(499);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
  });

  it("drops pictures from chunks fed before something was drawn over them", () => {
    const { p, shown } = pacer();
    p.feed();
    p.feed();
    p.overtaken(10);
    const late = picture(2 * STEP);
    p.output(picture(STEP));
    p.output(late);
    expect(shown).toEqual([]);
    expect(late.close).toHaveBeenCalled();
    // A chunk fed after it is newer than what was drawn, and shows.
    const ts = p.feed();
    p.output(picture(ts));
    expect(shown).toEqual([3]);
  });

  it("is behind while pictures are owed, until they come or the whole area is repainted", () => {
    const { p } = pacer(100);
    expect(p.behind()).toBe(false);
    p.feed();
    p.feed();
    expect(p.behind()).toBe(true);
    p.output(picture(STEP));
    expect(p.behind()).toBe(true);
    p.overtaken(60);
    expect(p.behind()).toBe(true);
    p.overtaken(40);
    expect(p.behind()).toBe(false);
  });

  it("releases a wait when the decoder closes", async () => {
    const { p } = pacer();
    p.feed();
    let settled = false;
    void p.settle(500).then(() => (settled = true));
    p.close();
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(true);
    const pic = picture(STEP);
    p.output(pic);
    expect(pic.close).toHaveBeenCalled();
  });
});
