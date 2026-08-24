import { describe, expect, it } from "vitest";
import { createSerialQueue } from "./serialQueue";

/** A promise that resolves after `ms` of real time. */
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe("createSerialQueue", () => {
  it("keeps a slow task ahead of a fast one queued behind it", async () => {
    // The whole point: a press that takes longer to reach the shell than the
    // release queued after it must still land first.
    const done: string[] = [];
    const queue = createSerialQueue();
    queue(async () => {
      await wait(20);
      done.push("press");
    });
    queue(async () => {
      done.push("release");
    });
    await wait(60);
    expect(done).toEqual(["press", "release"]);
  });

  it("starts a task only once the one before it has settled", async () => {
    const events: string[] = [];
    const queue = createSerialQueue();
    queue(async () => {
      events.push("a:start");
      await wait(10);
      events.push("a:end");
    });
    queue(async () => {
      events.push("b:start");
    });
    await wait(50);
    expect(events).toEqual(["a:start", "a:end", "b:start"]);
  });

  it("carries on after a task rejects, so one bad packet is not the end", async () => {
    const done: string[] = [];
    const queue = createSerialQueue();
    queue(() => Promise.reject(new Error("session went away")));
    queue(async () => {
      done.push("after");
    });
    await wait(30);
    expect(done).toEqual(["after"]);
  });
});
