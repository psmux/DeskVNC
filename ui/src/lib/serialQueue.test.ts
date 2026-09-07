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

  // The first task in each test below is deliberately slow: it occupies the
  // drain, so everything queued after it is still pending and can be seen to
  // coalesce or not. That is the real situation too, one packet in flight on a
  // slow IPC round trip while the compositor keeps producing more.

  it("lets a newer keyed task replace the keyed task still waiting", async () => {
    const done: string[] = [];
    const queue = createSerialQueue();
    queue(async () => {
      await wait(20);
      done.push("blocker");
    });
    queue(async () => {
      done.push("motion:1");
    }, "motion");
    queue(async () => {
      done.push("motion:2");
    }, "motion");
    queue(async () => {
      done.push("motion:3");
    }, "motion");
    await wait(60);
    // Two positions the user already left never went anywhere, which is the
    // whole point: only the newest one is worth sending.
    expect(done).toEqual(["blocker", "motion:3"]);
  });

  it("queues the replacement at the back, behind everything produced before it", async () => {
    // The replacement is a new task, produced after the press and the release
    // already waiting, so it goes out after them. It used to take over the
    // stale task's slot instead, ahead of both, and on a slow IPC round trip
    // that put the NEXT click's motion on the wire before THIS click's press:
    // the remote pointer went to the new place, clicked at the old one, and
    // sat there until the next motion.
    const done: string[] = [];
    const queue = createSerialQueue();
    queue(async () => {
      await wait(20);
      done.push("blocker");
    });
    queue(async () => {
      done.push("press");
    });
    queue(async () => {
      done.push("motion:1");
    }, "motion");
    queue(async () => {
      done.push("release");
    });
    queue(async () => {
      done.push("motion:2");
    }, "motion");
    await wait(60);
    expect(done).toEqual(["blocker", "press", "release", "motion:2"]);
  });

  it("never coalesces unkeyed tasks, however alike they are", async () => {
    // Presses and keystrokes carry no key, so three identical ones are three
    // separate events and all three have to land.
    const done: string[] = [];
    const queue = createSerialQueue();
    queue(async () => {
      await wait(20);
      done.push("blocker");
    });
    queue(async () => {
      done.push("key");
    });
    queue(async () => {
      done.push("key");
    });
    queue(async () => {
      done.push("key");
    });
    await wait(60);
    expect(done).toEqual(["blocker", "key", "key", "key"]);
  });

  it("carries on after a keyed task rejects, and the key is not left stuck", async () => {
    const done: string[] = [];
    const queue = createSerialQueue();
    queue(async () => {
      await wait(20);
      done.push("blocker");
    });
    queue(() => Promise.reject(new Error("session went away")), "motion");
    queue(async () => {
      done.push("after");
    });
    await wait(60);
    expect(done).toEqual(["blocker", "after"]);

    // A slot that rejected must not leave the key claimed by a task that will
    // never run, or motion would stop reaching the wire for the rest of the
    // session.
    queue(async () => {
      done.push("motion:later");
    }, "motion");
    await wait(30);
    expect(done).toEqual(["blocker", "after", "motion:later"]);
  });

  it("stays bounded when keyed tasks are produced faster than they drain", async () => {
    // The failure this whole mechanism exists for. Production is one packet
    // per animation frame; the drain is one IPC round trip. Once that round
    // trip passes the frame interval the old queue grew for as long as the
    // motion lasted, and everything queued behind it, keystrokes included,
    // waited out the whole backlog.
    let ran = 0;
    const queue = createSerialQueue();
    queue(async () => {
      await wait(30);
      ran++;
    });
    for (let i = 0; i < 500; i++) {
      queue(async () => {
        ran++;
      }, "motion");
    }
    await wait(80);
    // The one in flight, and the single survivor of the 500 behind it.
    expect(ran).toBe(2);
  });
});
