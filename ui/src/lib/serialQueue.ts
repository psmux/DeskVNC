/**
 * Run async tasks strictly one after another, in the order they were queued.
 *
 * The reason this exists is input. Every `invoke` is an independent IPC
 * request, and the shell may handle two of them in either order. For a stream
 * of pointer motion that is harmless. For a press and its release it is not:
 * reversed, the remote desktop is left holding a button the user has already
 * let go of, and nothing puts it right until some later event happens to carry
 * a mask without that bit.
 *
 * Pairs milliseconds apart are the normal case, not an exotic one: a trackpad
 * tap, a synthesised context click, and a dictation tool's paste chord all
 * produce one. So ordering belongs to the transport, not to each caller.
 *
 * ## Why there is a coalesce key
 *
 * Strict ordering alone is not enough, because the producer and the drain are
 * not coupled. Pointer motion is produced once per animation frame, so about
 * every 16 ms. It drains at one packet per IPC round trip. While the remote
 * screen is busy the webview's event loop is congested and that round trip
 * grows past 16 ms, at which point the queue grows for as long as the motion
 * lasts. Every packet is still delivered, faithfully and far too late, so the
 * remote pointer walks the scenic route through positions the user left
 * seconds ago. Keys queued behind that trail inherit the whole delay, which is
 * why keyboard control degrades along with the mouse.
 *
 * A task queued with a coalesce key REPLACES the pending task holding the same
 * key rather than queueing behind it. Stale pointer positions are worthless
 * the moment a newer one exists, so dropping them costs nothing and bounds
 * the queue by construction: at most one in flight and one pending per key.
 * Anything queued without a key keeps the old strict behaviour, so presses,
 * releases, wheel clicks and keystrokes are untouched.
 *
 * The replacement goes to the BACK of the queue; it does not inherit the
 * stale task's slot. It used to, and that let a motion overtake a click: with
 * motion(A) pending and a slow round trip in flight, press(A) and release(A)
 * queued behind it, and then the pointer moved on and motion(B) arrived. Put
 * in motion(A)'s slot, motion(B) went out ahead of the press, so the wire saw
 * the pointer go to B, then a click at A, and the remote cursor snapped back
 * to A after the user had left it. Every task is queued at the moment it was
 * produced, so the order it was produced in is the order of the queue, and a
 * replacement is a new task, produced after everything already waiting.
 */
export function createSerialQueue(): (task: () => Promise<unknown>, coalesceKey?: string) => void {
  type Entry = { task: () => Promise<unknown>; key?: string };
  const pending: Entry[] = [];
  let draining = false;

  const drain = async (): Promise<void> => {
    draining = true;
    // Re-checked every iteration: a task queued while we await is picked up here
    // rather than starting a second drain.
    while (pending.length > 0) {
      const entry = pending.shift() as Entry;
      try {
        await entry.task();
      } catch {
        // The catch is on the LINK, not the task: one rejected packet must not
        // break the chain for every packet queued after it.
      }
    }
    draining = false;
  };

  return (task, coalesceKey) => {
    if (coalesceKey !== undefined) {
      const stale = pending.findIndex((e) => e.key === coalesceKey);
      // Newest wins. The stale one is removed and the new one appended, not
      // written into the stale one's slot: anything queued between the two
      // was produced between them and has to stay between them.
      if (stale >= 0) pending.splice(stale, 1);
    }
    pending.push({ task, key: coalesceKey });
    if (!draining) void drain();
  };
}
