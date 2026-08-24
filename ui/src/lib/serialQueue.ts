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
 */
export function createSerialQueue(): (task: () => Promise<unknown>) => void {
  let tail: Promise<unknown> = Promise.resolve();
  return (task) => {
    // The catch is on the LINK, not the task: one rejected packet must not
    // break the chain for every packet queued after it.
    tail = tail.then(task, task);
  };
}
