/**
 * Timing marks for the keystroke-to-pixel trace.
 *
 * Off unless the app was started with `DVV_TRACE_PROTOCOL=1`, in which case
 * every mark is stamped with epoch milliseconds and batched to Rust a few
 * times a second, where it lands in the same log as the wire trace. With the
 * trace off a mark costs one boolean test.
 */
import { safeInvoke } from "../lib/tauri";

interface Mark {
  label: string;
  at: number;
  n: number;
}

let enabled = false;
let asked = false;
let marks: Mark[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;

export async function initTrace(): Promise<void> {
  if (asked) return;
  asked = true;
  enabled = await safeInvoke<boolean>("trace_enabled", undefined, false);
}

export function traceMark(label: string, n = 0): void {
  if (!enabled) return;
  marks.push({ label, at: performance.timeOrigin + performance.now(), n });
  if (flushTimer === null) flushTimer = setTimeout(flush, 250);
}

function flush(): void {
  flushTimer = null;
  const batch = marks;
  marks = [];
  if (batch.length === 0) return;
  void safeInvoke("trace_marks", { marks: batch }, null);
}
