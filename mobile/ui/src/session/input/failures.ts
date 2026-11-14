/**
 * Watches `sessionInput` results. Input is fire and forget, so a broken path
 * used to fail without a trace: every tap and key was dropped and nothing
 * said so. The first error is logged once; when calls keep failing the
 * screen is told, at most once per `repeatMs` while the failures go on.
 * One success clears the streak.
 */

export interface InputFailureOptions {
  /** Called when input keeps failing, with the latest error text. */
  onPersistent(message: string): void;
  /** Consecutive failures before the screen hears about it. */
  threshold?: number;
  /** Quiet time between two reports of the same streak. */
  repeatMs?: number;
  log?: (message: string) => void;
  now?: () => number;
}

export function errorText(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return String(err);
}

export class InputFailures {
  private streak = 0;
  private logged = false;
  private reportedAt: number | null = null;
  private readonly threshold: number;
  private readonly repeatMs: number;
  private readonly log: (message: string) => void;
  private readonly now: () => number;

  constructor(private readonly opts: InputFailureOptions) {
    this.threshold = opts.threshold ?? 3;
    this.repeatMs = opts.repeatMs ?? 15_000;
    this.log = opts.log ?? ((m) => console.warn(m));
    this.now = opts.now ?? (() => Date.now());
  }

  ok(): void {
    this.streak = 0;
    this.reportedAt = null;
  }

  fail(err: unknown): void {
    const message = errorText(err);
    if (!this.logged) {
      this.logged = true;
      this.log(`session input failed: ${message}`);
    }
    this.streak++;
    if (this.streak < this.threshold) return;
    const t = this.now();
    if (this.reportedAt !== null && t - this.reportedAt < this.repeatMs) return;
    this.reportedAt = t;
    this.opts.onPersistent(message);
  }
}
