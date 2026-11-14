/**
 * What a copy button says after it was pressed.
 *
 * `null` is the resting state. A press that reached the clipboard says so for
 * a moment, and one that did not says that instead, because a button that
 * looks the same either way leaves the person pasting nothing and finding out
 * from the other end (issue #41).
 */
export type CopyOutcome = null | { ok: boolean };

/** How long the answer stays on the button. A failure stays a little longer. */
export function copyOutcomeMs(ok: boolean): number {
  return ok ? 1500 : 4000;
}

export function copyButtonLabel(outcome: CopyOutcome, idle: string): string {
  if (outcome === null) return idle;
  return outcome.ok ? "Copied" : "Could not copy";
}

/** The hint shown next to a failed copy, so the text can still be taken. */
export function copyFailedHint(mac: boolean): string {
  return mac
    ? "Could not reach the clipboard. Select the text and press Command C."
    : "Could not reach the clipboard. Select the text and press Ctrl C.";
}
