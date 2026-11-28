/**
 * A Mac with someone else at its screen, before the session starts.
 *
 * macOS Screen Sharing can offer two sessions when another person is logged
 * in at the Mac: their screen, which asks them to accept first, or a session
 * of the viewer's own. The shell sends `mac-session-choice` when the host is
 * set to ask, and `mac-session-waiting` while the person at the Mac decides.
 * The copy lives here, apart from React, so it can be tested.
 */

/** What the session overlay shows for a Mac with someone at it. */
export type MacSessionPrompt =
  | { phase: "choose"; consoleUser: string; canShare: boolean; canSeparate: boolean }
  | { phase: "waiting"; consoleUser: string };

/** The per host default, as the host record stores it. Null is ask. */
export type MacSessionPref = "ask" | "share" | "separate";

export const MAC_SESSION_OPTIONS: { value: MacSessionPref; label: string }[] = [
  { value: "ask", label: "Ask each time" },
  { value: "share", label: "Ask to share their screen" },
  { value: "separate", label: "Log in to a separate session" },
];

/** Read a stored value. Anything this build does not know means ask. */
export function parseMacSessionPref(value: string | null | undefined): MacSessionPref {
  return value === "share" || value === "separate" ? value : "ask";
}

/** The stored form: ask is the absence of a choice. */
export function storeMacSessionPref(value: MacSessionPref): string | null {
  return value === "ask" ? null : value;
}

/**
 * The person at the Mac, by the account name the Mac sent. An empty name
 * should not reach here (nobody is asked then), but the copy still reads.
 */
export function macUserLabel(consoleUser: string): string {
  const name = consoleUser.trim();
  return name ? name : "The person at the Mac";
}

export function macChoiceTitle(consoleUser: string): string {
  const name = consoleUser.trim();
  return name ? `${name} is using this Mac` : "Someone is using this Mac";
}

export function macWaitingText(consoleUser: string): string {
  return `Waiting for ${macUserLabel(consoleUser)} to accept the request to share their screen.`;
}

export function macShareWithdrawn(consoleUser: string): string {
  return `The request to share ${possessive(consoleUser)} screen was withdrawn.`;
}

function possessive(consoleUser: string): string {
  const name = consoleUser.trim();
  if (!name) return "the Mac user's";
  return name.endsWith("s") ? `${name}'` : `${name}'s`;
}
