/**
 * A Mac with someone else at its screen, before the session starts.
 *
 * macOS Screen Sharing can offer two sessions when another person is logged
 * in at the Mac: their screen, which asks them to accept first, or a session
 * of the viewer's own. The shell sends `mac-session-choice` when the host is
 * set to ask, and `mac-session-waiting` while the person at the Mac decides.
 * The copy lives here, apart from React, so it can be tested. Each sentence
 * is whole in the catalog, with the name as a value, because word order and
 * the possessive differ between languages.
 */
import { currentLanguage, t } from "../i18n";

/** What the session overlay shows for a Mac with someone at it. */
export type MacSessionPrompt =
  | { phase: "choose"; consoleUser: string; canShare: boolean; canSeparate: boolean }
  | { phase: "waiting"; consoleUser: string };

/** The per host default, as the host record stores it. Null is ask. */
export type MacSessionPref = "ask" | "share" | "separate";

/** The choices the host editor offers, in the language in use. */
export function macSessionOptions(): { value: MacSessionPref; label: string }[] {
  return [
    { value: "ask", label: t("Ask each time") },
    { value: "share", label: t("Ask to share their screen") },
    { value: "separate", label: t("Log in to a separate session") },
  ];
}

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
  return name ? name : t("The person at the Mac");
}

export function macChoiceTitle(consoleUser: string): string {
  const name = consoleUser.trim();
  return name ? t("{name} is using this Mac", { name }) : t("Someone is using this Mac");
}

/** The first paragraph of the choice: what asking to share does. */
export function macShareText(consoleUser: string): string {
  const name = consoleUser.trim();
  return name
    ? t("You can ask {name} to share their screen. A request comes up on the Mac, and you see their screen once they accept it.", { name })
    : t("You can ask the person at the Mac to share their screen. A request comes up on the Mac, and you see their screen once they accept it.");
}

export function macWaitingText(consoleUser: string): string {
  const name = consoleUser.trim();
  return name
    ? t("Waiting for {name} to accept the request to share their screen.", { name })
    : t("Waiting for the person at the Mac to accept the request to share their screen.");
}

export function macShareWithdrawn(consoleUser: string): string {
  const name = consoleUser.trim();
  if (!name) return t("The request to share the Mac user's screen was withdrawn.");
  // English spells the possessive by the name's last letter, which no
  // catalog entry can do, so English keeps its own rule.
  if (currentLanguage() === "en") {
    return `The request to share ${name.endsWith("s") ? `${name}'` : `${name}'s`} screen was withdrawn.`;
  }
  return t("The request to share {name}'s screen was withdrawn.", { name });
}
