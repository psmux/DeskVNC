/**
 * Plain words for what the session is doing, and the colour of the
 * connection badge. Kept apart from the components so they can be tested.
 */
import type { SessionState, SessionStats } from "../api/contract";

export type Step = 0 | 1 | 2 | 3;

export const STEP_WORDS: Record<Step, string> = {
  0: "Finding the computer",
  1: "Checking it is really yours",
  2: "Signing in",
  3: "Almost there",
};

/** Which of the four friendly steps a session state belongs to. */
export function stepOf(s: SessionState): Step {
  switch (s.state) {
    case "idle":
    case "resolving":
    case "connecting":
      return 0;
    case "negotiating":
      return 1;
    case "authenticating":
      return 2;
    case "connected":
      return 3;
    case "reconnecting":
      return 0;
    case "disconnected":
      return 0;
  }
}

/** The words under the picture: like STEP_WORDS, but a Boundary session waiting for the other person says so. */
export function stepWords(s: SessionState): string {
  if (s.state === "authenticating" && s.method === "approval") return "Waiting for them to say yes";
  if (s.state === "reconnecting") return "Trying again";
  return STEP_WORDS[stepOf(s)];
}

export type Level = "good" | "fair" | "poor";

/** Green, amber or red from round trip time and frame rate. */
export function qualityLevel(stats: SessionStats | null): Level {
  if (!stats) return "good";
  const rtt = stats.rtt_ms;
  let level: Level = rtt > 250 ? "poor" : rtt > 110 ? "fair" : "good";
  // A still screen sends few frames, so a low rate alone means nothing. A
  // low rate on a link that is already slowish means the picture is lagging.
  if (stats.fps > 0 && stats.fps < 5 && rtt > 80) level = level === "good" ? "fair" : "poor";
  return level;
}

export const LEVEL_WORDS: Record<Level, string> = {
  good: "Good connection",
  fair: "A little slow",
  poor: "Slow connection",
};

export function formatSpeed(bps: number): string {
  const bits = bps * 8;
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mbit/s`;
  if (bits >= 1e3) return `${Math.round(bits / 1e3)} kbit/s`;
  return `${Math.round(bits)} bit/s`;
}

/**
 * Why a session that was showing the desktop stopped.
 *
 * * `paused`: this phone put it down, because DeskVNC sat in the background
 *   past the grace period (`lifecycle::REASON` on the Rust side).
 * * `remote`: the other side ended it on purpose. DeskVNC Support pressing
 *   End closes cleanly, which the Boundary driver reports as "Support session
 *   ended"; a computer that ends it with a reason says "That computer ended
 *   the session: ..."; RDP says "the server ended the session".
 * * `lost`: anything else, a link that failed.
 */
export type EndKind = "paused" | "remote" | "lost";

/** The phrase the Rust side sends when the background ended a session. */
export const BACKGROUND_REASON = "in the background for more than";

export function endKind(reason: string | null, wasHidden: boolean): EndKind {
  const m = (reason ?? "").toLowerCase();
  if (m.includes(BACKGROUND_REASON)) return "paused";
  // Leaving the app also ends a Boundary session cleanly, so while hidden a
  // clean end is the phone's own doing, not the other side's.
  if (wasHidden) return "paused";
  if (/ended the session|session ended|closed by peer|stopped sharing/.test(m)) return "remote";
  return "lost";
}

/**
 * A second reason for the same end. The background reason arrives after the
 * driver's own one, so it wins; otherwise the first reason stands.
 */
export function mergeEnd(prev: EndKind | null, next: EndKind): EndKind {
  if (prev === null || next === "paused") return next;
  return prev;
}

/** What the card over the stopped desktop says. */
export function endWords(kind: EndKind, reason: string | null): { title: string; lead: string } {
  switch (kind) {
    case "paused":
      return {
        title: "The connection was paused",
        lead: "This happens when DeskVNC is in the background for a while. Reconnect to pick up where you left off.",
      };
    case "remote": {
      const why = /ended the session:\s*(.+)$/i.exec(reason ?? "")?.[1]?.trim();
      return {
        title: "They ended the session",
        lead: why ? `The other side closed the connection: ${why}` : "The other side closed the connection.",
      };
    }
    case "lost":
      return {
        title: "The connection dropped",
        lead: "This happens when the network changes. Reconnect to pick up where you left off.",
      };
  }
}

/**
 * Turns a raw error from Rust or the server into a sentence a person can act
 * on. Unknown messages are kept, behind a friendly lead in.
 */
export function friendlyError(raw: string): { title: string; detail: string } {
  const m = raw.toLowerCase();
  if (/refused|unreachable|no route|timed out|timeout|resolve|not found|dns|host is down/.test(m)) {
    return {
      title: "We could not reach the computer",
      detail: "Check that it is switched on and that this phone is on the internet, then try again.",
    };
  }
  if (/auth|password|credential|denied|login|logon/.test(m)) {
    return { title: "That sign in did not work", detail: "The name or password was not accepted. Try again and check the spelling." };
  }
  if (/certificate|fingerprint|tls|trust/.test(m)) {
    return { title: "The computer's identity did not check out", detail: "For your safety we stopped. Try again, or ask the person who looks after it." };
  }
  if (/expired|invitation|code/.test(m)) {
    return { title: "That help code has run out", detail: "Ask for a new code and connect again." };
  }
  if (/closed|reset|ended|eof|broken pipe/.test(m)) {
    return { title: "The connection dropped", detail: "This happens when the network changes. Try again to pick up where you left off." };
  }
  return { title: "Something went wrong", detail: raw };
}
