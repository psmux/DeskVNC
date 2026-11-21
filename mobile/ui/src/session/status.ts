/**
 * Plain words for what the session is doing, and the colour of the
 * connection badge. Kept apart from the components so they can be tested.
 */
import type { BoundaryRoute, SessionState, SessionStats } from "../api/contract";

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

/** How a Boundary session travels, in the words the connection sheet shows. */
export function routeWords(route: BoundaryRoute): string {
  return route === "direct" ? "Direct" : "Through a relay";
}

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

type ErrorKind = "setting" | "encryption" | "untrusted" | "unreachable" | "sign-in" | "identity" | "code" | "dropped" | "other";

/** Sorts a raw error from Rust or the server. The order of the tests matters. */
function errorKind(raw: string): ErrorKind {
  const m = raw.toLowerCase();
  // The server answered but offers no way in this app can use (TigerVNC with
  // only TLSVnc, or a method DeskVNC lacks). The sentence names VncAuth and
  // encryption, so it has to be caught before the sign in and identity rules.
  if (/securitytypes|does not support/.test(m)) return "setting";
  // These two come first: both sentences mention a name or password that was
  // never sent, and the sign in rule below would claim it was refused.
  if (/key exchange/.test(m)) return "encryption";
  if (/not trusted/.test(m)) return "untrusted";
  // RDP puts this in front of the server's own reason, which can say the
  // computer "refused the sign in" and would otherwise read as unreachable.
  if (/^authentication failed/.test(m)) return "sign-in";
  if (/refused|unreachable|no route|timed out|timeout|resolve|not found|dns|host is down/.test(m)) return "unreachable";
  if (/auth|password|credential|denied|login|logon/.test(m)) return "sign-in";
  if (/certificate|fingerprint|tls|trust|identity/.test(m)) return "identity";
  if (/expired|invitation|code/.test(m)) return "code";
  if (/closed|reset|ended|eof|broken pipe/.test(m)) return "dropped";
  return "other";
}

/**
 * True when the computer turned down the name or password, as opposed to a
 * network failure or a key the person did not trust. After this a saved
 * password is stale, and sending it again only adds to the server's count
 * of failed sign ins.
 */
export function isSignInRefusal(raw: string | null): boolean {
  if (raw === null || errorKind(raw) !== "sign-in") return false;
  // A Mac that took the password but would not let the account share its
  // screen: the password is right, so it stays.
  return !/accepted the password/i.test(raw);
}

/**
 * Turns a raw error from Rust or the server into a sentence a person can act
 * on. Unknown messages are kept, behind a friendly lead in.
 */
export function friendlyError(raw: string): { title: string; detail: string } {
  switch (errorKind(raw)) {
    case "setting":
      return { title: "The computer's VNC server needs a setting changed", detail: raw };
    case "encryption":
      return {
        title: "The computer could not set up encryption",
        detail: "It ended the connection before asking for a name or password, so nothing was sent. Its VNC server may have no encryption key set up.",
      };
    case "untrusted":
      return { title: "You did not trust this computer", detail: "Nothing was sent to it. Connect again to look at its fingerprint once more." };
    case "unreachable":
      return {
        title: "We could not reach the computer",
        detail: "Check that it is switched on and that this phone is on the internet, then try again.",
      };
    case "sign-in":
      return { title: "That sign in did not work", detail: "The name or password was not accepted. Try again and check the spelling." };
    case "identity":
      return { title: "The computer's identity did not check out", detail: "For your safety we stopped. Try again, or ask the person who looks after it." };
    case "code":
      return { title: "That help code has run out", detail: "Ask for a new code and connect again." };
    case "dropped":
      return { title: "The connection dropped", detail: "This happens when the network changes. Try again to pick up where you left off." };
    case "other":
      return { title: "Something went wrong", detail: raw };
  }
}
