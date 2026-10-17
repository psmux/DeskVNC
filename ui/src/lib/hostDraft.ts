/**
 * Decisions the host editor makes, as pure functions.
 *
 * They live here rather than inside `HostDialog.tsx` so they can be tested
 * without rendering: the vitest `include` pattern is `src/**` + `.test.ts`,
 * so nothing in a `.tsx` file is collected at all, and these are exactly the
 * rules that are easy to get subtly wrong.
 */

import {
  DEFAULT_PORT,
  hostProtocol,
  type HostProfile,
  type OsHint,
  type ProtocolKind,
  type StoredCredentials,
} from "./types";

/**
 * What the port becomes when the user switches protocol.
 *
 * > Switching protocol changes the port only when the port is still the
 * > outgoing protocol's default and the user has not deliberately set it.
 *
 * So a VNC host saved on 5900 moves to 3389 when switched, and one saved on
 * 5901 keeps 5901, which is what somebody who deliberately chose 5901
 * expects.
 */
export function portOnProtocolChange(
  from: ProtocolKind,
  to: ProtocolKind,
  port: number,
  portTouched: boolean,
): number {
  if (portTouched) return port;
  if (port === DEFAULT_PORT[from]) return DEFAULT_PORT[to];
  return port;
}

/**
 * Whether an existing host's port counts as deliberately set.
 *
 * Seeded from the saved row rather than tracked from scratch: a host already
 * on a non-default port was put there on purpose, and switching its protocol
 * must not move it. This is the rule most likely to be got wrong, which is
 * why it is one line with a test rather than a condition inside a handler.
 */
export function portWasTouched(host: HostProfile | null | undefined): boolean {
  if (!host) return false;
  return host.port !== DEFAULT_PORT[hostProtocol(host)];
}

/**
 * Whether a VNC host's security type signs in with an account name.
 *
 * RFB is mostly password only, but not always. Apple's Screen Sharing auth
 * (type 30) wants a macOS account and its password, and so do VeNCrypt's
 * `*Plain` subtypes and RA2's subtype 1. A pinned VeNCrypt or RA2 may still
 * end up asking for a password alone, which is why a blank user name keeps
 * meaning "ask me if the server wants one" rather than being required.
 *
 * Auto counts when the host is a Mac, because Auto against macOS negotiates
 * Apple auth: it is the strongest type a Mac offers that this app speaks.
 * Without this there was no way to save the account name for a Mac at all,
 * only to type it into the prompt on every connect (issue #9).
 */
export function vncTakesUsername(securityPref: string | null, osHint: OsHint): boolean {
  switch (securityPref ?? "auto") {
    case "apple-dh":
    case "vencrypt-x509":
    case "ra2":
      return true;
    case "auto":
      return osHint === "macos";
    default:
      return false;
  }
}

/**
 * The `save_password` payload for a VNC host's editor, or `null` when there
 * is nothing to write.
 *
 * Only non-empty fields are sent, the same rule as the RDP and SSH saves: an
 * empty box means "keep what is stored", and the Rust side merges.
 *
 * When the security type signs in with a user name, the password goes in the
 * `vencrypt*` pair beside it. That is the slot the connect path reads first,
 * and the one a post-connect save writes for these methods, so a password
 * typed here replaces the one a prompt saved earlier instead of sitting
 * behind it unused.
 */
export function vncCredentialPayload(
  user: string,
  password: string,
  takesUsername: boolean,
): StoredCredentials | null {
  const payload: StoredCredentials = {};
  if (takesUsername) {
    if (user.trim()) payload.vencryptUser = user.trim();
    if (password) payload.vencryptPass = password;
  } else if (password) {
    payload.vncPassword = password;
  }
  return Object.keys(payload).length > 0 ? payload : null;
}
