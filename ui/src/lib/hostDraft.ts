/**
 * Decisions the host editor makes, as pure functions.
 *
 * They live here rather than inside `HostDialog.tsx` so they can be tested
 * without rendering: the vitest `include` pattern is `src/**` + `.test.ts`,
 * so nothing in a `.tsx` file is collected at all, and these are exactly the
 * rules that are easy to get subtly wrong.
 */

import { DEFAULT_PORT, hostProtocol, type HostProfile, type ProtocolKind } from "./types";

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
 * The `save_password` fields a VNC host's editor writes.
 *
 * The editor used to have nowhere to put a user name for VNC, so a Mac with
 * Screen Sharing (Apple's security type wants a user name AND a password)
 * could never be satisfied from the keychain: the password typed here was
 * stored, the prompt still came up for the user name, and it would not let
 * the person through without the password typed again (issue #9).
 *
 * A user name goes in `vencryptUser`, the field `connect_session` reads as
 * the VNC user name. A password goes in both password fields. The shell
 * prefers `vencryptPass` over `vncPassword`, so writing only the second
 * would leave an older answer to a prompt shadowing the one typed here.
 *
 * Only non-empty fields are sent: an empty box means "keep what is stored",
 * exactly as for the RDP and SSH fields.
 */
export function vncCredentialPayload(user: string, password: string): Record<string, string> {
  const payload: Record<string, string> = {};
  if (user.trim()) payload.vencryptUser = user.trim();
  if (password) {
    payload.vncPassword = password;
    payload.vencryptPass = password;
  }
  return payload;
}
