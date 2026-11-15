/**
 * The quick connect field on Your computers: one line that takes a name, an
 * address, `host:port`, a `vnc://` or `rdp://` link, a Boundary computer ID,
 * or a help code, and works out what to do with it.
 *
 * Plain rules only, so they are tested without a screen. The screen asks
 * Rust what answers at the address (`identify`) and then uses
 * `chooseService` to connect or to ask.
 */
import type { FoundComputer, Host, Protocol } from "../api/contract";
import { parsePhoneTarget } from "./address";
import { CODE_DIGITS, isInvitation } from "./code";

export type QuickInput =
  | { kind: "empty" }
  /** A help code or a `boundary1:` invitation: Help someone takes it. */
  | { kind: "help"; text: string }
  /** A computer already on the list. */
  | { kind: "saved"; host: Host }
  /** The input named its protocol, so there is nothing to work out. */
  | { kind: "direct"; protocol: Protocol; address: string; port: number; username: string | null }
  /** Ask what answers there. `port` is null when none was typed. */
  | { kind: "identify"; address: string; port: number | null; username: string | null }
  | { kind: "error"; error: string };

/** The address with a Boundary machine ID in front taken off. */
export function bareAddress(address: string): string {
  return address.replace(/^[0-9a-f]{64}@/i, "").toLowerCase();
}

function isHelpCode(text: string): boolean {
  return /^[\d\s-]+$/.test(text) && text.replace(/\D/g, "").length === CODE_DIGITS;
}

/** The most recently used first, so an address saved twice opens the one in use. */
function newest(list: Host[]): Host | null {
  return [...list].sort((a, b) => (b.lastConnectedAt ?? 0) - (a.lastConnectedAt ?? 0))[0] ?? null;
}

export function readQuickInput(input: string, hosts: Host[]): QuickInput {
  const text = input.trim();
  if (text === "") return { kind: "empty" };
  if (isHelpCode(text) || isInvitation(text)) return { kind: "help", text };

  const byName = hosts.filter((h) => h.name.trim().toLowerCase() === text.toLowerCase());
  if (byName.length > 0) return { kind: "saved", host: newest(byName)! };

  const parsed = parsePhoneTarget(text);
  if (!parsed.ok) return { kind: "error", error: parsed.error };
  const t = parsed.target;
  // The phone parser presets a protocol from a typed port (3389 reads as
  // Remote Desktop, anything else as VNC). Here only a scheme or a machine
  // ID counts as naming one; a typed port is a port to ask.
  const named = /^[a-z]+:\/\//i.test(text) || t.protocol === "boundary" ? t.protocol : null;

  const where = bareAddress(t.address);
  const matches = hosts.filter(
    (h) =>
      bareAddress(h.address) === where &&
      (!t.explicitPort || h.port === t.port) &&
      (named === null || h.protocol === named),
  );
  if (matches.length > 0) return { kind: "saved", host: newest(matches)! };

  if (named) {
    return { kind: "direct", protocol: named, address: t.address, port: t.port, username: t.username };
  }
  return { kind: "identify", address: t.address, port: t.explicitPort ? t.port : null, username: t.username };
}

const PROTOCOL_RANK: Record<Protocol, number> = { rdp: 0, vnc: 1, boundary: 2 };

/**
 * The order the pick sheet lists services in. Remote Desktop first on a
 * Windows PC, since that is the one built for it; screen sharing first
 * anywhere else. A Boundary computer last, then by port.
 */
export function orderServices(items: FoundComputer[]): FoundComputer[] {
  const windows = items.some((f) => f.os === "windows");
  const rank = (p: Protocol): number => {
    if (p === "boundary") return 2;
    if (windows) return PROTOCOL_RANK[p];
    return p === "vnc" ? 0 : 1;
  };
  return [...items].sort((a, b) => rank(a.protocol) - rank(b.protocol) || a.port - b.port);
}

/** Where the choice made for a machine is remembered: its bare address. */
export function choiceKey(address: string): string {
  return bareAddress(address);
}

/** How a choice is written down: `rdp:3389`. */
export function choiceValue(item: FoundComputer): string {
  return `${item.protocol}:${item.port}`;
}

export type ServiceChoice =
  | { kind: "none" }
  | { kind: "connect"; item: FoundComputer }
  | { kind: "pick"; items: FoundComputer[] };

/**
 * What to do with what answered: nothing, the one service, the one picked
 * last time at this address, or ask.
 */
export function chooseService(items: FoundComputer[], remembered: Record<string, string>): ServiceChoice {
  if (items.length === 0) return { kind: "none" };
  if (items.length === 1) return { kind: "connect", item: items[0] };
  const pick = items.find((f) => remembered[choiceKey(f.address)] === choiceValue(f));
  if (pick) return { kind: "connect", item: pick };
  return { kind: "pick", items: orderServices(items) };
}
