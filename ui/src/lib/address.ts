/**
 * One address parser for every place the user types where to connect:
 * QuickConnect, the host dialog, and anything that pastes a `vnc://` link.
 *
 * The forms accepted are the ones other viewers accept, so muscle memory
 * carries over:
 *
 * - `office`              -> office:5900
 * - `office:1`            -> office:5901   (display number, the VNC convention)
 * - `office:5901`         -> office:5901   (>= 100 reads as a literal port)
 * - `office::5901`        -> office:5901   (RealVNC's explicit-port form)
 * - `[fe80::1%en0]:5901`  -> fe80::1%en0:5901
 * - `fe80::1`             -> fe80::1:5900  (no room for a port without brackets)
 * - `vnc://office:5901/`  -> office:5901
 * - `rdp://box`            -> box:3389
 * - `rdp://alice@box`      -> box:3389, user alice
 * - `alice@box`            -> box:3389, user alice
 *
 * A protocol is only ever reported when the input NAMED one. `box:3389` comes
 * back with a null protocol, because the parser's job is to say what was
 * typed and 3389 is a port like any other; who resolves that null, and how,
 * is QuickConnect's decision and not the parser's.
 */

import { DEFAULT_PORT, type ProtocolKind } from "./types";

export const DEFAULT_VNC_PORT = DEFAULT_PORT.vnc;
export const DEFAULT_RDP_PORT = DEFAULT_PORT.rdp;

/**
 * Display numbers stop here: `host:99` is display 99, `host:100` is port 100.
 * The boundary is arbitrary but it is the one every other viewer draws, and no
 * real deployment uses displays that high.
 */
const MAX_DISPLAY_NUMBER = 100;

export interface Endpoint {
  address: string;
  port: number;
  /**
   * False when the port came from {@link DEFAULT_VNC_PORT} rather than from
   * what the user typed. The host dialog needs the difference: typing a bare
   * hostname there must leave a profile's saved port alone.
   */
  explicitPort: boolean;
}

export type AddressResult =
  | { ok: true; endpoint: Endpoint }
  | { ok: false; error: string };

export interface Target extends Endpoint {
  /**
   * The protocol the input NAMED, or null when it said nothing. Null is not
   * "vnc": QuickConnect resolves it against a saved profile first, so
   * `box:3389` still reaches an RDP host saved on that port.
   */
  protocol: ProtocolKind | null;
  /** User name carried in the address (`rdp://alice@box`). Never a password. */
  username: string | null;
}

export type TargetResult =
  | { ok: true; target: Target }
  | { ok: false; error: string };

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIpv4Literal(value: string): boolean {
  return IPV4.test(value) && value.split(".").every((octet) => Number(octet) <= 255);
}

/**
 * Whether `value` is an IPv6 literal.
 *
 * This carries real weight rather than being a nicety: it is what separates
 * `fe80::1` (an address, default port) from `office::5901` (a host and an
 * explicit port). So it has to reject anything whose groups are not hex
 * instead of just counting colons.
 */
export function isIpv6Literal(value: string): boolean {
  const zoned = value.split("%"); // a zone id, as in fe80::1%en0
  if (zoned.length > 2 || (zoned.length === 2 && zoned[1] === "")) return false;
  const bare = zoned[0];
  if (!bare.includes(":")) return false;

  const halves = bare.split("::");
  if (halves.length > 2) return false; // `::` may appear at most once

  const split = (s: string): string[] => (s === "" ? [] : s.split(":"));
  const groups = [...split(halves[0]), ...split(halves[1] ?? "")];

  // A trailing IPv4 form (`::ffff:192.0.2.1`) is legal and fills two groups.
  const last = groups[groups.length - 1];
  const hasIpv4Tail = last !== undefined && last.includes(".");
  if (hasIpv4Tail && !isIpv4Literal(last)) return false;

  const hex = hasIpv4Tail ? groups.slice(0, -1) : groups;
  if (!hex.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;

  // `::` stands for at least one omitted group, so a compressed address can
  // never already carry all eight.
  const slots = groups.length + (hasIpv4Tail ? 1 : 0);
  return halves.length === 2 ? slots < 8 : slots === 8;
}

function endpoint(address: string, digits: string, allowDisplayNumber: boolean): AddressResult {
  if (address === "") return { ok: false, error: "Enter an address before the colon" };
  const typed = Number(digits);
  const port = allowDisplayNumber && typed < MAX_DISPLAY_NUMBER ? DEFAULT_VNC_PORT + typed : typed;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "Port must be between 1 and 65535" };
  }
  return { ok: true, endpoint: { address, port, explicitPort: true } };
}

/** The scheme a URL-ish input names, and the rest of the input after it. */
function readScheme(raw: string): { protocol: ProtocolKind | null; rest: string; url: boolean } {
  if (/^(?:rdps?):\/\//i.test(raw)) {
    return { protocol: "rdp", rest: raw.replace(/^(?:rdps?):\/\//i, ""), url: true };
  }
  if (/^(?:vncs?|rfb):\/\//i.test(raw)) {
    return { protocol: "vnc", rest: raw.replace(/^(?:vncs?|rfb):\/\//i, ""), url: true };
  }
  return { protocol: null, rest: raw, url: false };
}

/**
 * Parse what the user typed, keeping the protocol it named.
 *
 * @param assume the protocol to parse AS when the input names none. The host
 *        dialog passes the draft's protocol, so `box:1` in an RDP host's
 *        address field reads as port 1 rather than as display 1 on 3390.
 *        QuickConnect passes nothing and resolves the null itself.
 *
 * The error strings are written to be shown verbatim next to the field.
 */
export function parseConnectTarget(input: string, assume?: ProtocolKind): TargetResult {
  const trimmed = input.trim();
  if (trimmed === "") return { ok: false, error: "Enter an address" };

  const { protocol: named, rest, url } = readScheme(trimmed);
  let raw = rest;
  let username: string | null = null;
  let protocol = named;

  if (url) {
    // A "connect" link off a wiki page or a chat message arrives as a URL, so
    // accept one rather than making the user edit it down by hand first. Only
    // a real URL gets its path trimmed: doing that unconditionally would turn
    // `192.168.1.20/24` into a silent connect to `192.168.1.20`.
    raw = raw.replace(/[/?#].*$/, "");
  }

  // Userinfo. An RDP scheme CAPTURES it, split at the LAST `@`, so
  // `rdp://alice@corp.example@box` yields user `alice@corp.example` and host
  // `box`. Splitting at the first would mangle a UPN, which is the commonest
  // form a domain user types. The VNC schemes keep discarding userinfo, so
  // nothing about VNC changes: RFB carries no user in the address form.
  const at = raw.lastIndexOf("@");
  if (at >= 0) {
    if (protocol === "vnc") {
      raw = raw.slice(at + 1);
    } else {
      // A bare `user@host` with no scheme means RDP. Nothing regresses: the
      // parser used to reject `@` outright, and a user name in an address bar
      // has no VNC meaning, since VeNCrypt asks at the prompt instead.
      const user = raw.slice(0, at);
      raw = raw.slice(at + 1);
      if (user !== "") username = user;
      protocol = "rdp";
    }
  }

  if (raw === "") return { ok: false, error: "Enter an address" };
  if (/\s/.test(raw)) return { ok: false, error: "An address cannot contain spaces" };
  if (/[/?#@]/.test(raw)) return { ok: false, error: "An address cannot contain / ? # or @" };

  // Display numbers are a VNC convention and do not exist for RDP, so
  // `rdp://box:1` is port 1 and not 3390.
  const resolved = protocol ?? assume ?? null;
  const displayNumbers = resolved !== "rdp";
  const fallbackPort = DEFAULT_PORT[resolved ?? "vnc"];

  const done = (result: AddressResult): TargetResult =>
    result.ok
      ? { ok: true, target: { ...result.endpoint, protocol, username } }
      : result;

  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  if (bracketed) {
    const [, inner, digits] = bracketed;
    if (!isIpv6Literal(inner)) return { ok: false, error: `${inner} is not a valid IPv6 address` };
    // Brackets exist to delimit the address, so a number after them is always
    // a literal port. Reading `[::1]:1` as display 1 would be a nasty surprise.
    if (digits === undefined) {
      return {
        ok: true,
        target: { address: inner, port: fallbackPort, explicitPort: false, protocol, username },
      };
    }
    return done(endpoint(inner, digits, false));
  }
  if (raw.includes("[") || raw.includes("]")) {
    return { ok: false, error: "Write an IPv6 address as [::1] or [::1]:5901" };
  }

  // Before the `host::port` rule below, or `fe80::1` would parse as host
  // `fe80` on port 1.
  //
  // The two forms genuinely collide when a hostname is one to four hex
  // characters: `dc::5901` is both "host dc, port 5901" and a valid literal.
  // The literal wins, because guessing wrong on `fe80::1` breaks something
  // common while `dc:5901`, with one colon, is an unambiguous way to say the
  // other thing.
  if (isIpv6Literal(raw)) {
    return {
      ok: true,
      target: { address: raw, port: fallbackPort, explicitPort: false, protocol, username },
    };
  }

  const explicit = /^(.+?)::(\d+)$/.exec(raw);
  if (explicit) {
    // `1::2::3` reaches here because it is not a valid literal, and reading it
    // as host `1::2` port 3 would be a guess dressed up as an answer. An IPv6
    // address with a port has exactly one spelling and it has brackets.
    if (isIpv6Literal(explicit[1])) {
      return { ok: false, error: "Write an IPv6 address as [::1] or [::1]:5901" };
    }
    return done(endpoint(explicit[1], explicit[2], false));
  }

  const suffixed = /^(.+?):(\d+)$/.exec(raw);
  if (suffixed) return done(endpoint(suffixed[1], suffixed[2], displayNumbers));

  if (raw.startsWith(":")) return { ok: false, error: "Enter an address before the colon" };
  if (raw.includes(":")) return { ok: false, error: "Add a port or display number after the colon" };
  return {
    ok: true,
    target: { address: raw, port: fallbackPort, explicitPort: false, protocol, username },
  };
}

/**
 * The original two-field parser, kept as a thin wrapper so nothing importing
 * it has to change in the same commit.
 */
export function parseConnectAddress(input: string): AddressResult {
  const result = parseConnectTarget(input);
  if (!result.ok) return result;
  const { address, port, explicitPort } = result.target;
  return { ok: true, endpoint: { address, port, explicitPort } };
}

/**
 * Render a target the way it should be typed back in.
 *
 * "The way it should be typed back in" is the whole contract: QuickConnect
 * stores these strings and re-parses them later, so anything that does not
 * survive the round trip connects somewhere the user never went. That is why
 * a low VNC port uses the explicit form: `office:42` would read back as
 * display 42, which is port 5942. And it is why an RDP target always carries
 * its scheme, even on the default port: a bare `box` reads back as VNC.
 */
export function formatTarget(
  protocol: ProtocolKind,
  address: string,
  port: number,
  username?: string | null,
): string {
  const host = isIpv6Literal(address) ? `[${address}]` : address;
  if (protocol === "rdp") {
    const user = username ? `${username}@` : "";
    return port === DEFAULT_RDP_PORT
      ? `rdp://${user}${host}`
      : `rdp://${user}${host}:${port}`;
  }
  if (isIpv6Literal(address)) {
    return port === DEFAULT_VNC_PORT ? host : `${host}:${port}`;
  }
  if (port === DEFAULT_VNC_PORT) return address;
  return port < MAX_DISPLAY_NUMBER ? `${address}::${port}` : `${address}:${port}`;
}

/** The VNC-only form, kept for existing importers. */
export function formatEndpoint(address: string, port: number): string {
  return formatTarget("vnc", address, port);
}

/**
 * The protocol to offer when the input named none and no saved profile
 * matched.
 *
 * Port 3389 presets RDP, and the chip shows it before Enter so the user can
 * flip it in one click. The hard rule this exists for: ambiguity never
 * resolves silently to VNC against port 3389. What must not ship is a
 * connect that sends an RFB handshake at 3389 without having said so.
 *
 * The inference lives here rather than in the parser on purpose. The parser
 * reports what the input NAMED; presetting is a separate, visible, reversible
 * decision made one layer up.
 */
export function presetProtocol(target: { port: number }): ProtocolKind {
  return target.port === DEFAULT_RDP_PORT ? "rdp" : "vnc";
}
