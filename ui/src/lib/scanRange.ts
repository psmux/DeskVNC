/**
 * Ranges a person types into "Scan an address range...", and the limits a
 * picked or typed range must pass. The same limits live in
 * `vnc_discovery::networks` and the shell applies them again before it
 * scans; this copy is here so the dialog can say what is wrong while the
 * person is still typing.
 */
import type { RangeVerdict, ScanNetwork, ScanNetworkKind } from "./types";

/** A /22, 1,022 hosts: larger than this asks first. */
export const CONFIRM_ABOVE_PREFIX = 22;
/** A /16, 65,534 hosts: larger than this is refused. */
export const LARGEST_PREFIX = 16;

export interface Cidr {
  /** Network address as a 32 bit unsigned number, host bits cleared. */
  network: number;
  prefix: number;
}

function parseIpv4(text: string): number | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function mask(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/** `a.b.c.d/nn`, or a bare `a.b.c.d` for that one address. */
export function parseCidr(text: string): Cidr | null {
  const t = text.trim();
  const slash = t.indexOf("/");
  const addr = parseIpv4(slash < 0 ? t : t.slice(0, slash).trim());
  if (addr === null) return null;
  let prefix = 32;
  if (slash >= 0) {
    const p = t.slice(slash + 1).trim();
    if (!/^\d{1,2}$/.test(p)) return null;
    prefix = Number(p);
    if (prefix > 32) return null;
  }
  return { network: (addr & mask(prefix)) >>> 0, prefix };
}

export function formatCidr(c: Cidr): string {
  const n = c.network;
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}/${c.prefix}`;
}

/** Host addresses a scan probes: the block less its network and broadcast. */
export function hostCount(c: Cidr): number {
  if (c.prefix === 32) return 1;
  if (c.prefix === 31) return 2;
  return 2 ** (32 - c.prefix) - 2;
}

const PRIVATE: Cidr[] = [
  { network: parseIpv4("10.0.0.0")!, prefix: 8 },
  { network: parseIpv4("172.16.0.0")!, prefix: 12 },
  { network: parseIpv4("192.168.0.0")!, prefix: 16 },
  // RFC 6598 shared space, where Tailscale and WARP hand out addresses.
  { network: parseIpv4("100.64.0.0")!, prefix: 10 },
];

export function isPrivate(c: Cidr): boolean {
  return PRIVATE.some(
    (b) => c.prefix >= b.prefix && ((c.network & mask(b.prefix)) >>> 0) === b.network,
  );
}

export function judgeRange(c: Cidr): RangeVerdict {
  if (!isPrivate(c)) return "public";
  if (c.prefix < LARGEST_PREFIX) return "too-large";
  if (c.prefix < CONFIRM_ABOVE_PREFIX) return "confirm";
  return "scan";
}

/**
 * The strictest verdict over several ranges, with the addresses summed.
 * Small ranges that add up to more than a /22 ask first as well, since the
 * question is about the count. Mirrors `judge_ranges` in vnc-discovery.
 */
export function judgeCidrs(cidrs: string[]): { verdict: RangeVerdict; addresses: number } {
  const order: RangeVerdict[] = ["scan", "confirm", "too-large", "public"];
  let verdict: RangeVerdict = "scan";
  let addresses = 0;
  for (const text of cidrs) {
    const c = parseCidr(text);
    const v: RangeVerdict = c ? judgeRange(c) : "public";
    if (c) addresses += hostCount(c);
    if (order.indexOf(v) > order.indexOf(verdict)) verdict = v;
  }
  if (verdict === "scan" && addresses > hostCount({ network: 0, prefix: CONFIRM_ABOVE_PREFIX })) {
    verdict = "confirm";
  }
  return { verdict, addresses };
}

/** "1 address", "254 addresses", "65,534 addresses". */
export function formatAddresses(n: number): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? "address" : "addresses"}`;
}

/**
 * Roughly how long the polite scan takes, for the confirmation. It probes
 * three ports per address (VNC, RDP and DeskVNC Support) with at most 200
 * connections open and a 500 ms timeout, so an address that never answers,
 * which is most of them, costs a slot for half a second: 400 a second at
 * best, under the 500 a second rate cap. A floor, not a promise.
 */
export function roughDuration(addresses: number): string {
  const seconds = Math.ceil((addresses * 3) / 400);
  if (seconds < 90) return "about a minute";
  return `about ${Math.round(seconds / 60)} minutes`;
}

/** Why a typed range cannot be scanned, or null when it can. */
export function rangeProblem(text: string): string | null {
  const c = parseCidr(text);
  if (!c) return "Type an address or a range, for example 192.168.1.0/24.";
  switch (judgeRange(c)) {
    case "public":
      return `${formatCidr(c)} is not a private range. Only 10.x, 172.16 to 172.31, 192.168.x and 100.64/10 can be scanned.`;
    case "too-large":
      return `${formatCidr(c)} has ${formatAddresses(hostCount(c))}, more than a /${LARGEST_PREFIX}. Scan a smaller part of it.`;
    default:
      return null;
  }
}

export const KIND_LABEL: Record<ScanNetworkKind, string> = {
  lan: "LAN",
  vpn: "VPN",
  warp: "WARP",
  routed: "Routed",
  virtual: "Virtual",
};

// ------------------------------------------------------------- last pick

/** What the person picked last time, so the menu can point it out again. */
export interface LastPick {
  name: string;
  range: string;
  cidrs: string[];
}

const LAST_PICK_KEY = "deskvnc.scan.lastPick";

export function readLastPick(): LastPick | null {
  try {
    const raw = localStorage.getItem(LAST_PICK_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as Partial<LastPick>;
    if (typeof v.name !== "string" || typeof v.range !== "string" || !Array.isArray(v.cidrs)) {
      return null;
    }
    if (!v.cidrs.every((c) => typeof c === "string" && parseCidr(c))) return null;
    return { name: v.name, range: v.range, cidrs: v.cidrs };
  } catch {
    return null;
  }
}

export function writeLastPick(pick: LastPick): void {
  try {
    localStorage.setItem(LAST_PICK_KEY, JSON.stringify(pick));
  } catch {
    /* storage unavailable; the menu simply does not remember */
  }
}

export function samePick(pick: LastPick | null, network: ScanNetwork): boolean {
  return !!pick && pick.cidrs.join(",") === network.cidrs.join(",");
}
