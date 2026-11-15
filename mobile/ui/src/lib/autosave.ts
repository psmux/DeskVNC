/**
 * Saving a computer to Your computers by itself, once a connection to it
 * has worked: what to call it, which picture to give it, and whether it is
 * on the list already. The screen does the saving (`session_save_host`),
 * only after the session reached connected.
 */
import type { Host, HostDraft, HostOs, Protocol } from "../api/contract";
import { isIpv6Literal } from "./address";
import { bareAddress } from "./quick";
import { PROTOCOL_COLOR, suggestName } from "./wizard";

/** What the screen that started a connection knew about the computer. */
export interface AutoSave {
  protocol: Protocol;
  address: string;
  port: number;
  username: string | null;
  /** The name Nearby or mDNS showed. */
  foundName: string | null;
  /** The name `identify` found. */
  identifiedName: string | null;
  os: HostOs;
}

/** What the session itself learned. */
export interface SessionNames {
  /** The VNC desktop name from ServerInit, or what an RDP server sent. */
  desktopName: string | null;
  /** The subject name of the RDP certificate, when one was shown. */
  certName: string | null;
}

const MAX_NAME = 60;
const BOUNDARY_PORT = 5940;

function looksLikeAddress(name: string): boolean {
  return /^[\d.]+$/.test(name) || isIpv6Literal(name) || /^[0-9a-f]{64}(@|$)/i.test(name);
}

function clean(name: string | null | undefined): string | null {
  const n = (name ?? "").replace(/\s+/g, " ").trim();
  if (!n || looksLikeAddress(n)) return null;
  return n.length > MAX_NAME ? `${n.slice(0, MAX_NAME - 1).trimEnd()}…` : n;
}

/**
 * The best name known: the Nearby or mDNS name, then the identify name, then
 * what the computer calls itself, then its certificate name, and the address
 * last.
 */
export function autoSaveName(a: AutoSave, s: SessionNames): string {
  const pick = [a.foundName, a.identifiedName, s.desktopName, s.certName].map(clean).find((n) => n !== null);
  if (pick) return pick;
  const where = a.address.replace(/^[0-9a-f]{64}@/i, "");
  if (/^[0-9a-f]{64}$/i.test(where)) return "Boundary computer";
  return suggestName(where) || where;
}

/** The picture: the hint when there is one, Windows for Remote Desktop. */
export function autoSaveOs(a: AutoSave): HostOs {
  if (a.os !== "unknown") return a.os;
  return a.protocol === "rdp" ? "windows" : "unknown";
}

/** `CN=STUDIO-PC` becomes `STUDIO-PC`; a subject with no CN is kept whole. */
export function certCommonName(subject: string | null | undefined): string | null {
  const s = (subject ?? "").trim();
  if (!s) return null;
  const cn = /(?:^|[,/]\s*)CN=([^,/]+)/i.exec(s);
  return (cn ? cn[1] : s).trim() || null;
}

function samePort(protocol: Protocol, a: number, b: number): boolean {
  if (protocol !== "boundary") return a === b;
  const norm = (p: number) => (p === 0 ? BOUNDARY_PORT : p);
  return norm(a) === norm(b);
}

/** Whether this computer is on the list already, by protocol, address and port. */
export function isSaved(hosts: Host[], a: AutoSave): boolean {
  const where = bareAddress(a.address);
  return hosts.some((h) => h.protocol === a.protocol && bareAddress(h.address) === where && samePort(a.protocol, h.port, a.port));
}

export function autoSaveDraft(a: AutoSave, s: SessionNames): HostDraft {
  return {
    name: autoSaveName(a, s),
    protocol: a.protocol,
    address: a.address,
    port: a.port,
    username: a.username?.trim() || null,
    os: autoSaveOs(a),
    color: PROTOCOL_COLOR[a.protocol],
    favorite: false,
    domain: null,
    boundaryInvitation: null,
  };
}
