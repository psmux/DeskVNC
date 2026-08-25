/**
 * The `hosts.sshSettings` JSON blob: read it, edit it, write it back.
 *
 * Shaped exactly like `rdp.ts`, for the same reasons: **unknown keys are kept
 * and re-emitted.** `save_host` carries the blob as an opaque string, so it
 * survives a round trip through a UI that has never heard of a field; the
 * *editor* does not, because it parses into a typed object and writes a fresh
 * one. Without this, a build predating a field silently drops it on every
 * save, and the field that makes that bite is `multiplexer`: a host quietly
 * stops attaching to the session the user actually meant.
 *
 * Mirrors `vnc_store::SshSettings`, which flattens `remote_core::SshOptions`
 * into itself plus the store-only `fontSize` and `scrollback`, so the blob is
 * one flat field list rather than two nested ones and the editor reads
 * everything at one level.
 */

import type { ProtocolKind } from "./types";

/** The blob version this build writes and the highest it understands. */
export const SSH_SETTINGS_V = 1;

/** `remote_core::MultiplexerKind`, serde `rename_all = "kebab-case"`, which
 *  for every one of these spells it exactly as written here. */
export type MultiplexerKind =
  | "auto"
  | "none"
  | "psmux"
  | "tmux"
  | "screen"
  | "zellij"
  | "custom";

/** `remote_core::DEFAULT_TERM`: the widest-compatible `TERM` value, present
 *  in every terminfo database going back decades. */
export const DEFAULT_TERM = "xterm-256color";

/** `remote_core::SshAuthKind`, serde `rename_all = "kebab-case"`, which for
 *  every one of these spells it exactly as written here. The default,
 *  `"agent"`, is the one setting that needs nothing stored; a profile that
 *  wants a password or a key file has to say so explicitly, which is the
 *  gap this type closes: without it the dialog had no way to ask for
 *  anything but agent auth, so a host with a password and no running agent
 *  failed to connect with no way to fix it here. */
export type SshAuthKind = "agent" | "password" | "key-file";

export interface SshSettings {
  v: number;
  /** How to authenticate. The secret itself never lives here: a password
   *  travels through `HostDraft.password` into the keychain, exactly like
   *  the RDP and VNC password fields already do. */
  auth: SshAuthKind;
  /** Private key path for `auth: "key-file"`. A path, not a key: the file is
   *  read on the Rust side at connect time and its contents never cross the
   *  IPC boundary. */
  keyPath: string | null;
  term: string;
  cols: number;
  rows: number;
  multiplexer: MultiplexerKind;
  sessionName: string;
  customCommand: string | null;
  fallbackToShell: boolean;
  startupCommand: string | null;

  /** UI-only: not in `remote_core::SshOptions`, only the store's JSON column
   *  and the host editor read these. */
  fontSize: number;
  scrollback: number;

  /** Keys this build did not recognise, kept so writing the blob back does
   *  not lose a newer build's settings. Never rendered. */
  unknown?: Record<string, unknown>;
}

/** The defaults the Rust side applies to a profile whose column is NULL. */
export function blankSshSettings(): SshSettings {
  return {
    v: SSH_SETTINGS_V,
    auth: "agent",
    keyPath: null,
    term: DEFAULT_TERM,
    cols: 80,
    rows: 24,
    multiplexer: "auto",
    sessionName: "deskvnc",
    customCommand: null,
    fallbackToShell: true,
    startupCommand: null,
    fontSize: 13,
    scrollback: 10_000,
  };
}

/** Every key this module owns, so anything else can be set aside verbatim. */
const KNOWN_KEYS: readonly string[] = [
  "v", "auth", "keyPath", "term", "cols", "rows", "multiplexer", "sessionName",
  "customCommand", "fallbackToShell", "startupCommand", "fontSize", "scrollback",
];

/**
 * Strict boolean read.
 *
 * `=== true` rather than a truthy test, matching `parseRdpSettings`'s own
 * booleans: `"yes"` is a string, JavaScript calls it truthy, and a blob
 * hand-edited or written by another tool must not turn a behaviour on by
 * being sloppy.
 */
function bool(v: unknown, fallback: boolean): boolean {
  return typeof v === "boolean" ? v : fallback;
}

function str(v: unknown, fallback: string): string {
  return typeof v === "string" ? v : fallback;
}

function nullableStr(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

function num(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], fallback: T): T {
  return typeof v === "string" && (allowed as readonly string[]).includes(v)
    ? (v as T)
    : fallback;
}

const MULTIPLEXER_KINDS: readonly MultiplexerKind[] = [
  "auto", "none", "psmux", "tmux", "screen", "zellij", "custom",
];

const SSH_AUTH_KINDS: readonly SshAuthKind[] = ["agent", "password", "key-file"];

/**
 * Read a stored blob. Tolerant of missing fields; a blob that is not an
 * object at all reads as "no settings", because the editor just needs
 * something to show. The Rust side is the one that refuses to CONNECT on a
 * malformed blob, and that asymmetry is deliberate: a bad blob must not make
 * a tile uneditable, and it must not make a connection guess.
 */
export function parseSshSettings(raw: string | null | undefined): SshSettings | null {
  if (!raw || !raw.trim() || raw.trim() === "null") return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const blank = blankSshSettings();

  const unknown: Record<string, unknown> = {};
  for (const key of Object.keys(o)) {
    if (!KNOWN_KEYS.includes(key)) unknown[key] = o[key];
  }

  return {
    v: num(o.v, SSH_SETTINGS_V),
    auth: oneOf(o.auth, SSH_AUTH_KINDS, "agent"),
    keyPath: nullableStr(o.keyPath),
    term: str(o.term, blank.term),
    cols: num(o.cols, blank.cols),
    rows: num(o.rows, blank.rows),
    multiplexer: oneOf(o.multiplexer, MULTIPLEXER_KINDS, "auto"),
    sessionName: str(o.sessionName, blank.sessionName),
    customCommand: nullableStr(o.customCommand),
    fallbackToShell: bool(o.fallbackToShell, blank.fallbackToShell),
    startupCommand: nullableStr(o.startupCommand),
    fontSize: num(o.fontSize, blank.fontSize),
    scrollback: num(o.scrollback, blank.scrollback),
    ...(Object.keys(unknown).length > 0 ? { unknown } : {}),
  };
}

/** Is this object still exactly what a fresh one would be? */
export function isBlankSshSettings(s: SshSettings): boolean {
  const blank = blankSshSettings();
  if (s.unknown && Object.keys(s.unknown).length > 0) return false;
  return JSON.stringify({ ...s, v: SSH_SETTINGS_V }) === JSON.stringify(blank);
}

/**
 * Serialize for the `sshSettings` column.
 *
 * A settings object that was never touched stores `null`, the same rule
 * `serializeRdpSettings` follows, so the column stays empty until the user
 * actually changes something and the Rust side keeps applying its own
 * defaults. Unrecognised keys are written back out first, so a field this
 * build has never heard of survives being edited here.
 */
export function serializeSshSettings(s: SshSettings | null): string | null {
  if (!s) return null;
  if (isBlankSshSettings(s)) return null;
  const { unknown, ...known } = s;
  return JSON.stringify({ ...(unknown ?? {}), ...known, v: SSH_SETTINGS_V });
}

/** The settings a host should be edited with: its own, or a fresh set when
 *  the column is empty or unreadable. */
export function sshSettingsFor(
  protocol: ProtocolKind,
  raw: string | null | undefined,
): SshSettings | null {
  if (protocol !== "ssh") return null;
  return parseSshSettings(raw) ?? blankSshSettings();
}
