/**
 * The `hosts.rdpSettings` JSON blob: read it, edit it, write it back.
 *
 * Shaped like the `parseSshTunnel` trio in `types.ts` and for the same
 * reasons, with one addition that matters more here than it does there.
 *
 * **Unknown keys are kept and re-emitted.** `save_host` carries the blob as
 * an opaque string, so it survives a round trip through a UI that has never
 * heard of it; the *editor* does not, because it parses into a typed object
 * and writes a fresh one. A build predating a field would silently drop it,
 * and the field that makes that bite is `legacyTls`: the host quietly stops
 * being reachable. Keeping the leftovers is one line in the serializer and
 * closes the whole class rather than just that field.
 *
 * Mirrors `vnc_store::RdpSettings`, which flattens `remote_core::RdpOptions`
 * into itself, so the blob is one flat field list rather than two nested
 * ones and the editor reads everything at one level.
 */

import type { ProtocolKind } from "./types";

/** The blob version this build writes and the highest it understands. */
export const RDP_SETTINGS_V = 1;

export type NlaPolicy = "required" | "allow-fallback";
export type RdpColorDepth = "auto" | "bpp15" | "bpp16" | "bpp24" | "bpp32";
export type AudioMode = "play-locally" | "leave-at-server" | "off";

/** `remote_core::MonitorPolicy`, externally tagged: two unit variants and one
 *  that carries a list of indices into the server's reported layout. */
export type MonitorPolicy = "primary" | "all" | { selected: number[] };

/**
 * What desktop size an RDP session asks the server for.
 *
 * The shape matches `RdpResolution` in `crates/remote-core/src/options.rs`,
 * which is serde-tagged on `mode`. A test there pins the exact JSON, because
 * this reader and that writer are two halves of one contract.
 */
export type RdpResolution =
  | { mode: "follow-window" }
  | { mode: "window-at-connect" }
  | { mode: "fixed"; width: number; height: number };

/** The sizes offered in the picker, plus whatever a profile already holds. */
export const RDP_FIXED_SIZES: readonly (readonly [number, number])[] = [
  [1280, 720],
  [1366, 768],
  [1600, 900],
  [1920, 1080],
  [2560, 1440],
  [3440, 1440],
  [3840, 2160],
];

/** MS-RDPEDISP's monitor layout bounds; the connect request clamps further. */
export const RDP_MIN_DIM = 200;
export const RDP_MAX_DIM = 8192;

/** `remote_core::CodecSet`. Every codec on by default; this exists to work
 *  around a server whose encoder is broken, not as a tuning knob.
 *  `uncompressed` is present so the list reads completely and is never
 *  settable to false: it is the fallback every path lands on. */
export interface CodecSet {
  uncompressed: boolean;
  interleavedRle: boolean;
  planar: boolean;
  nscodec: boolean;
  remotefx: boolean;
  clearcodec: boolean;
  progressive: boolean;
  avc420: boolean;
  avc444: boolean;
}

/** `remote_core::PerformanceFlags`, the `TS_EXTENDED_INFO_PACKET`
 *  performance bits as named booleans rather than a number, so a stored blob
 *  stays legible. */
export interface PerformanceFlags {
  disableWallpaper: boolean;
  disableFullWindowDrag: boolean;
  disableMenuAnimations: boolean;
  disableTheming: boolean;
  disableCursorShadow: boolean;
  disableCursorBlinking: boolean;
  enableFontSmoothing: boolean;
  enableDesktopComposition: boolean;
}

export interface RdpSettings {
  v: number;
  clipboard: boolean;
  microphone: boolean;
  consoleSession: boolean;
  restrictedAdmin: boolean;

  serverName: string | null;
  domain: string | null;
  nla: NlaPolicy;
  /** Allow TLS 1.0 and 1.1 for this host. Off by default, per host, and it
   *  never turns itself on: a server cannot request the downgrade, only the
   *  person editing this profile can. */
  legacyTls: boolean;
  colorDepth: RdpColorDepth;
  codecs: CodecSet;
  audio: AudioMode;
  monitors: MonitorPolicy;
  resolution: RdpResolution;
  keyboardLayout: number;
  clientName: string;
  performance: PerformanceFlags;
  gateway: unknown | null;
  autologon: boolean;
  kdcProxyUrl: string | null;
  sendMstshashCookie: boolean;
  allowAutoReconnect: boolean;
  desktopScaleFactor: number;

  /** Keys this build did not recognise, kept so writing the blob back does
   *  not lose a newer build's settings. Never rendered. */
  unknown?: Record<string, unknown>;
}

export function blankCodecSet(): CodecSet {
  return {
    uncompressed: true,
    interleavedRle: true,
    planar: true,
    nscodec: true,
    remotefx: true,
    clearcodec: true,
    progressive: true,
    avc420: true,
    avc444: true,
  };
}

export function blankPerformanceFlags(): PerformanceFlags {
  return {
    disableWallpaper: false,
    disableFullWindowDrag: false,
    disableMenuAnimations: false,
    disableTheming: false,
    disableCursorShadow: false,
    disableCursorBlinking: false,
    enableFontSmoothing: false,
    enableDesktopComposition: false,
  };
}

/** The defaults the Rust side applies to a profile whose column is NULL. */
export function blankRdpSettings(): RdpSettings {
  return {
    v: RDP_SETTINGS_V,
    clipboard: true,
    microphone: false,
    consoleSession: false,
    restrictedAdmin: false,
    serverName: null,
    domain: null,
    nla: "required",
    legacyTls: false,
    colorDepth: "auto",
    codecs: blankCodecSet(),
    audio: "play-locally",
    monitors: "primary",
    resolution: { mode: "window-at-connect" },
    keyboardLayout: 0,
    clientName: "",
    performance: blankPerformanceFlags(),
    gateway: null,
    autologon: true,
    kdcProxyUrl: null,
    sendMstshashCookie: false,
    allowAutoReconnect: true,
    desktopScaleFactor: 100,
  };
}

/** Every key this module owns, so anything else can be set aside verbatim. */
const KNOWN_KEYS: readonly string[] = [
  "v", "clipboard", "microphone", "consoleSession", "restrictedAdmin",
  "serverName", "domain", "nla", "legacyTls", "colorDepth", "codecs", "audio",
  "monitors", "resolution", "dynamicResolution", "keyboardLayout", "clientName",
  "performance", "gateway", "autologon", "kdcProxyUrl", "sendMstshashCookie",
  "allowAutoReconnect", "desktopScaleFactor",
];

/**
 * Strict boolean read.
 *
 * `=== true` rather than a truthy test, matching how `parseSshTunnel` treats
 * its own booleans. `"yes"` is a string, JavaScript calls it truthy, and a
 * blob hand-edited or written by another tool must not turn a security
 * relaxation on by being sloppy.
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

function readCodecs(v: unknown): CodecSet {
  const blank = blankCodecSet();
  if (!v || typeof v !== "object") return blank;
  const o = v as Record<string, unknown>;
  const out = { ...blank };
  for (const key of Object.keys(blank) as (keyof CodecSet)[]) {
    out[key] = bool(o[key], blank[key]);
  }
  // Not a choice: uncompressed bitmap updates are the only thing every
  // server can send, so the fallback path can never be turned off.
  out.uncompressed = true;
  return out;
}

function readPerformance(v: unknown): PerformanceFlags {
  const blank = blankPerformanceFlags();
  if (!v || typeof v !== "object") return blank;
  const o = v as Record<string, unknown>;
  const out = { ...blank };
  for (const key of Object.keys(blank) as (keyof PerformanceFlags)[]) {
    out[key] = bool(o[key], blank[key]);
  }
  return out;
}

/**
 * Read the resolution, migrating a profile written before it existed.
 *
 * `dynamicResolution` was the old boolean and nothing in Rust ever read it, so
 * it never did anything; it still says what the user meant, and honouring it
 * is better than resetting every existing profile to the default.
 */
function readResolution(v: unknown, legacyDynamic: unknown): RdpResolution {
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (o.mode === "follow-window") return { mode: "follow-window" };
    if (o.mode === "window-at-connect") return { mode: "window-at-connect" };
    if (o.mode === "fixed") {
      const w = Math.round(num(o.width, 0));
      const h = Math.round(num(o.height, 0));
      // An out of range pair is not a fixed size anyone can use, so it falls
      // back rather than being clamped into something the user never chose.
      if (w >= RDP_MIN_DIM && w <= RDP_MAX_DIM && h >= RDP_MIN_DIM && h <= RDP_MAX_DIM) {
        return { mode: "fixed", width: w, height: h };
      }
    }
  }
  return legacyDynamic === true
    ? { mode: "follow-window" }
    : { mode: "window-at-connect" };
}

function readMonitors(v: unknown): MonitorPolicy {
  if (v === "all") return "all";
  if (v && typeof v === "object" && Array.isArray((v as { selected?: unknown }).selected)) {
    const list = (v as { selected: unknown[] }).selected
      .filter((n): n is number => typeof n === "number" && Number.isFinite(n));
    return list.length > 0 ? { selected: list } : "primary";
  }
  return "primary";
}

/**
 * Read a stored blob. Tolerant of missing fields; a blob that is not an
 * object at all reads as "no settings", because the editor just needs
 * something to show. The Rust side is the one that refuses to CONNECT on a
 * malformed blob, and that asymmetry is deliberate: a bad blob must not make
 * a tile uneditable, and it must not make a connection guess.
 */
export function parseRdpSettings(raw: string | null | undefined): RdpSettings | null {
  if (!raw || !raw.trim() || raw.trim() === "null") return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const blank = blankRdpSettings();

  const unknown: Record<string, unknown> = {};
  for (const key of Object.keys(o)) {
    if (!KNOWN_KEYS.includes(key)) unknown[key] = o[key];
  }

  return {
    v: num(o.v, RDP_SETTINGS_V),
    clipboard: bool(o.clipboard, blank.clipboard),
    microphone: bool(o.microphone, blank.microphone),
    consoleSession: bool(o.consoleSession, blank.consoleSession),
    restrictedAdmin: bool(o.restrictedAdmin, blank.restrictedAdmin),
    serverName: nullableStr(o.serverName),
    domain: nullableStr(o.domain),
    // An unrecognised value reads as "required". This one is security
    // relevant: a typo must never relax network level authentication.
    nla: oneOf(o.nla, ["required", "allow-fallback"] as const, "required"),
    legacyTls: bool(o.legacyTls, false),
    colorDepth: oneOf(
      o.colorDepth,
      ["auto", "bpp15", "bpp16", "bpp24", "bpp32"] as const,
      "auto",
    ),
    codecs: readCodecs(o.codecs),
    audio: oneOf(o.audio, ["play-locally", "leave-at-server", "off"] as const, "play-locally"),
    monitors: readMonitors(o.monitors),
    resolution: readResolution(o.resolution, o.dynamicResolution),
    keyboardLayout: num(o.keyboardLayout, 0),
    clientName: str(o.clientName, ""),
    performance: readPerformance(o.performance),
    gateway: o.gateway ?? null,
    autologon: bool(o.autologon, blank.autologon),
    kdcProxyUrl: nullableStr(o.kdcProxyUrl),
    sendMstshashCookie: bool(o.sendMstshashCookie, blank.sendMstshashCookie),
    allowAutoReconnect: bool(o.allowAutoReconnect, blank.allowAutoReconnect),
    desktopScaleFactor: num(o.desktopScaleFactor, 100),
    ...(Object.keys(unknown).length > 0 ? { unknown } : {}),
  };
}

/** Is this object still exactly what a fresh one would be? */
export function isBlankRdpSettings(s: RdpSettings): boolean {
  const blank = blankRdpSettings();
  if (s.unknown && Object.keys(s.unknown).length > 0) return false;
  return JSON.stringify({ ...s, v: RDP_SETTINGS_V }) === JSON.stringify(blank);
}

/**
 * Serialize for the `rdpSettings` column.
 *
 * A settings object that was never touched stores `null`, the same rule
 * `serializeSshTunnel` follows, so the column stays empty until the user
 * actually changes something and the Rust side keeps applying its own
 * defaults. Unrecognised keys are written back out first, so a field this
 * build has never heard of survives being edited here.
 */
export function serializeRdpSettings(s: RdpSettings | null): string | null {
  if (!s) return null;
  if (isBlankRdpSettings(s)) return null;
  const { unknown, ...known } = s;
  return JSON.stringify({ ...(unknown ?? {}), ...known, v: RDP_SETTINGS_V });
}

/** The settings a host should be edited with: its own, or a fresh set when
 *  the column is empty or unreadable. */
export function rdpSettingsFor(
  protocol: ProtocolKind,
  raw: string | null | undefined,
): RdpSettings | null {
  if (protocol !== "rdp") return null;
  return parseRdpSettings(raw) ?? blankRdpSettings();
}
