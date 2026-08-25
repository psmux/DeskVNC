/**
 * The Preferences defaults that a NEW Remote Desktop host starts with.
 *
 * These settings were written and never read. Every `rdp_default_*` key had a
 * switch in Preferences, a row in the Rust store, and no consumer anywhere, so
 * turning one on changed nothing and the next host still arrived with the
 * hardcoded blank. This module is the missing half.
 *
 * They are cached rather than awaited because a draft is built synchronously
 * from eight call sites, and threading a promise through all of them to reach
 * a value that is already known would be a lot of churn for no gain. The load
 * happens when the library mounts, long before any dialog opens; a dialog that
 * somehow opens first gets the plain blank, which is the old behaviour and not
 * a wrong one.
 *
 * Preferences writes through here as well as to the store, so changing a
 * default takes effect on the next host rather than after a restart.
 */
import { safeInvoke } from "./tauri";
import type { RdpResolution, RdpSettings } from "./rdp";
import { RDP_MAX_DIM, RDP_MIN_DIM } from "./rdp";

/** The subset of a host's RDP settings that Preferences has a default for. */
type Defaults = Pick<RdpSettings, "monitors" | "resolution" | "audio" | "clipboard">;

/** The app-setting key for each, and what it means when unset. */
export const RDP_DEFAULT_KEYS = {
  monitors: "rdp_default_multi_monitor",
  resolution: "rdp_default_resolution",
  audio: "rdp_default_audio",
  clipboard: "rdp_default_redirect_clipboard",
} as const;

let cache: Partial<Defaults> = {};

/**
 * Encode a resolution as the token stored in app settings.
 *
 * A token rather than JSON: the store holds strings, and `1920x1080` is
 * legible to anyone reading the settings table, which a serialized object
 * would not be.
 */
export function encodeResolution(r: RdpResolution): string {
  return r.mode === "fixed" ? `${r.width}x${r.height}` : r.mode;
}

/** The inverse, tolerant of anything a newer build might have written. */
export function decodeResolution(raw: string | null | undefined): RdpResolution | null {
  if (!raw) return null;
  if (raw === "follow-window" || raw === "window-at-connect") return { mode: raw };
  const m = /^(\d+)x(\d+)$/.exec(raw);
  if (!m) return null;
  const [width, height] = [Number(m[1]), Number(m[2])];
  const ok = (n: number): boolean => n >= RDP_MIN_DIM && n <= RDP_MAX_DIM;
  return ok(width) && ok(height) ? { mode: "fixed", width, height } : null;
}

/** Read every default into the cache. Safe to call more than once. */
export async function loadRdpDefaults(): Promise<void> {
  const read = async (key: string): Promise<string | null> =>
    await safeInvoke<string | null>("get_app_setting", { key }, null);

  const [monitors, resolution, audio, clipboard] = await Promise.all([
    read(RDP_DEFAULT_KEYS.monitors),
    read(RDP_DEFAULT_KEYS.resolution),
    read(RDP_DEFAULT_KEYS.audio),
    read(RDP_DEFAULT_KEYS.clipboard),
  ]);

  const next: Partial<Defaults> = {};
  // Each is applied only when the key is actually present. An absent key means
  // the user never expressed a preference, and `blankRdpSettings` already says
  // what a host with no preference looks like.
  if (monitors !== null) next.monitors = monitors !== "false" ? "all" : "primary";
  const parsed = decodeResolution(resolution);
  if (parsed) next.resolution = parsed;
  if (audio !== null) next.audio = audio !== "false" ? "play-locally" : "leave-at-server";
  if (clipboard !== null) next.clipboard = clipboard !== "false";
  cache = next;
}

/** What a new host should start with, on top of the blank. */
export function rdpDefaults(): Partial<Defaults> {
  return cache;
}

/** Record a default that Preferences has just changed. */
export function setRdpDefault<K extends keyof Defaults>(key: K, value: Defaults[K]): void {
  cache = { ...cache, [key]: value };
}
