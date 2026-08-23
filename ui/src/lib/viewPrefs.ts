/**
 * The session view's own settings: what the floating toolbar changes, kept
 * from one connection to the next.
 *
 * Two layers, because they answer two different questions. Preferences sets
 * the DEFAULTS, which is what a computer you have never adjusted anything on
 * gets. Changing something from the toolbar or the menu writes it against
 * THAT computer, which is what it keeps from then on: a 4K desktop wants a
 * different scaling mode and a different monitor than a laptop, and a setting
 * that followed you between them would be wrong on one of them by definition.
 * Later edits to the defaults reach the computers that have never been
 * adjusted, and leave the ones that have alone.
 *
 * Everything here is decided in the webview, so it lives in `localStorage`
 * next to `lib/prefs` rather than in the Rust store. Note that the host
 * profile carries `quality_pref` and `view_only` columns which the backend
 * applies to the CONNECTION at connect time; what is remembered here is
 * applied on top once the session is up, because it is the more recent thing
 * the user actually did.
 */
import type { QualityPreset, ScalingMode } from "./types";
import type { DisplayChoice } from "./displays";

export interface ViewPrefs {
  scalingMode: ScalingMode;
  /** Only consulted while `scalingMode` is "custom". */
  zoom: number;
  quality: QualityPreset;
  /** Gray levels for the black-and-white preset. */
  bwLevels: number;
  alwaysRefresh: boolean;
  viewOnly: boolean;
  /**
   * Shortcut pass-through. Restored quietly: the switch comes back on and
   * capture is re-armed, but the Accessibility explainer is never raised on
   * its own, so a missing permission shows as the badge saying so rather than
   * as a dialog on every connect.
   */
  passthrough: boolean;
  /** The chosen monitor, or null for the whole desktop. */
  display: DisplayChoice | null;
}

/** What a computer with nothing remembered against it starts from. */
export const FACTORY_DEFAULTS: ViewPrefs = {
  scalingMode: "aspect-fit",
  zoom: 1,
  quality: "auto",
  bwLevels: 16,
  alwaysRefresh: false,
  viewOnly: false,
  passthrough: false,
  display: null,
};

const DEFAULTS_KEY = "deskvnc.viewdefaults.v1";
const HOST_PREFIX = "deskvnc.view.";

const SCALING_MODES: ScalingMode[] = ["fit", "aspect-fit", "actual", "custom", "remote-resize"];
const QUALITY_PRESETS: QualityPreset[] = ["auto", "high", "medium", "low", "bw"];
const GRAY_LEVELS = [256, 16, 8, 4, 2, 1];

function read<T>(key: string): Partial<T> | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Partial<T>) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable; the setting simply does not persist */
  }
}

/**
 * Merge a stored blob over a base, discarding anything that is not a value
 * this code can act on.
 *
 * `localStorage` is hand-editable and survives downgrades, so an unknown
 * scaling mode or a `NaN` zoom would otherwise reach the renderer and put the
 * view in a state with no way back out of it from the UI.
 */
function sanitize(base: ViewPrefs, raw: Partial<ViewPrefs> | null): ViewPrefs {
  if (!raw) return base;
  const num = (v: unknown, fallback: number): number =>
    typeof v === "number" && Number.isFinite(v) ? v : fallback;
  const bool = (v: unknown, fallback: boolean): boolean =>
    typeof v === "boolean" ? v : fallback;

  const d = raw.display;
  const display =
    d &&
    typeof d === "object" &&
    [d.id, d.x, d.y, d.width, d.height].every((n) => typeof n === "number" && Number.isFinite(n)) &&
    d.width > 0 &&
    d.height > 0
      ? { id: d.id, x: d.x, y: d.y, width: d.width, height: d.height }
      : base.display;

  return {
    scalingMode: SCALING_MODES.includes(raw.scalingMode as ScalingMode)
      ? (raw.scalingMode as ScalingMode)
      : base.scalingMode,
    // The toolbar's slider runs 25% to 400%; anything outside that came from
    // somewhere other than the UI.
    zoom: Math.min(Math.max(num(raw.zoom, base.zoom), 0.25), 4),
    quality: QUALITY_PRESETS.includes(raw.quality as QualityPreset)
      ? (raw.quality as QualityPreset)
      : base.quality,
    bwLevels: GRAY_LEVELS.includes(num(raw.bwLevels, base.bwLevels))
      ? num(raw.bwLevels, base.bwLevels)
      : base.bwLevels,
    alwaysRefresh: bool(raw.alwaysRefresh, base.alwaysRefresh),
    viewOnly: bool(raw.viewOnly, base.viewOnly),
    passthrough: bool(raw.passthrough, base.passthrough),
    display,
  };
}

/** The defaults Preferences edits. */
export function readViewDefaults(): ViewPrefs {
  return sanitize(FACTORY_DEFAULTS, read<ViewPrefs>(DEFAULTS_KEY));
}

export function writeViewDefaults(patch: Partial<ViewPrefs>): ViewPrefs {
  const next = sanitize(readViewDefaults(), patch);
  write(DEFAULTS_KEY, next);
  return next;
}

/**
 * Which computer a session belongs to, for the purpose of remembering things
 * about it.
 *
 * A saved profile wins over the endpoint so that renaming or re-addressing a
 * host keeps what was learnt about it, which is the same rule the shell's
 * `MachineKey` uses to decide what counts as one machine. A session with
 * neither (there should be none, but the query string is not ours to trust)
 * gets no key and simply remembers nothing.
 */
export function viewPrefsKey(params: {
  profileId: string | null;
  address: string | null;
  port: number;
}): string | null {
  const profile = params.profileId?.trim();
  if (profile) return `${HOST_PREFIX}p:${profile}`;
  const address = params.address?.trim().toLowerCase().replace(/\.$/, "");
  if (address) return `${HOST_PREFIX}e:${address}:${params.port}`;
  return null;
}

/** What this computer is set to: its own settings over the global defaults. */
export function readViewPrefs(key: string | null): ViewPrefs {
  const defaults = readViewDefaults();
  if (!key) return defaults;
  return sanitize(defaults, read<ViewPrefs>(key));
}

export function writeViewPrefs(key: string | null, value: ViewPrefs): void {
  if (!key) return;
  write(key, value);
}

/**
 * Whether two sets are the same, so a session that has changed nothing can be
 * left with nothing stored against it and go on following the defaults.
 *
 * Field by field rather than by comparing serialised forms, which would turn
 * a difference in key order into a spurious write on every render.
 */
export function sameViewPrefs(a: ViewPrefs, b: ViewPrefs): boolean {
  const sameDisplay =
    a.display === b.display ||
    (a.display !== null &&
      b.display !== null &&
      a.display.id === b.display.id &&
      a.display.x === b.display.x &&
      a.display.y === b.display.y &&
      a.display.width === b.display.width &&
      a.display.height === b.display.height);
  return (
    sameDisplay &&
    a.scalingMode === b.scalingMode &&
    a.zoom === b.zoom &&
    a.quality === b.quality &&
    a.bwLevels === b.bwLevels &&
    a.alwaysRefresh === b.alwaysRefresh &&
    a.viewOnly === b.viewOnly &&
    a.passthrough === b.passthrough
  );
}
