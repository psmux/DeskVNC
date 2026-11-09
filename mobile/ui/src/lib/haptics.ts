/**
 * A tiny haptics wrapper. On Android webviews `navigator.vibrate` works; iOS
 * webviews ignore it. The Rust side can plug in a native backend later with
 * `setHapticsBackend`, and every caller keeps working unchanged.
 */
import { readPrefs } from "./prefs";

export type HapticKind = "tap" | "select" | "success" | "warning" | "error";

type Backend = (kind: HapticKind) => void;

const PATTERNS: Record<HapticKind, number | number[]> = {
  tap: 8,
  select: 5,
  success: [10, 40, 18],
  warning: [20, 60, 20],
  error: [30, 50, 30, 50, 30],
};

let backend: Backend = (kind) => {
  try {
    if (typeof navigator === "undefined" || !("vibrate" in navigator)) return;
    // Browsers refuse (and log) a vibration before the first tap.
    const activation = (navigator as Navigator & { userActivation?: { hasBeenActive: boolean } }).userActivation;
    if (activation && !activation.hasBeenActive) return;
    navigator.vibrate(PATTERNS[kind]);
  } catch {
    // Some webviews throw when vibration is not allowed. Silence is fine.
  }
};

export function setHapticsBackend(next: Backend): void {
  backend = next;
}

export function haptic(kind: HapticKind = "tap"): void {
  if (!readPrefs().haptics) return;
  backend(kind);
}
