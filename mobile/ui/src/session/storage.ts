/**
 * Per phone conveniences (the touch mode, which gesture tips were seen).
 * localStorage can be missing or throw in some webviews and private modes, so
 * every access is guarded and the screen works the same without it.
 */
const PREFIX = "deskvnc.session.";

export function load(key: string): string | null {
  try {
    return localStorage.getItem(PREFIX + key);
  } catch {
    return null;
  }
}

export function save(key: string, value: string): void {
  try {
    localStorage.setItem(PREFIX + key, value);
  } catch {
    // Not remembered this time; nothing else depends on it.
  }
}
