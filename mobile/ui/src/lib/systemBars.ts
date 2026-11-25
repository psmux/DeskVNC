/**
 * The colour of the status bar and navigation bar icons.
 *
 * The app draws edge to edge, so the clock, the battery and the gesture
 * handle sit over whatever the page draws there. Left alone, Android picks
 * dark icons whenever the phone is in light mode and iOS does the same, so
 * with the light theme the icons were dark on the session's black stage and
 * close to invisible, and with the dark theme picked on a phone in light mode
 * they were dark on the dark home screen too.
 *
 * So the page decides, from what it draws under the bars: light icons over
 * the session stage whatever the theme, and over the dark theme; dark icons
 * over the light theme. "system" follows prefers-color-scheme, the same
 * media query theme.css follows, so the icons change when the phone does.
 *
 * Android takes the answer through window.DeskVNCSystemBars.set(), which
 * MainActivity adds, and iOS through the system_bars command. Neither is
 * there in a plain browser, where this does nothing.
 */
import type { ThemeChoice } from "./prefs";

/** "light" icons for a dark backdrop, "dark" icons for a light one. */
export type BarIcons = "light" | "dark";

export interface BarsState {
  theme: ThemeChoice;
  /** What prefers-color-scheme says now. */
  systemDark: boolean;
  /** Something dark covers the whole screen, under the bars too. */
  darkCover: boolean;
}

export function barIcons({ theme, systemDark, darkCover }: BarsState): BarIcons {
  if (darkCover) return "light";
  const darkTheme = theme === "dark" || (theme === "system" && systemDark);
  return darkTheme ? "light" : "dark";
}

/**
 * Whether the session screen shows its black stage under the bars. The
 * connecting and error screens cover it with the theme's own background; the
 * reconnect card leaves it there under a dark scrim.
 */
export function sessionCoversDark(phase: "connecting" | "connected" | "error" | "ended"): boolean {
  return phase === "connected" || phase === "ended";
}

// Every screen part that puts something dark under the bars holds a token
// until it goes away, so two of them overlapping, or React mounting one
// twice, never leaves the icons wrong.
const covers = new Set<symbol>();
const coverListeners = new Set<() => void>();

/** Say a dark cover is up. Call the function it returns when it is gone. */
export function holdDarkCover(): () => void {
  const token = Symbol("dark cover");
  covers.add(token);
  coverListeners.forEach((fn) => fn());
  return () => {
    if (!covers.delete(token)) return;
    coverListeners.forEach((fn) => fn());
  };
}

export function darkCoverUp(): boolean {
  return covers.size > 0;
}

export function onDarkCoverChange(fn: () => void): () => void {
  coverListeners.add(fn);
  return () => coverListeners.delete(fn);
}

export interface BarsWindow {
  matchMedia?: (query: string) => Pick<MediaQueryList, "matches" | "addEventListener" | "removeEventListener">;
  DeskVNCSystemBars?: { set(icons: BarIcons): void };
}

export interface BarsDeps {
  win: BarsWindow;
  readTheme: () => ThemeChoice;
  onThemeChange: (fn: () => void) => () => void;
  /** Where the answer goes when the Android bridge is not there (iOS). */
  fallback?: (icons: BarIcons) => void;
}

/**
 * Work out the icons now and again whenever the theme, the phone's dark mode
 * or a dark cover changes, and hand each new answer to the phone. Returns
 * the function that stops it.
 */
export function installSystemBars({ win, readTheme, onThemeChange, fallback }: BarsDeps): () => void {
  const query = win.matchMedia?.("(prefers-color-scheme: dark)");
  let sent: BarIcons | null = null;
  const send = (icons: BarIcons): void => {
    try {
      if (win.DeskVNCSystemBars) win.DeskVNCSystemBars.set(icons);
      else fallback?.(icons);
    } catch {
      // The bars keep their last colour; nothing on the page depends on them.
    }
  };
  const update = (): void => {
    const icons = barIcons({ theme: readTheme(), systemDark: !!query?.matches, darkCover: darkCoverUp() });
    if (icons === sent) return;
    sent = icons;
    send(icons);
  };
  query?.addEventListener("change", update);
  const offTheme = onThemeChange(update);
  const offCover = onDarkCoverChange(update);
  update();
  return () => {
    query?.removeEventListener("change", update);
    offTheme();
    offCover();
  };
}
