import { afterEach, describe, expect, it } from "vitest";
import type { ThemeChoice } from "./prefs";
import { barIcons, type BarIcons, holdDarkCover, installSystemBars, sessionCoversDark } from "./systemBars";

describe("which icons go over what is drawn", () => {
  it("puts light icons over the session stage in every theme", () => {
    for (const theme of ["light", "dark", "system"] as ThemeChoice[]) {
      for (const systemDark of [false, true]) {
        expect(barIcons({ theme, systemDark, darkCover: true })).toBe("light");
      }
    }
  });

  it("follows a theme picked in Settings, not the phone's dark mode", () => {
    expect(barIcons({ theme: "light", systemDark: true, darkCover: false })).toBe("dark");
    expect(barIcons({ theme: "dark", systemDark: false, darkCover: false })).toBe("light");
  });

  it("follows the phone when the theme is left on system", () => {
    expect(barIcons({ theme: "system", systemDark: false, darkCover: false })).toBe("dark");
    expect(barIcons({ theme: "system", systemDark: true, darkCover: false })).toBe("light");
  });

  it("counts the stage as dark only when the connecting and error screens are gone", () => {
    expect(sessionCoversDark("connecting")).toBe(false);
    expect(sessionCoversDark("error")).toBe(false);
    expect(sessionCoversDark("connected")).toBe(true);
    // The reconnect card sits on the stage under a dark scrim.
    expect(sessionCoversDark("ended")).toBe(true);
  });
});

describe("telling the phone", () => {
  const stops: (() => void)[] = [];
  afterEach(() => stops.splice(0).forEach((stop) => stop()));

  function rig(theme: ThemeChoice = "light", systemDark = false) {
    const sent: BarIcons[] = [];
    let current = theme;
    const themeListeners = new Set<() => void>();
    const mediaListeners = new Set<() => void>();
    const media = {
      matches: systemDark,
      addEventListener: (_: string, fn: () => void) => void mediaListeners.add(fn),
      removeEventListener: (_: string, fn: () => void) => void mediaListeners.delete(fn),
    };
    const win = {
      matchMedia: () => media as unknown as MediaQueryList,
      DeskVNCSystemBars: { set: (icons: BarIcons) => void sent.push(icons) },
    };
    const stop = installSystemBars({
      win,
      readTheme: () => current,
      onThemeChange: (fn) => {
        themeListeners.add(fn);
        return () => themeListeners.delete(fn);
      },
    });
    stops.push(stop);
    return {
      sent,
      stop,
      setTheme(next: ThemeChoice) {
        current = next;
        themeListeners.forEach((fn) => fn());
      },
      setSystemDark(dark: boolean) {
        media.matches = dark;
        mediaListeners.forEach((fn) => fn());
      },
      mediaListeners,
    };
  }

  it("sends the icons at start and on every change, once each", () => {
    const r = rig("light");
    expect(r.sent).toEqual(["dark"]);

    // A session connects, then ends.
    const release = holdDarkCover();
    expect(r.sent).toEqual(["dark", "light"]);
    release();
    release(); // twice is harmless
    expect(r.sent).toEqual(["dark", "light", "dark"]);

    r.setTheme("dark");
    expect(r.sent).toEqual(["dark", "light", "dark", "light"]);
    r.setTheme("dark"); // another setting changed, the icons did not
    expect(r.sent).toHaveLength(4);
  });

  it("keeps light icons while two dark covers overlap", () => {
    const r = rig("light");
    const a = holdDarkCover();
    const b = holdDarkCover();
    a();
    expect(r.sent.at(-1)).toBe("light");
    b();
    expect(r.sent.at(-1)).toBe("dark");
  });

  it("follows the phone switching dark mode while the theme is system", () => {
    const r = rig("system", false);
    r.setSystemDark(true);
    r.setSystemDark(false);
    expect(r.sent).toEqual(["dark", "light", "dark"]);
    // Over the stage the phone's mode does not matter.
    const release = holdDarkCover();
    r.setSystemDark(true);
    r.setSystemDark(false);
    expect(r.sent).toEqual(["dark", "light", "dark", "light"]);
    release();
  });

  it("goes to the fallback where Android's bridge is missing, and survives one that throws", () => {
    const sent: BarIcons[] = [];
    stops.push(installSystemBars({ win: {}, readTheme: () => "dark", onThemeChange: () => () => {}, fallback: (i) => void sent.push(i) }));
    expect(sent).toEqual(["light"]);
    const broken = {
      DeskVNCSystemBars: {
        set: () => {
          throw new Error("gone");
        },
      },
    };
    expect(() => stops.push(installSystemBars({ win: broken, readTheme: () => "light", onThemeChange: () => () => {} }))).not.toThrow();
  });

  it("stops listening when stopped", () => {
    const r = rig("light");
    r.stop();
    expect(r.mediaListeners.size).toBe(0);
    const release = holdDarkCover();
    r.setTheme("dark");
    expect(r.sent).toEqual(["dark"]);
    release();
  });
});
