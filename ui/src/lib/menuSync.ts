/**
 * Telling the native menu what the session in front is set to.
 *
 * The View and Session menus carry the whole floating toolbar, because
 * Preferences can switch that toolbar off and leave the menu as the only way
 * in. A menu that offers those choices has to show which of them is in force,
 * and none of that state exists in the shell: the scaling mode and the quality
 * preset live in the session view, and most of the monitor list is computed
 * there too (a server that describes no layout gets cuts guessed by width and
 * a seam found in the pixels). So the view pushes a snapshot whenever anything
 * changes, and again whenever its window takes the focus, since the menu is
 * one object shared by every window.
 */
import { useEffect } from "react";
import type { LocalCursor } from "../state/SettingsContext";
import type { QualityPreset, ScalingMode } from "./types";
import { PREF_HIDE_TOOLBAR, readBoolPref } from "./prefs";
import { safeInvoke } from "./tauri";

export interface SessionMenuState {
  scalingMode: ScalingMode;
  quality: QualityPreset;
  grayLevels: number;
  localCursor: LocalCursor;
  showRemoteCursor: boolean;
  viewOnly: boolean;
  passthrough: boolean;
  alwaysRefresh: boolean;
  zoomLocked: boolean;
  edgePan: boolean;
  /** False while the SSH probe is running, which greys out File Transfer. */
  filesAvailable: boolean;
  /** True when the monitor list is the server's own rather than guesses. */
  layoutKnown: boolean;
  displays: { id: number; label: string }[];
  displayId: number | null;
  /** `connect`, `follow`, a `WIDTHxHEIGHT` pair, or empty when the session's
   *  desktop size is not the user's to choose, which greys the submenu. */
  resolution: string;
  /** True for an SSH tab: a terminal with no desktop and no file panel, so
   *  the menu says File Transfer is not there rather than offering it. */
  terminal?: boolean;
}

/**
 * Push the menu's state. `session` is null from a window with nothing
 * connected in it, which greys the session half of the menu out rather than
 * leaving the last session's ticks standing over an empty library.
 */
export function syncSessionMenu(
  hideToolbar: boolean,
  session: SessionMenuState | null,
): void {
  void safeInvoke("sync_session_menu", { update: { hideToolbar, session } }, null);
}

/**
 * The menu state an SSH tab reports. An SSH tab has no file panel (File
 * Transfer opens SFTP beside a desktop session), so the item is greyed with
 * the reason in its label. The rest is neutral: no scaling row ticked, no
 * monitors, no resolution to choose.
 */
export function terminalSessionMenu(): SessionMenuState {
  return {
    scalingMode: "custom",
    quality: "auto",
    grayLevels: 256,
    localCursor: "standard",
    showRemoteCursor: false,
    viewOnly: false,
    passthrough: false,
    alwaysRefresh: false,
    zoomLocked: false,
    edgePan: false,
    filesAvailable: false,
    layoutKnown: true,
    displays: [],
    displayId: null,
    resolution: "",
    terminal: true,
  };
}

/**
 * Push the SSH tab's menu state whenever it is the view in front, and again
 * when its window takes the focus. The menu is one object shared by every
 * window and tab, so without this an SSH tab inherited whatever the last
 * desktop session left there, File Transfer enabled included, and the item
 * then did nothing because no view on screen could open a file panel.
 */
export function useTerminalMenu(owns: boolean): void {
  useEffect(() => {
    if (!owns) return;
    const push = (): void =>
      syncSessionMenu(readBoolPref(PREF_HIDE_TOOLBAR, false), terminalSessionMenu());
    push();
    window.addEventListener("focus", push);
    return () => window.removeEventListener("focus", push);
  }, [owns]);
}
