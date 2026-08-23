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
import type { LocalCursor } from "../state/SettingsContext";
import type { QualityPreset, ScalingMode } from "./types";
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
