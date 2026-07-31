/**
 * Thin bridge over @tauri-apps/api that degrades gracefully when the backend
 * (or a specific command) does not exist yet. Every call site passes an
 * explicit fallback so `npm run dev` in a plain browser still renders.
 */
import { invoke, isTauri as tauriDetect } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export function inTauri(): boolean {
  try {
    return tauriDetect();
  } catch {
    return false;
  }
}

const missingCommands = new Set<string>();

/**
 * Invoke a backend command; on any failure (no Tauri, command not yet
 * implemented, runtime error) resolve with `fallback` instead of throwing.
 */
export async function safeInvoke<T>(
  cmd: string,
  args: Record<string, unknown> | undefined,
  fallback: T,
): Promise<T> {
  if (!inTauri()) return fallback;
  try {
    return (await invoke<T>(cmd, args)) as T;
  } catch (err) {
    if (!missingCommands.has(cmd)) {
      missingCommands.add(cmd);
      console.warn(`[tauri] command "${cmd}" unavailable:`, err);
    }
    return fallback;
  }
}

/** Invoke that propagates errors (for flows where the UI must react, e.g. connect). */
export async function mustInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (!inTauri()) throw new Error("Backend not available (running outside Tauri)");
  return invoke<T>(cmd, args);
}

/** listen() that no-ops outside Tauri. */
export async function safeListen<T>(
  event: string,
  handler: (payload: T) => void,
): Promise<UnlistenFn> {
  if (!inTauri()) return () => undefined;
  try {
    return await listen<T>(event, (e) => handler(e.payload));
  } catch (err) {
    console.warn(`[tauri] listen "${event}" failed:`, err);
    return () => undefined;
  }
}

// ---------------------------------------------------------------------------
// OS clipboard
// ---------------------------------------------------------------------------
//
// Both directions go through the shell rather than `navigator.clipboard`.
// WebKit (macOS, Linux) only honours `writeText()`/`readText()` while a user
// gesture is still active, and remote clipboard text arrives from the socket
// with no gesture in sight, so the DOM API silently rejects. It stays as the
// fallback for `npm run dev` in a plain browser.

/** Write text into the OS clipboard. Returns false when nothing was written. */
export async function writeClipboard(text: string): Promise<boolean> {
  if (inTauri()) {
    try {
      await invoke("set_local_clipboard", { text });
      return true;
    } catch (err) {
      console.warn("[clipboard] native write failed:", err);
    }
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Read the OS clipboard. Returns null when it could not be read. */
export async function readClipboard(): Promise<string | null> {
  if (inTauri()) {
    try {
      return await invoke<string>("read_local_clipboard");
    } catch (err) {
      console.warn("[clipboard] native read failed:", err);
    }
  }
  try {
    return await navigator.clipboard.readText();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Opening session windows
// ---------------------------------------------------------------------------

/**
 * Preference key (store KV, read by Rust at connect time, NOT localStorage):
 * may one computer have several session windows at once? Default off, i.e.
 * connecting to a machine that is already open just focuses its window.
 */
export const ALLOW_MULTIPLE_SESSIONS_KEY = "allow_multiple_sessions_per_host";

/** Read the "several windows per computer" preference. */
export async function allowsMultipleSessions(): Promise<boolean> {
  const raw = await safeInvoke<string | null>(
    "get_app_setting",
    { key: ALLOW_MULTIPLE_SESSIONS_KEY },
    null,
  );
  return raw === "true" || raw === "1";
}

/** Result of `open_session_window` (`commands::session::SessionWindowOutcome`). */
export interface SessionWindowOutcome {
  /** The window the user is now looking at, new, or the one already open. */
  sessionId: string;
  /** True when an existing window was brought to the front (no new session). */
  reused: boolean;
}

export interface OpenSessionOptions {
  /** Saved host, the shell resolves the endpoint and name from the store. */
  profileId?: string;
  /** Ad-hoc connect (Nearby, quick connect). */
  address?: string;
  port?: number;
  /**
   * Bypass one-window-per-machine for this call, the explicit
   * "Connect in new window" command, which is only offered when the
   * preference that allows several windows per computer is on.
   */
  forceNew?: boolean;
}

/**
 * Open (or focus) a session window.
 *
 * Every connect gesture goes through here, so the shell can apply one rule in
 * one place: by default a machine that is already connected gets its existing
 * window restored and raised instead of a second session. `reused` says which
 * happened, so the caller can skip "connected again" bookkeeping.
 */
export function openSessionWindow(
  options: OpenSessionOptions,
): Promise<SessionWindowOutcome | null> {
  return safeInvoke<SessionWindowOutcome | null>(
    "open_session_window",
    {
      profileId: options.profileId ?? null,
      address: options.address ?? null,
      port: options.port ?? null,
      forceNew: options.forceNew ?? false,
    },
    null,
  );
}

// ---------------------------------------------------------------------------
// Interactive authentication (PRD/10 §3.4)
// ---------------------------------------------------------------------------

/**
 * Answer a `credentials-required` prompt. The session is parked mid-handshake
 * until this (or {@link cancelCredentials}) arrives.
 *
 * `username` must be null for password-only methods. `save` is the "remember
 * this" checkbox, the shell holds it in memory and only writes to the
 * keychain once the server actually accepts it, so a wrong password is never
 * persisted.
 *
 * SECURITY INVARIANT: passwords travel JS → Rust only. There is no read-back
 * command, and nothing here ever returns a secret. Deliberately NOT routed
 * through `safeInvoke`: a swallowed failure would leave the user staring at a
 * dialog that silently did nothing.
 */
export async function provideCredentials(
  sessionId: string,
  username: string | null,
  password: string,
  save: boolean,
): Promise<void> {
  if (!inTauri()) return;
  await invoke("provide_credentials", { sessionId, username, password, save });
}

/** Dismiss the prompt and abandon the connection attempt. */
export async function cancelCredentials(sessionId: string): Promise<void> {
  await safeInvoke("cancel_credentials", { sessionId }, null);
}

// ---------------------------------------------------------------------------
// Native keyboard capture, shortcut pass-through (PRD/06 §3 Tier 2)
// ---------------------------------------------------------------------------

/**
 * `vnc_input_capture::CaptureStatus`, serialized internally tagged on `state`
 * with kebab-case variants, the same convention as `SessionState`.
 *
 * `unsupported` is not only Wayland: macOS reports it while another app holds
 * secure keyboard entry, because the tap then receives nothing. `reason` is
 * always a human-readable sentence, safe to render as text.
 */
export type CaptureStatus =
  | { state: "active" }
  | { state: "inactive" }
  | { state: "permission-required" }
  | { state: "unsupported"; reason: string };

/** Payload of the app-wide `capture://event`. */
export interface CaptureEvent {
  status: CaptureStatus;
  sessionId: string | null;
}

export const CAPTURE_INACTIVE: CaptureStatus = { state: "inactive" };

/**
 * Turn pass-through ON for a session.
 *
 * A missing permission or an unsupported platform comes back as a *status*, not
 * a rejection, the UI turns those into the onboarding and explanation panels.
 * Outside Tauri this resolves `inactive` so the browser dev build still works.
 */
export function captureStart(sessionId: string): Promise<CaptureStatus> {
  return safeInvoke<CaptureStatus>("capture_start", { sessionId }, CAPTURE_INACTIVE);
}

/** Turn pass-through OFF. Safe to call even if capture was never started. */
export function captureStop(sessionId: string): Promise<CaptureStatus> {
  return safeInvoke<CaptureStatus>("capture_stop", { sessionId }, CAPTURE_INACTIVE);
}

/** Poll the live capture status (the toolbar indicator's source of truth). */
export function captureStatus(): Promise<CaptureStatus> {
  return safeInvoke<CaptureStatus>("capture_status", undefined, CAPTURE_INACTIVE);
}

/** Is the OS permission already granted? Never prompts. */
export function capturePermissionGranted(): Promise<boolean> {
  return safeInvoke<boolean>("capture_permission_granted", undefined, false);
}

/**
 * Ask the OS to show its permission prompt (macOS Accessibility).
 *
 * Only ever call this from an explicit user action, after explaining why, * an unprompted Accessibility request reads as spyware (PRD/06 §3).
 */
export function captureRequestPermission(): Promise<null> {
  return safeInvoke<null>("capture_request_permission", undefined, null);
}

/** Subscribe to capture status changes broadcast by the shell. */
export function listenCapture(handler: (event: CaptureEvent) => void): Promise<UnlistenFn> {
  return safeListen<CaptureEvent>("capture://event", handler);
}

/** Deep link to the macOS pane where Accessibility is granted. */
export const MACOS_ACCESSIBILITY_SETTINGS_URL =
  "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

/**
 * Open a URL in the OS handler (the System Settings deep link).
 *
 * Invoked through the opener plugin's command directly rather than its JS
 * package, which this app does not bundle. The capability files scope this to
 * `x-apple.systempreferences:*` only, so it cannot become a general
 * "open anything" hole in the session window.
 */
export async function openExternal(url: string): Promise<void> {
  if (!inTauri()) {
    window.open(url, "_blank", "noopener");
    return;
  }
  await safeInvoke("plugin:opener|open_url", { url }, null);
}

// ---------------------------------------------------------------------------
// File transfer, SFTP sidecar (PRD/08)
// ---------------------------------------------------------------------------

/**
 * `vnc_files::RemoteEntry`. **Every string is server-supplied and untrusted**, * render as text, never as HTML, and never build a local path from `name`
 * yourself: the Rust side normalises and rejects traversal.
 */
export interface RemoteEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  /** unix seconds */
  modified: number | null;
  /** permission bits, `0o7777` masked */
  mode: number;
  isSymlink: boolean;
}

/** `commands::files::LocalEntry`, the left-hand pane. */
export interface LocalEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modified: number | null;
  isSymlink: boolean;
}

/**
 * Result of `files_connect`.
 *
 * `host-key-prompt` is first contact: show the fingerprint and, if the user
 * accepts, call `filesConnect` again with `acceptHostKey` set to it.
 * `host-key-changed` is a **hard stop**, there is deliberately no way to
 * accept it (PRD/08 §4).
 */
export type FilesConnectOutcome =
  | { status: "connected"; host: string; port: number; username: string; home: string }
  | { status: "host-key-prompt"; host: string; port: number; keyType: string; fingerprint: string }
  | { status: "host-key-changed"; host: string; port: number; expected: string; actual: string };

export interface FilesStatus {
  connected: boolean;
  host: string | null;
  port: number | null;
  username: string | null;
  home: string | null;
  activeTransfers: number;
  queueLimit: number;
}

export type SshAuthKind = "stored" | "key-file" | "agent";

export interface FilesConnectConfig {
  host: string;
  port?: number;
  username: string;
  auth?: SshAuthKind;
  /** private key path for `key-file` auth (chosen in the native dialog) */
  keyPath?: string | null;
  /** host profile whose keychain entry holds the passphrase, never the secret itself */
  profileId?: string | null;
  defaultRemoteDir?: string | null;
  conflict?: "resume" | "skip" | "overwrite" | "rename";
}

/**
 * `files://event`, per-session transfer progress. Same conventions as
 * `session://event`: flat payload, `sessionId` alongside a kebab-case `type`.
 */
export type FilesEventPayload =
  | {
      sessionId: string;
      type: "started";
      id: string;
      name: string;
      total: number;
      direction: "upload" | "download";
    }
  | { sessionId: string; type: "progress"; id: string; transferred: number; total: number; bytesPerSec: number }
  | { sessionId: string; type: "completed"; id: string }
  | { sessionId: string; type: "failed"; id: string; error: string }
  | { sessionId: string; type: "cancelled"; id: string };

/** Is SSH reachable? Drives the enabled state of the toolbar Files button. */
export function filesProbe(host: string, port?: number): Promise<boolean> {
  return safeInvoke<boolean>("files_probe", { host, port: port ?? 22 }, false);
}

export function filesConnect(
  sessionId: string,
  config: FilesConnectConfig,
  acceptHostKey?: string,
): Promise<FilesConnectOutcome> {
  return mustInvoke<FilesConnectOutcome>("files_connect", {
    sessionId,
    config,
    acceptHostKey: acceptHostKey ?? null,
  });
}

export function filesDisconnect(sessionId: string): Promise<null> {
  return safeInvoke<null>("files_disconnect", { sessionId }, null);
}

const FILES_DISCONNECTED: FilesStatus = {
  connected: false,
  host: null,
  port: null,
  username: null,
  home: null,
  activeTransfers: 0,
  queueLimit: 3,
};

export function filesStatus(sessionId: string): Promise<FilesStatus> {
  return safeInvoke<FilesStatus>("files_status", { sessionId }, FILES_DISCONNECTED);
}

export function filesHome(sessionId: string): Promise<string> {
  return mustInvoke<string>("files_home", { sessionId });
}

export function filesList(sessionId: string, path: string): Promise<RemoteEntry[]> {
  return mustInvoke<RemoteEntry[]>("files_list", { sessionId, path });
}

export function filesMkdir(sessionId: string, path: string): Promise<null> {
  return mustInvoke<null>("files_mkdir", { sessionId, path });
}

export function filesRemove(sessionId: string, path: string, recursive: boolean): Promise<null> {
  return mustInvoke<null>("files_remove", { sessionId, path, recursive });
}

export function filesRename(sessionId: string, from: string, to: string): Promise<null> {
  return mustInvoke<null>("files_rename", { sessionId, from, to });
}

/** Queue uploads; resolves with one transfer id per local path. */
export function filesUpload(
  sessionId: string,
  localPaths: string[],
  remoteDir: string,
): Promise<string[]> {
  return mustInvoke<string[]>("files_upload", { sessionId, localPaths, remoteDir });
}

export function filesDownload(
  sessionId: string,
  remotePaths: string[],
  localDir: string,
): Promise<string[]> {
  return mustInvoke<string[]>("files_download", { sessionId, remotePaths, localDir });
}

export function filesCancel(sessionId: string, transferId: string): Promise<boolean> {
  return safeInvoke<boolean>("files_cancel", { sessionId, transferId }, false);
}

export function filesLocalHome(): Promise<string> {
  return safeInvoke<string>("files_local_home", undefined, "");
}

export function filesLocalList(path?: string | null): Promise<LocalEntry[]> {
  return mustInvoke<LocalEntry[]>("files_local_list", { path: path ?? null });
}

export function filesLocalMkdir(path: string): Promise<null> {
  return mustInvoke<null>("files_local_mkdir", { path });
}

export function filesLocalRename(from: string, to: string): Promise<null> {
  return mustInvoke<null>("files_local_rename", { from, to });
}

export function filesLocalRemove(path: string, recursive: boolean): Promise<null> {
  return mustInvoke<null>("files_local_remove", { path, recursive });
}

/** Subscribe to this window's transfer events. */
export function listenFiles(handler: (event: FilesEventPayload) => void): Promise<UnlistenFn> {
  return safeListen<FilesEventPayload>("files://event", handler);
}

/**
 * Native open dialog, invoked through the dialog plugin's command directly, * this app does not bundle `@tauri-apps/plugin-dialog`. PRD/08 §4: local file
 * access is user-chosen paths only, never a broad fs capability.
 */
async function nativeOpen(options: Record<string, unknown>): Promise<string[]> {
  if (!inTauri()) return [];
  const result = await safeInvoke<unknown>("plugin:dialog|open", { options }, null);
  if (result === null || result === undefined) return [];
  const one = (value: unknown): string | null => {
    if (typeof value === "string") return value;
    if (value && typeof value === "object" && "path" in value) {
      const p = (value as { path?: unknown }).path;
      return typeof p === "string" ? p : null;
    }
    return null;
  };
  const list = Array.isArray(result) ? result : [result];
  return list.map(one).filter((p): p is string => p !== null);
}

/** Pick files to upload. */
export function pickLocalFiles(title = "Choose files to send"): Promise<string[]> {
  return nativeOpen({ multiple: true, directory: false, title });
}

/** Pick the directory downloads land in. */
export async function pickLocalDirectory(
  title = "Choose a destination folder",
  defaultPath?: string,
): Promise<string | null> {
  const picked = await nativeOpen({
    multiple: false,
    directory: true,
    title,
    defaultPath,
  });
  return picked[0] ?? null;
}

/**
 * Forget every trusted key pin for an endpoint, TLS certificate and RA2 key
 * alike.
 *
 * A changed server identity is a deliberate hard stop, so a machine that was
 * legitimately rebuilt needs an explicit way back to first-contact state. The
 * user means "stop trusting this machine", so no scheme is left behind.
 */
export async function forgetCertificate(host: string, port: number): Promise<void> {
  await safeInvoke<null>("forget_certificate", { host, port }, null);
}
