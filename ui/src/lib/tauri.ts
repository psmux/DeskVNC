/**
 * Thin bridge over @tauri-apps/api that degrades gracefully when the backend
 * (or a specific command) does not exist yet. Every call site passes an
 * explicit fallback so `npm run dev` in a plain browser still renders.
 */
import { invoke, isTauri as tauriDetect } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ProtocolKind } from "./types";

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

/** Where a session is shown (`commands::session::SessionTarget`). */
export type SessionTarget = "window" | "tab";

/**
 * Connection parameters for a tab the caller has to mount itself
 * (`commands::session::SessionTabParams`).
 *
 * Exactly what a session window would have read out of its own query string;
 * a tab has no URL, so the shell hands them back as data instead.
 */
export interface SessionTabParams {
  profileId: string | null;
  address: string;
  port: number;
  name: string;
  /** Unconditional here, unlike the window's query key: this is a fresh JSON
   *  payload with no legacy readers. */
  protocol: ProtocolKind;
}

/** Result of `open_session_window` (`commands::session::SessionWindowOutcome`). */
export interface SessionWindowOutcome {
  /** The window the user is now looking at, new, or the one already open. */
  sessionId: string;
  /** True when an existing window was brought to the front (no new session). */
  reused: boolean;
  /**
   * Window or tab. A reuse reports where the session it found already lives,
   * which is not necessarily where a new one would have gone: a machine opened
   * in its own window before the preference was switched to tabs is still
   * found, and still raised as a window.
   */
  target: SessionTarget;
  /** Present only for a NEW tab: what to mount the viewer with. */
  params?: SessionTabParams;
}

export interface OpenSessionOptions {
  /** Saved host, the shell resolves the endpoint and name from the store. */
  profileId?: string;
  /** Ad-hoc connect (Nearby, quick connect). */
  address?: string;
  port?: number;
  /**
   * Which protocol to speak, for an ad-hoc connect. A saved host resolves it
   * from the profile, exactly as it already resolves the endpoint and the
   * name, so this is only for the case where there is no profile to ask.
   */
  protocol?: ProtocolKind;
  /**
   * Bypass one-window-per-machine for this call, the explicit
   * "Connect in new window" command, which is only offered when the
   * preference that allows several windows per computer is on.
   */
  forceNew?: boolean;
  /**
   * Show this session as a tab in the library window instead of giving it a
   * window of its own. The shell still applies every other rule (profile
   * resolution, one session per machine) and hands back `params` to mount.
   */
  asTab?: boolean;
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
      protocol: options.protocol ?? null,
      forceNew: options.forceNew ?? false,
      asTab: options.asTab ?? false,
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
 * `username` must be null for password-only methods, and `domain` for
 * everything except an RDP logon that has one. `save` is the "remember
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
  domain: string | null,
  password: string,
  save: boolean,
): Promise<void> {
  if (!inTauri()) return;
  await invoke("provide_credentials", { sessionId, username, domain, password, save });
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

// ---------------------------------------------------------------------------
// Remote shell (ssh-core)
// ---------------------------------------------------------------------------

/**
 * Which terminal multiplexer to attach to on the far side.
 *
 * This is what makes reconnecting worth anything. With `none`, a dropped link
 * destroys the remote PTY and everything running under it, so reconnecting
 * gets you a fresh empty shell. With a multiplexer the session belongs to a
 * daemon on the remote machine and survives the drop, so reattaching puts you
 * back in front of the same work.
 */
export type MultiplexerKind = "none" | "tmux" | "screen" | "zellij" | "custom";

export interface MultiplexerConfig {
  kind?: MultiplexerKind;
  /** letters, digits, dashes and underscores only, the shell rejects the rest */
  sessionName?: string;
  /** for `custom`; `{session}` is substituted */
  customCommand?: string | null;
  /** open a plain login shell when the multiplexer is not installed */
  fallbackToShell?: boolean;
}

export interface SshConnectConfig {
  host: string;
  port?: number;
  /** empty means "the same user as here" */
  username?: string;
  auth?: SshAuthKind;
  /** private key path for `key-file` auth (chosen in the native dialog) */
  keyPath?: string | null;
  /** host profile whose keychain entry holds the secret, never the secret itself */
  profileId?: string | null;
  cols?: number;
  rows?: number;
  multiplexer?: MultiplexerConfig;
}

/**
 * Result of `ssh_connect`. Same three-way shape as `filesConnect`, and for
 * the same reason: a host key is a decision for the user, not an error.
 *
 * `host-key-prompt` is first contact: show the fingerprint and, if the user
 * accepts, call `sshConnect` again with `acceptHostKey` set to it.
 * `host-key-changed` is a **hard stop**, there is deliberately no way to
 * accept it.
 */
export type SshConnectOutcome =
  | { status: "ready"; endpoint: string }
  | { status: "host-key-prompt"; host: string; port: number; keyType: string; fingerprint: string }
  | { status: "host-key-changed"; host: string; port: number; expected: string; actual: string };

/** The session's own view of where it is. */
export type SshTerminalState =
  | { state: "connecting"; endpoint: string }
  | {
      state: "connected";
      endpoint: string;
      /** null for a plain login shell, either by choice or by fallback */
      multiplexer: MultiplexerKind | null;
      /** true when this attach found work already running, rather than starting fresh */
      resumed: boolean;
    }
  | { state: "reconnecting"; attempt: number; delayMs: number; reason: string }
  | { state: "disconnected"; reason: string; canRetry: boolean; symbol: string | null };

/**
 * `ssh://event`, per-session terminal traffic. Flat payload, `sessionId`
 * alongside a kebab-case `type`, same as `files://event`.
 *
 * `data` is base64 because a PTY carries bytes, not text: a chunk can end
 * mid-UTF-8 and control bytes are ordinary content. Decode to a `Uint8Array`
 * and hand it to the emulator, never to `JSON.parse` or a string API.
 *
 * `reset` is the important one and it is deliberately not `output`. Those
 * bytes are the *shell's* correction after a link died, undoing mouse
 * reporting, bracketed paste and the alternate screen that the remote never
 * got the chance to switch off. Write them to the emulator exactly like
 * output, but never log or replay them as if the server had said them.
 */
export type SshEventPayload =
  | { sessionId: string; type: "output"; data: string }
  | { sessionId: string; type: "reset"; data: string }
  | { sessionId: string; type: "bell" }
  | { sessionId: string; type: "notice"; message: string }
  | ({ sessionId: string; type: "state" } & SshTerminalState);

/** Is SSH reachable? Drives the enabled state of the Terminal button. */
export function sshProbe(host: string, port?: number): Promise<boolean> {
  return safeInvoke<boolean>("ssh_probe", { host, port: port ?? 22, timeoutMs: 1500 }, false);
}

/**
 * Which WSL distributions does this host have installed?
 *
 * Connects, asks `wsl.exe -l -q`, and drops the connection. Routed through
 * `safeInvoke`, not `mustInvoke`: an empty list is the *documented* answer
 * for every ordinary case (no WSL, no `wsl.exe`, the host key not trusted
 * yet, credentials not held), not a failure, and this is a Detect button in a
 * settings form, not a connect attempt, so nothing here should ever surface
 * an error dialog. The host editor already knows what to do with an empty
 * answer: fall back to a free-text distribution field.
 */
export function sshListWslDistros(config: SshConnectConfig): Promise<string[]> {
  return safeInvoke<string[]>("ssh_list_wsl_distros", { config }, []);
}

/**
 * Open a supervised remote shell. `windowLabel` is the window that will
 * receive this session's `ssh://event` traffic.
 */
export function sshConnect(
  sessionId: string,
  windowLabel: string,
  config: SshConnectConfig,
  acceptHostKey?: string,
): Promise<SshConnectOutcome> {
  return mustInvoke<SshConnectOutcome>("ssh_connect", {
    sessionId,
    windowLabel,
    config: { ...config, acceptHostKey: acceptHostKey ?? null },
  });
}

/** Send keystrokes. Bytes in, base64 on the wire. */
export function sshSend(sessionId: string, bytes: Uint8Array): Promise<null> {
  return safeInvoke<null>("ssh_send", { sessionId, data: bytesToBase64(bytes) }, null);
}

export function sshResize(sessionId: string, cols: number, rows: number): Promise<null> {
  return safeInvoke<null>("ssh_resize", { sessionId, cols, rows }, null);
}

/** Skip the remaining reconnect backoff and retry now. */
export function sshReconnectNow(sessionId: string): Promise<null> {
  return safeInvoke<null>("ssh_reconnect_now", { sessionId }, null);
}

export function sshDisconnect(sessionId: string): Promise<null> {
  return safeInvoke<null>("ssh_disconnect", { sessionId }, null);
}

/** Subscribe to this window's terminal traffic. */
export function listenSsh(handler: (event: SshEventPayload) => void): Promise<UnlistenFn> {
  return safeListen<SshEventPayload>("ssh://event", handler);
}

/**
 * base64 without going through a string of code points.
 *
 * `btoa(String.fromCharCode(...bytes))` is the usual one-liner and it is
 * wrong twice over: spreading a large array blows the argument limit, and any
 * byte above 0x7f becomes a multi-byte character that `btoa` then rejects.
 * Terminal input hits both the moment somebody pastes.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** The inverse, for `output` and `reset` payloads. */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}
