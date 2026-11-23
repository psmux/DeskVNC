// The shape of every call between the phone UI and the Rust side.
// See mobile/CONTRACT.md. Both `tauri.ts` and `mock.ts` implement `Api`.

export type Protocol = "vnc" | "rdp" | "boundary";
export type HostOs = "windows" | "mac" | "linux" | "raspberry" | "unknown";

export interface Host {
  id: string;
  name: string;
  protocol: Protocol;
  /** Empty for a Boundary host, which is reached by code. */
  address: string;
  port: number;
  username: string | null;
  hasPassword: boolean;
  os: HostOs;
  /** One of the palette keys in ui/src/theme, picked by the user. */
  color: string;
  favorite: boolean;
  lastConnectedAt: number | null; // unix ms
  hasThumbnail: boolean;
  /** RDP only. */
  domain?: string | null;
  /** Boundary only: the saved invitation for a computer that allows reconnects. */
  boundaryInvitation?: string | null;
}

export type HostDraft = Omit<Host, "id" | "hasPassword" | "lastConnectedAt" | "hasThumbnail"> & {
  id?: string;
};

export interface FoundComputer {
  address: string;
  port: number;
  protocol: Protocol;
  name: string | null;
  os: HostOs;
}

export type ScanEvent =
  | { type: "found"; item: FoundComputer }
  | { type: "progress"; done: number; total: number }
  | { type: "complete" };

export type ConnectTarget =
  | { kind: "saved"; hostId: string }
  | { kind: "adhoc"; protocol: Protocol; address: string; port: number; username?: string; password?: string }
  | { kind: "boundary"; invitation: string; helperName: string }
  /** The built in demo computer. Handled entirely in the UI (src/api/index.ts
   *  routes it to the in browser mock session), never sent to Rust. */
  | { kind: "demo" };

export type SessionState =
  | { state: "idle" | "resolving" | "connecting" | "negotiating" | "connected" }
  | { state: "authenticating"; method: string }
  | { state: "reconnecting"; attempt: number; next_retry_ms: number; reason: string }
  | { state: "disconnected"; reason: string; can_retry: boolean };

export interface CredentialRequest {
  method: string;
  kind: "password-only" | "username-and-password";
  attempt: number;
  error: string | null;
  truncatesPassword: boolean;
  usernameHint: string | null;
}

export interface SessionStats {
  rtt_ms: number;
  throughput_bps: number;
  fps: number;
}

export type SessionEvent =
  | { sessionId: string; type: "state-changed"; state: SessionState }
  | { sessionId: string; type: "desktop-resize"; width: number; height: number }
  | { sessionId: string; type: "desktop-name"; name: string }
  | { sessionId: string; type: "cursor-position"; x: number; y: number }
  | { sessionId: string; type: "clipboard-text"; text: string }
  | {
      sessionId: string;
      type: "certificate-prompt";
      fingerprint: string;
      subject: string;
      isChange: boolean;
      scheme: string;
    }
  | { sessionId: string; type: "credentials-required"; request: CredentialRequest }
  | { sessionId: string; type: "stats"; stats: SessionStats }
  /** Boundary only: whether the session goes straight to the computer or through a relay. */
  | { sessionId: string; type: "boundary-route"; route: BoundaryRoute }
  /** Why the computer is not taking taps and keys, or null once it does again. */
  | { sessionId: string; type: "boundary-input"; trouble: string | null }
  | { sessionId: string; type: "error"; message: string }
  | { sessionId: string; type: "ended"; durationS: number };

export type BoundaryRoute = "direct" | "relay";

export type KeyCombo = "ctrl-alt-del" | "win" | "alt-tab" | "cmd-tab" | "ctrl-c" | "ctrl-v" | "esc";

export type Quality = "auto" | "speed" | "balanced" | "quality";

/**
 * Android 17's local network permission (Nearby devices in Settings).
 * Anywhere else, and before Android 17, it is always "granted".
 */
export type LocalNetwork = "granted" | "denied";

/**
 * The error `session_connect` gives at once, without dialing, when Android
 * would drop the connection for want of that permission. The same sentence
 * as `REFUSED` in `src-tauri/src/localnet.rs`.
 */
export const LOCAL_NETWORK_REFUSED =
  "Android is not letting DeskVNC reach the local network, so it cannot get to this computer. Allow Nearby devices for DeskVNC.";

export interface Api {
  hostsList(): Promise<Host[]>;
  hostsSave(host: HostDraft): Promise<Host>;
  hostsDelete(id: string): Promise<void>;
  hostsSetSecret(id: string, username: string | null, password: string | null): Promise<void>;
  hostsThumbnail(id: string): Promise<string | null>;

  scanStart(onEvent: (e: ScanEvent) => void): Promise<void>;
  scanStop(): Promise<void>;
  /** What answers at a typed name or address, best first. Empty when nothing
   *  does. `port` limits it to that one port. */
  identify(address: string, port: number | null): Promise<FoundComputer[]>;

  boundaryResolve(code: string): Promise<{ invitation: string }>;
  sessionConnect(
    target: ConnectTarget,
    onFrame: (msg: ArrayBuffer) => void,
    onEvent: (e: SessionEvent) => void,
  ): Promise<{ sessionId: string }>;
  /** Body in the desktop send_input layout. seq starts at 1 per session. */
  sessionInput(sessionId: string, seq: number, body: Uint8Array): Promise<void>;
  sessionText(sessionId: string, text: string): Promise<void>;
  sessionKeyCombo(sessionId: string, combo: KeyCombo): Promise<void>;
  sessionCredentials(sessionId: string, username: string | null, password: string | null, save: boolean): Promise<void>;
  sessionTrust(sessionId: string, fingerprint: string, scheme: string, accept: boolean): Promise<void>;
  sessionQuality(sessionId: string, quality: Quality): Promise<void>;
  sessionClipboard(sessionId: string, text: string): Promise<void>;
  sessionSnapshot(sessionId: string, rgba: Uint8Array, width: number, height: number): Promise<void>;
  sessionDisconnect(sessionId: string): Promise<void>;
  /** Save the computer an adhoc session reached, once it is connected, and
   *  make the session that host's. */
  sessionSaveHost(sessionId: string, host: HostDraft): Promise<Host>;

  /** Whether DeskVNC may use the local network now. */
  localNetworkState(): Promise<LocalNetwork>;
  /** Ask with Android's own prompt, where it still shows one, and say what
   *  the person chose. Answers at once when it is already granted. */
  localNetworkAsk(): Promise<LocalNetwork>;
  /** Open DeskVNC's page in Android settings. */
  openAppSettings(): Promise<void>;
}
