/**
 * Shared domain types mirroring the backend contract.
 *
 * Sources of truth, keep field-for-field in sync, see src-tauri/IPC_CONTRACT.md:
 *   HostProfile / HostGroup / HostTag / HistoryEntry -> crates/vnc-store/src/models.rs
 *     (all `#[serde(rename_all = "camelCase")]`)
 *   SessionState / SessionStats                      -> crates/vnc-core/src/types.rs
 *     (SessionState is `#[serde(tag = "state", rename_all = "kebab-case")]`;
 *      SessionStats has NO rename_all, so its fields stay snake_case)
 *   session:// and discovery:// events                -> src-tauri/src/commands/
 */

export type OsHint = "macos" | "windows" | "linux" | "qemu" | "unknown";
/**
 * How discovery arrived at a host's display name. Three of these are only ever
 * answered by a Windows machine, see `WINDOWS_NAME_SOURCES` below.
 */
export type NameSource =
  | "mdns"
  | "mdns-ptr"
  | "reverse-dns"
  | "netbios"
  | "llmnr"
  | "msrpc-epm"
  | "rdp-cert";
export type QualityPreset = "auto" | "high" | "medium" | "low" | "bw";
export type ScalingMode = "fit" | "aspect-fit" | "actual" | "custom" | "remote-resize";
export type SecurityLevel = "verified" | "unverified" | "unencrypted" | "unknown";

/**
 * Mirrors `vnc_store::HostProfile`. Every field here exists on the Rust
 * struct: `save_host` deserializes a WHOLE `HostProfile`, so a partial object
 * is rejected, build one with `blankHostProfile()` and override.
 */
export interface HostProfile {
  id: string;
  friendlyName: string;
  address: string;
  port: number;
  groupId: string | null;
  /** Rust `Option<String>`; constrained to OsHint values by convention. */
  osHint: OsHint | null;
  serverHint: string | null;
  securityPref: string | null;
  qualityPref: QualityPreset;
  colorDepth: number | null;
  scalingMode: ScalingMode;
  keyboardMode: string;
  passthrough: boolean;
  viewOnly: boolean;
  /** JSON blob: `{enabled, host, user, port, auth, ...}`. */
  sshTunnel: string | null;
  wolMac: string | null;
  wolBroadcast: string | null;
  networkId: string | null;
  certPin: string | null;
  hasPassword: boolean;
  thumbnailAt: number | null;
  lastConnected: number | null;
  connectCount: number;
  /** Tag ids, joined from `host_tags` (Rust field name is `tags`). */
  tags: string[];
  createdAt: number;
  updatedAt: number;

  // ---- UI-local only: NOT columns in the hosts table, NOT sent by Rust ----
  /** Client-side flag; the backend has no `favorite` column yet. */
  favorite?: boolean;
  /** Client-side reachability guess; the backend never sets it. */
  online?: boolean | null;
}

/** A blank profile with every required field present, ready to override. */
export function blankHostProfile(): HostProfile {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: "",
    friendlyName: "",
    address: "",
    port: 5900,
    groupId: null,
    osHint: "unknown",
    serverHint: null,
    securityPref: null,
    qualityPref: "auto",
    colorDepth: null,
    scalingMode: "fit",
    keyboardMode: "auto",
    passthrough: false,
    viewOnly: false,
    sshTunnel: null,
    wolMac: null,
    wolBroadcast: null,
    networkId: null,
    certPin: null,
    hasPassword: false,
    thumbnailAt: null,
    lastConnected: null,
    connectCount: 0,
    tags: [],
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * The `hosts.sshTunnel` JSON blob, camelCase, mirrors the Rust
 * `SshTunnelSettings` in `src-tauri/src/tunnel.rs`. When `enabled`, the RFB
 * stream runs over a `direct-tcpip` channel of an SSH connection to the
 * gateway instead of a plain TCP socket.
 */
export interface SshTunnelSettings {
  enabled: boolean;
  /** SSH gateway host; empty means "the profile's VNC address". */
  host: string;
  port: number;
  /** Remote user; empty means "same as the local user". */
  user: string;
  /** Same auth kinds as the Files panel; secrets stay in the keychain. */
  auth: "stored" | "key-file" | "agent";
  keyPath: string | null;
}

export function blankSshTunnel(): SshTunnelSettings {
  return { enabled: false, host: "", port: 22, user: "", auth: "stored", keyPath: null };
}

/**
 * Read a stored tunnel blob. Tolerant of missing fields (older blobs) but a
 * blob that is not an object at all reads as "no tunnel", the Rust side is
 * the one that must refuse to connect on a malformed blob, the editor just
 * needs something to show.
 */
export function parseSshTunnel(raw: string | null | undefined): SshTunnelSettings | null {
  if (!raw || !raw.trim() || raw.trim() === "null") return null;
  try {
    const v: unknown = JSON.parse(raw);
    if (!v || typeof v !== "object") return null;
    const o = v as Record<string, unknown>;
    return {
      enabled: o.enabled === true,
      host: typeof o.host === "string" ? o.host : "",
      port: typeof o.port === "number" && Number.isFinite(o.port) ? o.port : 22,
      user: typeof o.user === "string" ? o.user : "",
      auth: o.auth === "key-file" || o.auth === "agent" ? o.auth : "stored",
      keyPath: typeof o.keyPath === "string" && o.keyPath ? o.keyPath : null,
    };
  } catch {
    return null;
  }
}

/**
 * Serialize for the `sshTunnel` column. A tunnel that was never enabled and
 * never edited stores `null`, keeping the column empty for the overwhelming
 * majority of hosts.
 */
export function serializeSshTunnel(t: SshTunnelSettings | null): string | null {
  if (!t) return null;
  const blank = blankSshTunnel();
  const untouched =
    !t.enabled &&
    t.host === blank.host &&
    t.port === blank.port &&
    t.user === blank.user &&
    t.auth === blank.auth &&
    t.keyPath === blank.keyPath;
  return untouched ? null : JSON.stringify(t);
}

/**
 * Mirrors `SessionConnectOutcome` in `commands/session.rs` (tagged on
 * `status`). The ssh variants only occur for a profile whose tunnel is
 * enabled, before any session exists.
 */
export type SessionConnectOutcome =
  | { status: "started"; sessionId: string }
  | {
      status: "ssh-host-key-prompt";
      host: string;
      port: number;
      keyType: string;
      fingerprint: string;
    }
  | {
      status: "ssh-host-key-changed";
      host: string;
      port: number;
      expected: string;
      actual: string;
    };

/** Mirrors `vnc_store::Group`. */
export interface HostGroup {
  id: string;
  name: string;
  parentId: string | null;
  sort: number;
}

/** Mirrors `vnc_store::Tag`. */
export interface HostTag {
  id: string;
  name: string;
  color: string;
}

/** Mirrors `vnc_store::HistoryEntry` (the tail fields are `Option<_>`). */
export interface HistoryEntry {
  id: number;
  hostId: string;
  connectedAt: number;
  durationS: number | null;
  securityType: string | null;
  disconnectReason: string | null;
}

/** Mirrors `vnc_store::StoredCredentials`, write-only across IPC. */
export interface StoredCredentials {
  vncPassword?: string | null;
  vencryptUser?: string | null;
  vencryptPass?: string | null;
  sshPassphrase?: string | null;
}

/** Where secrets live; mirrors `vnc_store::CredentialBackend`. */
export type CredentialBackend = "OsKeychain" | "EncryptedFile" | "Locked";

/**
 * Shaped by the shell in `src-tauri/src/commands/discovery.rs`, NOT a direct
 * serialization of `vnc_discovery::DiscoveredHost`. `id` is `"<address>:<port>"`.
 */
export interface DiscoveredHost {
  id: string;
  name: string;
  address: string;
  port: number;
  osHint: OsHint;
  serverHint: string;
  securityHint: string | null;
  security: SecurityLevel;
  securityTypes: number[];
  source: "mdns" | "scan" | "manual";
  /**
   * Hardware address learned during discovery (NetBIOS), e.g.
   * `"9c:53:22:6a:36:7c"`. Optional as well as nullable: an event emitted by an
   * older shell build carries no such field at all, and a host found by mDNS
   * only never learns one. Read it through `hostMac()`.
   */
  mac?: string | null;
  /**
   * Which probe produced `name`. Optional/nullable for the same reason as
   * `mac`. A name from `netbios`, `msrpc-epm` or `rdp-cert` is PROOF the host
   * is Windows, nothing else answers those, so it outranks the substring
   * guessing behind `osHint`. Read it through `resolvedOsHint()`.
   */
  nameSource?: NameSource | null;
  /** Always null from the shell; the UI de-dupes against its own host list. */
  savedHostId: string | null;
}

/** Name sources only a Windows host can answer. */
const WINDOWS_NAME_SOURCES: readonly string[] = ["netbios", "msrpc-epm", "rdp-cert"];

/** True when this name could only have come from a Windows machine. */
export function isWindowsNameSource(source: NameSource | null | undefined): boolean {
  return typeof source === "string" && WINDOWS_NAME_SOURCES.includes(source);
}

/**
 * The OS to believe for a discovered host: proof from `nameSource` first, then
 * the backend's `osHint` guess. Tolerates a host object from an older shell
 * build, where neither field need be present.
 */
export function resolvedOsHint(host: {
  osHint?: OsHint | null;
  nameSource?: NameSource | null;
}): OsHint {
  if (isWindowsNameSource(host.nameSource)) return "windows";
  return host.osHint ?? "unknown";
}

/** Human phrase for how a name was learned, or null when it is not known. */
export function nameSourceLabel(source: NameSource | null | undefined): string | null {
  switch (source) {
    case "mdns":
    case "mdns-ptr":
      return "Bonjour/mDNS";
    case "reverse-dns":
      return "reverse DNS";
    case "netbios":
      return "NetBIOS";
    case "llmnr":
      return "LLMNR";
    case "msrpc-epm":
      return "MS-RPC endpoint mapper";
    case "rdp-cert":
      return "RDP certificate";
    default:
      return null;
  }
}

/**
 * A discovered host's MAC as a trimmed string, or null.
 *
 * Guards the field rather than trusting it: it may be absent, null, or (from a
 * mismatched build) something that is not a string at all, and a stray
 * `undefined` reaching an input's `value` is a React warning plus a literal
 * "undefined" typed into the Wake-on-LAN field.
 */
export function hostMac(host: { mac?: string | null } | null | undefined): string | null {
  const raw = host?.mac;
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Which server key a trust-on-first-use pin describes (`PinScheme` in
 * crates/vnc-core/src/types.rs).
 *
 * "tls" is a VeNCrypt X.509 certificate, "ra2" a RealVNC RSA key. One server
 * can offer both, and the fingerprints are unrelated, so a prompt says which
 * one it is about and the answer must carry the same value back untouched.
 * This never reaches the user; it is routing, not copy.
 */
export type PinScheme = "tls" | "ra2";

/** SessionState mirrors the serde repr: tag = "state", kebab-case. */
export type SessionState =
  | { state: "idle" }
  | { state: "resolving" }
  | { state: "connecting" }
  | { state: "authenticating"; method: string }
  | { state: "negotiating" }
  | { state: "connected" }
  | { state: "reconnecting"; attempt: number; next_retry_ms: number; reason: string }
  | { state: "disconnected"; reason: string; can_retry: boolean };

/**
 * `vnc_core::RttSource`, serde `rename_all = "kebab-case"`. Says which
 * instrument produced `SessionStats.rtt_ms`, because the three are not
 * comparable: `fence` is an exact round trip, `idle-probe` is a one-pixel
 * request timed into a quiet screen, and `update-pipeline` is the passive
 * readout taken on the normal update path (always available, including on
 * the Fence-less TightVNC family, but it includes this client's own decode
 * of the previous update, so it reads high). `none` means nothing has been
 * measured yet and `rtt_ms` is 0.
 */
export type RttSource = "none" | "fence" | "idle-probe" | "update-pipeline";

/** `vnc_core::SessionStats`, no rename_all, so these stay snake_case. */
export interface SessionStats {
  rtt_ms: number;
  /** Which instrument produced `rtt_ms`; `#[serde(default)]` in Rust. */
  rtt_source: RttSource;
  /**
   * 0 to 1: fraction of the last stats tick the client spent receiving and
   * decoding framebuffer updates. Approaches 1 when the server is streaming
   * flat out, approaches 0 on an idle desktop. `#[serde(default)]` in Rust.
   */
  server_duty_cycle: number;
  throughput_bps: number;
  /** TX bits/sec over the 1 s stats tick, mirroring the RX `throughput_bps`. */
  throughput_up_bps: number;
  fps: number;
  decode_ms: number;
  bytes_received: number;
  /** Cumulative TX bytes on the RFB transport (plaintext side). */
  bytes_sent: number;
  rects_decoded: number;
  current_encoding: number;
  jpeg_quality: number;
}

/** `vnc_core::CredentialKind`, serde `rename_all = "kebab-case"`. */
export type CredentialKind = "password-only" | "username-and-password";

/**
 * `vnc_core::CredentialRequest` (camelCase). Raised from inside the security
 * handshake while the session is PAUSED waiting for an answer, the UI must
 * reply with `provide_credentials` or `cancel_credentials` (PRD/10 §3.4).
 *
 * `method` and `error` are server-influenced strings: render as text only.
 */
export interface CredentialRequest {
  /** e.g. "VNC Authentication", "VeNCrypt (X509Plain)". */
  method: string;
  kind: CredentialKind;
  /** 1-based; greater than 1 means the previous attempt was rejected. */
  attempt: number;
  error: string | null;
  /** DES-based methods silently truncate to 8 chars, the UI must warn. */
  truncatesPassword: boolean;
  usernameHint: string | null;
}

/**
 * JSON payload of `session://event`. The discriminator and `sessionId` are on
 * the SAME object, the payload is flat, there is no nested `event` field.
 * Cursor SHAPES are not here: they arrive as binary msg_type 2 on the channel.
 */
export type SessionEvent =
  | { type: "state-changed"; state: SessionState }
  | { type: "desktop-resize"; width: number; height: number }
  | { type: "desktop-name"; name: string }
  | { type: "cursor-position"; x: number; y: number }
  | { type: "clipboard-text"; text: string }
  | { type: "clipboard-notify"; formats: number }
  | { type: "bell" }
  | {
      type: "certificate-prompt";
      fingerprint: string;
      subject: string;
      isChange: boolean;
      scheme: PinScheme;
    }
  | { type: "credentials-required"; request: CredentialRequest }
  | { type: "stats"; stats: SessionStats }
  | { type: "error"; message: string }
  | { type: "ended"; durationS: number };

export type SessionEventPayload = SessionEvent & { sessionId: string };

/** JSON payload of `discovery://event` (normalized by the shell). */
export type DiscoveryEventPayload =
  | { type: "found"; host: DiscoveredHost }
  | { type: "updated"; host: DiscoveredHost }
  | { type: "lost"; id: string }
  | { type: "scan-progress"; done: number; total: number }
  | { type: "scan-complete"; found: number }
  | { type: "error"; message: string };

export interface ScanProgress {
  running: boolean;
  done: number;
  total: number;
}
