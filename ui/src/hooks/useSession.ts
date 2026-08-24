/**
 * Session lifecycle hook. Wires the framebuffer Channel and `session://event`
 * listener. High-frequency data (frames, cursor) flows through `bridge`
 * callbacks straight to the renderer, it NEVER touches React state. Only
 * low-frequency state (connection state, stats, prompts) is React state.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import {
  cancelCredentials,
  inTauri,
  provideCredentials,
  safeInvoke,
  safeListen,
} from "../lib/tauri";
import {
  mockCredentialRequest,
  mockDisconnectReason,
  mockThumbnailKey,
  saveMockThumbnail,
} from "../lib/mock";
import {
  MSG_CURSOR,
  MSG_FRAMEBUFFER,
  messageType,
  parseCursorMessage,
  parseFrameMessage,
  type FrameMessage,
} from "../render/frameProtocol";
import type {
  CredentialRequest,
  PinScheme,
  ProtocolKind,
  QualityPreset,
  RemoteScreen,
  SessionConnectOutcome,
  SessionEventPayload,
  SessionState,
  SessionStats,
} from "../lib/types";
import { DEFAULT_PORT, isProtocolKind } from "../lib/types";

export interface SessionBridge {
  onFrame: (msg: FrameMessage) => void;
  onDesktopResize: (width: number, height: number) => void;
  onCursorShape: (w: number, h: number, hx: number, hy: number, rgba: Uint8Array) => void;
  onCursorPosition: (x: number, y: number) => void;
}

export interface CertPromptState {
  fingerprint: string;
  subject: string;
  isChange: boolean;
  /**
   * Which server key this fingerprint belongs to. Carried through the dialog
   * untouched and handed back to `trust_certificate`, so the pin is stored
   * against the key the user actually verified. Never displayed.
   */
  scheme: PinScheme;
}

export interface SessionParams {
  sessionId: string | null;
  profileId: string | null;
  address: string | null;
  port: number;
  name: string;
  /**
   * Which protocol this session speaks. The window's query string carries it
   * only when it is not VNC, so an absent key reads as `"vnc"` and every URL
   * an older build produced still parses.
   */
  protocol: ProtocolKind;
}

/**
 * First contact (or a hard-stop change) of the SSH tunnel gateway's host key.
 * Unlike `CertPromptState` this happens BEFORE any session exists: the
 * shell's `connect_session` returned without spawning one, and accepting
 * re-invokes it with the fingerprint.
 */
export interface SshHostKeyPromptState {
  host: string;
  port: number;
  /** Present for first contact. */
  keyType?: string;
  fingerprint: string;
  /** A pinned key CHANGED: never acceptable from here. */
  changed: boolean;
  expected?: string;
}

export interface SessionApi {
  state: SessionState;
  desktopName: string;
  /**
   * The server's monitor layout, empty until (and unless) it sends an
   * ExtendedDesktopSize rectangle describing one. Low-frequency, so it is
   * React state rather than a bridge callback.
   */
  screens: RemoteScreen[];
  stats: SessionStats | null;
  certPrompt: CertPromptState | null;
  /** The SSH tunnel gateway needs a trust decision before connecting. */
  sshHostKeyPrompt: SshHostKeyPromptState | null;
  /** Handshake is parked waiting for a password (PRD/10 §3.4). */
  credentialRequest: CredentialRequest | null;
  remoteClipboard: string | null;
  bellTick: number;
  sendInput: (packet: Uint8Array) => void;
  disconnect: () => void;
  reconnectNow: () => void;
  setQuality: (preset: QualityPreset) => void;
  setViewOnly: (viewOnly: boolean) => void;
  /** Re-fetch the whole screen every second (manual staleness override). */
  setAlwaysRefresh: (enabled: boolean) => void;
  refreshScreen: () => void;
  requestResize: (width: number, height: number) => void;
  sendClipboard: (text: string) => Promise<void>;
  releaseAllKeys: () => void;
  /**
   * Persist a library thumbnail from raw RGBA (no-op for ad-hoc sessions).
   * Resolves once the shell has taken the pixels, so a window that is closing
   * can wait for it.
   */
  captureThumbnail: (width: number, height: number, rgba: Uint8Array) => Promise<void>;
  trustCertificate: (permanent: boolean) => void;
  dismissCertPrompt: () => void;
  /** Pin the gateway key shown in `sshHostKeyPrompt` and connect again. */
  acceptSshHostKey: () => void;
  /** Dismiss the gateway prompt and abandon the connection attempt. */
  dismissSshHostKeyPrompt: () => void;
  /**
   * Answer the credentials prompt. `username` is null for password-only
   * methods, `domain` for everything except an RDP logon that has one; `save`
   * asks the shell to remember it *if* the server accepts it. The password
   * goes JS → Rust and is never read back.
   */
  submitCredentials: (
    username: string | null,
    domain: string | null,
    password: string,
    save: boolean,
  ) => void;
  /** Dismiss the credentials prompt and abandon the connection attempt. */
  dismissCredentialPrompt: () => void;
  /**
   * Start the session again from scratch.
   *
   * `reprompt` asks the shell to ignore the stored password for this attempt,
   * so a credential the server has already rejected is not silently replayed, * the interactive prompt comes up instead and the user can type a new one
   * (and tick "Remember" to replace what is in the keychain).
   */
  retryConnect: (options?: { reprompt?: boolean }) => void;
}

/**
 * Coerce a `state-changed` payload into something safe to render.
 *
 * The UI treats `reason`/`method` as strings and calls string methods on them
 * (`diagnose()` does `reason.toLowerCase()`). A payload missing one used to
 * throw *during render*, which unmounts the whole tree and leaves a blank
 * session window with no way out, the reported "crash". Anything unrecognised
 * is dropped rather than rendered.
 */
function normalizeState(raw: unknown): SessionState | null {
  if (!raw || typeof raw !== "object") return null;
  const s = raw as Record<string, unknown>;
  const text = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);
  const num = (v: unknown, fallback = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : fallback);
  switch (s.state) {
    case "idle":
    case "resolving":
    case "connecting":
    case "negotiating":
    case "connected":
      return { state: s.state };
    case "authenticating":
      return { state: "authenticating", method: text(s.method, "the server's method") };
    case "reconnecting":
      return {
        state: "reconnecting",
        attempt: num(s.attempt, 1),
        next_retry_ms: num(s.next_retry_ms, 0),
        reason: text(s.reason),
      };
    case "disconnected":
      return {
        state: "disconnected",
        reason: text(s.reason, "The connection ended."),
        can_retry: s.can_retry !== false,
      };
    default:
      return null;
  }
}

/**
 * Map the UI's quality shorthand onto the `vnc_core::QualityPreset` wire
 * value (serde `rename_all = "kebab-case"`). Only "bw" differs.
 */
function wireQuality(preset: QualityPreset): string {
  return preset === "bw" ? "black-and-white" : preset;
}

export function readSessionParams(): SessionParams {
  const q = new URLSearchParams(window.location.search);
  const protocol: ProtocolKind = isProtocolKind(q.get("protocol")) ? "rdp" : "vnc";
  return {
    sessionId: q.get("sessionId"),
    profileId: q.get("profileId"),
    address: q.get("address"),
    port: parseInt(q.get("port") ?? String(DEFAULT_PORT[protocol]), 10) || DEFAULT_PORT[protocol],
    name: q.get("name") ?? q.get("address") ?? "remote computer",
    protocol,
  };
}

/**
 * Copy for the connecting overlay's `authenticating` stage.
 *
 * The wire values are stable identifiers the workspace owns, not sentences,
 * so this maps them to copy the UI owns. An unrecognised one is shown
 * verbatim rather than as a blank, which is what already happens for a VNC
 * method this build has never heard of.
 */
export function authMethodLabel(method: string): string {
  switch (method) {
    case "nla-ntlm":
      return "CredSSP, NTLM";
    // Spelled out rather than abbreviated: this is a downgrade the user chose
    // to allow, and it should read like one.
    case "tls":
      return "TLS only, no network level authentication";
    case "nla-kerberos":
      return "CredSSP, Kerberos";
    default:
      return method;
  }
}

export function useSession(params: SessionParams, bridge: SessionBridge): SessionApi {
  const [state, setState] = useState<SessionState>({ state: "connecting" });
  const [desktopName, setDesktopName] = useState(params.name);
  const [screens, setScreens] = useState<RemoteScreen[]>([]);
  const [stats, setStats] = useState<SessionStats | null>(null);
  const [certPrompt, setCertPrompt] = useState<CertPromptState | null>(null);
  const [sshHostKeyPrompt, setSshHostKeyPrompt] = useState<SshHostKeyPromptState | null>(null);
  const [credentialRequest, setCredentialRequest] = useState<CredentialRequest | null>(null);
  const [remoteClipboard, setRemoteClipboard] = useState<string | null>(null);
  const [bellTick, setBellTick] = useState(0);
  const [connectNonce, setConnectNonce] = useState(0);

  const bridgeRef = useRef(bridge);
  bridgeRef.current = bridge;
  const sessionIdRef = useRef<string>(params.sessionId ?? "");
  const inputWarned = useRef(false);
  /** Set by `retryConnect({ reprompt: true })`; consumed by the next connect. */
  const repromptRef = useRef(false);
  /** Set by `acceptSshHostKey`; consumed (and cleared) by the next connect. */
  const acceptSshHostKeyRef = useRef<string | null>(null);
  /** Browser dev only: the synthetic handshake waiting for an answer. */
  const mockAuthRef = useRef<MockAuth | null>(null);

  // ---------------------------------------------------------------- connect

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;

    if (!inTauri()) {
      // Browser dev: run a small synthetic session so the screen is explorable.
      // `?mockCreds=…` additionally parks it on the auth prompt (see mock.ts).
      // `?mockError=…` parks it on a terminal failure instead, so the
      // disconnect copy is reviewable without the server that produces it.
      const mockReason = mockDisconnectReason();
      if (mockReason) {
        setState({ state: "disconnected", reason: mockReason, can_retry: true });
        return;
      }
      const mockCreds = mockCredentialRequest();
      if (mockCreds) {
        return runMockAuth(mockCreds, mockAuthRef, bridgeRef, {
          setState,
          setDesktopName,
          setCredentialRequest,
          setScreens,
        });
      }
      const stop = runMockSession(bridgeRef, setState, setDesktopName, setScreens);
      return stop;
    }

    // Binary channel: framebuffer updates (msg_type 1) AND cursor shapes
    // (msg_type 2). Anything else is ignored for forward compatibility.
    const channel = new Channel<ArrayBuffer>();
    channel.onmessage = (data: ArrayBuffer) => {
      if (cancelled) return;
      switch (messageType(data)) {
        case MSG_FRAMEBUFFER: {
          const msg = parseFrameMessage(data);
          // A parse failure silently discards a WHOLE update: every region it
          // covered stays stale until something else repaints it. If this
          // ever fires, the corruption on screen is explained right here.
          if (!msg) {
            console.warn(`[render] frame message failed to parse (${data.byteLength}B), update dropped`);
            break;
          }
          bridgeRef.current.onFrame(msg);
          break;
        }
        case MSG_CURSOR: {
          const cur = parseCursorMessage(data);
          if (cur) {
            bridgeRef.current.onCursorShape(
              cur.width, cur.height, cur.hotspotX, cur.hotspotY, cur.pixels,
            );
          }
          break;
        }
        default:
          break; // unknown msg_type, ignore
      }
    };

    // `session://event` payloads are FLAT: `{ sessionId, type, ...fields }`.
    const listening = safeListen<SessionEventPayload>("session://event", (ev) => {
      if (cancelled || !ev || typeof ev !== "object") return;
      if (ev.sessionId && sessionIdRef.current && ev.sessionId !== sessionIdRef.current) return;
      switch (ev.type) {
        case "state-changed": {
          const next = normalizeState(ev.state);
          if (!next) break; // unknown/garbled, never render it
          setState(next);
          // The prompt's own lifetime is the pause it caused: once the
          // handshake moved on (accepted, or given up on) it must not linger.
          if (next.state === "connected" || next.state === "disconnected") {
            setCredentialRequest(null);
          }
          break;
        }
        case "desktop-resize":
          bridgeRef.current.onDesktopResize(ev.width, ev.height);
          break;
        case "desktop-name":
          setDesktopName(ev.name);
          break;
        case "screen-layout":
          setScreens(Array.isArray(ev.screens) ? ev.screens : []);
          break;
        case "cursor-position":
          bridgeRef.current.onCursorPosition(ev.x, ev.y);
          break;
        case "clipboard-text":
          setRemoteClipboard(ev.text);
          break;
        case "clipboard-notify":
          // Formats only, no data. The session already answers a text notify
          // with a request, so the text follows as its own `clipboard-text`.
          break;
        case "bell":
          setBellTick((n) => n + 1);
          break;
        case "certificate-prompt":
          setCertPrompt({
            fingerprint: ev.fingerprint,
            subject: ev.subject,
            isChange: ev.isChange,
            scheme: ev.scheme,
          });
          break;
        case "credentials-required":
          // The session is PAUSED mid-handshake until we answer. A retry
          // (attempt > 1) replaces the request in place so the dialog can
          // show the rejection reason without flickering.
          setCredentialRequest(ev.request);
          break;
        case "stats":
          setStats(ev.stats);
          break;
        case "error": {
          setCredentialRequest(null);
          const message = typeof ev.message === "string" && ev.message ? ev.message : "The connection failed.";
          // `Error` is emitted immediately BEFORE the terminal `state-changed`
          // that carries the real `can_retry` (see session/reconnect.rs). Only
          // fill in a state we do not have yet, forcing `can_retry: true` here
          // and letting the next event overwrite it made the flag flap.
          setState((prev) =>
            prev.state === "disconnected"
              ? { ...prev, reason: message }
              : { state: "disconnected", reason: message, can_retry: true },
          );
          break;
        }
        case "ended":
          setCredentialRequest(null);
          setCertPrompt(null);
          // The session task is fully gone; no reconnect is in flight.
          setState((prev) =>
            prev.state === "disconnected"
              ? prev
              : { state: "disconnected", reason: "The connection ended.", can_retry: true },
          );
          break;
        default:
          break;
      }
    });

    // The listener MUST be registered before the session starts.
    //
    // `listen()` round-trips to Rust to register, so firing `connect_session`
    // without awaiting it races the handshake: Tauri events are not buffered,
    // so anything emitted before registration completes is silently dropped.
    // The handshake reaches `credentials-required` within milliseconds on a
    // LAN host, so the auth prompt was exactly the event that got lost, the
    // dialog never appeared, the core sat waiting for an answer, and the
    // session only ended once something else disconnected it ("authentication
    // was cancelled").
    void (async () => {
      try {
        const fn = await listening;
        if (cancelled) {
          fn();
          return;
        }
        unlisten = fn;
      } catch {
        // safeListen already degrades; connecting without events is useless,
        // so surface it rather than hanging on a silent connect.
        if (!cancelled) {
          setState({
            state: "disconnected",
            reason: "Could not subscribe to session events.",
            can_retry: true,
          });
        }
        return;
      }

      if (cancelled) return;
      setState({ state: "connecting" });
      try {
        const acceptSshHostKey = acceptSshHostKeyRef.current;
        acceptSshHostKeyRef.current = null;
        const outcome = await invoke<SessionConnectOutcome>("connect_session", {
          sessionId: params.sessionId,
          profileId: params.profileId,
          address: params.address,
          port: params.port,
          protocol: params.protocol,
          // Retrying after a rejected password must not replay it, ask.
          ignoreStoredCredentials: repromptRef.current,
          // Answers a previous ssh-host-key-prompt outcome, once.
          acceptSshHostKey,
          onEvent: channel,
        });
        repromptRef.current = false;

        // The SSH gateway needs a trust decision before anything connects.
        // No session was spawned; the dialog re-runs the connect on accept.
        // State stays "connecting": the attempt is pending on the answer.
        if (outcome.status === "ssh-host-key-prompt") {
          if (!cancelled) {
            setSshHostKeyPrompt({
              host: outcome.host,
              port: outcome.port,
              keyType: outcome.keyType,
              fingerprint: outcome.fingerprint,
              changed: false,
            });
          }
          return;
        }
        // Pinned gateway key CHANGED: hard stop, mirror of the sidecar rule.
        if (outcome.status === "ssh-host-key-changed") {
          if (!cancelled) {
            setSshHostKeyPrompt({
              host: outcome.host,
              port: outcome.port,
              fingerprint: outcome.actual,
              expected: outcome.expected,
              changed: true,
            });
            setState({
              state: "disconnected",
              reason: "The SSH gateway's host key has changed.",
              can_retry: false,
            });
          }
          return;
        }

        if (outcome.sessionId) sessionIdRef.current = outcome.sessionId;

        // Safety net for a prompt raised between the session starting and this
        // window being ready to hear about it. Events are fire-and-forget, so
        // without this a missed `credentials-required` hangs the connection
        // until something else tears it down.
        const outstanding = await safeInvoke<CredentialRequest | null>(
          "pending_credential_request",
          { sessionId: sessionIdRef.current },
          null,
        );
        if (!cancelled && outstanding) {
          setCredentialRequest((current) => current ?? outstanding);
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setState({
            state: "disconnected",
            reason: err instanceof Error ? err.message : String(err),
            can_retry: true,
          });
        }
      }
    })();

    return () => {
      cancelled = true;
      unlisten?.();
      void safeInvoke("disconnect_session", { sessionId: sessionIdRef.current }, null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.sessionId, params.profileId, params.address, params.port, connectNonce]);

  // ---------------------------------------------------------------- actions

  const sid = (): string => sessionIdRef.current;

  const sendInput = useCallback((packet: Uint8Array): void => {
    if (!inTauri()) return;
    // Raw binary body; session id rides in an invoke header (see FRAME_FORMAT notes).
    invoke("send_input", packet, { headers: { "x-session-id": sessionIdRef.current } }).catch(
      (err: unknown) => {
        if (!inputWarned.current) {
          inputWarned.current = true;
          console.warn("send_input failed:", err);
        }
      },
    );
  }, []);

  const disconnect = useCallback((): void => {
    void safeInvoke("disconnect_session", { sessionId: sid() }, null);
    setState({ state: "disconnected", reason: "Disconnected", can_retry: true });
  }, []);

  const reconnectNow = useCallback((): void => {
    void safeInvoke("reconnect_now", { sessionId: sid() }, null);
  }, []);

  const setQuality = useCallback((preset: QualityPreset): void => {
    // `set_quality` takes a vnc_core::QualityPreset, which is kebab-case:
    // BlackAndWhite serializes as "black-and-white", not the "bw" shorthand
    // used for the stored `qualityPref` column.
    void safeInvoke("set_quality", { sessionId: sid(), preset: wireQuality(preset) }, null);
  }, []);

  /**
   * Keep re-fetching the whole screen every second.
   *
   * The manual override for a server whose damage tracking cannot be trusted:
   * nothing infers when the picture is stale, it is simply refetched. Costs
   * bandwidth, hence a switch rather than a default.
   */
  const setAlwaysRefresh = useCallback((enabled: boolean): void => {
    void safeInvoke("set_always_refresh", { sessionId: sid(), enabled }, null);
  }, []);

  const setViewOnly = useCallback((viewOnly: boolean): void => {
    void safeInvoke("set_view_only", { sessionId: sid(), viewOnly }, null);
  }, []);

  const refreshScreen = useCallback((): void => {
    void safeInvoke("refresh_session", { sessionId: sid() }, null);
  }, []);

  const requestResize = useCallback((width: number, height: number): void => {
    void safeInvoke("request_resize", { sessionId: sid(), width, height }, null);
  }, []);

  // Resolves once the backend has ENQUEUED the ClipboardText command, which
  // is what lets a caller order a following keystroke after it (the
  // paste-chord sync in SessionInput awaits this).
  const sendClipboard = useCallback(
    (text: string): Promise<void> =>
      safeInvoke("send_clipboard", { sessionId: sid(), text }, null).then(() => undefined),
    [],
  );

  const releaseAllKeys = useCallback((): void => {
    void safeInvoke("release_all_keys", { sessionId: sid() }, null);
  }, []);

  /**
   * Raw RGBA body + `x-width`/`x-height` headers; Rust does the downscale and
   * PNG encode. The body length must be exactly width*height*4 or the command
   * rejects it. Rows are top-down, as read back from the frame texture.
   *
   * The shell resolves which host this belongs to from the session id, so an
   * ad-hoc session stores nothing and a compromised webview cannot overwrite
   * another host's tile.
   */
  const captureThumbnail = useCallback(
    async (width: number, height: number, rgba: Uint8Array): Promise<void> => {
      if (width === 0 || height === 0) return;
      if (rgba.byteLength !== width * height * 4) return;
      if (!inTauri()) {
        // Browser dev: same journey, minus the IPC (see mock.ts). Ad-hoc
        // sessions fall back to the endpoint key the shell uses.
        const key = mockThumbnailKey(params.profileId, params.address, params.port);
        if (key) saveMockThumbnail(key, width, height, rgba);
        return;
      }
      try {
        await invoke("capture_thumbnail", rgba, {
          headers: {
            "x-session-id": sessionIdRef.current,
            "x-width": String(width),
            "x-height": String(height),
          },
        });
      } catch (err: unknown) {
        console.warn("capture_thumbnail failed:", err);
      }
    },
    [params.profileId, params.address, params.port],
  );

  const trustCertificate = useCallback(
    (permanent: boolean): void => {
      if (!certPrompt) return;
      void safeInvoke(
        "trust_certificate",
        {
          sessionId: sid(),
          fingerprint: certPrompt.fingerprint,
          permanent,
          // Echoed back exactly as it arrived, the UI does not decide which
          // key it was shown.
          scheme: certPrompt.scheme,
        },
        null,
      );
      setCertPrompt(null);
    },
    [certPrompt],
  );

  const dismissCertPrompt = useCallback((): void => {
    setCertPrompt(null);
    disconnect();
  }, [disconnect]);

  const acceptSshHostKey = useCallback((): void => {
    // A CHANGED key is never acceptable from here, same as the sidecar.
    if (!sshHostKeyPrompt || sshHostKeyPrompt.changed) return;
    acceptSshHostKeyRef.current = sshHostKeyPrompt.fingerprint;
    setSshHostKeyPrompt(null);
    // No session exists yet, so "accept" means "run the connect again", this
    // time carrying the fingerprint the user just verified.
    setState({ state: "connecting" });
    setConnectNonce((n) => n + 1);
  }, [sshHostKeyPrompt]);

  const dismissSshHostKeyPrompt = useCallback((): void => {
    setSshHostKeyPrompt(null);
    setState({
      state: "disconnected",
      reason: "The SSH gateway's host key was not accepted.",
      can_retry: true,
    });
  }, []);

  const submitCredentials = useCallback(
    (username: string | null, domain: string | null, password: string, save: boolean): void => {
      // Optimistically close the dialog: the handshake resumes now, and a
      // rejection comes back as a fresh `credentials-required` with a higher
      // `attempt`, which reopens it with the reason shown.
      // The session state stays whatever the core reported (`authenticating`);
      // it drives the connecting overlay on its own from here.
      setCredentialRequest(null);
      if (mockAuthRef.current) {
        mockAuthRef.current.submit(username, password);
        return;
      }
      void provideCredentials(sid(), username, domain, password, save).catch((err: unknown) => {
        setState({
          state: "disconnected",
          reason: err instanceof Error ? err.message : String(err),
          can_retry: true,
        });
      });
    },
    [],
  );

  const dismissCredentialPrompt = useCallback((): void => {
    setCredentialRequest(null);
    mockAuthRef.current?.cancel();
    void cancelCredentials(sid());
    setState({
      state: "disconnected",
      reason: "Authentication was cancelled.",
      can_retry: true,
    });
  }, []);

  const retryConnect = useCallback((options?: { reprompt?: boolean }): void => {
    repromptRef.current = options?.reprompt === true;
    // Clear anything left over from the attempt that failed, so the fresh
    // connect starts from a clean screen rather than a stale prompt.
    setCertPrompt(null);
    setSshHostKeyPrompt(null);
    setCredentialRequest(null);
    setStats(null);
    setScreens([]);
    setState({ state: "connecting" });
    setConnectNonce((n) => n + 1);
  }, []);

  return {
    state, desktopName, screens, stats, certPrompt, sshHostKeyPrompt, credentialRequest, remoteClipboard, bellTick,
    sendInput, disconnect, reconnectNow, setQuality, setViewOnly, refreshScreen,
    requestResize, sendClipboard, releaseAllKeys, captureThumbnail, trustCertificate, setAlwaysRefresh,
    dismissCertPrompt, acceptSshHostKey, dismissSshHostKeyPrompt,
    submitCredentials, dismissCredentialPrompt, retryConnect,
  };
}

// ------------------------------------------------------------------- mock

/** The browser-dev handshake, parked waiting for an answer. */
interface MockAuth {
  submit: (username: string | null, password: string) => void;
  cancel: () => void;
}

/** Same budget the core enforces (`security::MAX_CREDENTIAL_ATTEMPTS`). */
const MOCK_MAX_CREDENTIAL_ATTEMPTS = 3;

/**
 * Browser-dev stand-in for the interactive authentication round trip, so the
 * *failure* half of PRD/10 §3.4, rejection, re-ask, exhaustion, cancellation, * is drivable without a VNC server. The event shapes and the ordering match
 * what `session::reconnect` really emits (`Error` immediately before the
 * terminal `Disconnected`).
 *
 *   `?mockPassword=<pw>`  the password this fake server accepts.
 *                         Omitted: every answer is rejected.
 */
function runMockAuth(
  first: CredentialRequest,
  ref: { current: MockAuth | null },
  bridgeRef: { current: SessionBridge },
  set: {
    setState: (s: SessionState) => void;
    setDesktopName: (n: string) => void;
    setCredentialRequest: (r: CredentialRequest | null) => void;
    setScreens: (s: RemoteScreen[]) => void;
  },
): () => void {
  const expected = new URLSearchParams(window.location.search).get("mockPassword");
  let attempt = first.attempt;
  let stopSession: (() => void) | null = null;

  set.setState({ state: "authenticating", method: first.method });
  set.setCredentialRequest(first);

  ref.current = {
    submit: (_username, password) => {
      if (expected !== null && password === expected) {
        ref.current = null;
        set.setCredentialRequest(null);
        stopSession = runMockSession(bridgeRef, set.setState, set.setDesktopName, set.setScreens);
        return;
      }
      attempt += 1;
      if (attempt > MOCK_MAX_CREDENTIAL_ATTEMPTS) {
        ref.current = null;
        set.setCredentialRequest(null);
        set.setState({
          state: "disconnected",
          reason: "The password was not accepted.",
          can_retry: false,
        });
        return;
      }
      set.setCredentialRequest({
        ...first,
        attempt,
        error: "The server rejected that password.",
      });
    },
    cancel: () => {
      ref.current = null;
    },
  };

  return () => {
    ref.current = null;
    stopSession?.();
  };
}

function runMockSession(
  bridgeRef: { current: SessionBridge },
  setState: (s: SessionState) => void,
  setDesktopName: (n: string) => void,
  setScreens: (s: RemoteScreen[]) => void,
): () => void {
  const W = 1280;
  const H = 800;
  let raf = 0;
  let interval = 0;
  const t0 = window.setTimeout(() => {
    setDesktopName("Demo desktop (no backend)");
    setState({ state: "connected" });
    bridgeRef.current.onDesktopResize(W, H);
    // Two side-by-side "monitors", so the Displays menu is drivable without
    // a multi-head VNC server.
    setScreens([
      { id: 1, x: 0, y: 0, width: W / 2, height: H },
      { id: 2, x: W / 2, y: 0, width: W / 2, height: H },
    ]);
    // full-frame gradient
    const px = new Uint8Array(W * H * 4);
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        const i = (y * W + x) * 4;
        px[i] = Math.floor((x / W) * 90) + 30;
        px[i + 1] = Math.floor((y / H) * 70) + 40;
        px[i + 2] = 96;
        px[i + 3] = 255;
      }
    }
    bridgeRef.current.onFrame({
      damageX: 0, damageY: 0, damageW: W, damageH: H,
      rects: [{ x: 0, y: 0, w: W, h: H, format: 0, payload: px, srcX: 0, srcY: 0 }],
    });
    // bouncing dirty rect to exercise the texSubImage2D path
    const box = new Uint8Array(64 * 64 * 4);
    let bx = 100, by = 100, vx = 7, vy = 5;
    interval = window.setInterval(() => {
      bx += vx; by += vy;
      if (bx < 0 || bx > W - 64) {
        vx = -vx;
        bx = Math.max(0, Math.min(W - 64, bx));
      }
      if (by < 0 || by > H - 64) {
        vy = -vy;
        by = Math.max(0, Math.min(H - 64, by));
      }
      const hue = (Date.now() / 20) % 255;
      for (let i = 0; i < box.length; i += 4) {
        box[i] = hue; box[i + 1] = 255 - hue; box[i + 2] = 200; box[i + 3] = 255;
      }
      bridgeRef.current.onFrame({
        damageX: bx, damageY: by, damageW: 64, damageH: 64,
        rects: [{ x: Math.max(0, bx), y: Math.max(0, by), w: 64, h: 64, format: 0, payload: box, srcX: 0, srcY: 0 }],
      });
    }, 33);
  }, 700);
  return () => {
    window.clearTimeout(t0);
    window.clearInterval(interval);
    cancelAnimationFrame(raf);
  };
}
