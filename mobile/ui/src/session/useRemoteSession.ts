/**
 * One remote session: connect through the `Api`, feed frames to the WebGL
 * renderer, keep the events in React state, and look after the app going to
 * the background and coming back.
 *
 * Patterned on the desktop app's ui/src/hooks/useSession.ts, cut down to what
 * the phone needs.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type {
  Api,
  ConnectTarget,
  CredentialRequest,
  Quality,
  SessionEvent,
  SessionState,
  SessionStats,
} from "../api/contract";
import { MSG_CURSOR, MSG_FRAMEBUFFER, messageType, parseCursorMessage, parseFrameMessage } from "./render/frameProtocol";
import { WebGLRenderer } from "./render/WebGLRenderer";
import { InputSender } from "./input/packets";

export type Phase = "connecting" | "connected" | "error" | "ended";

export interface CertPromptData {
  fingerprint: string;
  subject: string;
  isChange: boolean;
  scheme: string;
}

/** True when this webview can decode H.264 itself (WebCodecs). */
export function hasVideoDecoder(): boolean {
  return typeof VideoDecoder !== "undefined" && typeof EncodedVideoChunk !== "undefined";
}

/**
 * The quality to ask Rust for. Without WebCodecs (older Android System
 * WebView, iOS before 16.4) the phone cannot show H.264 rects, so "auto",
 * which lets the computer pick video, is sent as "quality", the preset that
 * keeps to JPEG and raw tiles. See README.md in this folder.
 */
export function wireQuality(q: Quality, videoOk: boolean): Quality {
  return q === "auto" && !videoOk ? "quality" : q;
}

export interface RemoteSession {
  phase: Phase;
  state: SessionState;
  sessionId: string | null;
  desktop: { w: number; h: number };
  desktopName: string | null;
  stats: SessionStats | null;
  credentials: CredentialRequest | null;
  cert: CertPromptData | null;
  error: string | null;
  remoteClipboard: string | null;
  hasCursorShape: boolean;
  /** Last pointer position the computer reported, framebuffer pixels. */
  serverCursor: { x: number; y: number; at: number } | null;
  /** Set when the app came back from the background and the session had ended. */
  needsReconnect: boolean;
  /** Bumped on every frame message, so the screen can tell pixels arrived. */
  frames: number;
  renderer: React.RefObject<WebGLRenderer | null>;
  sender: React.RefObject<InputSender | null>;
  attachCanvas(canvas: HTMLCanvasElement | null): void;
  reconnect(): void;
  disconnect(): Promise<void>;
  answerCredentials(username: string | null, password: string | null, save: boolean): void;
  cancelCredentials(): void;
  answerCert(accept: boolean): void;
  setQuality(q: Quality): void;
  snapshot(): Promise<boolean>;
  notice: string | null;
}

const IDLE: SessionState = { state: "connecting" };

export function useRemoteSession(api: Api, target: ConnectTarget): RemoteSession {
  const [phase, setPhase] = useState<Phase>("connecting");
  const [state, setState] = useState<SessionState>(IDLE);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [desktop, setDesktop] = useState({ w: 0, h: 0 });
  const [desktopName, setDesktopName] = useState<string | null>(null);
  const [stats, setStats] = useState<SessionStats | null>(null);
  const [credentials, setCredentials] = useState<CredentialRequest | null>(null);
  const [cert, setCert] = useState<CertPromptData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [remoteClipboard, setRemoteClipboard] = useState<string | null>(null);
  const [hasCursorShape, setHasCursorShape] = useState(false);
  const [serverCursor, setServerCursor] = useState<{ x: number; y: number; at: number } | null>(null);
  const [needsReconnect, setNeedsReconnect] = useState(false);
  const [frames, setFrames] = useState(0);
  const [attempt, setAttempt] = useState(0);
  const [canvas, setCanvas] = useState<HTMLCanvasElement | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const renderer = useRef<WebGLRenderer | null>(null);
  const sender = useRef<InputSender | null>(null);
  const sid = useRef<string | null>(null);
  const phaseRef = useRef<Phase>("connecting");
  const quality = useRef<Quality>("auto");
  const hidden = useRef(false);
  const endedWhileHidden = useRef(false);
  const exiting = useRef(false);

  const go = useCallback((p: Phase) => {
    phaseRef.current = p;
    setPhase(p);
  }, []);

  // Renderer lives as long as the canvas does.
  useEffect(() => {
    if (!canvas) return;
    let r: WebGLRenderer;
    try {
      r = new WebGLRenderer(canvas);
    } catch (e) {
      setError(`This phone could not start the picture: ${String(e)}`);
      go("error");
      return;
    }
    r.onNotice = (m) => setNotice(m);
    renderer.current = r;
    r.start();
    return () => {
      r.dispose();
      if (renderer.current === r) renderer.current = null;
    };
  }, [canvas, go]);

  // Connect, once per attempt.
  useEffect(() => {
    if (!canvas) return;
    let cancelled = false;
    let mySid: string | null = null;
    const videoOk = hasVideoDecoder();
    let frameCount = 0;
    let frameFlush = 0;

    go("connecting");
    setState(IDLE);
    setError(null);
    setNeedsReconnect(false);
    setCredentials(null);
    setCert(null);
    setStats(null);
    endedWhileHidden.current = false;
    exiting.current = false;

    const onFrame = (buf: ArrayBuffer): void => {
      if (cancelled) return;
      const r = renderer.current;
      if (!r) return;
      const t = messageType(buf);
      if (t === MSG_FRAMEBUFFER) {
        const msg = parseFrameMessage(buf);
        if (msg) r.applyFrame(msg);
        frameCount++;
        if (!frameFlush) {
          // One React update per animation frame at most, not per message.
          frameFlush = requestAnimationFrame(() => {
            frameFlush = 0;
            setFrames(frameCount);
          });
        }
        if (phaseRef.current === "connecting" && msg && msg.rects.length > 0) go("connected");
      } else if (t === MSG_CURSOR) {
        const c = parseCursorMessage(buf);
        if (c) {
          r.setCursorShape(c.width, c.height, c.hotspotX, c.hotspotY, c.pixels);
          setHasCursorShape(c.width > 0 && c.height > 0);
        }
      }
    };

    const onEvent = (e: SessionEvent): void => {
      if (cancelled) return;
      if (mySid && e.sessionId && e.sessionId !== mySid) return;
      switch (e.type) {
        case "state-changed": {
          setState(e.state);
          if (e.state.state === "connected") {
            go("connected");
          } else if (e.state.state === "disconnected") {
            if (exiting.current) return;
            if (hidden.current) endedWhileHidden.current = true;
            if (phaseRef.current === "connected") {
              setNeedsReconnect(true);
              go("ended");
            } else {
              const reason = e.state.reason;
              setError((prev) => prev ?? reason);
              go("error");
            }
          }
          break;
        }
        case "desktop-resize":
          renderer.current?.setRemoteSize(e.width, e.height);
          setDesktop({ w: e.width, h: e.height });
          break;
        case "desktop-name":
          setDesktopName(e.name);
          break;
        case "cursor-position":
          renderer.current?.setCursorPosition(e.x, e.y);
          setServerCursor({ x: e.x, y: e.y, at: performance.now() });
          break;
        case "clipboard-text":
          setRemoteClipboard(e.text);
          break;
        case "certificate-prompt":
          setCert({ fingerprint: e.fingerprint, subject: e.subject, isChange: e.isChange, scheme: e.scheme });
          break;
        case "credentials-required":
          setCredentials(e.request);
          break;
        case "stats":
          setStats(e.stats);
          break;
        case "error":
          setError(e.message);
          if (phaseRef.current !== "connected") go("error");
          break;
        case "ended":
          if (exiting.current) return;
          if (hidden.current) endedWhileHidden.current = true;
          setNeedsReconnect(true);
          if (phaseRef.current !== "error") go("ended");
          break;
        default:
          break;
      }
    };

    api
      .sessionConnect(target, onFrame, onEvent)
      .then(({ sessionId: id }) => {
        if (cancelled) {
          void api.sessionDisconnect(id).catch(() => {});
          return;
        }
        mySid = id;
        sid.current = id;
        setSessionId(id);
        sender.current = new InputSender({
          send: (seq, body) => {
            void api.sessionInput(id, seq, body).catch(() => {});
          },
        });
        const q = wireQuality(quality.current, videoOk);
        if (q !== "auto") void api.sessionQuality(id, q).catch(() => {});
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(typeof err === "string" ? err : err instanceof Error ? err.message : String(err));
        go("error");
      });

    return () => {
      cancelled = true;
      if (frameFlush) cancelAnimationFrame(frameFlush);
      const s = sender.current;
      if (s && mySid) s.releaseAll();
      sender.current = null;
      if (mySid) void api.sessionDisconnect(mySid).catch(() => {});
      sid.current = null;
      setSessionId(null);
    };
  }, [api, target, attempt, canvas, go]);

  // Background and foreground.
  useEffect(() => {
    const onVis = (): void => {
      const r = renderer.current;
      if (document.visibilityState === "hidden") {
        hidden.current = true;
        sender.current?.releaseAll();
        r?.stop();
      } else {
        hidden.current = false;
        if (endedWhileHidden.current || phaseRef.current === "ended") {
          setNeedsReconnect(true);
          if (phaseRef.current !== "error") go("ended");
        } else {
          r?.start();
          r?.markDirty();
        }
      }
    };
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, [go]);

  const reconnect = useCallback(() => {
    exiting.current = false;
    setAttempt((a) => a + 1);
  }, []);

  const snapshot = useCallback(async (): Promise<boolean> => {
    const r = renderer.current;
    const id = sid.current;
    if (!r || !id || !r.hasFrame()) return false;
    const shot = r.readPreviewRGBA(480);
    if (!shot) return false;
    try {
      await api.sessionSnapshot(id, shot.pixels, shot.width, shot.height);
      return true;
    } catch {
      return false;
    }
  }, [api]);

  const disconnect = useCallback(async (): Promise<void> => {
    exiting.current = true;
    const id = sid.current;
    if (id && phaseRef.current === "connected") await snapshot();
    sender.current?.releaseAll();
    if (id) await api.sessionDisconnect(id).catch(() => {});
  }, [api, snapshot]);

  const answerCredentials = useCallback(
    (username: string | null, password: string | null, save: boolean) => {
      const id = sid.current;
      setCredentials(null);
      if (id) void api.sessionCredentials(id, username, password, save).catch((e) => setError(String(e)));
    },
    [api],
  );

  const cancelCredentials = useCallback(() => {
    setCredentials(null);
    const id = sid.current;
    exiting.current = true;
    if (id) void api.sessionDisconnect(id).catch(() => {});
    setError("Sign in was cancelled.");
    go("error");
  }, [api, go]);

  const answerCert = useCallback(
    (accept: boolean) => {
      const c = cert;
      const id = sid.current;
      setCert(null);
      if (c && id) void api.sessionTrust(id, c.fingerprint, c.scheme, accept).catch(() => {});
      if (!accept) {
        exiting.current = true;
        setError("You chose not to trust this computer, so we did not connect.");
        go("error");
      }
    },
    [api, cert, go],
  );

  const setQuality = useCallback(
    (q: Quality) => {
      quality.current = q;
      const id = sid.current;
      if (id) void api.sessionQuality(id, wireQuality(q, hasVideoDecoder())).catch(() => {});
    },
    [api],
  );

  return {
    phase,
    state,
    sessionId,
    desktop,
    desktopName,
    stats,
    credentials,
    cert,
    error,
    remoteClipboard,
    hasCursorShape,
    serverCursor,
    needsReconnect,
    frames,
    renderer,
    sender,
    attachCanvas: setCanvas,
    reconnect,
    disconnect,
    answerCredentials,
    cancelCredentials,
    answerCert,
    setQuality,
    snapshot,
    notice,
  };
}
