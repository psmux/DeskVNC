/** Session window: WebGL2 canvas + floating toolbar + reconnect UX (PRD/05). */
import {
  Component,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { WebGLRenderer } from "../render/WebGLRenderer";
import { SessionInput } from "../render/input";
import { KEYSYM } from "../render/keysyms";
import { useSession, readSessionParams, type SessionBridge } from "../hooks/useSession";
import { useLivePreview } from "../hooks/useLivePreview";
import { SessionToolbar } from "../components/SessionToolbar";
import { CertPrompt } from "../components/CertPrompt";
import { CredentialPrompt } from "../components/CredentialPrompt";
import { DropOverlay, FilePanel } from "../components/FilePanel";
import { useFiles } from "../hooks/useFiles";
import { ToastShelf } from "../components/primitives";
import { useToasts } from "../state/ToastContext";
import { useSettings } from "../state/SettingsContext";
import { Dialog } from "../components/primitives";
import type { QualityPreset, ScalingMode, SessionState } from "../lib/types";
import {
  CAPTURE_INACTIVE,
  MACOS_ACCESSIBILITY_SETTINGS_URL,
  captureStart,
  captureStatus as fetchCaptureStatus,
  captureStop,
  captureRequestPermission,
  filesProbe,
  inTauri,
  listenCapture,
  openExternal,
  readClipboard,
  safeInvoke,
  writeClipboard,
  type CaptureStatus,
} from "../lib/tauri";

/**
 * How long to let the desktop settle after `connected` before grabbing the
 * library thumbnail. Long enough that the first frames have painted a real
 * desktop rather than a blank/loading screen, short enough to stay inside the
 * "tile shows a thumbnail within 2 s of connect" acceptance test (PRD/03 §7).
 */
const THUMBNAIL_SETTLE_MS = 1200;

/** Longest a closing session window will wait for its exit capture. */
const CAPTURE_CLOSE_BUDGET_MS = 700;

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => window.setTimeout(resolve, ms));

// ---------------------------------------------------------------- closing
//
// THE close bug (user report: "if I manually disconnect, the close button on
// the dialog does not work").
//
// While a `tauri://close-requested` listener is registered, tauri prevents
// EVERY close, including one this webview asked for itself
// (`tauri/src/manager/window.rs`: `if window.has_js_listener(…) { api.prevent_close() }`).
// The `@tauri-apps/api` wrapper then finishes the job with `window.destroy()`,
// and `capabilities/session.json` grants `core:window:allow-close` but NOT
// `core:window:allow-destroy`, so that last invoke was rejected by the ACL and
// the window simply never went away. Every dismissal path (this button, Escape,
// the OS close button) died the same way, for every session opened from a saved
// host (ad-hoc sessions never registered the listener, so they closed fine).
//
// The fix: drop the hold BEFORE closing. With no JS listener left, a plain
// `close()` is not intercepted, so it runs the shell's `CloseRequested`
// handler, which is what releases the keyboard grab, cancels file transfers
// and shuts the session down. `destroy()` is only a last-resort fallback (and
// the capability now allows it), because it would skip all of that.

/** Releases this window's close-requested hold, if one is installed. */
let releaseCloseHold: (() => void | Promise<void>) | null = null;
/** Latched once a close is genuinely under way, so the hold falls through. */
let closingWindow = false;

/**
 * Dismiss the session window for good. Safe to call from anywhere, including
 * the error-boundary fallback, and idempotent.
 */
async function closeSessionWindow(sessionId: string | null): Promise<void> {
  if (!inTauri()) {
    // Browser dev build: one window, so "close" means "back to the library".
    window.location.search = "";
    return;
  }
  closingWindow = true;
  // Tear the session down explicitly. The normal `close()` path below does
  // this via the shell's CloseRequested handler, but the `destroy()` fallback
  // skips window events entirely, and an orphaned entry in
  // `AppState.sessions` would hold the socket open after the window is gone.
  if (sessionId) await safeInvoke("disconnect_session", { sessionId }, null);

  const release = releaseCloseHold;
  releaseCloseHold = null;
  try {
    await release?.();
  } catch {
    /* already gone */
  }

  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    const win = getCurrentWindow();
    try {
      await win.close();
    } catch (err) {
      console.warn("window.close() failed, forcing destroy:", err);
      await win.destroy();
    }
  } catch (err) {
    console.error("could not close the session window:", err);
  }
}

export function Session(): ReactNode {
  return (
    <SessionErrorBoundary>
      <SessionView />
    </SessionErrorBoundary>
  );
}

function SessionView(): ReactNode {
  const params = useMemo(readSessionParams, []);
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rendererRef = useRef<WebGLRenderer | null>(null);
  const inputRef = useRef<SessionInput | null>(null);
  /** Last-chance thumbnail capture, run before the renderer is disposed. */
  const teardownCaptureRef = useRef<() => void>(() => undefined);
  const { push } = useToasts();
  const { settings } = useSettings();

  // Honour the "show remote pointer" preference (Preferences ▸ Input). Purely
  // visual: hiding it does not change what input we send.
  useEffect(() => {
    rendererRef.current?.setCursorVisible(settings.showRemoteCursor);
  }, [settings.showRemoteCursor]);

  const [scalingMode, setScalingModeState] = useState<ScalingMode>("aspect-fit");
  const [zoom, setZoomState] = useState(1);
  const [quality, setQualityState] = useState<QualityPreset>("auto");
  const [bwLevels, setBwLevelsState] = useState(16);
  const [passthrough, setPassthroughState] = useState(false);
  const [capture, setCapture] = useState<CaptureStatus>(CAPTURE_INACTIVE);
  const [showCaptureHelp, setShowCaptureHelp] = useState(false);
  const [viewOnly, setViewOnlyState] = useState(false);
  const [recallSignal, setRecallSignal] = useState(0);
  const [remoteSize, setRemoteSize] = useState<{ w: number; h: number } | null>(null);
  const [scrimFading, setScrimFading] = useState(false);
  const [filesOpen, setFilesOpen] = useState(false);
  /** null while the SSH probe runs; false disables the Files button. */
  const [sshAvailable, setSshAvailable] = useState<boolean | null>(null);
  const [dropCount, setDropCount] = useState<number | null>(null);
  const wasReconnecting = useRef(false);

  // ------------------------------------------------------------- bridge

  /** Frames applied so far, lets the preview publisher skip idle ticks. */
  const frameCountRef = useRef(0);

  const bridge = useMemo(
    (): SessionBridge => ({
      onFrame: (msg) => {
        frameCountRef.current += 1;
        rendererRef.current?.applyFrame(msg);
      },
      onDesktopResize: (w, h) => {
        rendererRef.current?.setRemoteSize(w, h);
        setRemoteSize({ w, h });
      },
      onCursorShape: (w, h, hx, hy, rgba) => rendererRef.current?.setCursorShape(w, h, hx, hy, rgba),
      onCursorPosition: (x, y) => rendererRef.current?.setCursorPosition(x, y),
    }),
    [],
  );

  const session = useSession(params, bridge);
  const sessionRef = useRef(session);
  sessionRef.current = session;

  // ------------------------------------------------- renderer + input setup

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    let renderer: WebGLRenderer;
    try {
      renderer = new WebGLRenderer(canvas);
    } catch (err) {
      console.error(err);
      return;
    }
    rendererRef.current = renderer;
    renderer.start();

    const input = new SessionInput(canvas, {
      renderer,
      send: (pkt) => sessionRef.current.sendInput(pkt),
      releaseAllKeys: () => sessionRef.current.releaseAllKeys(),
      onAppHotkey: (e) => {
        const mod = e.metaKey || e.ctrlKey;
        if (mod && e.shiftKey && e.code === "KeyM") {
          setRecallSignal((n) => n + 1);
          return true;
        }
        if (mod && e.altKey && e.code === "Enter") {
          void toggleFullscreen();
          return true;
        }
        return false;
      },
      onZoomGesture: (z) => {
        setScalingModeState("custom");
        setZoomState(z);
        renderer.setScalingMode("custom");
        renderer.setZoom(z);
      },
    });
    inputRef.current = input;
    input.attach();

    // HiDPI-correct sizing: device pixels from devicePixelContentBoxSize when available
    const applySize = (deviceW: number, deviceH: number): void => {
      renderer.setCanvasSize(deviceW, deviceH);
    };
    const fallbackMeasure = (): void => {
      const r = container.getBoundingClientRect();
      applySize(
        Math.round(r.width * window.devicePixelRatio),
        Math.round(r.height * window.devicePixelRatio),
      );
    };
    const ro = new ResizeObserver((entries) => {
      const entry = entries[entries.length - 1];
      const dpb = entry.devicePixelContentBoxSize;
      if (dpb && dpb.length > 0) {
        applySize(dpb[0].inlineSize, dpb[0].blockSize);
      } else {
        fallbackMeasure();
      }
      scheduleRemoteResize();
    });
    try {
      ro.observe(container, { box: "device-pixel-content-box" as ResizeObserverBoxOptions });
    } catch {
      ro.observe(container);
    }
    fallbackMeasure();

    // DPR changes (window moved between monitors) may not fire the RO fallback
    let mq: MediaQueryList | null = null;
    const watchDpr = (): void => {
      mq?.removeEventListener("change", onDprChange);
      mq = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
      mq.addEventListener("change", onDprChange);
    };
    const onDprChange = (): void => {
      fallbackMeasure();
      watchDpr();
    };
    watchDpr();

    // Remote-resize mode: debounce ~500ms, request the window's physical pixels
    let resizeTimer = 0;
    const scheduleRemoteResize = (): void => {
      if (modeRef.current !== "remote-resize") return;
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        sessionRef.current.requestResize(canvas.width, canvas.height);
      }, 500);
    };

    return () => {
      // BEFORE dispose(): a disposed renderer has no framebuffer to read.
      teardownCaptureRef.current();
      ro.disconnect();
      mq?.removeEventListener("change", onDprChange);
      window.clearTimeout(resizeTimer);
      input.detach();
      renderer.dispose();
      rendererRef.current = null;
      inputRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const modeRef = useRef(scalingMode);
  modeRef.current = scalingMode;

  // ------------------------------------------------------- derived wiring

  useEffect(() => {
    inputRef.current?.setViewOnly(viewOnly);
    session.setViewOnly(viewOnly);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewOnly]);

  useEffect(() => {
    inputRef.current?.setPassthrough(passthrough);
  }, [passthrough]);

  // --------------------------------------------------- native key capture
  //
  // Tier 1 (`SessionInput.setPassthrough`, above) can only preventDefault what
  // the webview actually receives. Tier 2 is the native hook in the shell: the
  // toggle asks for it, and the shell reports back on `capture://event` as it
  // arms, disarms on blur, and force-releases (PRD/06 §3).

  // The shell is the source of truth for the indicator, it releases capture on
  // blur, window close and the Ctrl+Alt+Shift+Esc escape hatch without asking.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void listenCapture((ev) => {
      if (cancelled) return;
      // `sessionId` is null for a broadcast force-release.
      if (ev.sessionId && params.sessionId && ev.sessionId !== params.sessionId) return;
      setCapture(ev.status);
      // A force-release must also flip the switch back, or the UI would claim
      // pass-through is on while nothing is grabbed.
      if (ev.sessionId === null && ev.status.state === "inactive") setPassthroughState(false);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    void fetchCaptureStatus().then((s) => {
      if (!cancelled) setCapture(s);
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [params.sessionId]);

  // Release the grab when the session ends, whatever ended it.
  useEffect(() => {
    const sid = params.sessionId;
    if (!sid) return;
    if (session.state.state === "disconnected") {
      setPassthroughState(false);
      void captureStop(sid);
    }
  }, [session.state.state, params.sessionId]);

  // …and on unmount, belt-and-braces alongside the shell's window hooks.
  useEffect(() => {
    const sid = params.sessionId;
    return () => {
      if (sid) void captureStop(sid);
    };
  }, [params.sessionId]);

  const togglePassthrough = useCallback(
    (want: boolean): void => {
      setPassthroughState(want);
      const sid = params.sessionId;
      if (!sid) return;
      if (!want) {
        void captureStop(sid).then(setCapture);
        return;
      }
      void captureStart(sid).then((status) => {
        setCapture(status);
        // Only explain on first refusal, the OS prompt itself comes later,
        // from the user pressing the button in the dialog (PRD/06 §3: never
        // demand Accessibility unasked).
        if (status.state === "permission-required") setShowCaptureHelp(true);
      });
    },
    [params.sessionId],
  );

  useEffect(() => {
    const r = rendererRef.current;
    if (!r) return;
    if (scalingMode === "remote-resize") {
      r.setScalingMode("aspect-fit");
      const c = canvasRef.current;
      if (c) session.requestResize(c.width, c.height);
    } else {
      r.setScalingMode(scalingMode === "custom" ? "custom" : scalingMode);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scalingMode]);

  useEffect(() => {
    rendererRef.current?.setZoom(zoom);
  }, [zoom]);

  useEffect(() => {
    rendererRef.current?.setGrayLevels(quality === "bw" ? bwLevels : 0);
  }, [quality, bwLevels]);

  // Window title: name + resolution
  useEffect(() => {
    document.title = remoteSize
      ? `${session.desktopName}, ${remoteSize.w}×${remoteSize.h}`
      : session.desktopName;
  }, [session.desktopName, remoteSize]);

  // Reconnected toast; keyboard safety on any non-connected transition
  useEffect(() => {
    if (session.state.state === "reconnecting") {
      wasReconnecting.current = true;
    } else if (session.state.state === "connected" && wasReconnecting.current) {
      wasReconnecting.current = false;
      // fade the scrim out over 150ms, then a brief confirmation toast
      setScrimFading(true);
      window.setTimeout(() => setScrimFading(false), 180);
      push("success", "Reconnected");
      session.refreshScreen();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.state]);

  // Remote clipboard -> local (text only). The write is native: the webview's
  // own clipboard API is gesture-gated and this text arrives from the socket.
  useEffect(() => {
    const text = session.remoteClipboard;
    if (text === null) return;
    void writeClipboard(text);
  }, [session.remoteClipboard]);

  // Bell: brief visual pulse via toast
  useEffect(() => {
    if (session.bellTick > 0) push("info", " Bell");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.bellTick]);

  // ---------------------------------------------------------- library thumbnail
  //
  // PRD/03 §3.1: capture on every successful connect (once the desktop is
  // actually on screen) and again on the way out, so the tile reflects the
  // latest state.
  //
  // This deliberately does NOT gate on `params.profileId`. A session started
  // from the Nearby list has no profile, but the shell keys those captures by
  // endpoint (`thumbnail::discovered_key`), so the unfamiliar machine you most
  // need to recognise is exactly the one that used to have no picture. The
  // shell is the only thing that decides where (or whether) a capture is
  // stored; the webview just offers the pixels.

  // A prompt on top of the canvas means the framebuffer may be a login screen, // PRD/03 §3.2 is explicit that we never store one.
  const promptUp = session.credentialRequest !== null || session.certPrompt !== null;
  const promptUpRef = useRef(promptUp);
  promptUpRef.current = promptUp;

  // Library live previews (~2 fps), same prompt guard as the thumbnail
  // capture below, plus its own enabled/connected/hasFrame gates.
  useLivePreview({
    params,
    rendererRef,
    connected: session.state.state === "connected",
    promptUp,
    frameCountRef,
  });

  /** Resolves true only if pixels actually reached the shell. */
  const captureThumb = useCallback(async (): Promise<boolean> => {
    if (promptUpRef.current) return false;
    // A session that never rendered a real frame (auth cancelled, connection
    // failed at the handshake) still has a texture, it is just blank. Storing
    // it would overwrite a perfectly good tile picture with a black rectangle.
    if (!rendererRef.current?.hasFrame()) return false;
    const frame = rendererRef.current?.readFramebufferRGBA();
    if (!frame) return false;
    await sessionRef.current.captureThumbnail(frame.width, frame.height, frame.pixels);
    return true;
  }, []);

  // Debounced to once per session: the settle timer is armed by the first
  // `connected` transition and never re-arms, so a frame storm (or a flapping
  // reconnect) cannot turn into a PNG encode per frame.
  const settledCapture = useRef(false);
  useEffect(() => {
    if (session.state.state !== "connected") return;
    if (settledCapture.current) return;
    const t = window.setTimeout(() => {
      settledCapture.current = true;
      void captureThumb();
    }, THUMBNAIL_SETTLE_MS);
    return () => window.clearTimeout(t);
  }, [session.state.state, captureThumb]);

  // The exit capture. Runs at most once, from whichever of these happens
  // first: the user disconnecting, the connection dropping, the window being
  // closed, or the view unmounting. Latched only on a capture that really
  // happened, so an early teardown with nothing rendered yet (StrictMode's
  // dev remount, a hot reload) does not spend the one shot.
  const exitCaptured = useRef(false);
  const captureOnExit = useCallback(async (): Promise<void> => {
    if (exitCaptured.current) return;
    if (await captureThumb()) exitCaptured.current = true;
  }, [captureThumb]);

  useEffect(() => {
    if (session.state.state === "disconnected") void captureOnExit();
  }, [session.state.state, captureOnExit]);

  /** The one way this window goes away, from every button and from Escape. */
  const dismiss = useCallback((): void => {
    void closeSessionWindow(params.sessionId);
  }, [params.sessionId]);

  // Closing the session window is the most common way a session ends, and it
  // tears the webview down before any React cleanup could finish an invoke, // so hold the close just long enough to hand over the pixels.
  //
  // `closingWindow` latches UNCONDITIONALLY, whatever the capture does: a
  // failed capture must never wedge the window open. `closeSessionWindow` is
  // what actually finishes the job, see the note at the top of this file for
  // why calling `win.close()` from in here was not enough.
  useEffect(() => {
    if (!inTauri()) return;
    let cancelled = false;
    void import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => {
        const win = getCurrentWindow();
        return win.onCloseRequested((event) => {
          if (closingWindow) return; // already on the way out, let it close
          closingWindow = true;
          event.preventDefault();
          return Promise.race([captureOnExit(), delay(CAPTURE_CLOSE_BUDGET_MS)])
            .catch(() => undefined)
            .then(() => closeSessionWindow(params.sessionId));
        });
      })
      .then((fn) => {
        if (cancelled) void fn();
        else releaseCloseHold = fn;
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
      const release = releaseCloseHold;
      releaseCloseHold = null;
      void release?.();
    };
  }, [params.sessionId, captureOnExit]);

  // Belt-and-braces for an unmount that is not a window close (browser dev,
  // hot reload). Invoked from the renderer effect's cleanup rather than this
  // one: effect cleanups run in declaration order, so by the time a cleanup
  // down here ran, the renderer above had already been disposed and the
  // framebuffer read would return nothing.
  teardownCaptureRef.current = captureOnExit;

  // -------------------------------------------------------- file transfer

  // Kept mounted whenever SFTP is usable so drag-and-drop uploads and their
  // progress events keep working with the panel closed (PRD/08 §3.1:
  // "transfers continue while the user keeps working in the session").
  const files = useFiles(params.sessionId ?? "", sshAvailable === true);
  const filesRef = useRef(files);
  filesRef.current = files;

  // Capability probe (PRD/08 §2.1), quiet: a closed port is the normal case
  // for a Windows box without OpenSSH Server, not an error worth a toast.
  useEffect(() => {
    if (!params.address || session.state.state !== "connected") return;
    let cancelled = false;
    void filesProbe(params.address, 22).then((ok) => {
      if (!cancelled) setSshAvailable(ok);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.address, session.state.state]);

  /** Where a drop lands: whatever the remote pane shows, else the remote home. */
  const dropDir = useCallback((): string => {
    const remotePath = filesRef.current.remote.path;
    if (remotePath) return remotePath;
    const conn = filesRef.current.conn;
    return conn.state === "connected" ? conn.home : "~";
  }, []);

  /** Open the sidecar on demand; safe to call repeatedly. */
  const ensureFilesConnected = useCallback((): void => {
    const api = filesRef.current;
    if (!params.address) return;
    if (api.conn.state !== "idle" && api.conn.state !== "error") return;
    void api.connect({
      host: params.address,
      port: 22,
      // Empty means "the same user as here"; Rust fills it in and loads any
      // stored passphrase from the keychain. Secrets never travel through JS.
      username: "",
      auth: "stored",
      profileId: params.profileId,
    });
  }, [params.address, params.profileId]);

  useEffect(() => {
    if (filesOpen) ensureFilesConnected();
  }, [filesOpen, ensureFilesConnected]);

  // Drag files onto the session window -> upload (PRD/08 §3.1). Tauri owns the
  // OS drag session when `dragDropEnabled` is on, so HTML5 drag events never
  // fire for real files, this is the only path that sees them.
  useEffect(() => {
    if (!inTauri() || sshAvailable !== true) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void import("@tauri-apps/api/webview")
      .then(({ getCurrentWebview }) =>
        getCurrentWebview().onDragDropEvent((event) => {
          const payload = event.payload as { type: string; paths?: string[] };
          switch (payload.type) {
            case "enter":
            case "over":
              setDropCount(payload.paths?.length ?? 0);
              ensureFilesConnected();
              break;
            case "drop": {
              setDropCount(null);
              const paths = payload.paths ?? [];
              if (paths.length === 0) return;
              const target = dropDir();
              void filesRef.current.upload(paths, target).then(() => {
                push("info", `Sending ${paths.length} file${paths.length === 1 ? "" : "s"} to ${target}`);
              });
              break;
            }
            default:
              setDropCount(null);
              break;
          }
        }),
      )
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [sshAvailable, ensureFilesConnected, dropDir, push]);

  // ------------------------------------------------------------- actions

  /**
   * Grab the final thumbnail BEFORE asking the shell to tear the session down:
   * `capture_thumbnail` resolves the host from the live session registry, and
   * that entry disappears as soon as the session task ends.
   */
  const disconnectWithThumbnail = useCallback((): void => {
    void Promise.race([captureOnExit(), delay(CAPTURE_CLOSE_BUDGET_MS)]).finally(() => {
      sessionRef.current.disconnect();
    });
  }, [captureOnExit]);

  const toggleFullscreen = useCallback(async (): Promise<void> => {
    if (inTauri()) {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        const win = getCurrentWindow();
        await win.setFullscreen(!(await win.isFullscreen()));
        return;
      } catch {
        /* fall through to DOM fullscreen */
      }
    }
    if (document.fullscreenElement) void document.exitFullscreen();
    else void document.documentElement.requestFullscreen();
  }, []);

  const sendCombo = useCallback(
    (combo: "ctrl-alt-del" | "cmd-tab" | "win" | "alt-f4" | "escape"): void => {
      const input = inputRef.current;
      if (!input) return;
      switch (combo) {
        case "ctrl-alt-del":
          input.sendKeyCombo([KEYSYM.Control_L, KEYSYM.Alt_L, KEYSYM.Delete]);
          break;
        case "cmd-tab":
          input.sendKeyCombo([KEYSYM.Alt_L, KEYSYM.Tab]);
          break;
        case "win":
          input.sendKeyCombo([KEYSYM.Super_L]);
          break;
        case "alt-f4":
          input.sendKeyCombo([KEYSYM.Alt_L, KEYSYM.F4]);
          break;
        case "escape":
          input.sendKeyCombo([KEYSYM.Escape]);
          break;
      }
    },
    [],
  );

  const screenshot = useCallback(async (): Promise<void> => {
    const blob = await rendererRef.current?.screenshot();
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${session.desktopName.replace(/[^\w.-]+/g, "_")}-${Date.now()}.png`;
    a.click();
    URL.revokeObjectURL(url);
    push("success", "Screenshot saved");
  }, [session.desktopName, push]);

  const clipboardSend = useCallback(async (): Promise<void> => {
    const text = await readClipboard();
    if (text === null) {
      push("warning", "Could not read the local clipboard");
      return;
    }
    if (text) {
      session.sendClipboard(text);
      push("success", "Clipboard sent to remote");
    }
  }, [session, push]);

  // ------------------------------------------------------------- render

  const st = session.state;

  // Escape dismisses a terminal session window.
  //
  // The remote keyboard hook sits on `window` in the CAPTURE phase and
  // `preventDefault()`s everything it forwards, so the only reliable place to
  // answer Escape is another capture-phase listener, and there is no remote
  // left to send it to once the session is over.
  const terminal = st.state === "disconnected";
  useEffect(() => {
    if (!terminal) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      dismiss();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [terminal, dismiss]);

  const showConnecting =
    st.state === "resolving" || st.state === "connecting" ||
    st.state === "authenticating" || st.state === "negotiating" || st.state === "idle";

  return (
    <div ref={containerRef} className="relative h-full w-full overflow-hidden bg-canvas">
      <canvas
        ref={canvasRef}
        className="session-canvas"
        tabIndex={0}
        aria-label={`Remote desktop: ${session.desktopName}`}
      />

      <SessionToolbar
        desktopName={session.desktopName}
        state={st}
        stats={session.stats}
        scalingMode={scalingMode}
        zoom={zoom}
        quality={quality}
        bwLevels={bwLevels}
        passthrough={passthrough}
        captureStatus={capture}
        viewOnly={viewOnly}
        recallSignal={recallSignal}
        onScalingMode={setScalingModeState}
        onZoom={(z) => {
          setScalingModeState("custom");
          setZoomState(z);
        }}
        onQuality={(q) => {
          setQualityState(q);
          session.setQuality(q);
        }}
        onBwLevels={setBwLevelsState}
        onPassthrough={togglePassthrough}
        onCapturePermission={() => setShowCaptureHelp(true)}
        onSendCombo={sendCombo}
        onClipboardSend={() => void clipboardSend()}
        onFiles={() => setFilesOpen(true)}
        filesAvailable={sshAvailable}
        onFullscreen={() => void toggleFullscreen()}
        onViewOnly={setViewOnlyState}
        onScreenshot={() => void screenshot()}
        onRefresh={session.refreshScreen}
        onDisconnect={disconnectWithThumbnail}
      />

      {showConnecting ? <ConnectingOverlay state={st} name={session.desktopName} /> : null}

      {scrimFading && st.state === "connected" ? (
        <div className="scrim-out pointer-events-none absolute inset-0 z-20 bg-scrim" aria-hidden="true" />
      ) : null}

      {st.state === "reconnecting" ? (
        <ReconnectOverlay
          name={session.desktopName}
          attempt={st.attempt}
          nextRetryMs={st.next_retry_ms}
          reason={st.reason}
          onRetryNow={session.reconnectNow}
          onDisconnect={session.disconnect}
        />
      ) : null}

      {st.state === "disconnected" ? (
        <DisconnectedOverlay
          name={session.desktopName}
          reason={st.reason}
          canRetry={st.can_retry}
          onReconnect={session.retryConnect}
          onClose={dismiss}
        />
      ) : null}

      {showCaptureHelp ? (
        <CapturePermissionDialog
          status={capture}
          onGrant={() => {
            captureRequestPermission();
            // The OS panel is modal to the user, not to us; re-check on a beat
            // so the dialog can flip to "granted" without another click.
            window.setTimeout(() => {
              void fetchCaptureStatus().then(setCapture);
            }, 1500);
          }}
          onRetry={() => {
            setShowCaptureHelp(false);
            togglePassthrough(true);
          }}
          onClose={() => setShowCaptureHelp(false)}
        />
      ) : null}

      {filesOpen ? (
        <FilePanel
          files={files}
          hostName={session.desktopName}
          onClose={() => setFilesOpen(false)}
        />
      ) : null}

      {dropCount !== null ? (
        <DropOverlay
          count={dropCount}
          hostName={session.desktopName}
          remoteDir={dropDir()}
        />
      ) : null}

      {session.certPrompt ? (
        <CertPrompt
          data={{
            fingerprint: session.certPrompt.fingerprint,
            subject: session.certPrompt.subject,
            isChange: session.certPrompt.isChange,
            hostName: session.desktopName,
          }}
          onTrust={() => session.trustCertificate(true)}
          onConnectOnce={() => session.trustCertificate(false)}
          onCancel={session.dismissCertPrompt}
        />
      ) : null}

      {/*
        The handshake is parked here, so the connecting overlay is still up.
        `relative z-50` gives this subtree its own stacking context ABOVE that
        overlay (z-auto) and every other scrim, without it the "Connecting…"
        panel paints over the dialog and the user sees nothing to answer.
      */}
      {session.credentialRequest ? (
        <div className="relative z-50">
          <CredentialPrompt
            request={session.credentialRequest}
            hostName={session.desktopName}
            onSubmit={session.submitCredentials}
            onCancel={session.dismissCredentialPrompt}
          />
        </div>
      ) : null}

      <ToastShelf />
    </div>
  );
}

// ------------------------------------------------ capture permission onboarding

/**
 * Explain BEFORE prompting (PRD/06 §3).
 *
 * macOS Accessibility is the same permission a keylogger would ask for, so an
 * unexplained system prompt reads as spyware. This dialog states exactly what
 * the permission is used for, what it is not used for, and only then offers the
 * button that triggers the OS panel, plus a deep link for the case where the
 * user already denied it and macOS will not ask twice.
 */
function CapturePermissionDialog({
  status,
  onGrant,
  onRetry,
  onClose,
}: {
  status: CaptureStatus;
  onGrant: () => void;
  onRetry: () => void;
  onClose: () => void;
}): ReactNode {
  const isMac = navigator.platform.toLowerCase().includes("mac");

  if (status.state === "unsupported") {
    return (
      <Dialog title="Shortcut pass-through isn't available here" onClose={onClose} width={480}>
        <div className="space-y-3 p-5 text-sm text-secondary">
          <p>{status.reason}</p>
          <p>
            Everything the browser engine can see still reaches the remote. For the shortcuts it
            can't, use <strong>Send to remote</strong> in the keyboard menu, Ctrl+Alt+Del,
            Cmd/Alt+Tab and the Windows key are all deliverable that way.
          </p>
          <div className="flex justify-end pt-1">
            <button type="button" data-autofocus className="btn-primary" onClick={onClose}>
              Got it
            </button>
          </div>
        </div>
      </Dialog>
    );
  }

  const granted = status.state === "active";

  return (
    <Dialog title="Let this app capture system shortcuts" onClose={onClose} width={520}>
      <div className="space-y-3.5 p-5 text-sm text-secondary">
        <p>
          To send {isMac ? "⌘Tab, ⌘Space and ⌘Q" : "Alt+Tab and the Windows key"} to the remote
          computer instead of this one, {isMac ? "macOS" : "the system"} has to let this app see
          keys before the {isMac ? "window server" : "shell"} does.
        </p>
        {isMac ? (
          <div className="rounded-md bg-inset p-3.5">
            <p className="text-xs text-primary">
              macOS calls this <strong>Accessibility</strong>. It is only used while a session
              window is focused and pass-through is switched on. Keys are forwarded to the remote
              computer you are connected to and are never stored or sent anywhere else.
            </p>
          </div>
        ) : null}
        <p className="text-xs text-tertiary">
          You can release the keyboard at any time with{" "}
          <span className="mono">Ctrl+Alt+Shift+Esc</span>, and it releases automatically when this
          window loses focus or closes.
        </p>

        <div className="flex flex-wrap justify-end gap-2.5 pt-1">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Not now
          </button>
          {isMac ? (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void openExternal(MACOS_ACCESSIBILITY_SETTINGS_URL)}
            >
              Open System Settings
            </button>
          ) : null}
          {granted ? (
            <button type="button" data-autofocus className="btn-primary" onClick={onRetry}>
              Turn pass-through on
            </button>
          ) : (
            <button type="button" data-autofocus className="btn-primary" onClick={onGrant}>
              Allow…
            </button>
          )}
        </div>
        {isMac ? (
          <p className="text-2xs text-tertiary">
            Already allowed but still not working? A macOS update or a new build can silently
            invalidate the grant, remove the app from the Accessibility list and add it again.
          </p>
        ) : null}
      </div>
    </Dialog>
  );
}

// -------------------------------------------------------- connecting overlay

const STAGES = ["resolving", "connecting", "authenticating", "negotiating"] as const;

function stageLabel(st: SessionState): string {
  switch (st.state) {
    case "resolving":
      return "Resolving";
    case "connecting":
      return "Connecting";
    case "authenticating":
      return `Authenticating (${st.method})`;
    case "negotiating":
      return "Negotiating";
    default:
      return "Preparing";
  }
}

function ConnectingOverlay({ state, name }: { state: SessionState; name: string }): ReactNode {
  const idx = STAGES.indexOf(state.state as (typeof STAGES)[number]);
  return (
    <div className="absolute inset-0 flex items-center justify-center bg-canvas" role="status" aria-live="polite">
      <div className="w-80 rounded-lg border border-subtle bg-surface p-5 shadow-(--shadow-pop)">
        <p className="mb-3 text-sm font-medium text-primary">Connecting to {name}</p>
        <ol className="space-y-1.5">
          {STAGES.map((s, i) => (
            <li key={s} className="flex items-center gap-2 text-xs">
              <span
                className={
                  i < idx
                    ? "h-1.5 w-1.5 rounded-full bg-success"
                    : i === idx
                      ? "h-1.5 w-1.5 animate-pulse rounded-full bg-accent"
                      : "h-1.5 w-1.5 rounded-full bg-inset"
                }
              />
              <span className={i === idx ? "text-primary" : "text-tertiary"}>
                {i === idx ? stageLabel(state) : s[0].toUpperCase() + s.slice(1)}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

// --------------------------------------------------------- reconnect overlay

function ReconnectOverlay({
  name,
  attempt,
  nextRetryMs,
  reason,
  onRetryNow,
  onDisconnect,
}: {
  name: string;
  attempt: number;
  nextRetryMs: number;
  reason: string;
  onRetryNow: () => void;
  onDisconnect: () => void;
}): ReactNode {
  const [remaining, setRemaining] = useState(nextRetryMs);
  useEffect(() => {
    setRemaining(nextRetryMs);
    const started = performance.now();
    const iv = window.setInterval(() => {
      const left = nextRetryMs - (performance.now() - started);
      setRemaining(Math.max(0, left));
      if (left <= 0) window.clearInterval(iv);
    }, 250);
    return () => window.clearInterval(iv);
  }, [nextRetryMs, attempt]);

  const secs = Math.ceil(remaining / 1000);

  // Translucent scrim OVER the last known frame, never a blank screen.
  return (
    <div
      className="fade-in absolute inset-0 z-20 flex items-center justify-center bg-scrim"
      role="alert"
      aria-live="assertive"
    >
      <div className="w-96 max-w-[calc(100vw-32px)] rounded-lg border border-subtle bg-raised p-5 shadow-(--shadow-pop)">
        <div className="mb-1 overflow-hidden rounded-pill bg-inset">
          <div className="indeterminate-bar h-0.5 w-1/3 bg-accent" />
        </div>
        <p className="mt-3 text-sm font-medium text-primary">
          Reconnecting to {name}… attempt {attempt}
          {secs > 0 ? ` · retrying in ${secs}s` : " · retrying now"}
        </p>
        {reason ? <p className="mt-1 text-xs text-secondary">{reason}</p> : null}
        <div className="mt-4 flex justify-end gap-2.5">
          <button type="button" className="btn-secondary" onClick={onDisconnect}>
            Disconnect
          </button>
          <button type="button" className="btn-primary" onClick={onRetryNow}>
            Retry now
          </button>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------- terminal disconnect

/**
 * Was this a rejected credential? Those get a different offer: replaying the
 * same stored password would just fail again, so the retry has to ask.
 */
function isAuthFailure(reason: string): boolean {
  const r = reason.toLowerCase();
  if (r.includes("cancel")) return true;
  return r.includes("auth") || r.includes("password") || r.includes("credential");
}

/**
 * Turn a raw failure reason into a sentence.
 *
 * `reason` is typed `string` but arrives over IPC, so it is coerced first: a
 * `reason.toLowerCase()` on a payload that turned out not to carry one threw
 * during render, and with nothing to catch it React unmounted the whole tree, * the "crash" that left a white session window with no way out.
 */
function diagnose(reason: unknown): string {
  const text = typeof reason === "string" ? reason : "";
  const r = text.toLowerCase();
  // Ordered: "cancelled" must win over the generic auth match below, or
  // dismissing the password prompt would be reported as a failed login.
  if (r.includes("cancel")) return "Authentication was cancelled. Reconnect to try again.";
  if (r.includes("refused")) return "Connection refused, the VNC server may not be running on this port.";
  if (r.includes("timed out") || r.includes("timeout")) return "The computer didn't respond, it may be asleep, off, or unreachable from this network.";
  if (r.includes("auth") || r.includes("password")) return "Incorrect password, the server did not accept it.";
  if (r.includes("certificate") || r.includes("tls")) return "The secure connection could not be verified.";
  if (r.includes("reset")) return "The connection was closed by the other side.";
  return text || "The connection ended.";
}

function DisconnectedOverlay({
  name,
  reason,
  canRetry,
  onReconnect,
  onClose,
}: {
  name: string;
  reason: string;
  canRetry: boolean;
  onReconnect: (options?: { reprompt?: boolean }) => void;
  onClose: () => void;
}): ReactNode {
  const panelRef = useRef<HTMLDivElement>(null);
  // Move focus off the canvas: it keeps Enter/Space on the default action and
  // takes the keystrokes out of the remote input hook's reach.
  useEffect(() => {
    const el = panelRef.current;
    (el?.querySelector<HTMLElement>("[data-autofocus]") ??
      el?.querySelector<HTMLElement>("button"))?.focus();
  }, []);

  const authFailure = isAuthFailure(typeof reason === "string" ? reason : "");
  // A rejected password is ALWAYS retryable from the user's side, whatever the
  // core said: `can_retry: false` means "do not reconnect automatically", not
  // "there is nothing this person can do". Offering only a Close button after
  // three wrong attempts is the dead end the report was about.
  const retryable = canRetry || authFailure;

  return (
    <div className="fade-in absolute inset-0 z-30 flex items-center justify-center bg-scrim">
      {/*
        `role="dialog"` is load-bearing, not decoration: the remote keyboard hook
        (render/input.ts `LOCAL_UI_SELECTOR`) uses it to tell our own overlays
        from the remote desktop, so without it every keystroke in here would be
        forwarded and preventDefault-ed.
      */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Disconnected from ${name}`}
        className="w-96 max-w-[calc(100vw-32px)] rounded-lg border border-subtle bg-raised p-5 shadow-(--shadow-pop)"
      >
        <p className="text-base font-semibold text-primary">Disconnected from {name}</p>
        <p className="mt-2 text-sm text-secondary" role="alert">
          {diagnose(reason)}
        </p>
        {authFailure ? (
          <p className="mt-1.5 text-xs text-tertiary">
            Reconnecting asks for the password again instead of reusing the saved one.
          </p>
        ) : null}
        <div className="mt-4 flex flex-wrap justify-end gap-2.5">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
          {retryable ? (
            <button
              type="button"
              data-autofocus
              className="btn-primary"
              onClick={() => onReconnect(authFailure ? { reprompt: true } : undefined)}
            >
              Reconnect
            </button>
          ) : null}
        </div>
        <p className="mt-2 text-right text-2xs text-tertiary">Press Esc to close this window</p>
      </div>
    </div>
  );
}

// ------------------------------------------------------------ error boundary

/**
 * Last line of defence for the session window.
 *
 * A throw during render unmounts the entire React tree, which in a window whose
 * only content IS the session reads as the app crashing: a blank white window
 * with no toolbar, no message and no way to close it. Catching it here turns
 * that into a readable panel with a working dismiss, the failure is still a
 * bug, but it stops being a trap.
 */
class SessionErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error): { error: Error } {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("session window crashed:", error, info.componentStack);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    const sessionId = new URLSearchParams(window.location.search).get("sessionId");
    return (
      <div className="flex h-full w-full items-center justify-center bg-canvas p-6">
        <div
          role="alertdialog"
          aria-modal="true"
          aria-label="This session window ran into a problem"
          className="w-[28rem] max-w-full rounded-lg border border-danger bg-raised p-5 shadow-(--shadow-pop)"
        >
          <p className="text-base font-semibold text-primary">
            This session window ran into a problem
          </p>
          <p className="mt-2 text-sm text-secondary">
            The connection has been closed. Nothing was saved from this session.
          </p>
          <p className="mono mt-3 max-h-24 overflow-auto rounded-md bg-inset p-2.5 text-xs text-tertiary">
            {error.message || String(error)}
          </p>
          <div className="mt-4 flex justify-end gap-2.5">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => this.setState({ error: null })}
            >
              Try again
            </button>
            <button
              type="button"
              data-autofocus
              className="btn-primary"
              onClick={() => void closeSessionWindow(sessionId)}
            >
              Close window
            </button>
          </div>
        </div>
      </div>
    );
  }
}
