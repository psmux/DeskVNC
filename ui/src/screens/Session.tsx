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
import { KEY_COMBO } from "../render/keysyms";
import {
  useSession,
  readSessionParams,
  type SessionBridge,
  type SessionParams,
} from "../hooks/useSession";
import { useLivePreview } from "../hooks/useLivePreview";
import { SessionToolbar } from "../components/SessionToolbar";
import { CertPrompt } from "../components/CertPrompt";
import { CredentialPrompt } from "../components/CredentialPrompt";
import { SshHostKeyPrompt } from "../components/SshHostKeyPrompt";
import { DropOverlay, FilePanel } from "../components/FilePanel";
import { useFiles } from "../hooks/useFiles";
import { ToastShelf } from "../components/primitives";
import { useToasts } from "../state/ToastContext";
import { useSettings } from "../state/SettingsContext";
import { classNames } from "../lib/util";
import { Dialog } from "../components/primitives";
import type { QualityPreset, ScalingMode, SessionState } from "../lib/types";
import {
  PREF_CLIPBOARD_AUTO,
  PREF_CLIPBOARD_ON_PASTE,
  PREF_FORWARD_INSERTED_TEXT,
  PREF_CLIPBOARD_ON_FOCUS,
  PREF_MATCH_LOCAL_LAYOUT,
  PREF_NATURAL_SCROLL,
  PREF_ZOOM_LOCKED,
  readBoolPref,
  writeBoolPref,
} from "../lib/prefs";
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

/**
 * How this viewer is being shown.
 *
 * With no props at all it is what it always was: the only thing in a window of
 * its own, reading its connection parameters out of that window's query
 * string. `embedded` is the tabbed view, where several of these are mounted
 * side by side in the library window and only one is on screen at a time, so
 * everything window-wide (the title, the close hold, the keyboard listeners,
 * the toast shelf) has to belong to the shell instead.
 */
export interface SessionProps {
  /** Connection parameters. Omit in a session window, where the URL has them. */
  params?: SessionParams;
  /** Mounted as a tab rather than owning the window it is in. */
  embedded?: boolean;
  /** This tab is the one on screen. Only meaningful when embedded. */
  active?: boolean;
  /** Embedded: take this tab off the strip. */
  onClose?: () => void;
  /** The server told us what this desktop is called. */
  onDesktopName?: (name: string) => void;
  /** Connection state changed, for the tab's status dot. */
  onState?: (state: SessionState) => void;
  /**
   * First refusal on a keystroke, ahead of this view's own shortcuts and the
   * remote desktop. The remote keyboard hook sits on `window` in the capture
   * phase and `preventDefault`s what it forwards, so a shell-level shortcut
   * (switch tabs, close tab) can only be seen through here.
   */
  onAppHotkey?: (e: KeyboardEvent) => boolean;
}

export function Session(props: SessionProps = {}): ReactNode {
  return (
    <SessionErrorBoundary embedded={props.embedded} onClose={props.onClose}>
      <SessionView {...props} />
    </SessionErrorBoundary>
  );
}

function SessionView({
  params: paramsProp,
  embedded = false,
  active = true,
  onClose,
  onDesktopName,
  onState,
  onAppHotkey,
}: SessionProps): ReactNode {
  const params = useMemo(() => paramsProp ?? readSessionParams(), [paramsProp]);
  /**
   * Is this view the one the user is looking at? A session window always is.
   * A background tab is mounted and still connected, but must not draw, must
   * not hold the keyboard, and must not answer file drops.
   */
  const visible = !embedded || active;
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rendererRef = useRef<WebGLRenderer | null>(null);
  const inputRef = useRef<SessionInput | null>(null);
  /** Last-chance thumbnail capture, run before the renderer is disposed. */
  const teardownCaptureRef = useRef<() => void>(() => undefined);
  const { push } = useToasts();
  const { settings, update } = useSettings();

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
  /** Flipped once the renderer and input handler exist, so the effects that
   *  arm and disarm them have something to run against. */
  const [viewReady, setViewReady] = useState(false);

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
      // A forwarded Cmd/Ctrl+V pushes the CURRENT local clipboard first, so
      // clipboard-mode dictation (write transcript, synthesize paste) pastes
      // the transcript and not whatever the remote heard about last. Behind
      // both the master sync switch and its own preference: with either off,
      // nothing leaves this machine implicitly.
      onForwardedPaste: () =>
        readBoolPref(PREF_CLIPBOARD_AUTO, true) && readBoolPref(PREF_CLIPBOARD_ON_PASTE, true)
          ? pushClipboardRef.current(false)
          : Promise.resolve("unchanged" as const),
      onAppHotkey: (e) => {
        // The shell (the tab strip) gets first refusal: its shortcuts have to
        // beat both this view's and the remote desktop's.
        if (appHotkeyRef.current?.(e)) return true;
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
    // Attaching is NOT done here: `SessionInput` listens on `window` in the
    // capture phase, so with several tabs mounted the background ones would
    // swallow every keystroke meant for the tab in front. The effect below
    // arms exactly one of them.
    setViewReady(true);

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
      setViewReady(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const modeRef = useRef(scalingMode);
  modeRef.current = scalingMode;

  const appHotkeyRef = useRef(onAppHotkey);
  appHotkeyRef.current = onAppHotkey;

  // Only the view on screen owns the keyboard and the pointer. `detach()`
  // releases whatever was still held, so a modifier held down through the
  // switch does not stay down on the desktop being left behind.
  useEffect(() => {
    const input = inputRef.current;
    if (!viewReady || !input || !visible) return;
    input.attach();
    return () => input.detach();
  }, [viewReady, visible]);

  // Coming to the front takes the focus with it. The remote keyboard hook
  // deliberately ignores keystrokes aimed at our own inputs and dialogs, so a
  // tab opened from the library search box would otherwise send everything
  // typed into that box instead of to the remote desktop. Focus goes to the
  // input handler's hidden capture element (not the canvas), which is what
  // lets IMEs and dictation deliver text to the session at all.
  useEffect(() => {
    if (!viewReady || !visible) return;
    if (inputRef.current) inputRef.current.focus();
    else canvasRef.current?.focus({ preventScroll: true });
  }, [viewReady, visible]);

  // …and only the view on screen draws. Frames for a background tab still
  // arrive and are still uploaded into its texture, so switching back shows
  // the current desktop rather than a stale one; what stops is the per-frame
  // GL draw, which is what would otherwise cost a full render pass per tab.
  useEffect(() => {
    const renderer = rendererRef.current;
    if (!viewReady || !renderer) return;
    if (visible) {
      renderer.start();
      renderer.markDirty();
    } else {
      renderer.stop();
    }
  }, [viewReady, visible]);

  // ------------------------------------------------------- derived wiring

  useEffect(() => {
    inputRef.current?.setViewOnly(viewOnly);
    session.setViewOnly(viewOnly);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewOnly]);

  useEffect(() => {
    inputRef.current?.setPassthrough(passthrough);
  }, [passthrough]);

  // Preferences ▸ Input (localStorage-backed, no live cross-window push, same
  // as the clipboard prefs below): read them fresh on mount and whenever the
  // window regains focus, since Preferences may have changed them while this
  // session wasn't the one on screen. The keyboard mode lives in the protocol
  // core (it decides keysym vs scancode on the wire), so it is pushed to the
  // backend rather than into the input handler.
  useEffect(() => {
    if (!viewReady || !visible) return;
    const sid = params.sessionId;
    const sync = (): void => {
      inputRef.current?.setNaturalScroll(readBoolPref(PREF_NATURAL_SCROLL, true));
      inputRef.current?.setForwardInsertedText(readBoolPref(PREF_FORWARD_INSERTED_TEXT, true));
      if (sid) {
        const matchLocal = readBoolPref(PREF_MATCH_LOCAL_LAYOUT, false);
        void safeInvoke(
          "set_prefer_scancodes",
          { sessionId: sid, prefer: !matchLocal },
          null,
        );
      }
    };
    sync();
    window.addEventListener("focus", sync);
    return () => window.removeEventListener("focus", sync);
  }, [viewReady, visible, params.sessionId]);

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

  // Switching tabs is not a window blur, so none of the shell's focus hooks
  // fire: a tab going to the back has to hand the keyboard back itself, or it
  // would keep swallowing the shortcuts meant for the tab in front. The
  // pass-through switch stays ON, so coming back re-arms without asking again.
  const passthroughRef = useRef(passthrough);
  passthroughRef.current = passthrough;
  const captureSuspended = useRef(false);
  useEffect(() => {
    const sid = params.sessionId;
    if (!embedded || !sid) return;
    if (!active) {
      if (!passthroughRef.current) return;
      captureSuspended.current = true;
      void captureStop(sid).then(setCapture);
    } else if (captureSuspended.current) {
      captureSuspended.current = false;
      if (passthroughRef.current) void captureStart(sid).then(setCapture);
    }
  }, [embedded, active, params.sessionId]);

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

  // Window title: name + resolution. A tab does not own the window title,
  // the shell sets it from whichever tab is in front.
  useEffect(() => {
    if (embedded) return;
    document.title = remoteSize
      ? `${session.desktopName}, ${remoteSize.w}×${remoteSize.h}`
      : session.desktopName;
  }, [embedded, session.desktopName, remoteSize]);

  // Report upwards so a tab can be labelled with what the server calls itself
  // and show the connection's state, rather than the address it was dialled at.
  //
  // Read through refs so these fire on a real change and nothing else: the
  // shell re-renders whenever a tab's label changes, which would hand us fresh
  // callbacks, which would report again, which would re-render the shell.
  const reportRef = useRef({ onDesktopName, onState });
  reportRef.current = { onDesktopName, onState };

  useEffect(() => {
    reportRef.current.onDesktopName?.(session.desktopName);
  }, [session.desktopName]);

  useEffect(() => {
    reportRef.current.onState?.(session.state);
  }, [session.state]);

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

  /**
   * The text most recently moved in either direction, so neither automatic
   * half of the sync repeats itself: without it, text copied on the remote is
   * written to the local clipboard and then pushed straight back the next time
   * this window is focused.
   */
  const lastClipboardRef = useRef<string | null>(null);

  // Remote clipboard -> local (text only). The write is native: the webview's
  // own clipboard API is gesture-gated and this text arrives from the socket.
  useEffect(() => {
    const text = session.remoteClipboard;
    if (text === null) return;
    lastClipboardRef.current = text;
    void writeClipboard(text);
  }, [session.remoteClipboard]);

  /**
   * Local clipboard -> remote.
   *
   * `force` is the toolbar button: an explicit "send clipboard" re-sends even
   * when the text has not changed. The automatic callers pass false, so an
   * unchanged clipboard costs nothing on the wire.
   */
  const pushClipboard = useCallback(
    async (force: boolean): Promise<"sent" | "unchanged" | "unreadable"> => {
      const text = await readClipboard();
      if (text === null) return "unreadable";
      if (!text || (!force && text === lastClipboardRef.current)) return "unchanged";
      lastClipboardRef.current = text;
      // Await the enqueue: the paste-chord sync (SessionInput.deferForPaste)
      // relies on this resolving only once the text is ordered ahead of any
      // keystroke sent after it.
      await session.sendClipboard(text);
      return "sent";
    },
    [session],
  );

  /**
   * Automatic local -> remote sync (Preferences ▸ Clipboard).
   *
   * There is no OS clipboard-change event to subscribe to, and while this
   * session holds the keyboard every Ctrl/Cmd+C goes to the remote, so a local
   * copy can only have been made while we were somewhere else. Arriving is
   * therefore exactly the moment the local clipboard may have changed, which
   * is what the preference promises: "send your local clipboard to the remote
   * when you switch back to the session".
   *
   * Without this the RFB stream carried nothing until the user found the
   * toolbar button, so pasting into the remote pasted whatever that machine
   * had on its own clipboard.
   */
  /**
   * Held in a ref so the effect below can depend only on the things that
   * should actually re-arm it. `useSession` returns a fresh object every
   * render and the stats event re-renders once a second, so depending on the
   * callback directly re-ran the effect every second: the OS clipboard was
   * read once per second for the life of the session, which on macOS is both
   * a stream of warnings and repeated pasteboard access.
   */
  const pushClipboardRef = useRef(pushClipboard);
  pushClipboardRef.current = pushClipboard;

  const clipboardReady = session.state.state === "connected";
  useEffect(() => {
    if (!clipboardReady || !visible) return;
    const sync = (): void => {
      if (!readBoolPref(PREF_CLIPBOARD_AUTO, true)) return;
      if (!readBoolPref(PREF_CLIPBOARD_ON_FOCUS, true)) return;
      void pushClipboardRef.current(false);
    };
    // Connecting, or switching to this tab, counts as arriving: whatever was
    // copied beforehand should be there to paste.
    sync();
    window.addEventListener("focus", sync);
    return () => window.removeEventListener("focus", sync);
  }, [clipboardReady, visible]);

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
  const promptUp =
    session.credentialRequest !== null ||
    session.certPrompt !== null ||
    session.sshHostKeyPrompt !== null;
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

  /**
   * The one way this view goes away, from every button and from Escape.
   *
   * A tab grabs its parting thumbnail BEFORE it comes off the strip, for the
   * same reason the window path holds the close and `disconnectWithThumbnail`
   * races the capture first: `capture_thumbnail` resolves which host the pixels
   * belong to from the live session registry, and that entry goes away with the
   * session. Unmounting does still capture, from the renderer effect's cleanup,
   * but it runs after `useSession`'s (hooks tear down in declaration order, and
   * that one asks for the disconnect), so it is racing the teardown rather than
   * finishing ahead of it. The tab strip's own close button takes that path.
   */
  const dismiss = useCallback((): void => {
    if (embedded) {
      void Promise.race([captureOnExit(), delay(CAPTURE_CLOSE_BUDGET_MS)])
        .catch(() => undefined)
        .finally(() => onClose?.());
      return;
    }
    void closeSessionWindow(params.sessionId);
  }, [embedded, onClose, captureOnExit, params.sessionId]);

  // Closing the session window is the most common way a session ends, and it
  // tears the webview down before any React cleanup could finish an invoke, // so hold the close just long enough to hand over the pixels.
  //
  // `closingWindow` latches UNCONDITIONALLY, whatever the capture does: a
  // failed capture must never wedge the window open. `closeSessionWindow` is
  // what actually finishes the job, see the note at the top of this file for
  // why calling `win.close()` from in here was not enough.
  //
  // A tab installs none of this: it does not own the window, and a hold taken
  // out per tab would fight both the other tabs and the library. Closing the
  // library window with tabs open therefore skips the exit capture (the shell
  // still shuts the sessions down cleanly); closing the tab itself does not.
  useEffect(() => {
    if (!inTauri() || embedded) return;
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
  }, [embedded, params.sessionId, captureOnExit]);

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
  //
  // Tauri reports a drop to the whole window, not to a part of it, so only the
  // tab in front may listen: otherwise one dropped file would be uploaded once
  // per open tab, to whichever machines those happen to be.
  useEffect(() => {
    if (!inTauri() || sshAvailable !== true || !visible) return;
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
  }, [sshAvailable, visible, ensureFilesConnected, dropDir, push]);

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
          input.sendKeyCombo([KEY_COMBO.Control_L, KEY_COMBO.Alt_L, KEY_COMBO.Delete]);
          break;
        case "cmd-tab":
          input.sendKeyCombo([KEY_COMBO.Alt_L, KEY_COMBO.Tab]);
          break;
        case "win":
          input.sendKeyCombo([KEY_COMBO.Super_L]);
          break;
        case "alt-f4":
          input.sendKeyCombo([KEY_COMBO.Alt_L, KEY_COMBO.F4]);
          break;
        case "escape":
          input.sendKeyCombo([KEY_COMBO.Escape]);
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

  // Manual staleness override; off by default because it costs bandwidth.
  /**
   * Pinch-to-zoom off. Persisted rather than per-session: someone who finds
   * the gesture disruptive on their trackpad finds it disruptive every time,
   * and a setting that forgot itself on reconnect would be worse than none.
   */
  const [zoomLocked, setZoomLockedState] = useState(() =>
    readBoolPref(PREF_ZOOM_LOCKED, false),
  );
  const toggleZoomLocked = useCallback((locked: boolean): void => {
    setZoomLockedState(locked);
    writeBoolPref(PREF_ZOOM_LOCKED, locked);
    inputRef.current?.setZoomLocked(locked);
  }, []);

  // The input handler is created after first render, so the stored value has
  // to be pushed once it exists, not only when it changes.
  useEffect(() => {
    inputRef.current?.setZoomLocked(zoomLocked);
  }, [zoomLocked, viewReady]);

  const [alwaysRefresh, setAlwaysRefresh] = useState(false);
  const toggleAlwaysRefresh = useCallback(
    (enabled: boolean): void => {
      setAlwaysRefresh(enabled);
      session.setAlwaysRefresh(enabled);
    },
    [session],
  );

  const clipboardSend = useCallback(async (): Promise<void> => {
    const outcome = await pushClipboard(true);
    if (outcome === "unreadable") {
      push("warning", "Could not read the local clipboard");
      return;
    }
    if (outcome === "sent") push("success", "Clipboard sent to remote");
  }, [pushClipboard, push]);

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
    if (!terminal || !visible) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      dismiss();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [terminal, visible, dismiss]);

  const showConnecting =
    st.state === "resolving" || st.state === "connecting" ||
    st.state === "authenticating" || st.state === "negotiating" || st.state === "idle";

  return (
    <div ref={containerRef} className="relative h-full w-full overflow-hidden bg-canvas">
      <canvas
        ref={canvasRef}
        className={classNames(
          "session-canvas",
          settings.localCursor === "dot" && "local-cursor-dot",
          settings.localCursor === "off" && "local-cursor-hidden",
        )}
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
        zoomLocked={zoomLocked}
        onZoomLocked={toggleZoomLocked}
        showRemoteCursor={settings.showRemoteCursor}
        onShowRemoteCursor={(show) => update({ showRemoteCursor: show })}
        localCursor={settings.localCursor}
        onLocalCursor={(mode) => update({ localCursor: mode })}
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
        alwaysRefresh={alwaysRefresh}
        onAlwaysRefresh={toggleAlwaysRefresh}
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
        The connect is parked on this answer while the overlay says
        "Connecting…", so it needs the same stacking-context lift as the
        credential prompt below.
      */}
      {session.sshHostKeyPrompt ? (
        <div className="relative z-50">
          <SshHostKeyPrompt
            data={session.sshHostKeyPrompt}
            onAccept={session.acceptSshHostKey}
            onCancel={session.dismissSshHostKeyPrompt}
          />
        </div>
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

      {/* One shelf per window: in tabbed view the library shell owns it. */}
      {embedded ? null : <ToastShelf />}
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
class SessionErrorBoundary extends Component<
  { children: ReactNode; embedded?: boolean; onClose?: () => void },
  { error: Error | null }
> {
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
    const { embedded, onClose } = this.props;
    const sessionId = new URLSearchParams(window.location.search).get("sessionId");
    return (
      <div className="flex h-full w-full items-center justify-center bg-canvas p-6">
        <div
          role="alertdialog"
          aria-modal="true"
          aria-label="This session ran into a problem"
          className="w-[28rem] max-w-full rounded-lg border border-danger bg-raised p-5 shadow-(--shadow-pop)"
        >
          <p className="text-base font-semibold text-primary">
            This session ran into a problem
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
              onClick={() => {
                if (embedded) onClose?.();
                else void closeSessionWindow(sessionId);
              }}
            >
              {embedded ? "Close tab" : "Close window"}
            </button>
          </div>
        </div>
      </div>
    );
  }
}
