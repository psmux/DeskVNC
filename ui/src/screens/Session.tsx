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
import { SessionStatusDetails, SessionToolbar } from "../components/SessionToolbar";
import { CertPrompt } from "../components/CertPrompt";
import { CredentialPrompt } from "../components/CredentialPrompt";
import { SshHostKeyPrompt } from "../components/SshHostKeyPrompt";
import { DropOverlay, FilePanel } from "../components/FilePanel";
import { SshTerminal } from "../components/SshTerminal";
import { ConnectingOverlay, DisconnectedOverlay, ReconnectOverlay } from "../components/SessionOverlays";
import { SshSession } from "./SshSession";
import { useFiles } from "../hooks/useFiles";
import type { RdpResolution } from "../lib/rdp";
import { parseRdpSettings } from "../lib/rdp";
import { encodeResolution } from "../lib/rdpDefaults";
import { ToastShelf } from "../components/primitives";
import { useToasts } from "../state/ToastContext";
import { useSettings } from "../state/SettingsContext";
import { classNames } from "../lib/util";
import { emit } from "@tauri-apps/api/event";
import { EDIT_HOST_EVENT } from "../lib/editHost";
import { Dialog } from "../components/primitives";
import { candidateSeams, detectVerticalSeam } from "../render/seams";
import type { QualityPreset, ScalingMode, SessionState } from "../lib/types";
import {
  buildDisplayOptions,
  displayLabel,
  matchDisplay,
  orderDisplays,
  toChoice,
  type DisplayChoice,
} from "../lib/displays";
import {
  readViewPrefs,
  sameViewPrefs,
  viewPrefsKey,
  writeViewPrefs,
  type ViewPrefs,
} from "../lib/viewPrefs";
import { syncSessionMenu, type SessionMenuState } from "../lib/menuSync";
import {
  PREF_CLIPBOARD_AUTO,
  PREF_CLIPBOARD_ON_PASTE,
  PREF_FORWARD_INSERTED_TEXT,
  PREF_CLIPBOARD_ON_FOCUS,
  PREF_HIDE_TOOLBAR,
  PREF_MATCH_LOCAL_LAYOUT,
  PREF_NATURAL_SCROLL,
  PREF_EDGE_PAN,
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
  safeListen,
  writeClipboard,
  type CaptureStatus,
  type SshConnectConfig,
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

/** How long a settings change is left to settle before it is written out. */
const SETTINGS_WRITE_MS = 400;

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
export async function closeSessionWindow(sessionId: string | null): Promise<void> {
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
  /**
   * This view is being painted: its tab is in front. Several may be at once,
   * one per pane of a split. Only meaningful when embedded.
   */
  onScreen?: boolean;
  /**
   * This view owns the window: the keyboard, the native menu, file drops and
   * the clipboard sync all belong to it.
   *
   * Separate from {@link onScreen} because a split shows several sessions at
   * the same time and every one of those is a single, window-wide resource.
   * Exactly one mounted view may hold this, and it is the one the user last
   * clicked into. Only meaningful when embedded.
   */
  focused?: boolean;
  /**
   * The pane's rectangle in viewport coordinates, for the chrome that has to
   * be positioned against the window rather than against this view's own box.
   * Omitted when the session has the whole window.
   */
  frame?: { x: number; y: number; width: number; height: number };
  /**
   * Divide the pane this view is in. Omitted for a session in a window of its
   * own, which has no pane and so shows no split controls.
   */
  onSplit?: (dir: "row" | "column") => void;
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
  // Resolved here, at the wrapper, rather than inside `SessionView`:
  // `SessionView`'s hooks build a WebGL renderer and an input pipeline on a
  // canvas that an SSH session has no use for, and React cannot skip hooks
  // conditionally, so the branch has to happen a level up, before either
  // child mounts.
  const params = props.params ?? readSessionParams();
  return (
    <SessionErrorBoundary embedded={props.embedded} onClose={props.onClose}>
      {params.protocol === "ssh" ? (
        <SshSession {...props} params={params} />
      ) : (
        <SessionView {...props} />
      )}
    </SessionErrorBoundary>
  );
}

function SessionView({
  params: paramsProp,
  embedded = false,
  onScreen: onScreenProp = true,
  focused: focusedProp = true,
  frame: frameProp,
  onSplit,
  onClose,
  onDesktopName,
  onState,
  onAppHotkey,
}: SessionProps): ReactNode {
  const params = useMemo(() => paramsProp ?? readSessionParams(), [paramsProp]);
  /**
   * Two questions that used to be one, and are not the same once a tab can be
   * split between several sessions at once.
   *
   * `painted` is about pixels: a view in a background tab is still connected
   * and still taking frames into its texture, but it does not draw. Every pane
   * of the tab in front is painted.
   *
   * `owns` is about the things there is only one of in a window: the keyboard,
   * the native menu bar, the OS drag-and-drop session, the clipboard. Exactly
   * one view may hold those, whatever is on screen beside it. A session in a
   * window of its own is both, always.
   */
  const painted = !embedded || onScreenProp;
  const owns = !embedded || focusedProp;

  /**
   * The pane's box, pinned to its numbers rather than to the object carrying
   * them. The shell rebuilds that object on every render, and it renders once
   * a second for the bandwidth readout on every open session, so passing it
   * straight through re-ran the toolbar's whole placement calculation on every
   * tick of every pane for a rectangle that had not moved.
   */
  const frame = useMemo(
    () => frameProp,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [frameProp?.x, frameProp?.y, frameProp?.width, frameProp?.height],
  );
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

  /**
   * What this computer is set to (Preferences ▸ Session supplies the defaults
   * for one nothing has been changed on). Read once: `params` is fixed for the
   * life of the view, and every later change goes out through the write effect
   * below rather than coming back in through here.
   */
  const prefsKey = useMemo(() => viewPrefsKey(params), [params]);
  const [stored] = useState(() => readViewPrefs(prefsKey));

  const [scalingMode, setScalingModeState] = useState<ScalingMode>(stored.scalingMode);
  // The remote desktop's size, as opposed to how it is scaled once it arrives.
  // RDP only, and `null` until the profile has been read (or forever, for VNC,
  // whose remote size is driven by the scaling mode). Changing it here lasts
  // for this session; the profile stays the answer for the next connect.
  const [resolution, setResolution] = useState<RdpResolution | null>(null);
  const resolutionRef = useRef<RdpResolution | null>(null);
  resolutionRef.current = resolution;
  const [zoom, setZoomState] = useState(stored.zoom);
  const [quality, setQualityState] = useState<QualityPreset>(stored.quality);
  const [bwLevels, setBwLevelsState] = useState(stored.bwLevels);
  /**
   * The switch, not the grab. It comes back on from the stored settings, but
   * capture itself is only armed once there is a session to arm it for, by the
   * reapply effect further down.
   */
  const [passthrough, setPassthroughState] = useState(stored.passthrough);
  const [capture, setCapture] = useState<CaptureStatus>(CAPTURE_INACTIVE);
  const [showCaptureHelp, setShowCaptureHelp] = useState(false);
  const [viewOnly, setViewOnlyState] = useState(stored.viewOnly);
  /** Manual staleness override; off by default because it costs bandwidth. */
  const [alwaysRefresh, setAlwaysRefresh] = useState(stored.alwaysRefresh);
  const [recallSignal, setRecallSignal] = useState(0);
  const [connectionInfoOpen, setConnectionInfoOpen] = useState(false);
  /**
   * Bumped by every native-menu action, so the menu's state is re-asserted
   * after the render even when the action changed nothing. See the note where
   * it is bumped.
   */
  const [menuNonce, setMenuNonce] = useState(0);
  /**
   * Preferences ▸ Session can take the floating toolbar away entirely, in
   * which case the View and Session menus are the only way to any of it. Read
   * on mount and re-read on focus, the same way the input preferences are: the
   * window that changed it is not this one.
   */
  const [hideToolbar, setHideToolbar] = useState(() => readBoolPref(PREF_HIDE_TOOLBAR, false));
  /**
   * Latest values for the native-menu listener below. It is registered once
   * per visible view, while these callbacks are defined further down and are
   * rebuilt on most renders; reading them through refs keeps the listener
   * from either capturing stale values or being torn down and re-added on
   * every keystroke.
   */
  const viewOnlyRef = useRef(false);
  viewOnlyRef.current = viewOnly;
  const sendComboRef = useRef<((c: "ctrl-alt-del") => void) | null>(null);
  const disconnectRef = useRef<(() => void) | null>(null);
  const [remoteSize, setRemoteSize] = useState<{ w: number; h: number } | null>(null);
  /**
   * The monitor the user asked for, remembered against this computer, or null
   * for the whole desktop.
   *
   * This is the INTENT, not the applied selection: it survives a layout that
   * goes away and comes back (a reconnect arrives with an empty screen list
   * before the server describes itself again, and the seam detector only runs
   * a second after the desktop has settled), where an applied id could only be
   * dropped on the floor. What is showing right now is `activeDisplay` below,
   * derived by matching this against whatever the session is currently
   * offering.
   */
  const [desiredDisplay, setDesiredDisplay] = useState<DisplayChoice | null>(stored.display);
  const [scrimFading, setScrimFading] = useState(false);
  const [filesOpen, setFilesOpen] = useState(false);
  /** null while the SSH probe runs; false disables the Files button. */
  const [sshAvailable, setSshAvailable] = useState<boolean | null>(null);
  /**
   * The remote-shell overlay. `null` when closed; a window label once one is
   * being opened, `SshTerminal` needs to know which webview to receive
   * `ssh://event` on before it can call `ssh_connect`, so opening is a small
   * async step (see `openTerminal` below) rather than a plain state flip.
   */
  const [terminalWindow, setTerminalWindow] = useState<string | null>(null);
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
      // This view never mounts for an SSH session (see the `Session` wrapper
      // below, which renders `SshSession` instead), so the framebuffer-and-
      // cursor renderer here never receives msg_type 3.
      onPty: () => undefined,
    }),
    [],
  );

  const session = useSession(params, bridge, frame);
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
        // Something has already acted on this. Claim it anyway rather than
        // falling through: a consumed keystroke must not go on to reach the
        // remote desktop as well.
        if (e.defaultPrevented) return true;
        // The shell (the tab strip, and the pane layout) gets first refusal:
        // its shortcuts have to beat both this view's and the remote desktop's.
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
      // For RDP the resolution setting is the authority; for VNC, whose remote
      // size has no setting of its own, the scaling mode still is.
      const rdp = resolutionRef.current;
      const follows = rdp ? rdp.mode === "follow-window" : modeRef.current === "remote-resize";
      if (!follows) return;
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

  // Only the focused view owns the keyboard and the pointer, which in a split
  // is one of several views the user can see. `detach()` releases whatever was
  // still held, so a modifier held down while the focus moves to the pane next
  // door does not stay down on the desktop being left behind.
  useEffect(() => {
    const input = inputRef.current;
    if (!viewReady || !input || !owns) return;
    input.attach();
    return () => input.detach();
  }, [viewReady, owns]);

  // Coming to the front takes the focus with it. The remote keyboard hook
  // deliberately ignores keystrokes aimed at our own inputs and dialogs, so a
  // tab opened from the library search box would otherwise send everything
  // typed into that box instead of to the remote desktop. Focus goes to the
  // input handler's hidden capture element (not the canvas), which is what
  // lets IMEs and dictation deliver text to the session at all.
  useEffect(() => {
    if (!viewReady || !owns) return;
    if (inputRef.current) inputRef.current.focus();
    else canvasRef.current?.focus({ preventScroll: true });
  }, [viewReady, owns]);

  // …and only the view on screen draws. Frames for a background tab still
  // arrive and are still uploaded into its texture, so switching back shows
  // the current desktop rather than a stale one; what stops is the per-frame
  // GL draw, which is what would otherwise cost a full render pass per tab.
  useEffect(() => {
    const renderer = rendererRef.current;
    if (!viewReady || !renderer) return;
    if (painted) {
      renderer.start();
      renderer.markDirty();
    } else {
      renderer.stop();
    }
  }, [viewReady, painted]);

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
    if (!viewReady || !painted) return;
    const sid = params.sessionId;
    const sync = (): void => {
      inputRef.current?.setNaturalScroll(readBoolPref(PREF_NATURAL_SCROLL, true));
      inputRef.current?.setForwardInsertedText(readBoolPref(PREF_FORWARD_INSERTED_TEXT, true));
      setHideToolbar(readBoolPref(PREF_HIDE_TOOLBAR, false));
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
  }, [viewReady, painted, params.sessionId]);

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
  //
  // The GRAB, not the switch. The switch is what this computer remembers about
  // pass-through, and a session ending is not the user saying they want it
  // off: clearing it here wrote "off" back to the stored settings on every
  // disconnect, so the preference could never survive one. Reconnecting re-arms
  // from it (see the reapply effect), and the force-release below does still
  // clear it, because that one IS the user asking for their keyboard back.
  useEffect(() => {
    const sid = params.sessionId;
    if (!sid) return;
    if (session.state.state === "disconnected") void captureStop(sid);
  }, [session.state.state, params.sessionId]);

  // …and on unmount, belt-and-braces alongside the shell's window hooks.
  useEffect(() => {
    const sid = params.sessionId;
    return () => {
      if (sid) void captureStop(sid);
    };
  }, [params.sessionId]);

  // Switching tabs, or moving the focus to the pane next door, is not a window
  // blur, so none of the shell's focus hooks fire: a view losing the focus has
  // to hand the keyboard back itself, or it would keep swallowing the
  // keystrokes meant for the one that took it. The pass-through switch stays
  // ON, so coming back re-arms without asking again.
  //
  // This follows the focus rather than the pixels for the same reason the
  // keyboard hook does: the native grab is one per window, and a split showing
  // four desktops must not have four of them fighting over it.
  const passthroughRef = useRef(passthrough);
  passthroughRef.current = passthrough;
  const captureSuspended = useRef(false);
  useEffect(() => {
    const sid = params.sessionId;
    if (!embedded || !sid) return;
    if (!owns) {
      if (!passthroughRef.current) return;
      captureSuspended.current = true;
      void captureStop(sid).then(setCapture);
    } else if (captureSuspended.current) {
      captureSuspended.current = false;
      if (passthroughRef.current) void captureStart(sid).then(setCapture);
    }
  }, [embedded, owns, params.sessionId]);

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

  /**
   * Seam detection: when the server sends no layout, look for the column
   * where two side by side monitors visibly meet (see render/seams.ts).
   *
   * Runs once the desktop has settled after connect (windows restored,
   * wallpaper painted), again on every desktop resize, and on demand from
   * the menu's "Detect again", because a window straddling the seam at
   * sampling time hides it. Stored per remote width so a resize can never
   * leave a seam from the old geometry standing.
   */
  const [detectedSeam, setDetectedSeam] = useState<{ x: number; forWidth: number } | null>(null);
  const detectDisplays = useCallback((): void => {
    const r = rendererRef.current;
    if (!r || !r.hasFrame()) return;
    const { width } = r.getRemoteSize();
    if (width < 1280) return;
    const band = r.readSampledRowsRGBA(96);
    if (!band) return;
    const guess = detectVerticalSeam(band.pixels, band.width, band.rows, candidateSeams(band.width));
    setDetectedSeam(guess ? { x: guess.x, forWidth: band.width } : null);
  }, []);

  const layoutKnown = session.screens.length >= 2;
  /**
   * Guessing where the monitors are is a VNC-only affordance.
   *
   * RFB servers frequently paint several monitors into one framebuffer and
   * never say where the joins are, so reading the picture for a seam and
   * offering splits by width is the best available answer. A Remote Desktop
   * session without multiple monitors negotiated really is one display, and
   * cutting it in half would be inventing monitors that are not there.
   */
  /**
   * Change the remote desktop's size for this session.
   *
   * A fixed size and "match the window" both need one request sent now;
   * "match at connect" is the absence of one, and deliberately leaves the
   * desktop at whatever size it already has rather than snapping it back.
   */
  const applyResolution = useCallback(
    (next: RdpResolution): void => {
      setResolution(next);
      if (next.mode === "fixed") {
        session.requestResize(next.width, next.height);
      } else if (next.mode === "follow-window") {
        const c = canvasRef.current;
        if (c) session.requestResize(c.width, c.height);
      }
    },
    [session],
  );

  // Seed the resolution from the host profile. The shell already used it to
  // size the connection; this copy is what decides whether a window resize
  // reaches the server afterwards, and what the menu shows as current.
  useEffect(() => {
    if (params.protocol !== "rdp") return;
    const id = params.profileId;
    if (!id) {
      // An ad-hoc connect has no profile, so it gets the same default a new
      // one would: sized at connect, then left alone.
      setResolution({ mode: "window-at-connect" });
      return;
    }
    let cancelled = false;
    void safeInvoke<{ rdpSettings?: string | null } | null>("get_host", { hostId: id }, null).then(
      (host) => {
        if (cancelled) return;
        setResolution(parseRdpSettings(host?.rdpSettings ?? null)?.resolution ?? {
          mode: "window-at-connect",
        });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [params.protocol, params.profileId]);

  const guessDisplays = params.protocol !== "rdp";
  useEffect(() => {
    if (!guessDisplays || layoutKnown || session.state.state !== "connected") return;
    const t = window.setTimeout(detectDisplays, THUMBNAIL_SETTLE_MS);
    return () => window.clearTimeout(t);
  }, [guessDisplays, layoutKnown, session.state.state, remoteSize, detectDisplays]);

  /** What the Displays menus offer (see `lib/displays`). */
  const displayOptions = useMemo(
    () =>
      guessDisplays || session.screens.length >= 2
        ? buildDisplayOptions(
            session.screens,
            remoteSize,
            detectedSeam && detectedSeam.forWidth === remoteSize?.w ? detectedSeam.x : null,
          )
        : [],
    [guessDisplays, session.screens, remoteSize, detectedSeam],
  );

  /**
   * The monitor actually on display: the remembered choice resolved against
   * what is on offer right now, or null when nothing matches it any more.
   *
   * Derived rather than stored, which is what makes the choice stick. A
   * reconnect, a desktop resize and the seam detector each rebuild the list,
   * and the old code cleared the selection whenever its id was momentarily
   * missing from it, so the monitor was lost on every one of those. Here a
   * list that no longer matches simply shows the whole desktop until one does
   * again; the intent is never destroyed by anything except the user changing
   * it.
   */
  const activeDisplay = useMemo(
    () => matchDisplay(desiredDisplay, displayOptions),
    [desiredDisplay, displayOptions],
  );
  const displayId = activeDisplay?.id ?? null;

  const chooseDisplay = useCallback(
    (id: number | null): void => {
      setDesiredDisplay(
        id === null ? null : toChoice(displayOptions.find((o) => o.id === id)),
      );
    },
    [displayOptions],
  );

  // Push the monitor view into the renderer. `remoteSize` is a dependency on
  // purpose: a desktop resize clears the renderer's view rect (the old
  // geometry is gone), and the resize event lands before the fresh layout
  // does, so the selection has to be re-applied against whichever arrives.
  useEffect(() => {
    const r = rendererRef.current;
    if (!viewReady || !r) return;
    if (activeDisplay) {
      r.setViewRect(activeDisplay.x, activeDisplay.y, activeDisplay.width, activeDisplay.height);
    } else {
      r.clearViewRect();
    }
  }, [viewReady, activeDisplay, remoteSize]);

  useEffect(() => {
    rendererRef.current?.setGrayLevels(quality === "bw" ? bwLevels : 0);
  }, [quality, bwLevels]);

  // ------------------------------------------------------ remembered settings

  /**
   * Write what the toolbar changed back against this computer.
   *
   * One effect for the lot rather than a write inside each setter, so a new
   * setting cannot be added and quietly forgotten. Debounced because `zoom`
   * moves continuously under a pinch gesture and under the toolbar's slider,
   * and a `localStorage` write per frame for the length of a gesture is a
   * write per frame nobody asked for; the timer coalesces them into one.
   */
  useEffect(() => {
    const next: ViewPrefs = {
      scalingMode,
      zoom,
      quality,
      bwLevels,
      alwaysRefresh,
      viewOnly,
      passthrough,
      display: desiredDisplay,
    };
    // Nothing has been adjusted on this computer yet, so leave it with none of
    // its own: writing the blob out here would pin today's Preferences
    // defaults against it, and a later change to those defaults would then
    // never reach a machine merely because it had once been connected to.
    if (sameViewPrefs(next, stored)) return;
    const t = window.setTimeout(() => writeViewPrefs(prefsKey, next), SETTINGS_WRITE_MS);
    return () => window.clearTimeout(t);
  }, [
    stored,
    prefsKey,
    scalingMode,
    zoom,
    quality,
    bwLevels,
    alwaysRefresh,
    viewOnly,
    passthrough,
    desiredDisplay,
  ]);

  /**
   * Put the remembered settings back once there is a session to put them to.
   *
   * Three of them are not the view's to apply on its own: quality and view-only
   * are connection state in the protocol core, and pass-through is a keyboard
   * grab in the shell. They are re-asserted on every arrival at `connected`,
   * not only the first, because an automatic reconnect builds a fresh
   * connection underneath a view that never unmounted.
   *
   * Read through a ref so the effect fires on the connection state and nothing
   * else: depending on the values themselves would re-push all of them every
   * time any one of them changed, and `useSession` hands back a new object on
   * every stats tick.
   */
  const restoreRef = useRef({ quality, viewOnly, alwaysRefresh, passthrough });
  restoreRef.current = { quality, viewOnly, alwaysRefresh, passthrough };
  useEffect(() => {
    if (session.state.state !== "connected") return;
    const want = restoreRef.current;
    const api = sessionRef.current;
    api.setQuality(want.quality);
    api.setViewOnly(want.viewOnly);
    api.setAlwaysRefresh(want.alwaysRefresh);
    // Quietly: the Accessibility explainer is a response to the user asking
    // for pass-through, not something to raise on its own on every connect.
    // A refusal leaves the badge and the menu showing what really happened.
    const sid = params.sessionId;
    if (want.passthrough && sid) void captureStart(sid).then(setCapture);
  }, [session.state.state, params.sessionId]);

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
    if (!clipboardReady || !owns) return;
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
  }, [clipboardReady, owns]);

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

  /**
   * Same host, same "same user as here" stored credential as the file
   * transfer sidecar above, tmux by default because that is what makes a
   * dropped link worth reconnecting to: a plain login shell dies with the
   * link and a fresh reconnect gets an empty prompt, a tmux session survives
   * it and a reconnect walks back into whatever was running.
   * `SshTerminal` fills in `cols`/`rows` itself once it has measured the
   * terminal it is about to open one with, this only carries where and how.
   */
  const sshTerminalConfig = useMemo<SshConnectConfig>(
    () => ({
      host: params.address ?? "",
      port: 22,
      username: "",
      auth: "stored",
      profileId: params.profileId,
      multiplexer: { kind: "tmux", sessionName: "deskvnc", fallbackToShell: true },
    }),
    [params.address, params.profileId],
  );

  /**
   * `ssh_connect` needs to know which webview to stream `ssh://event` to, and
   * that is only available through the async `@tauri-apps/api/window` import
   * (dynamic for the same reason the window-close hold above is: nothing in
   * this file needs it on every render, only the moment a terminal opens).
   * Outside Tauri (browser dev) there is no window label to ask for; the
   * placeholder never matters because `sshConnect` cannot reach a backend
   * there either, and `SshTerminal` surfaces that as its own error state.
   */
  const openTerminal = useCallback((): void => {
    if (!inTauri()) {
      setTerminalWindow("dev");
      return;
    }
    void import("@tauri-apps/api/window").then(({ getCurrentWindow }) => {
      setTerminalWindow(getCurrentWindow().label);
    });
  }, []);

  // Drag files onto the session window -> upload (PRD/08 §3.1). Tauri owns the
  // OS drag session when `dragDropEnabled` is on, so HTML5 drag events never
  // fire for real files, this is the only path that sees them.
  //
  // Tauri reports a drop to the whole window, not to a part of it, so only the
  // focused view may listen: otherwise one dropped file would be uploaded once
  // per open pane, to whichever machines those happen to be. In a split that
  // means files go to the pane you last clicked in, which is also the only
  // reading of "here" the OS gives us anything to work with.
  useEffect(() => {
    if (!inTauri() || sshAvailable !== true || !owns) return;
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
  }, [sshAvailable, owns, ensureFilesConnected, dropDir, push]);

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
  disconnectRef.current = disconnectWithThumbnail;

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

  /**
   * Native menu items that act on the session.
   *
   * `menu.rs` emits every custom item as `menu://action` and expects the
   * frontend to route it; the library window and the app shell each listen
   * for the items they own. Nothing listened for the session's, so the whole
   * Session and Connection menus, and the three View items that are not
   * handled natively, silently did nothing (issue #1). Only the FOCUSED view
   * may act: the event reaches every mounted pane, and the menu bar shows one
   * session's settings, so the pane whose settings those are is the one that
   * has to answer for them.
   *
   * The table itself is built further down (`menuActionsRef`), once every
   * callback it reaches for exists. Through a ref rather than in the
   * dependency list because the menu now covers the whole toolbar: listing
   * two dozen callbacks here would tear the listener down and re-register it
   * on most renders, and leaving them out is how a switch quietly acts on a
   * stale value.
   */
  const menuActionsRef = useRef<(id: string) => void>(() => undefined);
  useEffect(() => {
    if (!owns) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void safeListen<{ id: string }>("menu://action", ({ id }) => {
      menuActionsRef.current(id);
    }).then((fn) => {
      // Registered late, after a cleanup that could not cancel it yet: hand it
      // straight back, or this view keeps answering menu items forever and a
      // toggle picked once is applied twice.
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [owns]);

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
  sendComboRef.current = sendCombo;

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

  /** Edge auto-scroll, the counterpart of the zoom lock. On by default: the
   *  screen past the edge is otherwise unreachable at 1:1. */
  const [edgePan, setEdgePanState] = useState(() => readBoolPref(PREF_EDGE_PAN, true));
  const toggleEdgePan = useCallback((on: boolean): void => {
    setEdgePanState(on);
    writeBoolPref(PREF_EDGE_PAN, on);
    inputRef.current?.setEdgePan(on);
  }, []);

  // The input handler is created after first render, so the stored value has
  // to be pushed once it exists, not only when it changes.
  useEffect(() => {
    inputRef.current?.setZoomLocked(zoomLocked);
    inputRef.current?.setEdgePan(edgePan);
  }, [zoomLocked, edgePan, viewReady]);

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

  const changeQuality = useCallback((q: QualityPreset): void => {
    setQualityState(q);
    sessionRef.current.setQuality(q);
  }, []);

  /** Step the zoom, for the menu, which has no slider to drag. */
  const zoomBy = useCallback((factor: number): void => {
    setScalingModeState("custom");
    setZoomState((z) => Math.min(Math.max(z * factor, 0.25), 4));
  }, []);

  // ------------------------------------------------------------- native menu

  /** The rows both Displays menus show, in the order both of them show them. */
  const orderedDisplays = useMemo(
    () => orderDisplays(displayOptions, layoutKnown),
    [displayOptions, layoutKnown],
  );

  /**
   * Everything the View and Session menus can ask of this view.
   *
   * Assigned on every render rather than memoised: it is only ever reached
   * through `menuActionsRef` when the user picks something, so a fresh closure
   * costs nothing and can never be reading a stale value.
   */
  menuActionsRef.current = (id: string): void => {
    // muda ticks a check item itself the moment it is clicked, which is a
    // guess at the new state rather than the truth. A guess that turns out
    // right is corrected by the push that the state change below triggers,
    // but picking the option ALREADY in force changes nothing and re-renders
    // nothing, so the tick would be left sitting next to the option it had
    // just been taken off.
    //
    // Bumping a counter the push effect watches covers both cases with one
    // push, after the render: a timer instead of this raced that render and
    // sometimes asserted the state the action had just replaced.
    setMenuNonce((n) => n + 1);
    switch (id) {
      // View
      case "menu:toggle-toolbar":
        setRecallSignal((n) => n + 1);
        break;
      case "menu:hide-toolbar": {
        // Read back rather than flipping the local copy: this is a global
        // preference and another window may have changed it since.
        const next = !readBoolPref(PREF_HIDE_TOOLBAR, false);
        writeBoolPref(PREF_HIDE_TOOLBAR, next);
        setHideToolbar(next);
        break;
      }
      case "menu:scale-fit":
        setScalingModeState("fit");
        break;
      case "menu:scale-aspect":
        setScalingModeState("aspect-fit");
        break;
      case "menu:scale-actual":
        setScalingModeState("actual");
        break;
      case "menu:scale-remote":
        setScalingModeState("remote-resize");
        // On RDP the resolution setting owns this, so the two do not disagree.
        if (params.protocol === "rdp") applyResolution({ mode: "follow-window" });
        break;
      case "menu:res:connect":
        applyResolution({ mode: "window-at-connect" });
        break;
      case "menu:res:follow":
        applyResolution({ mode: "follow-window" });
        break;
      case "menu:zoom-in":
        zoomBy(1.25);
        break;
      case "menu:zoom-out":
        zoomBy(1 / 1.25);
        break;
      case "menu:zoom-reset":
        setScalingModeState("custom");
        setZoomState(1);
        break;
      case "menu:lock-zoom":
        toggleZoomLocked(!zoomLocked);
        break;
      case "menu:edge-pan":
        toggleEdgePan(!edgePan);
        break;
      case "menu:display:all":
        chooseDisplay(null);
        break;
      case "menu:detect-displays":
        detectDisplays();
        break;
      case "menu:remote-cursor":
        update({ showRemoteCursor: !settings.showRemoteCursor });
        break;
      case "menu:cursor:standard":
        update({ localCursor: "standard" });
        break;
      case "menu:cursor:dot":
        update({ localCursor: "dot" });
        break;
      case "menu:cursor:off":
        update({ localCursor: "off" });
        break;

      // Session
      case "menu:connection-info":
        setConnectionInfoOpen(true);
        break;
      case "menu:view-only":
        setViewOnlyState(!viewOnlyRef.current);
        break;
      case "menu:always-refresh":
        toggleAlwaysRefresh(!alwaysRefresh);
        break;
      case "menu:refresh":
        sessionRef.current.refreshScreen();
        break;
      case "menu:passthrough":
        togglePassthrough(!passthrough);
        break;
      case "menu:send-cad":
        sendComboRef.current?.("ctrl-alt-del");
        break;
      case "menu:send-cmd-tab":
        sendCombo("cmd-tab");
        break;
      case "menu:send-win":
        sendCombo("win");
        break;
      case "menu:send-alt-f4":
        sendCombo("alt-f4");
        break;
      case "menu:send-escape":
        sendCombo("escape");
        break;
      case "menu:release-keys":
        sessionRef.current.releaseAllKeys();
        break;
      case "menu:clipboard-send":
        void clipboardSend();
        break;
      case "menu:files":
        if (sshAvailable === true) setFilesOpen(true);
        break;
      case "menu:screenshot":
        void screenshot();
        break;

      // Connection
      case "menu:reconnect":
        sessionRef.current.reconnectNow();
        break;
      case "menu:disconnect":
        disconnectRef.current?.();
        break;

      default:
        if (id.startsWith("menu:quality:")) {
          changeQuality(id.slice("menu:quality:".length) as QualityPreset);
        } else if (id.startsWith("menu:gray:")) {
          setBwLevelsState(Number(id.slice("menu:gray:".length)));
        } else if (id.startsWith("menu:display:")) {
          chooseDisplay(Number(id.slice("menu:display:".length)));
        } else {
          // The fixed sizes share one shape, so they are matched rather than
          // listed a second time here.
          const size = /^menu:res:(\d+)x(\d+)$/.exec(id);
          if (size) {
            applyResolution({ mode: "fixed", width: Number(size[1]), height: Number(size[2]) });
          }
        }
    }
  };

  /**
   * Keep the native menu showing what is actually in force.
   *
   * Pushed again on focus because the menu bar is one object shared by every
   * window: whichever session the user brings to the front has to re-assert
   * its own state over whatever the last one left there.
   */
  const menuState = useMemo(
    (): SessionMenuState => ({
      scalingMode,
      quality,
      grayLevels: bwLevels,
      localCursor: settings.localCursor,
      showRemoteCursor: settings.showRemoteCursor,
      viewOnly,
      passthrough,
      alwaysRefresh,
      zoomLocked,
      edgePan,
      filesAvailable: sshAvailable === true,
      layoutKnown,
      displays: orderedDisplays.map((o, i) => ({ id: o.id, label: displayLabel(o, i) })),
      displayId,
      // Empty for VNC, whose remote size follows the scaling mode and is not a
      // choice of its own.
      resolution: resolution ? encodeResolution(resolution) : "",
    }),
    [
      resolution,
      scalingMode,
      quality,
      bwLevels,
      settings.localCursor,
      settings.showRemoteCursor,
      viewOnly,
      passthrough,
      alwaysRefresh,
      zoomLocked,
      edgePan,
      sshAvailable,
      layoutKnown,
      orderedDisplays,
      displayId,
    ],
  );

  const pushMenuRef = useRef<() => void>(() => undefined);
  pushMenuRef.current = () => syncSessionMenu(hideToolbar, menuState);

  useEffect(() => {
    if (!owns) return;
    const push = (): void => pushMenuRef.current();
    push();
    window.addEventListener("focus", push);
    return () => window.removeEventListener("focus", push);
  }, [owns, hideToolbar, menuState, menuNonce]);

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
    if (!terminal || !owns) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      dismiss();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [terminal, owns, dismiss]);

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

      {/* Preferences ▸ Session can take the bar away; the View and Session
          menus carry the same options either way.

          Only the focused view draws one. The bar's position is a single
          app-wide preference, so a split would otherwise stack one toolbar per
          pane at the same point, and every button on it acts on a particular
          session: four disconnect buttons in a heap, no way to tell whose is
          whose. Following the focus gives the same answer the menu bar does. */}
      {hideToolbar || !owns ? null : (
        <SessionToolbar
          frame={frame}
          onSplit={onSplit}
          desktopName={session.desktopName}
          protocol={params.protocol}
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
          edgePan={edgePan}
          onEdgePan={toggleEdgePan}
          screens={orderedDisplays}
          layoutKnown={layoutKnown}
          displayId={displayId}
          onDisplay={chooseDisplay}
          onDetectDisplays={detectDisplays}
          showRemoteCursor={settings.showRemoteCursor}
          onShowRemoteCursor={(show) => update({ showRemoteCursor: show })}
          localCursor={settings.localCursor}
          onLocalCursor={(mode) => update({ localCursor: mode })}
          onQuality={changeQuality}
          onBwLevels={setBwLevelsState}
          onPassthrough={togglePassthrough}
          onCapturePermission={() => setShowCaptureHelp(true)}
          onSendCombo={sendCombo}
          onClipboardSend={() => void clipboardSend()}
          onFiles={() => setFilesOpen(true)}
          filesAvailable={sshAvailable}
          onTerminal={openTerminal}
          terminalAvailable={sshAvailable}
          onFullscreen={() => void toggleFullscreen()}
          onViewOnly={setViewOnlyState}
          onScreenshot={() => void screenshot()}
          onRefresh={session.refreshScreen}
          alwaysRefresh={alwaysRefresh}
          onAlwaysRefresh={toggleAlwaysRefresh}
          onDisconnect={disconnectWithThumbnail}
        />
      )}

      {/* The toolbar's status button as a dialog, for Session ▸ Connection
          Info: with the bar hidden the latency reading has nowhere else to
          live, and it is the first thing anyone asks for when a session feels
          slow. */}
      {connectionInfoOpen ? (
        <Dialog title="Connection info" onClose={() => setConnectionInfoOpen(false)} width={360}>
          <div className="p-4">
            <SessionStatusDetails stats={session.stats} desktopName={session.desktopName} />
            <div className="mt-4 flex justify-end">
              <button
                type="button"
                data-autofocus
                className="btn-primary"
                onClick={() => setConnectionInfoOpen(false)}
              >
                Done
              </button>
            </div>
          </div>
        </Dialog>
      ) : null}

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
          profileId={params.profileId}
          onEditSecurity={
            params.profileId
              ? () => {
                  // The editor lives in the library window, which this
                  // session may not be in, so the request is broadcast and
                  // the library opens the dialog with Advanced and Security
                  // already expanded.
                  void emit(EDIT_HOST_EVENT, {
                    hostId: params.profileId,
                    section: "security",
                  });
                }
              : null
          }
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

      {terminalWindow !== null ? (
        <SshTerminal
          sessionId={params.sessionId ?? ""}
          windowLabel={terminalWindow}
          config={sshTerminalConfig}
          hostName={session.desktopName}
          onClose={() => setTerminalWindow(null)}
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
            scheme: session.certPrompt.scheme,
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
            protocol={params.protocol}
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
