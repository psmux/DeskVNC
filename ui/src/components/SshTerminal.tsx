/**
 * A live remote shell (PRD/09-ish, ssh-core), rendered with xterm.js.
 *
 * Owns the whole lifecycle of one terminal: it opens the PTY itself on
 * mount and tears it down on unmount, the way `CredentialPrompt` and
 * `CertPrompt` own their own turn rather than being driven by a hook a
 * parent holds. `FilePanel` stays mounted with the panel closed so uploads
 * keep moving in the background; a shell has no such continuation to
 * protect, so closing this one simply ends it.
 *
 * `SshHostKeyPrompt` is reused verbatim for trust-on-first-use, the same
 * component the SSH tunnel gateway uses in `Session.tsx`: one host-key
 * store, one prompt, whichever feature asks first.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import {
  base64ToBytes,
  listenSsh,
  sshConnect,
  sshDisconnect,
  sshReconnectNow,
  sshResize,
  sshSend,
  type SshConnectConfig,
  type SshTerminalState,
} from "../lib/tauri";
import type { SshHostKeyPromptState } from "../hooks/useSession";
import { SshHostKeyPrompt } from "./SshHostKeyPrompt";
import { usePaneVisible } from "./Pane";
import { useToasts } from "../state/ToastContext";
import { classNames } from "../lib/util";
import { IconAlert, IconX } from "./icons";

export interface SshTerminalProps {
  /** Identifies this shell in the `ssh-core` registry; independent of any
   *  VNC/RDP session id, though callers commonly derive it from one. */
  sessionId: string;
  /** The webview whose `ssh://event` stream carries this shell's traffic. */
  windowLabel: string;
  /** Everything but `cols`/`rows`: those come from the terminal itself once
   *  it has been measured, see the connect effect below. */
  config: SshConnectConfig;
  /** Shown in the header and announced to screen readers. */
  hostName: string;
  onClose: () => void;
}

/**
 * Where this component is in the handshake. Unlike the VNC session (whose
 * `SessionState` is entirely the core's to drive) the first leg here is a
 * single request/response (`ssh_connect`) that either seats a live shell or
 * hands back a decision for the user, so that leg gets its own state and
 * `SshTerminalState` only starts driving the UI once a shell actually exists.
 */
type Phase =
  | { kind: "handshake" }
  | { kind: "host-key-prompt" | "host-key-changed"; data: SshHostKeyPromptState }
  | { kind: "error"; message: string }
  /** A shell exists. `state` is null for the instant between `ssh_connect`
   *  resolving and the first `ssh://event` state frame landing. */
  | { kind: "shell"; state: SshTerminalState | null };

function describeError(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return String(err);
}

// ------------------------------------------------------------------ theme
//
// xterm ships a `theme` option rather than CSS, so the app's palette has to
// be read out of the custom properties and handed to it directly. Read once
// per mount plus once per theme change, not on every render: `Terminal`
// mutates its own `options.theme` in place and repaints, it does not need a
// fresh object every time this component does.

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// -------------------------------------------------------------- terminal setup
//
// Shared with `SshSession.tsx`, the full-window terminal for a session whose
// protocol IS ssh (as opposed to this component, the sidecar dialog opened
// from a VNC/RDP session): same fonts, same WebGL-over-canvas upgrade, same
// debounced resize watch, same live-theme follow. Extracted here rather than
// duplicated so the two entry points cannot quietly drift apart.

export interface TerminalSetup {
  term: Terminal;
  fit: FitAddon;
  /** Cancel the WebGL addon load if it has not landed yet, so a promise that
   *  resolves after the terminal is disposed never calls `loadAddon` on it. */
  cancelWebgl: () => void;
}

/**
 * An xterm.js terminal wired the same way wherever it appears in this app.
 * The canvas 2D renderer works everywhere; WebGL is only an upgrade, loaded
 * async and swallowed on failure, context creation genuinely fails in some
 * webviews, and an unhandled throw here would blank the terminal before it
 * ever shows a prompt. Caller still owns `term.open(container)`, this only
 * builds the instance.
 */
export function createTerminal(): TerminalSetup {
  const term = new Terminal({
    fontFamily: cssVar("--font-mono") || "monospace",
    fontSize: 13,
    lineHeight: 1.35,
    cursorBlink: true,
    cursorStyle: "block",
    scrollback: 5000,
    allowProposedApi: true,
    theme: buildTheme(),
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon());
  let cancelled = false;
  void import("@xterm/addon-webgl")
    .then(({ WebglAddon }) => {
      if (cancelled) return;
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    })
    .catch((err) => {
      console.warn("[terminal] WebGL renderer unavailable, using the canvas renderer:", err);
    });
  return {
    term,
    fit,
    cancelWebgl: () => {
      cancelled = true;
    },
  };
}

/**
 * Debounced ResizeObserver -> `fit.fit()`. Window drags fire a resize per
 * animation frame; `fit()` itself is cheap, but each call that actually
 * changes the grid drives a resize round trip on the wire (`onResize`
 * below), so the observer is debounced rather than the round trip.
 */
export function watchTerminalResize(
  container: HTMLElement,
  fit: FitAddon,
  debounceMs = 100,
): () => void {
  let timer = 0;
  const ro = new ResizeObserver(() => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fit.fit(), debounceMs);
  });
  ro.observe(container);
  return () => {
    window.clearTimeout(timer);
    ro.disconnect();
  };
}

/**
 * Re-run `apply` whenever the app's theme actually changes: an explicit
 * Preferences ▸ Appearance choice (the `data-theme` attribute) or the OS
 * followed by "system". xterm reads colors once into `options.theme`, it
 * cannot follow a `prefers-color-scheme` media query on its own.
 */
export function watchThemeChanges(apply: () => void): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  mq.addEventListener("change", apply);
  const mo = new MutationObserver(apply);
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  return () => {
    mq.removeEventListener("change", apply);
    mo.disconnect();
  };
}

/** Same resolution order `index.css` uses: an explicit choice wins, "system"
 *  falls through to the OS. Mirrored here because xterm reads colors once,
 *  it cannot follow a `prefers-color-scheme` media query on its own. */
function isDarkTheme(): boolean {
  const explicit = document.documentElement.getAttribute("data-theme");
  if (explicit === "dark") return true;
  if (explicit === "light") return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function parseHex(color: string): [number, number, number] | null {
  const m = color.match(/^#([0-9a-f]{6})$/i);
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/** Push a token color toward white, for the "bright" half of the ANSI
 *  palette. Falls back to the color itself if it is not a plain `#rrggbb`
 *  (none of the tokens this reads ever are anything else). */
function brighten(hex: string, t: number): string {
  const rgb = parseHex(hex);
  if (!rgb) return hex;
  const [r, g, b] = rgb;
  return `rgb(${Math.round(r + (255 - r) * t)}, ${Math.round(g + (255 - g) * t)}, ${Math.round(b + (255 - b) * t)})`;
}

/**
 * Derive an xterm theme from the app's own tokens instead of shipping a
 * packaged one: background, foreground, cursor and the red/green/yellow/blue
 * of the ANSI set all come straight from `index.css`, so the terminal sits
 * in the same palette as the rest of the window in both light and dark. The
 * app has no magenta or cyan token to borrow, those two are the only hand
 * picked colors here, chosen to sit quietly next to the blue accent rather
 * than clash with it.
 */
export function buildTheme(): ITheme {
  const bg = cssVar("--bg-inset") || "#1a1d24";
  const fg = cssVar("--text-primary") || "#e9ebef";
  const secondary = cssVar("--text-secondary") || "#a4aab6";
  const tertiary = cssVar("--text-tertiary") || "#757c89";
  const accent = cssVar("--accent") || "#5b95f5";
  const danger = cssVar("--danger") || "#ee6055";
  const success = cssVar("--success") || "#3fc873";
  const warning = cssVar("--warning") || "#e3a13c";
  const dark = isDarkTheme();
  const magenta = dark ? "#c792ea" : "#9d5cc9";
  const cyan = dark ? "#56d4dd" : "#1f8f96";

  return {
    background: bg,
    foreground: fg,
    cursor: accent,
    cursorAccent: bg,
    selectionBackground: dark ? "rgba(91, 149, 245, 0.35)" : "rgba(47, 111, 228, 0.28)",
    black: dark ? "#4b5160" : "#c4c9d2",
    red: danger,
    green: success,
    yellow: warning,
    blue: accent,
    magenta,
    cyan,
    white: secondary,
    brightBlack: tertiary,
    brightRed: brighten(danger, 0.25),
    brightGreen: brighten(success, 0.25),
    brightYellow: brighten(warning, 0.25),
    brightBlue: brighten(accent, 0.25),
    brightMagenta: brighten(magenta, 0.2),
    brightCyan: brighten(cyan, 0.2),
    brightWhite: fg,
  };
}

// -------------------------------------------------------------- component

export function SshTerminal({
  sessionId,
  windowLabel,
  config,
  hostName,
  onClose,
}: SshTerminalProps): ReactNode {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  /** Re-run `ssh_connect`, for the TOFU accept and for "Reconnect" after a
   *  hard disconnect. Assigned inside the effect below, read from JSX. */
  const connectRef = useRef<(acceptHostKey?: string) => void>(() => undefined);
  const [phase, setPhase] = useState<Phase>({ kind: "handshake" });
  const [notice, setNotice] = useState<string | null>(null);
  const [bellTick, setBellTick] = useState(0);
  const onScreen = usePaneVisible();
  const { push } = useToasts();

  // Latest config/onClose for the mount effect to read without depending on
  // them: `config` is a fresh object on most parent renders (it is usually
  // built inline), and re-running the whole connect+terminal dance every
  // time the parent re-renders would drop the shell out from under the user.
  const configRef = useRef(config);
  configRef.current = config;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  // ---------------------------------------------------------- terminal + wire
  //
  // One effect for the lot, the way `Session.tsx`'s renderer setup is: the
  // terminal, its addons, the event subscription and the connect all belong
  // to the same lifetime and have to tear down together. Subscribing BEFORE
  // connecting is load-bearing, not tidiness: `ssh_connect`'s own session can
  // start emitting `ssh://event` before the command's promise resolves, and a
  // listener registered after that race would miss the opening lines.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    let cancelled = false;

    const { term, fit, cancelWebgl } = createTerminal();
    term.open(container);
    fit.fit();
    term.focus();
    termRef.current = term;

    const dData = term.onData((d) => void sshSend(sessionId, new TextEncoder().encode(d)));
    const dResize = term.onResize(({ cols, rows }) => void sshResize(sessionId, cols, rows));

    const stopResizeWatch = watchTerminalResize(container, fit);

    const connect = (acceptHostKey?: string): void => {
      setPhase({ kind: "handshake" });
      // Sized from the terminal's OWN measurement, not whatever the caller's
      // `config` carried: that object is built before this component (and
      // therefore the terminal) exists, so it cannot know the real grid.
      void sshConnect(
        sessionId,
        windowLabel,
        { ...configRef.current, cols: term.cols, rows: term.rows },
        acceptHostKey,
      )
        .then((outcome) => {
          if (cancelled) return;
          switch (outcome.status) {
            case "ready":
              setPhase({ kind: "shell", state: null });
              break;
            case "host-key-prompt":
              setPhase({
                kind: "host-key-prompt",
                data: {
                  host: outcome.host,
                  port: outcome.port,
                  keyType: outcome.keyType,
                  fingerprint: outcome.fingerprint,
                  changed: false,
                },
              });
              break;
            case "host-key-changed":
              setPhase({
                kind: "host-key-changed",
                data: {
                  host: outcome.host,
                  port: outcome.port,
                  fingerprint: outcome.actual,
                  changed: true,
                  expected: outcome.expected,
                },
              });
              break;
          }
        })
        .catch((err) => {
          if (cancelled) return;
          setPhase({ kind: "error", message: describeError(err) });
        });
    };
    connectRef.current = connect;

    let unlisten: (() => void) | undefined;
    void listenSsh((e) => {
      if (cancelled || e.sessionId !== sessionId) return;
      switch (e.type) {
        case "output":
        case "reset":
          // xterm decodes UTF-8 itself and carries a partial sequence across
          // writes, which is exactly why the backend hands over bytes: a
          // manual `TextDecoder` here would mangle any chunk boundary that
          // split a multi-byte character.
          term.write(base64ToBytes(e.data));
          break;
        case "bell":
          setBellTick((n) => n + 1);
          break;
        case "notice":
          setNotice(e.message);
          break;
        case "state":
          // A state frame proves the shell exists whether or not the
          // `ssh_connect` promise above has resolved yet in JS: the two
          // travel over different channels and can arrive out of order.
          setPhase({ kind: "shell", state: e });
          break;
      }
    }).then((fn) => {
      if (cancelled) {
        fn();
        return;
      }
      unlisten = fn;
      connect();
    });

    return () => {
      cancelled = true;
      cancelWebgl();
      stopResizeWatch();
      unlisten?.();
      void sshDisconnect(sessionId);
      dData.dispose();
      dResize.dispose();
      term.dispose();
      termRef.current = null;
      connectRef.current = () => undefined;
    };
    // sessionId and windowLabel are fixed for the life of this component
    // (a fresh instance is mounted whenever the caller opens a new shell);
    // config and onClose are read through the refs above on purpose.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, windowLabel]);

  // The Session view re-grabs focus for the remote desktop's own capture
  // element every time a background tab comes back to the front (see the
  // "coming to the front takes the focus" effect in `Session.tsx`), which
  // would otherwise win the race and leave a reopened tab typing into the
  // remote instead of this panel. `Dialog` fixes the same race for every
  // other modal in the app by re-focusing on the same trigger; this mirrors
  // it rather than depending on effect ordering to sort itself out.
  useEffect(() => {
    if (onScreen) termRef.current?.focus();
  }, [onScreen]);

  // Live theme: re-read the tokens whenever the app's theme actually
  // changes, rather than only once at mount, so switching Preferences ▸
  // Appearance while a terminal is open does not leave it in the old colors.
  useEffect(() => {
    const apply = (): void => {
      const term = termRef.current;
      if (term) term.options.theme = buildTheme();
    };
    return watchThemeChanges(apply);
  }, []);

  // "Reattached to your tmux session" is the one moment worth interrupting
  // for: it is the answer to "did my work survive the disconnect". A toast
  // fits it better than a banner over the terminal, since by the time it
  // shows there is already a live shell underneath worth looking at.
  const resumeToasted = useRef(false);
  useEffect(() => {
    if (phase.kind !== "shell" || !phase.state) return;
    if (phase.state.state === "connected" && phase.state.resumed) {
      if (!resumeToasted.current) {
        resumeToasted.current = true;
        push("success", "Reattached to your tmux session");
      }
    } else {
      resumeToasted.current = false;
    }
  }, [phase, push]);

  // Notices are rare and informational (PRD wording: "tmux is not installed
  // ... this session will not survive a disconnect"); they say their piece
  // and then get out of the way rather than piling into the toast shelf.
  useEffect(() => {
    if (!notice) return;
    const t = window.setTimeout(() => setNotice(null), 8000);
    return () => window.clearTimeout(t);
  }, [notice]);

  // Esc closes the panel, same convention as `FilePanel`; not while this
  // pane is in the background, or it would answer a keystroke meant for
  // whichever session is actually on screen.
  useEffect(() => {
    if (!onScreen) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") onCloseRef.current();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onScreen]);

  const status = statusPill(phase);
  const shellState = phase.kind === "shell" ? phase.state : null;
  const connectingEndpoint =
    shellState?.state === "connecting"
      ? shellState.endpoint
      : `${config.host}:${config.port ?? 22}`;

  return (
    <div
      className="fade-in absolute inset-0 z-30 flex flex-col bg-scrim"
      role="dialog"
      aria-modal="true"
      aria-label={`Terminal, ${hostName}`}
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="m-auto flex h-[min(88vh,760px)] w-[min(96vw,1100px)] flex-col overflow-hidden rounded-lg border border-subtle bg-surface shadow-(--shadow-pop)">
        <div className="flex items-center justify-between border-b border-subtle px-4 py-2.5">
          <h2 className="truncate text-sm font-semibold text-primary">Terminal, {hostName}</h2>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-2xs text-tertiary">
              <span className={classNames("h-1.5 w-1.5 rounded-full", status.dot)} />
              {status.label}
            </span>
            <button
              type="button"
              aria-label="Close terminal"
              className="rounded-sm p-1 text-tertiary hover:text-primary"
              onClick={onClose}
            >
              <IconX size={16} />
            </button>
          </div>
        </div>

        <div className="relative min-h-0 flex-1 bg-inset">
          <div ref={containerRef} className="h-full w-full px-3 py-2" />

          {shellState === null || shellState.state === "connecting" ? (
            <div
              className="pointer-events-none absolute left-1/2 top-3 -translate-x-1/2 rounded-pill border border-subtle bg-raised/95 px-3 py-1 text-2xs text-secondary shadow-(--shadow-pop)"
              role="status"
            >
              <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent align-middle" />
              Connecting to {connectingEndpoint}
            </div>
          ) : null}

          {shellState?.state === "reconnecting" ? (
            <ReconnectingBanner
              attempt={shellState.attempt}
              delayMs={shellState.delayMs}
              reason={shellState.reason}
              onRetryNow={() => void sshReconnectNow(sessionId)}
            />
          ) : null}

          {shellState?.state === "disconnected" ? (
            <DisconnectedBanner
              reason={shellState.reason}
              canRetry={shellState.canRetry}
              onReconnect={() => connectRef.current()}
              onClose={onClose}
            />
          ) : null}

          {phase.kind === "error" ? (
            <ConnectErrorBanner
              message={phase.message}
              onRetry={() => connectRef.current()}
              onClose={onClose}
            />
          ) : null}

          {bellTick > 0 ? (
            <div
              key={bellTick}
              aria-hidden="true"
              className="shutter-flash pointer-events-none absolute inset-0 bg-accent/10"
            />
          ) : null}
        </div>

        {notice ? (
          <div className="border-t border-subtle bg-inset/50 px-3 py-1.5 text-2xs text-tertiary">
            {notice}
          </div>
        ) : null}
      </div>

      {/*
        `SshHostKeyPrompt` renders a Close-only hard stop when `data.changed`
        is set, so the accept below is already unreachable for a changed key.
        It is still wired to a no-op rather than to the retry, deliberately: a
        live callback there would mean a later refactor of that dialog could
        quietly turn a changed host key into something a user can accept, and
        that is the one outcome this path exists to forbid (PRD/08 §4,
        PRD/10 §4.3). First contact is the only case that may retry.
      */}
      {phase.kind === "host-key-prompt" || phase.kind === "host-key-changed" ? (
        <SshHostKeyPrompt
          data={phase.data}
          onAccept={
            phase.kind === "host-key-prompt"
              ? () => connectRef.current(phase.data.fingerprint)
              : () => {}
          }
          onCancel={onClose}
        />
      ) : null}
    </div>
  );
}

// --------------------------------------------------------------- status pill

function statusPill(phase: Phase): { label: string; dot: string } {
  if (phase.kind === "error") return { label: "Connection failed", dot: "bg-danger" };
  if (phase.kind === "host-key-prompt") return { label: "Verifying host key", dot: "bg-warning" };
  if (phase.kind === "host-key-changed") return { label: "Host key changed", dot: "bg-danger" };
  const s = phase.kind === "shell" ? phase.state : null;
  if (!s || s.state === "connecting") return { label: "Connecting…", dot: "bg-tertiary animate-pulse" };
  switch (s.state) {
    case "connected":
      return { label: "Connected", dot: "bg-success" };
    case "reconnecting":
      return { label: `Reconnecting (attempt ${s.attempt})`, dot: "bg-warning animate-pulse" };
    case "disconnected":
      return { label: "Disconnected", dot: "bg-danger" };
    default:
      return { label: "Connected", dot: "bg-success" };
  }
}

// ------------------------------------------------------------------ banners

function ReconnectingBanner({
  attempt,
  delayMs,
  reason,
  onRetryNow,
}: {
  attempt: number;
  delayMs: number;
  reason: string;
  onRetryNow: () => void;
}): ReactNode {
  // Mirrors `Session.tsx`'s `ReconnectOverlay`: a bare spinner with no number
  // is what makes people force-quit, so the countdown is the point.
  const [remaining, setRemaining] = useState(delayMs);
  useEffect(() => {
    setRemaining(delayMs);
    const started = performance.now();
    const iv = window.setInterval(() => {
      const left = delayMs - (performance.now() - started);
      setRemaining(Math.max(0, left));
      if (left <= 0) window.clearInterval(iv);
    }, 250);
    return () => window.clearInterval(iv);
  }, [delayMs, attempt]);
  const secs = Math.ceil(remaining / 1000);

  return (
    <div
      className="fade-in absolute inset-0 z-10 flex items-center justify-center bg-scrim"
      role="alert"
      aria-live="assertive"
    >
      <div className="w-80 max-w-[calc(100%-32px)] rounded-lg border border-subtle bg-raised p-4 shadow-(--shadow-pop)">
        <div className="mb-1 overflow-hidden rounded-pill bg-inset">
          <div className="indeterminate-bar h-0.5 w-1/3 bg-accent" />
        </div>
        <p className="mt-3 text-sm font-medium text-primary">
          Reconnecting… attempt {attempt}
          {secs > 0 ? ` · retrying in ${secs}s` : " · retrying now"}
        </p>
        {reason ? <p className="mt-1 text-xs text-secondary">{reason}</p> : null}
        <div className="mt-3 flex justify-end">
          <button type="button" className="btn-primary px-3 py-1 text-xs" onClick={onRetryNow}>
            Reconnect now
          </button>
        </div>
      </div>
    </div>
  );
}

function DisconnectedBanner({
  reason,
  canRetry,
  onReconnect,
  onClose,
}: {
  reason: string;
  canRetry: boolean;
  onReconnect: () => void;
  onClose: () => void;
}): ReactNode {
  return (
    <div className="fade-in absolute inset-0 z-10 flex items-center justify-center bg-scrim" role="alert">
      <div className="w-80 max-w-[calc(100%-32px)] rounded-lg border border-subtle bg-raised p-4 shadow-(--shadow-pop)">
        <p className="text-sm font-semibold text-primary">Disconnected</p>
        <p className="mt-1.5 text-xs text-secondary">{reason || "The connection was closed."}</p>
        <div className="mt-3 flex justify-end gap-2">
          <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={onClose}>
            Close
          </button>
          {canRetry ? (
            <button type="button" className="btn-primary px-3 py-1 text-xs" onClick={onReconnect}>
              Reconnect
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function ConnectErrorBanner({
  message,
  onRetry,
  onClose,
}: {
  message: string;
  onRetry: () => void;
  onClose: () => void;
}): ReactNode {
  return (
    <div className="fade-in absolute inset-0 z-10 flex items-center justify-center bg-scrim" role="alert">
      <div className="w-80 max-w-[calc(100%-32px)] rounded-lg border border-danger bg-raised p-4 shadow-(--shadow-pop)">
        <p className="flex items-center gap-2 text-sm font-semibold text-danger">
          <IconAlert size={15} />
          Couldn&apos;t open a terminal
        </p>
        <p className="mono mt-1.5 max-h-24 overflow-auto text-xs text-secondary">{message}</p>
        <div className="mt-3 flex justify-end gap-2">
          <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={onClose}>
            Close
          </button>
          <button type="button" className="btn-primary px-3 py-1 text-xs" onClick={onRetry}>
            Try again
          </button>
        </div>
      </div>
    </div>
  );
}
