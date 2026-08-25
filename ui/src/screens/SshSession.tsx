/**
 * The primary surface for a session whose protocol IS ssh: a full-window
 * terminal instead of the framebuffer canvas `SessionView` draws for VNC and
 * RDP (PRD/09-ish, ssh-core end to end).
 *
 * SSH goes through the exact same `connect_session` path as the other two
 * protocols, so this reuses `useSession` wholesale, state machine, reconnect,
 * disconnect, credentials, the SSH tunnel gateway's own host-key prompt, and
 * differs only in its render surface: `onPty` (msg_type 3) drives an xterm.js
 * terminal instead of `onFrame`/`onCursorShape` driving a WebGL canvas. The
 * terminal setup itself (fonts, WebGL-over-canvas upgrade, resize watch, live
 * theme) is shared with the sidecar `SshTerminal` dialog a VNC/RDP session can
 * still open on top of its own desktop; see `components/SshTerminal.tsx` for
 * the extracted pieces.
 */
import { useCallback, useEffect, useMemo, useRef, type ReactNode } from "react";
import type { Terminal } from "@xterm/xterm";
import {
  authMethodLabel,
  readSessionParams,
  useSession,
  type SessionBridge,
  type SessionParams,
} from "../hooks/useSession";
import { buildTheme, createTerminal, watchTerminalResize, watchThemeChanges } from "../components/SshTerminal";
import { ConnectingOverlay, DisconnectedOverlay, ReconnectOverlay } from "../components/SessionOverlays";
import { CertPrompt } from "../components/CertPrompt";
import { CredentialPrompt } from "../components/CredentialPrompt";
import { SshHostKeyPrompt } from "../components/SshHostKeyPrompt";
import { ToastShelf } from "../components/primitives";
import { useToasts } from "../state/ToastContext";
import { classNames } from "../lib/util";
import { inTauri, safeInvoke } from "../lib/tauri";
import type { SessionState } from "../lib/types";

export interface SshSessionProps {
  /** Connection parameters. Omit in a session window, where the URL has them. */
  params?: SessionParams;
  /** Mounted as a tab rather than owning the window it is in. */
  embedded?: boolean;
  /** This tab is the one on screen. Only meaningful when embedded. */
  active?: boolean;
  /** Embedded: take this tab off the strip. */
  onClose?: () => void;
  /** Connection state changed, for the tab's status dot. */
  onState?: (state: SessionState) => void;
}

/** Status pill next to the host name; mirrors `SshTerminal`'s but keyed off
 *  `useSession`'s state machine rather than the sidecar's own. */
function statusPill(state: SessionState): { label: string; dot: string } {
  switch (state.state) {
    case "connected":
      return { label: "Connected", dot: "bg-success" };
    case "authenticating":
      return { label: `Authenticating (${authMethodLabel(state.method)})`, dot: "bg-tertiary animate-pulse" };
    case "reconnecting":
      return { label: `Reconnecting (attempt ${state.attempt})`, dot: "bg-warning animate-pulse" };
    case "disconnected":
      return { label: "Disconnected", dot: "bg-danger" };
    default:
      return { label: "Connecting…", dot: "bg-tertiary animate-pulse" };
  }
}

/** The words the app uses for a multiplexer kind, for "reattached to your
 *  ___ session". `MultiplexerKind` is kebab-case on the wire (`ssh-core`);
 *  "auto"/"none" never reach here with `resumed: true`. */
function multiplexerLabel(kind: string | null): string {
  switch (kind) {
    case "tmux":
      return "tmux";
    case "psmux":
      return "psmux";
    case "screen":
      return "screen";
    case "zellij":
      return "zellij";
    case "custom":
      return "configured";
    default:
      return "remote";
  }
}

export function SshSession({
  params: paramsProp,
  embedded = false,
  active = true,
  onClose,
  onState,
}: SshSessionProps): ReactNode {
  const params = paramsProp ?? readSessionParams();
  const visible = !embedded || active;
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const { push } = useToasts();

  const bridge = useMemo<SessionBridge>(
    () => ({
      // A framebuffer/cursor bridge has no meaning here; the terminal is the
      // whole surface. `SessionView`'s bridge returns the favour for msg_type
      // 3, see the comment on its own `onPty` no-op.
      onFrame: () => undefined,
      onDesktopResize: () => undefined,
      onCursorShape: () => undefined,
      onCursorPosition: () => undefined,
      onPty: (_stream, bytes) => {
        // Both streams are written verbatim: stream 1 (a terminal-mode reset)
        // has to reach the terminal exactly like output to actually undo
        // whatever DEC private mode a dead link left switched on, it is only
        // kept off `stream` 0 so it is never logged or treated as something
        // the remote program said (FRAME_FORMAT.md msg_type=3). xterm decodes
        // UTF-8 itself and carries a partial sequence across writes, which is
        // exactly why the backend hands over bytes rather than a string.
        termRef.current?.write(bytes);
      },
    }),
    [],
  );

  const session = useSession(params, bridge);
  const sessionRef = useRef(session);
  sessionRef.current = session;

  // ------------------------------------------------------------- terminal

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const { term, fit, cancelWebgl } = createTerminal();
    term.open(container);
    fit.fit();
    termRef.current = term;

    const dData = term.onData((d) => sessionRef.current.sendTerminalInput(new TextEncoder().encode(d)));
    const dResize = term.onResize(({ cols, rows }) => sessionRef.current.sendTerminalResize(cols, rows));
    const stopResizeWatch = watchTerminalResize(container, fit);

    return () => {
      cancelWebgl();
      stopResizeWatch();
      dData.dispose();
      dResize.dispose();
      term.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * Tell the remote how big the terminal actually is, once there is a remote
   * to tell.
   *
   * `fit()` runs the moment the terminal mounts, which fires `onResize` and
   * sends a resize immediately. The session is still connecting at that point
   * (a TCP dial, a key exchange, authentication, the multiplexer probe and a
   * pty request all have to finish first), so that first resize reaches a
   * session that does not exist yet and is dropped. Nothing resent it, so the
   * pty kept whatever size the profile was saved with, usually 80x24, and a
   * full-screen program drew into the top-left corner of a much larger window
   * for the rest of the session.
   *
   * Resending on `connected` also covers the reconnect case, where the far
   * side is a brand new pty that has never been told anything.
   */
  useEffect(() => {
    if (session.state.state !== "connected") return;
    const term = termRef.current;
    if (!term) return;
    session.sendTerminalResize(term.cols, term.rows);
    // `session` is deliberately not a dependency: it is rebuilt on every
    // render, and this must fire on the transition into `connected`, not on
    // every render that happens while connected.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.state.state]);

  // Live theme: re-read the tokens whenever the app's theme actually
  // changes, not only once at mount (Preferences ▸ Appearance while a
  // session window is open).
  useEffect(() => {
    const apply = (): void => {
      const term = termRef.current;
      if (term) term.options.theme = buildTheme();
    };
    return watchThemeChanges(apply);
  }, []);

  // Coming to the front takes the focus with it, same reasoning as
  // `SessionView`'s equivalent effect: a background tab must not hold the
  // keyboard, and switching to this one has to grab it back.
  useEffect(() => {
    if (visible) termRef.current?.focus();
  }, [visible]);

  // A tab does not own the window title; the shell sets it from whichever
  // tab is in front.
  useEffect(() => {
    if (embedded) return;
    document.title = params.name;
  }, [embedded, params.name]);

  const reportStateRef = useRef(onState);
  reportStateRef.current = onState;
  useEffect(() => {
    reportStateRef.current?.(session.state);
  }, [session.state]);

  // "Reattached to your tmux session" is the one moment worth interrupting
  // for: it is the answer to "did my work survive the disconnect". Toasted
  // once per attach, not once per `ssh-attached` state object (a reconnect
  // that resumes again is worth saying again).
  const resumeToasted = useRef(false);
  useEffect(() => {
    if (session.state.state !== "connected") {
      resumeToasted.current = false;
      return;
    }
    if (session.sshAttached?.resumed && !resumeToasted.current) {
      resumeToasted.current = true;
      push("success", `Reattached to your ${multiplexerLabel(session.sshAttached.multiplexer)} session`);
    }
  }, [session.state.state, session.sshAttached, push]);

  // `ssh-notice` is for a status area, never the terminal (FRAME_FORMAT.md);
  // it says its piece and gets out of the way rather than piling into the
  // toast shelf, same convention `SshTerminal`'s own notice line uses.
  const notice = session.sshNotice;

  // ------------------------------------------------------------- close

  const dismiss = useCallback((): void => {
    if (embedded) {
      onClose?.();
      return;
    }
    if (!inTauri()) {
      window.location.search = "";
      return;
    }
    void safeInvoke("disconnect_session", { sessionId: params.sessionId }, null).finally(() => {
      void import("@tauri-apps/api/window").then(({ getCurrentWindow }) => {
        const win = getCurrentWindow();
        void win.close().catch(() => void win.destroy());
      });
    });
  }, [embedded, onClose, params.sessionId]);

  // ------------------------------------------------------------- render

  const st = session.state;
  const showConnecting =
    st.state === "resolving" || st.state === "connecting" ||
    st.state === "authenticating" || st.state === "negotiating" || st.state === "idle";
  const pill = statusPill(st);

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden bg-canvas">
      <div className="flex shrink-0 items-center justify-between border-b border-subtle bg-surface px-4 py-2">
        <h1 className="truncate text-sm font-semibold text-primary">{params.name}</h1>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-2xs text-tertiary">
            <span className={classNames("h-1.5 w-1.5 rounded-full", pill.dot)} />
            {pill.label}
          </span>
          {st.state === "connected" || st.state === "reconnecting" ? (
            <button
              type="button"
              className="btn-secondary px-2.5 py-1 text-xs"
              onClick={session.disconnect}
            >
              Disconnect
            </button>
          ) : null}
        </div>
      </div>

      <div className="relative min-h-0 flex-1 bg-inset">
        <div ref={containerRef} className="h-full w-full px-3 py-2" />

        {showConnecting ? <ConnectingOverlay state={st} name={params.name} /> : null}

        {st.state === "reconnecting" ? (
          <ReconnectOverlay
            name={params.name}
            attempt={st.attempt}
            nextRetryMs={st.next_retry_ms}
            reason={st.reason}
            onRetryNow={session.reconnectNow}
            onDisconnect={session.disconnect}
          />
        ) : null}

        {st.state === "disconnected" ? (
          <DisconnectedOverlay
            name={params.name}
            reason={st.reason}
            canRetry={st.can_retry}
            profileId={params.profileId}
            onEditSecurity={null}
            onReconnect={session.retryConnect}
            onClose={dismiss}
          />
        ) : null}
      </div>

      {notice ? (
        <div className="shrink-0 border-t border-subtle bg-inset/50 px-3 py-1.5 text-2xs text-tertiary">
          {notice}
        </div>
      ) : null}

      {session.certPrompt ? (
        <CertPrompt
          data={{
            fingerprint: session.certPrompt.fingerprint,
            subject: session.certPrompt.subject,
            isChange: session.certPrompt.isChange,
            hostName: params.name,
            scheme: session.certPrompt.scheme,
          }}
          onTrust={() => session.trustCertificate(true)}
          onConnectOnce={() => session.trustCertificate(false)}
          onCancel={session.dismissCertPrompt}
        />
      ) : null}

      {/* Same stacking lift `Session.tsx` gives this prompt: the connect is
          parked on the answer while the overlay above still says "Connecting…". */}
      {session.sshHostKeyPrompt ? (
        <div className="relative z-50">
          <SshHostKeyPrompt
            data={session.sshHostKeyPrompt}
            onAccept={session.acceptSshHostKey}
            onCancel={session.dismissSshHostKeyPrompt}
          />
        </div>
      ) : null}

      {session.credentialRequest ? (
        <div className="relative z-50">
          <CredentialPrompt
            request={session.credentialRequest}
            hostName={params.name}
            protocol={params.protocol}
            onSubmit={session.submitCredentials}
            onCancel={session.dismissCredentialPrompt}
          />
        </div>
      ) : null}

      {embedded ? null : <ToastShelf />}
    </div>
  );
}
