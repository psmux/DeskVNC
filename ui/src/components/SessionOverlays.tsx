/**
 * Connecting / reconnecting / disconnected overlays for a session window.
 *
 * Pulled out of `Session.tsx` so `SshSession.tsx` can render the exact same
 * panels over a terminal that `SessionView` renders over the framebuffer
 * canvas, rather than a second copy that drifts from the original the next
 * time the wording or the reconnect countdown changes. Nothing in here is
 * VNC/RDP specific; the only per-protocol shaping (auth method labels, the
 * "security settings" deep link) already lives behind props the caller
 * supplies.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { authMethodLabel } from "../hooks/useSession";
import { diagnose, isAuthFailure, opensSecuritySettings } from "../lib/diagnose";
import type { SessionState } from "../lib/types";

// -------------------------------------------------------- connecting overlay

const STAGES = ["resolving", "connecting", "authenticating", "negotiating"] as const;

function stageLabel(st: SessionState): string {
  switch (st.state) {
    case "resolving":
      return "Resolving";
    case "connecting":
      return "Connecting";
    case "authenticating":
      // The wire value is a stable identifier, so the copy is the UI's own.
      // An unrecognised one comes back verbatim rather than as a blank.
      return `Authenticating (${authMethodLabel(st.method)})`;
    case "negotiating":
      return "Negotiating";
    default:
      return "Preparing";
  }
}

export function ConnectingOverlay({ state, name }: { state: SessionState; name: string }): ReactNode {
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

export function ReconnectOverlay({
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
//
// `diagnose` and `isAuthFailure` live in `lib/diagnose.ts`. They are pure
// string-to-string functions with no React in them, and the vitest include
// pattern does not collect `.tsx`, so while they were here the branch
// ordering everything below depends on could not be tested at all.

export function DisconnectedOverlay({
  name,
  reason,
  canRetry,
  profileId,
  onEditSecurity,
  onReconnect,
  onClose,
}: {
  name: string;
  reason: string;
  canRetry: boolean;
  /** Null for an ad-hoc session: there is no profile to open in the editor. */
  profileId: string | null;
  onEditSecurity: (() => void) | null;
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

  const text = typeof reason === "string" ? reason : "";
  const authFailure = isAuthFailure(text);
  const securityFix = opensSecuritySettings(text);
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
        {/*
          The message above names a setting, so the panel offers the way to
          it rather than making the user find the host in the library first.
          An ad-hoc session has no profile to edit, so it gets the sentence
          that says what to do instead.
        */}
        {securityFix ? (
          profileId && onEditSecurity ? (
            <button
              type="button"
              className="mt-2.5 text-xs font-medium text-accent underline underline-offset-2"
              onClick={onEditSecurity}
            >
              Open this computer's security settings
            </button>
          ) : (
            <p className="mt-1.5 text-xs text-tertiary">
              Save this computer to your library first, then change the setting in
              its settings.
            </p>
          )
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
