/**
 * A Mac with someone else at its screen, before the session starts.
 *
 * `MacSessionChoice` is raised by `mac-session-choice` while the handshake is
 * paused: share the screen of the person at the Mac (they are asked to
 * accept), or log in to a separate session. Dismissing it abandons the
 * attempt. `MacSessionWaiting` covers the connecting overlay while that
 * person decides; its button closes the connection, which withdraws the
 * request on the Mac.
 *
 * The user name is server supplied and is rendered as text only.
 */
import { useEffect, useRef, type ReactNode } from "react";
import { Dialog } from "./primitives";
import { macChoiceTitle, macShareText, macWaitingText } from "../lib/macSession";
import { useT } from "../i18n";

export function MacSessionChoice({
  consoleUser,
  canShare,
  canSeparate,
  onChoose,
  onCancel,
}: {
  consoleUser: string;
  canShare: boolean;
  canSeparate: boolean;
  onChoose: (share: boolean) => void;
  onCancel: () => void;
}): ReactNode {
  const t = useT();
  return (
    <Dialog title={macChoiceTitle(consoleUser)} onClose={onCancel} width={460}>
      <div className="space-y-3 text-sm text-secondary">
        {canShare ? (
          <p className="break-words">{macShareText(consoleUser)}</p>
        ) : null}
        {canSeparate ? (
          <p>{t("Or log in to a separate session of your own, which leaves their screen alone.")}</p>
        ) : (
          <p>{t("This Mac cannot give you a separate session right now.")}</p>
        )}
      </div>
      <div className="mt-5 flex flex-wrap justify-end gap-2.5">
        <button type="button" className="btn-secondary" onClick={onCancel}>
          {t("Cancel")}
        </button>
        {canSeparate ? (
          <button
            type="button"
            className={canShare ? "btn-secondary" : "btn-primary"}
            onClick={() => onChoose(false)}
          >
            {t("Log in separately")}
          </button>
        ) : null}
        {canShare ? (
          <button type="button" className="btn-primary" data-autofocus onClick={() => onChoose(true)}>
            {t("Ask to share screen")}
          </button>
        ) : null}
      </div>
    </Dialog>
  );
}

export function MacSessionWaiting({
  consoleUser,
  onCancel,
}: {
  consoleUser: string;
  onCancel: () => void;
}): ReactNode {
  const t = useT();
  const panelRef = useRef<HTMLDivElement>(null);
  // Off the canvas, so Enter and Escape stay with this panel and the remote
  // keyboard hook leaves them alone.
  useEffect(() => {
    panelRef.current?.querySelector<HTMLElement>("button")?.focus();
  }, []);
  return (
    <div className="absolute inset-0 flex items-center justify-center bg-canvas">
      {/* `role="dialog"` keeps keystrokes in here from going to the remote. */}
      <div
        ref={panelRef}
        role="dialog"
        aria-label={t("Waiting for the person at the Mac")}
        onKeyDown={(e) => {
          if (e.key === "Escape") onCancel();
        }}
        className="w-96 max-w-[calc(100vw-32px)] rounded-lg border border-subtle bg-raised p-5 shadow-(--shadow-pop)"
      >
        <div className="mb-1 overflow-hidden rounded-pill bg-inset">
          <div className="indeterminate-bar h-0.5 w-1/3 bg-accent" />
        </div>
        <p className="mt-3 text-sm font-medium break-words text-primary" role="status" aria-live="polite">
          {macWaitingText(consoleUser)}
        </p>
        <p className="mt-1 text-xs text-secondary">
          {t("DeskVNC waits up to three minutes for an answer. The Mac may give up sooner.")}
        </p>
        <div className="mt-4 flex justify-end">
          <button type="button" className="btn-secondary" onClick={onCancel}>
            {t("Cancel request")}
          </button>
        </div>
      </div>
    </div>
  );
}
