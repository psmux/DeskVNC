/**
 * What the person sees until the desktop shows: a phone and a computer with
 * a pulse running between them and the step in plain words. On failure the
 * same scene, broken, with one big Try again button.
 */
import type { EndKind, Step } from "../status";
import { STEP_WORDS, endWords, friendlyError } from "../status";
import { ConnectArt } from "./art";
import { IconRefresh } from "./icons";

export function ConnectingScreen({
  title,
  step,
  words,
  reconnecting,
  onCancel,
}: {
  title: string;
  step: Step;
  /** What is happening, in plain words. */
  words: string;
  reconnecting: boolean;
  onCancel(): void;
}) {
  const steps: Step[] = [0, 1, 2, 3];
  return (
    <div className="dv-s-scene-screen" role="status" aria-live="polite">
      <div className="dv-s-scene-body">
        <ConnectArt step={step} failed={false} />
        <div className="dv-s-scene-text">
          <p className="dv-s-scene-kicker">{reconnecting ? "Reconnecting" : "Connecting"}</p>
          <h1 className="dv-s-scene-title">{title}</h1>
          <p className="dv-s-scene-step">{words}</p>
          <ol className="dv-s-steps" aria-label="Progress">
            {steps.map((s) => (
              <li key={s} className={s < step ? "done" : s === step ? "now" : ""} aria-current={s === step ? "step" : undefined}>
                <span className="sr-only">{STEP_WORDS[s]}</span>
              </li>
            ))}
          </ol>
          <button type="button" className="dv-s-plain" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

export function ErrorScreen({ message, onRetry, onExit }: { title?: string; message: string | null; onRetry(): void; onExit(): void }) {
  const f = friendlyError(message ?? "");
  return (
    <div className="dv-s-scene-screen" role="alert">
      <div className="dv-s-scene-body">
        <ConnectArt step={0} failed />
        <div className="dv-s-scene-text">
          <h1 className="dv-s-scene-title">{message ? f.title : "We could not connect"}</h1>
          <p className="dv-s-scene-detail">{message ? f.detail : "Check that it is switched on, then try again."}</p>
          <div className="dv-s-scene-actions">
            <button type="button" className="dv-s-big" onClick={onRetry}>
              <IconRefresh size={24} /> Try again
            </button>
            <button type="button" className="dv-s-plain" onClick={onExit}>
              Back to my computers
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Over a desktop that stopped. Paused or dropped offers Reconnect first. When
 * the other side ended it, leaving is the main answer, and connecting again
 * is only offered where it can work: a Boundary invitation is good for one
 * session, so a helper needs a new one.
 */
export function ReconnectCard({
  title,
  kind,
  reason,
  canReconnect,
  onReconnect,
  onExit,
}: {
  title: string;
  kind: EndKind;
  reason: string | null;
  canReconnect: boolean;
  onReconnect(): void;
  onExit(): void;
}) {
  const words = endWords(kind, reason);
  const byThem = kind === "remote";
  return (
    <div className="dv-s-reconnect" role="alertdialog" aria-label={words.title}>
      <div className="dv-s-reconnect-card">
        <ConnectArt step={0} failed={!byThem} />
        <h2>{byThem ? words.title : title}</h2>
        <p className="dv-s-lead">{byThem ? words.lead : `${words.title}. ${words.lead}`}</p>
        {byThem ? (
          <>
            <button type="button" className="dv-s-big" onClick={onExit}>
              Back to my computers
            </button>
            {canReconnect ? (
              <button type="button" className="dv-s-plain" onClick={onReconnect}>
                Connect again
              </button>
            ) : null}
          </>
        ) : (
          <>
            <button type="button" className="dv-s-big" onClick={onReconnect}>
              <IconRefresh size={24} /> Reconnect
            </button>
            <button type="button" className="dv-s-plain" onClick={onExit}>
              Back to my computers
            </button>
          </>
        )}
      </div>
    </div>
  );
}
