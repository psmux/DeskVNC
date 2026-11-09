/**
 * What the person sees until the desktop shows: a phone and a computer with
 * a pulse running between them and the step in plain words. On failure the
 * same scene, broken, with one big Try again button.
 */
import type { Step } from "../status";
import { STEP_WORDS, friendlyError } from "../status";
import { ConnectArt } from "./art";
import { IconRefresh } from "./icons";

export function ConnectingScreen({
  title,
  step,
  reconnecting,
  onCancel,
}: {
  title: string;
  step: Step;
  reconnecting: boolean;
  onCancel(): void;
}) {
  const steps: Step[] = [0, 1, 2, 3];
  return (
    <div className="dv-s-scene-screen" role="status" aria-live="polite">
      <div className="dv-s-scene-body">
        <ConnectArt step={step} failed={false} />
        <div className="dv-s-scene-text">
          <h1 className="dv-s-scene-title">{reconnecting ? `Getting ${title} back` : `Connecting to ${title}`}</h1>
          <p className="dv-s-scene-step">{STEP_WORDS[step]}</p>
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

export function ErrorScreen({ title, message, onRetry, onExit }: { title: string; message: string | null; onRetry(): void; onExit(): void }) {
  const f = friendlyError(message ?? "");
  return (
    <div className="dv-s-scene-screen" role="alert">
      <div className="dv-s-scene-body">
        <ConnectArt step={0} failed />
        <div className="dv-s-scene-text">
          <h1 className="dv-s-scene-title">{message ? f.title : `We could not connect to ${title}`}</h1>
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

export function ReconnectCard({ title, onReconnect, onExit }: { title: string; onReconnect(): void; onExit(): void }) {
  return (
    <div className="dv-s-reconnect" role="alertdialog" aria-label="Connection paused">
      <div className="dv-s-reconnect-card">
        <ConnectArt step={0} failed />
        <h2>The connection to {title} was paused</h2>
        <p className="dv-s-lead">This happens when DeskVNC is in the background for a while, or the network changes.</p>
        <button type="button" className="dv-s-big" onClick={onReconnect}>
          <IconRefresh size={24} /> Reconnect
        </button>
        <button type="button" className="dv-s-plain" onClick={onExit}>
          Back to my computers
        </button>
      </div>
    </div>
  );
}
