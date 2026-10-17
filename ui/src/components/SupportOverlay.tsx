import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  rememberedCodeService,
  setCodeService,
  support,
  useSupport,
  type SupportView,
} from "../lib/support";

/**
 * What Get help puts in front of the person, wherever they are in the app:
 * the question when a helper asks to be let in, and a banner for as long as
 * one is connected, with a way to end it.
 *
 * Mounted once, in the main window. Rust brings that window forward when a
 * helper knocks or comes in unattended, so neither waits unseen.
 */
export function SupportOverlay(): ReactNode {
  const view = useSupport();
  useEffect(() => {
    const url = rememberedCodeService();
    if (url) void setCodeService(url).catch(() => undefined);
  }, []);
  if (!view) return null;
  return (
    <>
      {view.pending ? (
        <Approval
          key={view.pending.peer}
          asking={view.pending}
          inputPermission={view.inputPermission}
          note="The name is supplied by the helper. Confirm it with the person you invited."
          onDecide={(decision, allowTools) => support.answer(decision, allowTools)}
        />
      ) : view.unattended.ask ? (
        <Approval
          key={view.unattended.ask.peer}
          asking={view.unattended.ask}
          inputPermission={view.inputPermission}
          note="They are connecting with this computer's ID and are not paired with it. The name is supplied by the helper, so only allow someone you expect."
          pairable
          onDecide={(decision, allowTools, pair) => support.answerAsk(decision, allowTools, pair)}
        />
      ) : null}
      {view.sharing && view.connected ? <SharingBanner view={view} /> : null}
      {view.unattended.active.map((active) => (
        <UnattendedBanner key={active.id} active={active} />
      ))}
    </>
  );
}

type Decision = "control" | "view" | "deny";

/**
 * Asks the person whether to let a helper in. The same question for an
 * invited helper and for one connecting by this computer's ID; only the
 * second can be paired from here.
 */
function Approval({
  asking,
  inputPermission,
  note,
  pairable = false,
  onDecide,
}: {
  asking: { name: string; peer: string; tools: boolean };
  inputPermission: boolean;
  note: string;
  pairable?: boolean;
  onDecide: (decision: Decision, allowTools: boolean, pair: boolean) => Promise<unknown>;
}): ReactNode {
  const dialog = useRef<HTMLDialogElement>(null);
  const [allowTools, setAllowTools] = useState(false);
  const [pair, setPair] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const el = dialog.current;
    if (el && !el.open) el.showModal();
    return () => el?.close();
  }, []);
  const pending = asking;
  const decide = (decision: Decision) => {
    setError("");
    onDecide(decision, allowTools, pair).catch((err) => setError(String(err)));
  };
  return (
    <dialog
      ref={dialog}
      // Escape is not an answer. The helper waits until the person chooses.
      onCancel={(event) => event.preventDefault()}
      className="m-auto w-full max-w-md rounded-lg border border-subtle bg-raised p-6 text-primary shadow-lg backdrop:bg-black/50"
    >
      <h2 className="text-lg font-semibold">Approve this helper?</h2>
      <p className="mt-3 text-base">{pending.name} wants to see your screen.</p>
      <p className="mt-1 text-xs text-secondary">{note}</p>
      <p className="mt-3 text-xs text-secondary">Helper connection identity</p>
      <p className="mono break-all text-xs">{pending.peer}</p>
      {pending.tools ? (
        <div className="mt-4">
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={allowTools}
              onChange={(event) => setAllowTools(event.target.checked)}
            />
            <span>Also let their tools run commands and copy files on this computer</span>
          </label>
          <p className="mt-1 text-xs text-secondary">
            Their tools act as you, outside what the screen shows. Leave this off unless you asked
            for it. You can turn it off at any time, and each command shows here as it runs.
          </p>
        </div>
      ) : null}
      {pairable ? (
        <label className="mt-4 flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={pair}
            onChange={(event) => setPair(event.target.checked)}
          />
          <span>Let them connect any time without asking me again</span>
        </label>
      ) : null}
      <div className="mt-5 flex flex-wrap gap-2">
        <button
          type="button"
          className="btn-primary"
          disabled={!inputPermission}
          onClick={() => decide("control")}
        >
          Allow viewing and control
        </button>
        <button type="button" className="btn-secondary" onClick={() => decide("view")}>
          Allow viewing
        </button>
        <button type="button" className="btn-secondary" onClick={() => decide("deny")}>
          Decline
        </button>
      </div>
      {!inputPermission ? (
        <p className="mt-2 text-xs text-secondary">
          Accessibility permission is needed for control. You can allow viewing now.
        </p>
      ) : null}
      {error ? <p role="alert" className="mt-2 text-sm text-danger">{error}</p> : null}
    </dialog>
  );
}

function Activity({ lines }: { lines: string[] }): ReactNode {
  if (lines.length === 0) return null;
  return (
    <div className="mt-1">
      {lines.map((line, index) => (
        <p key={index} className="mono truncate text-2xs opacity-90">
          {line}
        </p>
      ))}
    </div>
  );
}

function Banner({ children }: { children: ReactNode }): ReactNode {
  return (
    <div role="status" className="border-b border-danger bg-danger px-4 py-2 text-sm text-white">
      {children}
    </div>
  );
}

/** A helper this person let in, in this session. */
function SharingBanner({ view }: { view: SupportView }): ReactNode {
  const name = view.helper?.name || "Your helper";
  return (
    <Banner>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">
          {name} can see your screen
          {view.control ? " and use your mouse and keyboard" : ""}.
        </span>
        <div className="ml-auto flex gap-2">
          {view.control ? (
            <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={() => void support.setControl(false)}>
              Stop control
            </button>
          ) : null}
          {view.tools ? (
            <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={() => void support.setTools(false)}>
              Stop their commands
            </button>
          ) : null}
          <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={() => void support.stop()}>
            End session
          </button>
        </div>
      </div>
      {view.tools ? <p className="text-xs">Their tools can run commands and copy files on this computer.</p> : null}
      <Activity lines={view.activity.slice(-3)} />
    </Banner>
  );
}

/** A paired helper who came in with nobody's approval. One per helper. */
function UnattendedBanner({ active }: { active: SupportView["unattended"]["active"][number] }): ReactNode {
  return (
    <Banner>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">
          {active.name} is connected to this computer
          {active.control ? " and can use the mouse and keyboard" : ", watching"}
        </span>
        <div className="ml-auto flex gap-2">
          {active.tools ? (
            <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={() => void support.stopUnattendedTools(active.id)}>
              Stop their commands
            </button>
          ) : null}
          <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={() => void support.endUnattended(active.id)}>
            End their session
          </button>
        </div>
      </div>
      {active.tools ? <p className="text-xs">Their tools can run commands and copy files on this computer.</p> : null}
      <Activity lines={active.activity} />
    </Banner>
  );
}
