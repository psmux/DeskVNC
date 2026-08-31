/**
 * How somebody connects an agent, in one modal, in one press.
 *
 * WHAT THIS IS FOR. The agent plane is off in every install and there is
 * nothing on screen to discover it by, which is correct (`AGENT_BRIEF` D2) and
 * leaves exactly one problem: a person who wants it has no idea it is there.
 * This is that door. It is reachable with the plane off, it is the only agent
 * chrome that is, and everything else in the product stays exactly as it was
 * until somebody presses the switch in here.
 *
 * WHAT CHANGED, AND WHY IT IS THE WHOLE POINT. This used to hand somebody a
 * command and ask them to go and run it. Asking a person to do work an
 * application can do for itself is the application telling them their time is
 * worth less than its own, and the command had a hole in it besides. So the
 * shell registers the server now and the screen has one button on it. The
 * lines are still here, folded away, for reading and for anybody driving a
 * different agent, and every one of them is complete.
 *
 * WHAT IT IS NOT. Not an explanation of the architecture. A person arrives
 * here to make something work, so the switch and the button come first, the
 * honest list of what an agent can do comes second, and everything a terminal
 * would be needed for is behind a fold. Anything longer is a modal that gets
 * closed.
 *
 * TWO RULES IT KEEPS.
 *
 * Nothing offered here can fail on the state the person is actually in. With
 * the plane off there is no button and no `claude mcp add` line at all, because
 * registering a server against a socket that does not exist teaches somebody
 * that this feature is broken. The switch comes first and everything else
 * appears after it.
 *
 * A bearer token is never drawn. The HTTP line carries the name of an
 * environment variable rather than the secret, and the token itself goes from
 * the shell to the clipboard without passing through React state, without
 * being rendered and without ever sitting in something a screenshot would
 * catch. See {@link CopyToken}.
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { classNames } from "../lib/util";
import { safeInvoke, writeClipboard } from "../lib/tauri";
import { AGENT_HTTP_TOKEN_COMMAND } from "../lib/agentActivity";
import {
  AGENT_BOUNDARY_WHY,
  AGENT_CAN,
  AGENT_CANNOT,
  AGENT_REGISTER_COMMAND,
  HTTP_DEFAULT_URL,
  binaryNote,
  doctorLine,
  httpAddLine,
  mcpAddLine,
  httpServeLine,
  needsManualSetup,
  parseRegisterResult,
  registerLine,
  registerTone,
  type RegisterResult,
} from "../lib/agentSetup";
import { useAgentActivity } from "../state/AgentActivityContext";
import { Dialog } from "./primitives";
import {
  IconAlert,
  IconCheck,
  IconChevronDown,
  IconChevronRight,
  IconClipboard,
  IconLock,
} from "./icons";

/** How long a copy button says it copied. Long enough to be seen, no longer. */
const COPIED_MS = 1600;

/** Which block was copied last, and whether the clipboard actually took it. */
interface Copied {
  key: string;
  ok: boolean;
}

/**
 * One "it copied" flag, shared by every button in the modal.
 *
 * Keyed rather than boolean, so pressing the second button takes the tick off
 * the first one: two blocks both claiming to be on the clipboard is the one
 * thing this feedback must not say.
 *
 * A refused clipboard says so. Silence after a press is the worst of the three
 * answers, because the person pastes and finds out later.
 */
function useCopied(): [Copied | null, (key: string, text: string) => void] {
  const [copied, setCopied] = useState<Copied | null>(null);
  const timer = useRef<number | null>(null);
  useEffect(() => () => {
    if (timer.current !== null) window.clearTimeout(timer.current);
  }, []);
  const copy = useCallback((key: string, text: string): void => {
    void writeClipboard(text).then((ok) => {
      setCopied({ key, ok });
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(null), ok ? COPIED_MS : COPIED_MS * 2);
    });
  }, []);
  return [copied, copy];
}

/** A line to paste, and the button that puts it on the clipboard. */
function CopyLine({
  text,
  copiedKey,
  copied,
  onCopy,
}: {
  text: string;
  copiedKey: string;
  copied: Copied | null;
  onCopy: (key: string, text: string) => void;
}): ReactNode {
  const mine = copied?.key === copiedKey ? copied : null;
  return (
    <div className="flex items-stretch gap-1.5 rounded-md border border-subtle bg-inset/60">
      {/*
        Wraps rather than scrolls, breaking anywhere it has to. A path is long
        exactly on the machines where getting it right matters, and half a
        command with the path cut off at the edge is the one thing somebody
        cannot check before they run it. There is a button for selecting it,
        so the only job left for the text is being readable.
      */}
      <code className="mono min-w-0 flex-1 px-2.5 py-2 text-2xs text-primary [overflow-wrap:anywhere]">
        {text}
      </code>
      <button
        type="button"
        onClick={() => onCopy(copiedKey, text)}
        aria-label={mine?.ok ? "Copied" : "Copy this line"}
        title="Copy"
        className={classNames(
          "flex shrink-0 items-center gap-1 rounded-r-md border-l border-subtle px-2.5 text-2xs font-medium",
          mine === null
            ? "text-secondary hover:bg-inset hover:text-primary"
            : mine.ok
              ? "text-success"
              : "text-warning",
        )}
      >
        {mine === null ? (
          <IconClipboard size={13} />
        ) : mine.ok ? (
          <IconCheck size={13} />
        ) : (
          <IconAlert size={13} />
        )}
        {/*
          Announced, because the tick is the only thing that changes and a
          person who cannot see it has pressed a button that did nothing.
        */}
        <span aria-live="polite">
          {mine === null ? "Copy" : mine.ok ? "Copied" : "Blocked"}
        </span>
      </button>
    </div>
  );
}

/**
 * Put the bearer token on the clipboard without anybody seeing it.
 *
 * The token is fetched when the button is pressed and dropped the moment it is
 * written, so it is never in state, never in the DOM and never in a re-render.
 * A shell that has no such command answers nothing, which is not an error and
 * is not treated as one: the line underneath says where to get it by hand.
 */
function CopyToken(): ReactNode {
  const [said, setSaid] = useState<"copied" | "unavailable" | null>(null);
  const timer = useRef<number | null>(null);
  useEffect(() => () => {
    if (timer.current !== null) window.clearTimeout(timer.current);
  }, []);

  const grab = useCallback((): void => {
    void safeInvoke<string | null>(AGENT_HTTP_TOKEN_COMMAND, undefined, null).then(
      async (token) => {
        const ok = typeof token === "string" && token.length > 0
          ? await writeClipboard(token)
          : false;
        setSaid(ok ? "copied" : "unavailable");
        if (timer.current !== null) window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setSaid(null), COPIED_MS * 2);
      },
    );
  }, []);

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={grab}
        className="btn-secondary text-2xs"
        title="The token goes straight to the clipboard. It is never shown here."
      >
        Copy the token
      </button>
      <span
        className={classNames(
          "text-2xs",
          said === "unavailable" ? "text-warning" : "text-tertiary",
        )}
        aria-live="polite"
      >
        {said === "copied"
          ? "On the clipboard. Paste it into the prompt above."
          : said === "unavailable"
            ? "This build will not hand it over. Read it from dvv doctor instead."
            : "It is never shown here, only copied."}
      </span>
    </div>
  );
}

function Step({
  n,
  title,
  children,
}: {
  n: number;
  title: string;
  children: ReactNode;
}): ReactNode {
  return (
    <section className="flex gap-2.5">
      <span
        aria-hidden="true"
        className="mono mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent/15 text-2xs font-medium text-accent"
      >
        {n}
      </span>
      <div className="min-w-0 flex-1 space-y-1.5">
        <h3 className="text-sm font-medium text-primary">{title}</h3>
        {children}
      </div>
    </section>
  );
}

/**
 * The one press, and everything it can come back with.
 *
 * Five answers, five sentences, and not one of them is silence. A button that
 * appears to do nothing is worse than the paste it replaced, because at least
 * a paste fails in a terminal where a person can read why. Three of the five
 * leave something to do by hand, and those three open the fold below rather
 * than mentioning it and leaving the reader to go looking.
 */
function Register({ onFallback }: { onFallback: () => void }): ReactNode {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<RegisterResult | null>(null);
  const alive = useRef(true);
  useEffect(() => () => {
    alive.current = false;
  }, []);

  const run = useCallback((): void => {
    setBusy(true);
    // `safeInvoke` rather than `mustInvoke`: a build without this command
    // answers null, which parses to `unsupported` and sends the reader to the
    // lines below. A thrown error here would be a modal with nothing in it.
    void safeInvoke<unknown>(AGENT_REGISTER_COMMAND, undefined, null).then((raw) => {
      if (!alive.current) return;
      const parsed = parseRegisterResult(raw);
      setBusy(false);
      setResult(parsed);
      if (needsManualSetup(parsed.outcome)) onFallback();
    });
  }, [onFallback]);

  const tone = result ? registerTone(result.outcome) : null;

  return (
    <section className="rounded-lg border border-accent/40 bg-accent/10 p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-primary">Connect Claude Code</h3>
          <p className="mt-0.5 text-xs text-secondary">
            This registers the server for you. No terminal, nothing to copy.
          </p>
        </div>
        <button
          type="button"
          data-autofocus
          disabled={busy}
          className={classNames("btn-primary shrink-0", busy && "opacity-70")}
          onClick={run}
        >
          {/*
            "Try again" only where trying again is the thing to do. Offering it
            after a success invites somebody to press a button that has already
            worked, and then to wonder whether the second press undid it.
          */}
          {busy ? "Connecting…" : result && needsManualSetup(result.outcome) ? "Try again" : "Connect"}
        </button>
      </div>
      {/*
        Always mounted, so a screen reader announces the answer rather than the
        arrival of a new region it has never seen.
      */}
      <div role="status" aria-live="polite" className="empty:hidden">
        {result === null ? null : (
          <div
            className={classNames(
              "mt-3 flex items-start gap-2 rounded-md px-2.5 py-2 text-xs",
              tone === "success"
                ? "bg-success-subtle text-success"
                : tone === "info"
                  ? "bg-inset text-secondary"
                  : "bg-warning-subtle text-warning",
            )}
          >
            <span className="mt-px shrink-0">
              {tone === "warning" ? <IconAlert size={14} /> : <IconCheck size={14} />}
            </span>
            <span className="min-w-0 [overflow-wrap:anywhere]">{registerLine(result)}</span>
          </div>
        )}
      </div>
    </section>
  );
}

/**
 * What an agent can do, and the one thing it will not.
 *
 * Four to one rather than a balanced pair of columns, because that is the
 * shape of the truth now and a two column grid would have to pad the short
 * side to keep looking symmetrical. The boundary gets a lock and its reason,
 * so it reads as a property of the product rather than as a to-do.
 */
function Limits(): ReactNode {
  return (
    <div className="space-y-3 border-t border-subtle pt-4">
      <div>
        <p className="mb-1.5 text-2xs font-semibold uppercase tracking-wider text-tertiary">
          What an agent can do
        </p>
        <ul className="space-y-1">
          {AGENT_CAN.map((line) => (
            <li key={line} className="flex gap-2 text-xs text-secondary">
              <span
                aria-hidden="true"
                className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-success"
              />
              <span>{line}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="flex gap-2.5 rounded-md bg-inset px-3 py-2.5">
        <span aria-hidden="true" className="mt-px shrink-0 text-tertiary">
          <IconLock size={14} />
        </span>
        <div className="min-w-0 space-y-0.5">
          {AGENT_CANNOT.map((line) => (
            <p key={line} className="text-xs font-medium text-primary">
              {line}
            </p>
          ))}
          <p className="text-2xs text-tertiary">{AGENT_BOUNDARY_WHY}</p>
        </div>
      </div>
    </div>
  );
}

/**
 * Everything a terminal is needed for, folded away.
 *
 * Shut by default and opened by the two things that should open it: somebody
 * asking, and the button failing. Most people will never see inside it, which
 * is the point of putting it here rather than on the way in.
 */
function ManualSetup({
  binary,
  httpUrl,
  open,
  onToggle,
  copied,
  onCopy,
}: {
  binary: string | null;
  httpUrl: string | null;
  open: boolean;
  onToggle: () => void;
  copied: Copied | null;
  onCopy: (key: string, text: string) => void;
}): ReactNode {
  const note = binaryNote(binary);
  // No rule above it deliberately. The footer below draws one and the limits
  // above draw one, and a third between two short rows would make the fold
  // look like a section of its own rather than the footnote it is.
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls="agent-manual"
        className="flex items-center gap-1 text-xs font-medium text-secondary hover:text-primary"
      >
        <span aria-hidden="true">
          {open ? <IconChevronDown size={13} /> : <IconChevronRight size={13} />}
        </span>
        Do it by hand, or connect a different agent
      </button>
      {open ? (
        <div id="agent-manual" className="mt-3.5 space-y-4">
          <Step n={1} title="Register it yourself">
            <CopyLine
              text={mcpAddLine(binary)}
              copiedKey="stdio"
              copied={copied}
              onCopy={onCopy}
            />
            {/*
              The path is the whole difficulty of this line, and in an
              installed build there is no difficulty left: the plane reports
              where `dvv` is and the line above is complete. The note appears
              only when it truthfully cannot, which is a development build that
              has not built the binary, and it says so rather than leaving
              somebody staring at a placeholder wondering whose fault it is.
            */}
            {note ? <p className="text-xs text-tertiary">{note}</p> : null}
          </Step>

          {/*
            Always offered, never conditional on the plane reporting a URL.
            The HTTP server lives in the `dvv` process and is started by the
            person reading this, so the shell has no way to know whether one
            is listening or where. Hiding this until it could say would hide
            it forever, and somebody who needs HTTP (a hosted assistant, a
            container, anything that cannot spawn a subprocess) would never
            learn it exists.
          */}
          <Step n={2} title="Or reach it over HTTP">
            <CopyLine
              text={httpServeLine(binary)}
              copiedKey="http-serve"
              copied={copied}
              onCopy={onCopy}
            />
            <p className="text-xs text-tertiary">
              Starts a listener on <code className="mono">{HTTP_DEFAULT_URL}</code> and prints
              the line below with your token already in it. Loopback only, and it needs the
              token even there, because any page your browser has open can reach a port on
              this machine.
            </p>
            <CopyLine
              text={httpAddLine(httpUrl ?? HTTP_DEFAULT_URL)}
              copiedKey="http"
              copied={copied}
              onCopy={onCopy}
            />
            <CopyToken />
          </Step>

          <Step n={3} title="Check it">
            <CopyLine
              text={doctorLine(binary)}
              copiedKey="doctor"
              copied={copied}
              onCopy={onCopy}
            />
            <p className="text-xs text-tertiary">
              It prints the socket path and whether it is present. Present means this
              application is running with the plane on, which is what an agent needs.
            </p>
          </Step>
        </div>
      ) : null}
    </div>
  );
}

export function AgentConnect({ onClose }: { onClose: () => void }): ReactNode {
  const { plane, setPlaneEnabled } = useAgentActivity();
  const [copied, copy] = useCopied();
  const [manual, setManual] = useState(false);
  const openManual = useCallback(() => setManual(true), []);

  return (
    <Dialog title="AI agents" onClose={onClose} width={620}>
      <div className="space-y-5">
        {plane.on ? (
          <>
            <Register onFallback={openManual} />

            <p className="text-xs text-secondary">
              Then ask your agent to open one of your machines by name. It reads the same
              library you see here.
            </p>

            <Limits />

            <ManualSetup
              binary={plane.binary}
              httpUrl={plane.httpUrl}
              open={manual}
              onToggle={() => setManual((v) => !v)}
              copied={copied}
              onCopy={copy}
            />

            <div className="flex items-center justify-between gap-4 border-t border-subtle pt-4">
              <div className="min-w-0">
                <p className="text-xs text-secondary">The plane is on.</p>
                {plane.socket ? (
                  <p className="mono truncate text-2xs text-tertiary" title={plane.socket}>
                    {plane.socket}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                className="btn-secondary shrink-0"
                onClick={() => setPlaneEnabled(false)}
                title="Close the socket and unlink it. Every agent loses its connection at once."
              >
                Turn it off
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="text-sm text-secondary">
              An agent can open your machines, drive them and read the screen, while you
              watch and take over whenever you want.
            </p>
            <p className="text-sm text-secondary">
              None of it exists until you switch it on. With the plane off there is no socket,
              nothing is listening, and this application behaves exactly as it does now.
            </p>
            {plane.error ? (
              <p className="rounded-md border border-warning bg-warning-subtle px-3 py-2 text-xs text-warning">
                The last attempt to start it failed: {plane.error}
              </p>
            ) : null}
            <div className="flex items-center gap-3">
              <button
                type="button"
                data-autofocus
                className="btn-primary"
                onClick={() => setPlaneEnabled(true)}
              >
                Turn on the agent plane
              </button>
              <span className="text-xs text-tertiary">
                One socket, on this computer only. Nothing opens on the network.
              </span>
            </div>
            {/*
              Deliberately no button and no commands here. Registering a server
              against a socket that does not exist teaches somebody that this
              feature does not work, and a button that cannot succeed is worse
              than no button. Both appear the moment the switch above takes.
            */}
            <Limits />
          </>
        )}
      </div>
    </Dialog>
  );
}
