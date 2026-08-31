/**
 * Every machine an agent is driving, at once.
 *
 * WHERE THIS LIVES, AND WHY IT IS A STRIP ALONG THE BOTTOM.
 *
 * Three constraints decided it, and between them they rule out the other three
 * shapes this could have taken.
 *
 * It has to show every limb, not the ones in front. The pane grid only draws
 * the tab that is selected, and an agent driving eight machines will have them
 * spread across tabs; a limb the plane holds may not be mounted in this window
 * at all. So an overlay drawn on the grid can only ever show a subset of the
 * work, which is the one thing this view exists to avoid. That rules out the
 * overlay.
 *
 * It has to be there when nobody is touching anything. `SessionToolbar` fades
 * to a chevron after three seconds of no interaction, which is exactly the
 * condition an unattended agent works under (`PRDAgentPlug/10` ruling W5-22).
 * That rules out putting it in the toolbar, and it rules out hover to reveal.
 *
 * It has to cost nothing when the plane is off. A side panel takes width from
 * the widest pane and would have to be collapsible, which means a control, a
 * remembered state and a way to hide the thing that must not hide. A strip that
 * is simply not rendered until a lease is held takes zero height, has no
 * setting, and appears the way the tab strip appears when the first session
 * connects.
 *
 * So: a strip, along the bottom, one card per driven limb, present only while
 * an agent holds something. It reads like a row of machines rather than a list
 * of events, which is the difference between watching and reading a log.
 *
 * UNTRUSTED CONTENT. A card can quote what the far side printed. That text is
 * data and never instruction (`AGENT_BRIEF` D6): it arrives already neutralised
 * through `sanitizeRemoteText`, it is rendered as a text node and never as
 * markup, it is drawn in a quoted, monospace, muted style that no chrome of
 * ours uses, and it carries a label naming the surface it came off. See
 * {@link RemoteQuote}.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { classNames } from "../lib/util";
import {
  holderLabel,
  planeStatusDetail,
  planeStatusLine,
  remoteLabel,
  type AgentActivity,
  type AgentIntent,
  type IntentOutcome,
  type RemoteText,
} from "../lib/agentActivity";
import {
  PREF_CHANGED_EVENT,
  PREF_HIDE_AGENT_STATUS,
  readBoolPref,
  type PrefChanged,
} from "../lib/prefs";
import { useAgentActivity } from "../state/AgentActivityContext";
import { IconMonitor, IconStop, IconTerminal } from "./icons";

/**
 * A clock local to this component.
 *
 * The ages on the cards have to move for the strip to read as live, and this
 * is the only thing that wants a tick. Keeping it here rather than in the
 * context means a pane grid of twelve does not re-render once a second while
 * an agent quietly works.
 */
function useSecondsTick(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const iv = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(iv);
  }, [active]);
  return now;
}

/**
 * Does this person want the counts?
 *
 * Read on mount and then followed, rather than read on use like most of
 * `lib/prefs`: this is chrome that is already on screen when the switch is
 * flipped, and Preferences shares this window with it, so it has to change
 * under the person who changed it. `PREF_CHANGED_EVENT` is that push and it is
 * window local, which is all this needs.
 */
function useStatusHidden(): boolean {
  const [hidden, setHidden] = useState(() => readBoolPref(PREF_HIDE_AGENT_STATUS, false));
  useEffect(() => {
    const onChange = (e: Event): void => {
      const detail = (e as CustomEvent<PrefChanged>).detail;
      if (detail?.key === PREF_HIDE_AGENT_STATUS) setHidden(detail.value);
    };
    window.addEventListener(PREF_CHANGED_EVENT, onChange);
    return () => window.removeEventListener(PREF_CHANGED_EVENT, onChange);
  }, []);
  return hidden;
}

/** Short and absolute, so a glance reads it: "4s", "1m 20s". */
function age(from: number, now: number): string {
  if (!from) return "";
  const s = Math.max(0, Math.round((now - from) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function outcomeStyle(outcome: IntentOutcome): { className: string; label: string } {
  switch (outcome) {
    case "in-flight":
      return { className: "bg-accent/15 text-accent", label: "in flight" };
    case "accepted":
      return { className: "bg-success-subtle text-success", label: "accepted" };
    case "refused":
      return { className: "bg-warning-subtle text-warning", label: "refused" };
    case "failed":
      return { className: "bg-danger-subtle text-danger", label: "failed" };
    default:
      // The plane said something we do not read. Say so, rather than picking
      // whichever of the four would look tidiest.
      return { className: "bg-inset text-tertiary", label: "unread" };
  }
}

/**
 * Something a remote machine printed, quoted as evidence and never as chrome.
 *
 * The styling is doing safety work rather than decoration. It is monospace,
 * muted, indented behind a rule and wrapped in quotation marks, so a line the
 * far side wrote can never be mistaken for a line we wrote, however carefully
 * it is composed to look like one. `dir="ltr"` with an isolate keeps a
 * residual right to left run from reordering the label beside it, on top of
 * the bidirectional control characters already stripped on the way in.
 */
function RemoteQuote({ remote }: { remote: RemoteText }): ReactNode {
  return (
    <div className="flex min-w-0 items-baseline gap-1.5 border-l border-strong pl-1.5">
      <span className="shrink-0 text-[9px] uppercase tracking-wide text-tertiary">
        {remoteLabel(remote)}
      </span>
      {/*
        The quotation marks are drawn OUTSIDE the box that truncates, so the
        closing one cannot be pushed off the end by a long enough line. A
        boundary marker that the content can shift out of view is not a
        boundary marker, which is the same reasoning that puts a nonce on the
        plane's own untrusted delimiters (`00 R32`).
      */}
      <span className="flex min-w-0 items-baseline">
        <span aria-hidden="true" className="mono shrink-0 text-2xs text-tertiary">“</span>
        <span
          dir="ltr"
          // React renders this as a text node. It is never passed to
          // `dangerouslySetInnerHTML`, and nothing downstream reads it back as
          // an instruction to anything.
          style={{ unicodeBidi: "isolate" }}
          className="mono min-w-0 truncate text-2xs text-secondary"
          title={remote.text}
        >
          {remote.text}
        </span>
        <span aria-hidden="true" className="mono shrink-0 text-2xs text-tertiary">”</span>
      </span>
    </div>
  );
}

/** The intent line, and what became of it. */
function IntentRow({ intent }: { intent: AgentIntent | null }): ReactNode {
  if (!intent) {
    return <p className="truncate text-2xs text-tertiary">Holding the lease, nothing in flight</p>;
  }
  const outcome = outcomeStyle(intent.outcome);
  return (
    <div className="flex min-w-0 items-center gap-1.5">
      <span
        className={classNames(
          "shrink-0 rounded-pill px-1.5 py-px text-[9px] font-medium",
          outcome.className,
        )}
      >
        {outcome.label}
      </span>
      <span className="mono shrink-0 truncate text-2xs text-primary" title={intent.kind}>
        {intent.kind}
      </span>
      {intent.summary ? (
        // The summary gives way first. What was asked for matters more than the
        // arguments it was asked with, and a line reading "pointer.cl… (612,
        // 448)" has kept the half nobody needed.
        <span className="mono min-w-0 flex-1 truncate text-right text-2xs text-tertiary">
          {intent.summary}
        </span>
      ) : null}
    </div>
  );
}

function Card({
  entry,
  now,
  onGo,
  onStop,
}: {
  entry: AgentActivity;
  now: number;
  onGo: () => void;
  onStop: () => void;
}): ReactNode {
  const holder = entry.holder;
  const driven = holder?.kind === "agent";
  const label = entry.machine?.label ?? entry.sessionId;
  const inFlight = entry.intent?.outcome === "in-flight";

  return (
    <div
      className={classNames(
        // Fixed width, not content width: a row of cards that each sized
        // themselves would change shape every time a machine did something,
        // and the whole point of the ordering is that a card stays put.
        "relative flex w-64 shrink-0 flex-col gap-1 overflow-hidden rounded-md border bg-surface px-2.5 py-1.5",
        driven ? "border-subtle" : "border-accent/50",
      )}
    >
      {/*
        The left edge is the card's pulse. A solid bar means the lease is held
        and idle; a breathing one means an intent is actually on the wire. It is
        the one moving thing on a card, which is what lets a row of twelve be
        read in a second.
      */}
      <span
        aria-hidden="true"
        className={classNames(
          "absolute inset-y-0 left-0 w-0.5",
          driven ? "bg-warning" : "bg-accent",
          inFlight && "animate-pulse",
        )}
      />

      <div className="flex min-w-0 items-center gap-1.5">
        <span
          aria-hidden="true"
          className={classNames(
            "h-1.5 w-1.5 shrink-0 rounded-[1px]",
            driven ? "bg-warning" : "bg-accent",
          )}
        />
        <button
          type="button"
          onClick={onGo}
          className="min-w-0 flex-1 truncate text-left text-2xs font-medium text-primary hover:text-accent hover:underline"
          title={
            entry.machine
              ? `${entry.machine.address}:${entry.machine.port}`
              : "Show this machine"
          }
        >
          {label}
        </button>
        <span className="shrink-0 text-tertiary" aria-hidden="true">
          {entry.machine?.protocol === "ssh" ? <IconTerminal size={10} /> : <IconMonitor size={10} />}
        </span>
        <span className="mono shrink-0 text-[9px] tabular-nums text-tertiary">
          {age(holder?.since ?? entry.preempted?.at ?? 0, now)}
        </span>
        {driven ? (
          <button
            type="button"
            onClick={onStop}
            className="shrink-0 rounded-sm p-0.5 text-warning hover:bg-danger-subtle hover:text-danger"
            aria-label={`Stop the agent driving ${label}, and take control`}
            title={`Stop ${holderLabel(holder)} and take control`}
          >
            <IconStop size={11} />
          </button>
        ) : null}
      </div>

      <p
        className={classNames(
          "truncate text-2xs",
          driven ? "text-secondary" : "font-medium text-accent",
        )}
        title={holder?.capability ? `Capability: ${holder.capability}` : undefined}
      >
        {driven
          ? holderLabel(holder)
          : entry.preempted
            ? `You took the wheel from ${entry.preempted.agent}`
            : holderLabel(holder)}
      </p>

      {driven ? (
        // Keyed by the intent so each new one fades in. A card that changed
        // silently would be a card nobody notices changing.
        <div key={entry.intent?.id ?? "idle"} className="fade-in flex min-w-0 flex-col gap-1">
          <IntentRow intent={entry.intent} />
          {entry.intent?.remote ? <RemoteQuote remote={entry.intent.remote} /> : null}
        </div>
      ) : (
        <p className="truncate text-2xs text-tertiary">Input is yours, the agent was stopped</p>
      )}
    </div>
  );
}

export function AgentWall({
  onShowSession,
}: {
  /** Bring the pane holding this session forward. */
  onShowSession: (sessionId: string) => void;
}): ReactNode {
  const { wall, count, plane, stopAgent, stopAll } = useAgentActivity();
  const now = useSecondsTick(wall.length > 0);
  const scroller = useRef<HTMLDivElement>(null);
  const hidden = useStatusHidden();

  /**
   * The counts live HERE rather than in a second surface of their own.
   *
   * This strip is already the agent surface: it is outside the tabs, it is
   * there when nobody is touching anything, and it costs no height until there
   * is something to say. A status bar somewhere else would be a second thing
   * to find, a second thing to hide, and two places that could disagree about
   * the same three numbers.
   *
   * So the strip's headline IS the status bar. It appears as soon as the plane
   * is on, with or without a card under it, which is the case the old headline
   * could not cover: an agent attached and driving nothing was a strip that
   * rendered nothing at all.
   */
  const showStatus = plane.on && !hidden;
  const headline = useMemo(
    () => (showStatus ? planeStatusLine(plane) : "Agent activity"),
    [showStatus, plane],
  );

  // Nothing at all with the plane off, and nothing when a person has put the
  // counts away and no agent is driving. This is what "the interactive product
  // does not regress" looks like in a component: no strip, no border, and no
  // height taken from the panes.
  if (wall.length === 0 && !showStatus) return null;

  return (
    <div
      className="fade-in flex shrink-0 flex-col gap-1 border-t border-subtle bg-inset/60 px-2 py-1.5"
      // Announced, but not interrupting: a person watching this is looking at
      // it, and a person who is not should not have their work read over.
      role="region"
      aria-label="Agent activity"
    >
      <div className="flex items-center gap-2 px-0.5">
        <span
          aria-hidden="true"
          className={classNames(
            "h-1.5 w-1.5 shrink-0 rounded-[1px]",
            // The plane's own number rather than this window's, so the dot and
            // the sentence beside it can never disagree.
            plane.driving > 0 ? "bg-warning" : "bg-tertiary",
          )}
        />
        {/*
          Tabular figures, because this line changes while it is being read and
          a proportional "1" would shuffle the words either side of it every
          time a machine was taken or given back.
        */}
        <h2
          className="text-2xs font-medium tabular-nums text-secondary"
          aria-live="polite"
          title={showStatus ? planeStatusDetail(plane) : undefined}
        >
          {headline}
        </h2>
        <span className="flex-1" />
        {count > 0 ? (
          <button
            type="button"
            onClick={stopAll}
            className="shrink-0 rounded-sm px-1.5 py-0.5 text-2xs font-medium text-warning hover:bg-danger-subtle hover:text-danger"
            // Says what it does to all of them, because a person reaching for
            // this on a wall of twelve is not reading carefully.
            title="Take every lease back from every agent, at once"
          >
            Stop all
          </button>
        ) : null}
      </div>

      {/*
        No cards, no row: with the plane on and nothing being driven the strip
        is one line of text, and an empty scroller would leave a few pixels of
        nothing under it for as long as that lasted.
      */}
      {wall.length > 0 ? (
        <div
          ref={scroller}
          // Horizontal rather than wrapping: a row that reflows moves cards
          // between lines as machines come and go, and the point of the ordering
          // in `wallEntries` is that a card stays where a person left it.
          className="flex gap-1.5 overflow-x-auto pb-0.5"
        >
          {wall.map((entry) => (
            <Card
              key={entry.sessionId}
              entry={entry}
              now={now}
              onGo={() => onShowSession(entry.sessionId)}
              onStop={() => stopAgent(entry.sessionId)}
            />
          ))}
        </div>
      ) : null}
    </div>
  );
}
