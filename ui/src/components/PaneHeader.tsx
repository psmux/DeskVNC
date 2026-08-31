/**
 * The strip along the top of a pane, once a tab holds more than one.
 *
 * It answers three questions a split otherwise leaves open: which machine is
 * this, which pane has the keyboard, and how do I move it. A single pane shows
 * none of this and stays full bleed, exactly as it did before splits existed.
 *
 * Dragging it swaps two panes rather than re-flowing the layout around a drop
 * point. Swapping is the operation the tree already has (`swapPanes`), it keeps
 * both boxes exactly where they are so nothing else on screen jumps, and it has
 * an obvious meaning when the target is occupied, which "insert here" does not.
 *
 * It answers a fourth question once the agent plane is on: is something else
 * driving this machine, what is it doing, and how do I stop it. That belongs
 * here rather than on the session toolbar because this strip never auto hides
 * and the toolbar does (`PRDAgentPlug/10` ruling W5-22). Everything below is
 * inert until a lease is actually held, so a person who never turns the plane
 * on sees the strip they have always seen.
 */
import { type ReactNode } from "react";
import { classNames } from "../lib/util";
import type { ProtocolKind, SessionState } from "../lib/types";
import {
  drivenByAgent,
  holderLabel,
  intentLine,
  type AgentActivity,
} from "../lib/agentActivity";
import {
  IconGripVertical, IconMaximize, IconMinimize, IconMonitor, IconStop, IconTerminal, IconX,
} from "./icons";

/** How tall the strip is. Taken out of the session's area, so it is modest. */
export const PANE_HEADER_PX = 24;

/** Same colours the tab strip uses, so one connection reads the same everywhere. */
function statusDot(state: SessionState): string {
  switch (state.state) {
    case "connected":
      return "bg-success";
    case "disconnected":
      return "bg-danger";
    case "reconnecting":
      return "bg-warning animate-pulse";
    default:
      return "bg-accent animate-pulse";
  }
}

export function PaneHeader({
  title,
  protocol,
  state,
  focused,
  dragging,
  dropTarget,
  zoomed,
  agent = null,
  onStopAgent,
  onZoom,
  onClose,
  onPointerDown,
}: {
  title: string;
  /** Absent for an empty pane, which has no machine to name. */
  protocol: ProtocolKind | null;
  state: SessionState | null;
  focused: boolean;
  /** This pane is the one being dragged. */
  dragging: boolean;
  /** Dropping here would swap with the pane being dragged. */
  dropTarget: boolean;
  /** This pane is filling the whole tab. */
  zoomed: boolean;
  /**
   * Who holds this session's lease and what they have in flight, or null.
   *
   * Null for every pane until the agent plane is switched on and something
   * takes a lease, and the strip then looks exactly as it did before any of
   * this existed.
   */
  agent?: AgentActivity | null;
  /** Take the lease. Only reachable while an agent holds it. */
  onStopAgent?: () => void;
  onZoom: () => void;
  onClose: () => void;
  onPointerDown: (e: React.PointerEvent) => void;
}): ReactNode {
  const driven = drivenByAgent(agent ?? undefined);
  const intent = driven ? (agent?.intent ?? null) : null;
  // The handover survives the agent leaving the lease, which is the moment it
  // has to be readable: "the robot stopped" and "I stopped the robot" are two
  // different things and a person must never have to guess which happened.
  const handover = !driven && agent?.preempted ? agent.preempted.agent : null;
  const flight = intentLine(intent);
  const holder = agent?.holder ?? null;

  return (
    <div
      className={classNames(
        "flex shrink-0 items-center gap-1.5 border-b border-subtle px-1.5 select-none",
        focused ? "bg-raised" : "bg-inset",
        dropTarget && "bg-accent/25",
        dragging && "opacity-50",
      )}
      style={{ height: PANE_HEADER_PX, cursor: dragging ? "grabbing" : "grab" }}
      onPointerDown={onPointerDown}
      // The usual gesture for "make this one big", and the way back.
      onDoubleClick={onZoom}
    >
      <span className="text-tertiary" aria-hidden="true">
        <IconGripVertical size={12} />
      </span>
      {state ? (
        <span
          aria-hidden="true"
          className={classNames("h-1.5 w-1.5 shrink-0 rounded-full", statusDot(state))}
        />
      ) : null}
      {/*
        The agent badge, and it is a SQUARE rather than a recoloured dot.

        The dot beside it is already spoken for: its colour means connection
        state, and it means the same thing here and in `TabStrip`, deliberately,
        so that one connection reads the same everywhere. Recolouring it for an
        agent would break that in two files at once. Two circles and a square
        reads as "connected, and something is driving it" with no legend, and it
        survives being one of twelve at a glance, which is the whole
        requirement (`10` §2.2).

        It pulses only while an intent is actually in flight, so a wall of
        twelve panes shows which four are working rather than which four are
        merely claimed.
      */}
      {driven ? (
        <span
          aria-hidden="true"
          title={holderLabel(holder)}
          className={classNames(
            "h-1.5 w-1.5 shrink-0 rounded-[1px] bg-warning",
            intent?.outcome === "in-flight" && "animate-pulse",
          )}
        />
      ) : null}
      <span className="shrink-0 text-tertiary" aria-hidden="true">
        {protocol === "ssh" ? <IconTerminal size={11} /> : <IconMonitor size={11} />}
      </span>
      <span
        className={classNames(
          "min-w-0 truncate text-2xs",
          // The machine name gives up room to the intent line while an agent is
          // driving, and only then. In a narrow pane you already know which
          // machine this is from where it sits; what you do not know is what is
          // being done to it.
          driven || handover ? "max-w-[45%] shrink" : "flex-1",
          focused ? "text-primary" : "text-secondary",
        )}
      >
        {title}
      </span>

      {/*
        One line, replaced, never a log and never scrollable (`10` §2.4).

        It lives here rather than on the session toolbar because the toolbar
        fades to a chevron after three seconds of nobody touching anything,
        which is precisely the condition an unattended agent works under. This
        strip is 24 pixels and it never hides.
      */}
      {handover ? (
        <span
          className="fade-in min-w-0 flex-1 truncate text-2xs font-medium text-accent"
          title={`You took the wheel from ${handover}`}
        >
          You took the wheel from {handover}
        </span>
      ) : flight ? (
        <span
          // Keyed by the intent, so each new one fades in rather than swapping
          // silently. On a wall of twelve that flicker is the only cue that
          // anything moved at all.
          key={intent?.id}
          className="fade-in mono min-w-0 flex-1 truncate text-2xs text-tertiary"
          title={`${holderLabel(holder)}: ${flight}`}
        >
          {flight}
        </span>
      ) : null}

      {/*
        Stop, and it means stopped rather than asked to stop.

        There is no busy state and nothing to wait out: pressing it writes the
        revoked state before the shell is told, so the button disappears with
        the badge on the same frame as the click (`00 R13`).
      */}
      {driven && onStopAgent ? (
        <button
          type="button"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={onStopAgent}
          className="shrink-0 rounded-sm p-0.5 text-warning hover:bg-danger-subtle hover:text-danger"
          aria-label={`Stop the agent driving ${title}, and take control`}
          title={`Stop ${holderLabel(holder)} and take control`}
        >
          <IconStop size={11} />
        </button>
      ) : null}
      <button
        type="button"
        onPointerDown={(e) => e.stopPropagation()}
        onClick={onZoom}
        className="shrink-0 rounded-sm p-0.5 text-tertiary hover:bg-strong/25 hover:text-primary"
        aria-label={zoomed ? `Restore pane: ${title}` : `Maximise pane: ${title}`}
        title={zoomed ? "Restore this pane" : "Maximise this pane"}
      >
        {zoomed ? <IconMinimize size={11} /> : <IconMaximize size={11} />}
      </button>
      <button
        type="button"
        // Stop the press reaching the strip, or closing a pane would begin a
        // drag of the pane being closed.
        onPointerDown={(e) => e.stopPropagation()}
        onClick={onClose}
        className="shrink-0 rounded-sm p-0.5 text-tertiary hover:bg-strong/25 hover:text-primary"
        aria-label={`Close pane: ${title}`}
        title="Close this pane"
      >
        <IconX size={11} />
      </button>
    </div>
  );
}
