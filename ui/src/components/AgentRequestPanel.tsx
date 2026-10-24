/**
 * The one panel where a person answers agents asking for a machine they are
 * using.
 *
 * Not a dialog. It sits in the bottom right corner of the window, takes no
 * keyboard focus when it appears, and keeps focus where it was when one of
 * its buttons is pressed (the pointer down is not allowed to move focus), so
 * a person typing into a session can keep typing while it is on screen. It
 * lists every waiting agent on every machine and is redrawn from the latest
 * list the shell sent, so a second agent asking adds a row and never a second
 * panel. With nobody waiting it is gone; while requests are muted it shrinks
 * to a small badge.
 *
 * The words are all in `TEXT` in `../lib/agentRequests`.
 */

import { useState, type ReactNode, type SyntheticEvent } from "react";
import {
  TEXT,
  machineName,
  secondsUntil,
  waitedFor,
  type AgentRequest,
  type RequestsState,
} from "../lib/agentRequests";
import { classNames } from "../lib/util";

export interface AgentRequestPanelProps {
  state: RequestsState;
  now: number;
  /** The title of the tab showing this session, if any. */
  titleOf: (sessionId: string) => string | null;
  /** One request when both ids are given, every request when neither is. */
  onAllow: (sessionId?: string, attachmentId?: string) => void;
  onNotNow: (sessionId?: string, attachmentId?: string) => void;
  /** Minutes, or null for "until I take my hands off". */
  onMute: (minutes: number | null) => void;
  onUnmute: () => void;
}

/** Keep focus where it is: the person may be typing into a session. */
const keepFocus = (e: SyntheticEvent): void => e.preventDefault();

function Button({
  children,
  onClick,
  title,
  strong,
}: {
  children: ReactNode;
  onClick: () => void;
  title?: string;
  strong?: boolean;
}): ReactNode {
  return (
    <button
      type="button"
      onPointerDown={keepFocus}
      onMouseDown={keepFocus}
      onClick={onClick}
      title={title}
      className={classNames(
        "shrink-0 rounded-sm px-1.5 py-0.5 text-2xs",
        strong
          ? "bg-accent text-accent-fg hover:opacity-90"
          : "border border-subtle text-primary hover:bg-raised",
      )}
    >
      {children}
    </button>
  );
}

function Row({
  request,
  now,
  titleOf,
  onAllow,
  onNotNow,
}: {
  request: AgentRequest;
  now: number;
  titleOf: (sessionId: string) => string | null;
  onAllow: AgentRequestPanelProps["onAllow"];
  onNotNow: AgentRequestPanelProps["onNotNow"];
}): ReactNode {
  return (
    <li
      className="flex flex-col gap-1 border-t border-subtle py-1.5 first:border-t-0"
      data-request={`${request.sessionId}:${request.attachmentId}`}
    >
      <div className="flex min-w-0 items-baseline gap-1 text-2xs">
        <span className="truncate font-medium text-primary" title={request.agent}>
          {request.agent}
        </span>
        <span className="shrink-0 truncate text-secondary">
          {TEXT.onMachine(machineName(request, titleOf))}
        </span>
      </div>
      {request.reason ? (
        <p className="line-clamp-2 text-2xs text-secondary" title={request.reason}>
          “{request.reason}”
        </p>
      ) : null}
      <div className="flex items-center gap-1 text-2xs text-tertiary">
        <span>{TEXT.waited(waitedFor(request.askedAt, now))}</span>
        {request.freesAt !== null ? (
          <span className="truncate" data-countdown>
            , {TEXT.countdown(secondsUntil(request.freesAt, now))}
          </span>
        ) : null}
      </div>
      <div className="flex gap-1">
        <Button
          strong
          title={TEXT.allowTitle}
          onClick={() => onAllow(request.sessionId, request.attachmentId)}
        >
          {TEXT.allow}
        </Button>
        <Button
          title={TEXT.notNowTitle}
          onClick={() => onNotNow(request.sessionId, request.attachmentId)}
        >
          {TEXT.notNow}
        </Button>
      </div>
    </li>
  );
}

export function AgentRequestPanel(props: AgentRequestPanelProps): ReactNode {
  const { state, now, titleOf, onAllow, onNotNow, onMute, onUnmute } = props;
  const [choosing, setChoosing] = useState(false);

  if (state.muted) {
    return (
      <div
        role="status"
        aria-live="polite"
        data-agent-requests="muted"
        className="fixed right-3 bottom-3 z-40 flex items-center gap-1.5 rounded-md border border-subtle bg-surface px-2 py-1 text-2xs text-secondary shadow"
      >
        <span>{TEXT.mutedUntil(state.muted)}</span>
        {state.muted.waiting > 0 ? (
          <span className="text-tertiary">({TEXT.mutedWaiting(state.muted.waiting)})</span>
        ) : null}
        <Button onClick={onUnmute}>{TEXT.unmute}</Button>
      </div>
    );
  }

  if (state.requests.length === 0) return null;
  const many = state.requests.length > 1;

  return (
    <section
      aria-label={TEXT.heading(state.requests.length)}
      data-agent-requests="open"
      className="fixed right-3 bottom-3 z-40 flex max-h-[60vh] w-80 flex-col rounded-md border border-subtle bg-surface px-2.5 py-2 shadow-lg"
    >
      <h2 className="text-2xs font-semibold text-primary">
        {TEXT.heading(state.requests.length)}
      </h2>
      <ul className="mt-1 min-h-0 overflow-y-auto">
        {state.requests.map((request) => (
          <Row
            key={`${request.sessionId}:${request.attachmentId}`}
            request={request}
            now={now}
            titleOf={titleOf}
            onAllow={onAllow}
            onNotNow={onNotNow}
          />
        ))}
      </ul>
      <div className="mt-1.5 flex flex-wrap items-center gap-1 border-t border-subtle pt-1.5">
        {many ? (
          <>
            <Button onClick={() => onAllow()}>{TEXT.allowAll}</Button>
            <Button onClick={() => onNotNow()}>{TEXT.notNowAll}</Button>
          </>
        ) : null}
        {choosing ? (
          <div className="flex flex-wrap items-center gap-1" data-mute-choices>
            <span className="text-2xs text-secondary">{TEXT.muteFor}</span>
            {TEXT.muteChoices.map((choice) => (
              <Button
                key={choice.label}
                onClick={() => {
                  setChoosing(false);
                  onMute(choice.minutes);
                }}
              >
                {choice.label}
              </Button>
            ))}
          </div>
        ) : (
          <Button onClick={() => setChoosing(true)}>{TEXT.mute}</Button>
        )}
      </div>
    </section>
  );
}
