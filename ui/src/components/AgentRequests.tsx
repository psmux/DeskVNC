/**
 * [`AgentRequestPanel`] wired to the shell: seeded on mount, kept current from
 * the agent event, and with a clock that ticks once a second only while there
 * is something on screen to count.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AGENT_ACTIVITY_EVENT } from "../lib/agentActivity";
import {
  ANSWER_COMMAND,
  EMPTY_REQUESTS,
  MUTE_COMMAND,
  REQUESTS_COMMAND,
  UNMUTE_COMMAND,
  parseRequestsEvent,
  type RequestsState,
} from "../lib/agentRequests";
import { safeInvoke, safeListen } from "../lib/tauri";
import { useTabs } from "../state/TabsContext";
import { AgentRequestPanel } from "./AgentRequestPanel";

export function AgentRequests(): ReactNode {
  const [state, setState] = useState<RequestsState>(EMPTY_REQUESTS);
  const [now, setNow] = useState(() => Date.now());
  const { sessions } = useTabs();

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    void safeInvoke<unknown>(REQUESTS_COMMAND, undefined, null).then((raw) => {
      const seeded = parseRequestsEvent(raw);
      if (!cancelled && seeded) setState(seeded);
    });
    void safeListen<unknown>(AGENT_ACTIVITY_EVENT, (raw) => {
      const next = parseRequestsEvent(raw);
      if (!cancelled && next) setState(next);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const showing = state.requests.length > 0 || state.muted !== null;
  useEffect(() => {
    if (!showing) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [showing]);

  const titleOf = useCallback(
    (sessionId: string): string | null => sessions[sessionId]?.title ?? null,
    [sessions],
  );

  return (
    <AgentRequestPanel
      state={state}
      now={now}
      titleOf={titleOf}
      onAllow={(sessionId, attachmentId) =>
        void safeInvoke(ANSWER_COMMAND, { sessionId, attachmentId, answer: "allow" }, null)
      }
      onNotNow={(sessionId, attachmentId) =>
        void safeInvoke(ANSWER_COMMAND, { sessionId, attachmentId, answer: "not-now" }, null)
      }
      onMute={(minutes) => void safeInvoke(MUTE_COMMAND, { minutes }, null)}
      onUnmute={() => void safeInvoke(UNMUTE_COMMAND, undefined, null)}
    />
  );
}
