/**
 * The library window's ear on the agent plane.
 *
 * An agent driven session is an ordinary session in the existing registry, not
 * a side channel (`PRDAgentPlug/01 §5`, `10` ruling W5-20), so this context
 * adds no parallel visibility path and holds no connection state. It answers
 * exactly three questions the rest of the UI cannot answer for itself: who
 * holds a lease, what that holder has in flight, and how to take it away.
 *
 * The event name and the payload are decoded in `../lib/agentActivity`, which
 * is the ONE place either is written down. Nothing else in `ui/src` calls
 * `listen` for this, so reconciling with the shell is a change to that file.
 *
 * With the plane switched off no event ever arrives, the state stays empty,
 * and every consumer renders exactly what it rendered before any of this
 * existed (`AGENT_BRIEF` D2). There is no timer, no subscription cost beyond
 * one idle listener, and no chrome.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { safeInvoke, safeListen } from "../lib/tauri";
import { mockAgentFrames, mockAgentsEnabled, mockPlaneStatus } from "../lib/mock";
import {
  AGENT_ACTIVITY_EVENT,
  AGENT_LEASES_COMMAND,
  AGENT_PLANE_ENABLED_KEY,
  AGENT_PLANE_OFF,
  AGENT_PLANE_ON,
  AGENT_REVOKE_COMMAND,
  EMPTY_AGENT_STATE,
  PREEMPT_NOTICE_MS,
  applyActivityEvent,
  applyHandover,
  clearNotice,
  drivenByAgent,
  drivenCount,
  forgetSession,
  parseActivityEvent,
  mergePlaneStatus,
  parsePlaneStatus,
  planeView,
  seedRows,
  wallEntries,
  type AgentActivity,
  type AgentState,
  type PlaneStatus,
  type PlaneView,
  type RevokeReason,
} from "../lib/agentActivity";

/**
 * Session lifecycle, borrowed rather than re-derived.
 *
 * The plane should retract a lease when its limb goes, and a card left behind
 * by a missed retraction would claim a robot was driving a machine that is not
 * connected any more. That is the one wrong thing this screen must never say,
 * so the end of a session is heard from the shell directly as well.
 */
const SESSIONS_EVENT = "sessions://event";

/** What this person is called on a lease they have just taken. */
const SELF = "You";

interface AgentActivityContextValue {
  /** What an agent is doing to this session, or null for an ordinary one. */
  forSession: (sessionId: string) => AgentActivity | null;
  /** Is an agent holding this session's lease right now? */
  driving: (sessionId: string) => boolean;
  /** Every limb the wall shows, in an order that does not move. */
  wall: readonly AgentActivity[];
  /** How many machines an agent is driving. */
  count: number;
  /**
   * The plane itself: whether it is on, how many agents are attached, how much
   * of this computer they are driving, and where it is listening.
   *
   * Everything about it comes from `lib/agentActivity`, so a surface reading
   * these numbers never touches the wire's names. With the plane off, `on` is
   * false and every count is zero.
   */
  plane: PlaneView;
  /**
   * Switch the plane on, or off, from the UI.
   *
   * The store key is the switch (`crate::agent::AGENT_PLANE_ENABLED_KEY`), and
   * the shell binds or unlinks the socket the moment it is written, so there
   * is nothing to restart and nothing to poll. Deliberately no optimism: the
   * `plane` event that follows the write is what moves `plane` above, on the
   * arm where the socket bound and on the arm where it did not, so a plane
   * that failed to start is never shown as running.
   */
  setPlaneEnabled: (on: boolean) => void;
  /**
   * A person has clicked into this pane, so it is theirs.
   *
   * A no-op unless an agent holds it, which is why every pane can call it on
   * every click without anybody having to ask first.
   */
  takeWheel: (sessionId: string) => void;
  /** The stop button. The same revocation, recorded under its own reason. */
  stopAgent: (sessionId: string) => void;
  /** Every agent, at once. One button for a wall of twelve. */
  stopAll: () => void;
}

const AgentActivityContext = createContext<AgentActivityContextValue | null>(null);

export function AgentActivityProvider({ children }: { children: ReactNode }): ReactNode {
  const [state, setState] = useState<AgentState>(EMPTY_AGENT_STATE);
  /**
   * The last thing the plane said about itself, or null before it has said
   * anything, which is also what it says forever when it is switched off.
   */
  const [reported, setReported] = useState<PlaneStatus | null>(null);

  // Read inside callbacks and timers registered once, which must not close
  // over a snapshot the events themselves are changing.
  const stateRef = useRef(state);
  stateRef.current = state;

  // ------------------------------------------------------------ event intake

  useEffect(() => {
    let cancelled = false;
    const unlisteners: Array<() => void> = [];
    const hook = <T,>(event: string, handler: (payload: T) => void): void => {
      void safeListen<T>(event, (payload) => {
        if (!cancelled) handler(payload);
      }).then((fn) => {
        // `safeListen` resolves a turn after the effect that asked for it, so
        // a cleanup that has already run has to be able to cancel it here or
        // the listener stays registered for good.
        if (cancelled) fn();
        else unlisteners.push(fn);
      });
    };

    hook<unknown>(AGENT_ACTIVITY_EVENT, (raw) => {
      // Two payloads share one event. Each parser refuses what the other one
      // takes, so this offers every payload to both and at most one moves.
      const status = parsePlaneStatus(raw);
      if (status) {
        // MERGE, never replace. Three payloads share this shape and none of
        // them carries every field: `plane` says whether the socket is up and
        // says nothing about the counts, `counts` says the opposite, and only
        // the `agent_status` seed carries both. Replacing wholesale would let a
        // counts event blank the socket path and read as the plane switching
        // itself off, so the whole surface would blink away every time a number
        // moved. A null field means this payload had no news about it.
        setReported((prev) => (prev ? mergePlaneStatus(prev, status) : status));
        return;
      }
      const ev = parseActivityEvent(raw);
      if (!ev) return;
      setState((prev) => applyActivityEvent(prev, ev, Date.now()));
    });

    hook<{ type?: string; sessionId?: string }>(SESSIONS_EVENT, (ev) => {
      if (!ev || ev.type !== "ended" || typeof ev.sessionId !== "string") return;
      setState((prev) => forgetSession(prev, ev.sessionId as string));
    });

    // Seed a window that opened while agents were already at work, the way
    // `agent_status` seeds a window that opened while agents were already
    // driving, the way `pending_credential_request` seeds a credential prompt
    // that was answered before anyone was listening. With the plane switched
    // off it answers no attachments and nothing at all changes on screen.
    void safeInvoke<unknown>(AGENT_LEASES_COMMAND, undefined, null).then((answer) => {
      if (cancelled) return;
      // The same answer carries the plane's own state, and it is the only
      // thing that does until the plane next changes: a window that opens
      // while the plane is quietly running hears no `plane` event at all.
      const status = parsePlaneStatus(answer);
      if (status) setReported(status);
      const rows = seedRows(answer);
      if (rows.length === 0) return;
      setState((prev) => {
        const now = Date.now();
        let next = prev;
        for (const row of rows) {
          const ev = parseActivityEvent(row);
          if (ev) next = applyActivityEvent(next, ev, now);
        }
        return next;
      });
    });

    return () => {
      cancelled = true;
      for (const fn of unlisteners) fn();
    };
  }, []);

  /**
   * A pretend plane, for `npm run dev` in a plain browser with `?mockAgents`.
   *
   * `useMockData` is false in every build that is not the dev server, so this
   * whole branch is dead code Vite removes; and without the query flag the dev
   * server itself shows no agent chrome either. It exists because the shell
   * side of this is being written in parallel, and a live activity view that
   * nobody can look at until then is a view nobody can review.
   */
  useEffect(() => {
    if (!mockAgentsEnabled()) return;
    setReported(parsePlaneStatus(mockPlaneStatus()));
    const ids = ["mock-1", "mock-2", "mock-3", "mock-4"];
    const feed = (): void => {
      const now = Date.now();
      setState((prev) => {
        let next = prev;
        for (const raw of mockAgentFrames(ids)) {
          const ev = parseActivityEvent(raw);
          // A revocation sticks. The pretend plane stops driving a limb the
          // moment a person takes it, the way the real one does, so that
          // pressing stop here can actually be seen to work.
          if (!ev || (prev[ev.sessionId] && !drivenByAgent(prev[ev.sessionId]))) continue;
          next = applyActivityEvent(next, ev, now);
        }
        return next;
      });
    };
    feed();
    const iv = window.setInterval(feed, 2000);
    return () => window.clearInterval(iv);
  }, []);

  // ------------------------------------------------------------- revocation

  /**
   * Take a lease off an agent and give it to this person.
   *
   * The order here is the whole point, and it is `00 R13`. The new state is
   * written FIRST, synchronously, and the command goes afterwards without
   * anybody waiting on it. There is no pending flag, so there is nothing for a
   * spinner to be spun for: a human outranks an agent by default and the plane
   * releases keys and stops dispatch on the lease change itself (`00 R11`), so
   * a UI that waited for an acknowledgement would be showing two seconds of
   * nothing happening under a button labelled stop. That is the exact failure
   * BrowserGlass measured at 2,008 ms and the reason this is a revocation
   * rather than a request.
   *
   * The store then ignores what the plane says about this session for a very
   * short window, because an event minted before the click cannot know about
   * it. See `HANDOVER_MUTE_MS`.
   */
  const revoke = useCallback((sessionId: string, reason: RevokeReason): void => {
    if (!drivenByAgent(stateRef.current[sessionId])) return;
    const now = Date.now();
    setState((prev) => applyHandover(prev, sessionId, SELF, now));
    void safeInvoke(AGENT_REVOKE_COMMAND, { sessionId, reason }, null);
    // The notice retires on a schedule rather than against a ticking clock, so
    // watching an agent work costs no re-renders at all.
    window.setTimeout(() => {
      setState((prev) => clearNotice(prev, sessionId, Date.now()));
    }, PREEMPT_NOTICE_MS + 50);
  }, []);

  const takeWheel = useCallback(
    (sessionId: string): void => revoke(sessionId, "took-the-wheel"),
    [revoke],
  );

  const stopAgent = useCallback(
    (sessionId: string): void => revoke(sessionId, "stopped"),
    [revoke],
  );

  const stopAll = useCallback((): void => {
    for (const entry of Object.values(stateRef.current)) {
      if (drivenByAgent(entry)) revoke(entry.sessionId, "stopped");
    }
  }, [revoke]);

  // ---------------------------------------------------------------- lookups

  const forSession = useCallback(
    (sessionId: string): AgentActivity | null => state[sessionId] ?? null,
    [state],
  );

  const driving = useCallback(
    (sessionId: string): boolean => drivenByAgent(state[sessionId]),
    [state],
  );

  // Recomputed only when the store changes. The freshness test inside is belt
  // and braces: the scheduled retirement above is what actually clears a
  // notice, and it edits the state, so this list is never stale on screen.
  const wall = useMemo(() => wallEntries(state, Date.now()), [state]);
  const count = useMemo(() => drivenCount(state), [state]);
  const plane = useMemo(() => planeView(reported, state), [reported, state]);

  /**
   * The switch, written through the same command Preferences writes every
   * other store backed setting with.
   *
   * Nothing is guessed about the result. The shell answers the write with a
   * `plane` event, on the arm where the socket bound and on the arm where it
   * did not, so this sets the setting and lets the plane report what became
   * of it.
   */
  const setPlaneEnabled = useCallback((on: boolean): void => {
    void safeInvoke(
      "set_app_setting",
      { key: AGENT_PLANE_ENABLED_KEY, value: on ? AGENT_PLANE_ON : AGENT_PLANE_OFF },
      null,
    );
  }, []);

  const value = useMemo(
    () => ({ forSession, driving, wall, count, plane, takeWheel, stopAgent, stopAll, setPlaneEnabled }),
    [forSession, driving, wall, count, plane, takeWheel, stopAgent, stopAll, setPlaneEnabled],
  );

  return (
    <AgentActivityContext.Provider value={value}>{children}</AgentActivityContext.Provider>
  );
}

export function useAgentActivity(): AgentActivityContextValue {
  const ctx = useContext(AgentActivityContext);
  if (!ctx) throw new Error("useAgentActivity outside AgentActivityProvider");
  return ctx;
}
