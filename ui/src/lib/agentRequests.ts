/**
 * Agents asking for a machine the person is using.
 *
 * The shell keeps one list of every agent waiting for a machine a person has
 * typed or clicked in during the last 20 seconds, across every machine, and
 * sends the whole list on the agent event whenever it changes (and once a
 * second while it is not empty). This file reads that list and words what the
 * panel shows. The panel renders the latest list and nothing else, which is
 * what keeps it to one panel however many agents ask.
 *
 * Everything an agent wrote (its label, its reason) is untrusted text. It is
 * only ever rendered as text, and it is cut to a length here.
 */

/** Seed for a window that mounts while agents are already asking. */
export const REQUESTS_COMMAND = "agent_requests";
/** The person's answer: `{ sessionId?, attachmentId?, answer: "allow" | "not-now" }`. */
export const ANSWER_COMMAND = "agent_request_answer";
/** `{ minutes?: number }`, absent minutes meaning until the person stops. */
export const MUTE_COMMAND = "agent_requests_mute";
export const UNMUTE_COMMAND = "agent_requests_unmute";

export interface AgentRequest {
  sessionId: string;
  attachmentId: string;
  /** The agent, as it named itself: MCP client and process id. Untrusted. */
  agent: string;
  /** What it said it wants the machine for. Untrusted. */
  reason: string | null;
  /** `host:port`, for a machine no tab here names. */
  address: string | null;
  /** Wall clock (ms) when it first asked. */
  askedAt: number;
  /** Wall clock (ms) when it gets the machine anyway if the person stops now. */
  freesAt: number | null;
}

export interface MuteState {
  /** Wall clock (ms) the mute ends, or null for "until I take my hands off". */
  until: number | null;
  untilIdle: boolean;
  /** Agents that asked in the last minute and were told requests are muted. */
  waiting: number;
}

export interface RequestsState {
  requests: AgentRequest[];
  muted: MuteState | null;
  personIdleMs: number;
}

export const EMPTY_REQUESTS: RequestsState = { requests: [], muted: null, personIdleMs: 20_000 };

/** The longest piece of agent text shown, so one agent cannot fill the window. */
export const AGENT_TEXT_MAX = 160;

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) ? v : null;

/** Agent text, made safe to show: control characters out, length bounded. */
export function agentText(v: unknown): string {
  // eslint-disable-next-line no-control-regex
  const clean = str(v).replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").trim();
  return clean.length > AGENT_TEXT_MAX ? `${clean.slice(0, AGENT_TEXT_MAX - 1)}…` : clean;
}

/** Read a `requests` event, or null for any other payload. */
export function parseRequestsEvent(raw: unknown): RequestsState | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (r.type !== "requests") return null;
  const rows = Array.isArray(r.requests) ? r.requests : [];
  const requests: AgentRequest[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const q = row as Record<string, unknown>;
    const sessionId = str(q.sessionId);
    const attachmentId = str(q.attachmentId);
    if (!sessionId || !attachmentId) continue;
    const reason = agentText(q.reason);
    requests.push({
      sessionId,
      attachmentId,
      agent: agentText(q.agent) || "An agent",
      reason: reason || null,
      address: str(q.address) || null,
      askedAt: num(q.askedAt) ?? Date.now(),
      freesAt: num(q.freesAt),
    });
  }
  let muted: MuteState | null = null;
  if (r.muted && typeof r.muted === "object") {
    const m = r.muted as Record<string, unknown>;
    muted = {
      until: num(m.until),
      untilIdle: m.untilIdle === true,
      waiting: num(m.waiting) ?? 0,
    };
  }
  return { requests, muted, personIdleMs: num(r.personIdleMs) ?? 20_000 };
}

/** "8 s", "2 min", for how long somebody has waited. */
export function waitedFor(askedAt: number, now: number): string {
  const s = Math.max(0, Math.floor((now - askedAt) / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`;
}

/** Seconds left until a time, never below zero. */
export function secondsUntil(at: number, now: number): number {
  return Math.max(0, Math.ceil((at - now) / 1000));
}

/** `14:32` in the person's own time zone. */
export function clockTime(at: number): string {
  const d = new Date(at);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

// ------------------------------------------------------------- the words

/**
 * Every string the panel shows, in one place so they can be reworded without
 * reading the component.
 */
export const TEXT = {
  heading: (n: number): string =>
    n === 1
      ? "An agent is asking to use a machine you are using"
      : `${n} agents are asking to use machines you are using`,
  onMachine: (machine: string): string => `on ${machine}`,
  waited: (w: string): string => `waiting ${w}`,
  countdown: (s: number): string =>
    s > 0 ? `gets it in ${s} s if you stop typing` : "gets it as soon as you stop typing",
  allow: "Let it use this machine",
  allowTitle: "Hand this machine to the agent now. Typing or clicking in it takes it back.",
  notNow: "Not now",
  notNowTitle: "Refuse this request. The agent is told you said not now and will not ask again for a minute.",
  allowAll: "Let them all in",
  notNowAll: "Not now to all",
  mute: "Mute requests",
  muteFor: "Mute requests for",
  muteChoices: [
    { label: "5 minutes", minutes: 5 },
    { label: "15 minutes", minutes: 15 },
    { label: "1 hour", minutes: 60 },
    { label: "Until I take my hands off", minutes: null },
  ] as ReadonlyArray<{ label: string; minutes: number | null }>,
  mutedUntil: (m: MuteState): string =>
    m.untilIdle || m.until === null
      ? "Agent requests muted until you stop using the machine"
      : `Agent requests muted until ${clockTime(m.until)}`,
  mutedWaiting: (n: number): string => (n === 1 ? "1 asked" : `${n} asked`),
  unmute: "Unmute",
} as const;

/** What a machine is called in a row: the tab's title, then its address. */
export function machineName(
  request: AgentRequest,
  titleOf: (sessionId: string) => string | null,
): string {
  return titleOf(request.sessionId) || request.address || "a machine";
}
