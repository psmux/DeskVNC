/**
 * What an agent is doing to a session, as this window understands it.
 *
 * This is the ONE place the agent plane's live event is named and decoded.
 * Every component reads the shapes below and none of them calls `listen`
 * itself, so when the plane settles on a different event name or a different
 * field this file is the only thing that changes.
 *
 * Nothing here is React. The subscription, the store and the hooks live in
 * `../state/AgentActivityContext`, which keeps the parsing and the reducer
 * testable: the runner only collects `src/**` + `/*.test.ts`, so logic that
 * needs a renderer cannot be covered at all and logic that does not, is.
 *
 * Two rules from the PRD set are enforced here rather than in a component,
 * because a component is the wrong place to be trusted with either.
 *
 * A holder whose kind we do not recognise is `unknown`, never `human`
 * (`10` ruling W5-21). A UI that renders an unnamed holder as a person is a UI
 * that will one day tell somebody a robot was a colleague. There is a real
 * window in which this happens: a lease change and a presence broadcast are two
 * events, and anything driving a session from outside the plane has no presence
 * entry at all.
 *
 * Text that came off a remote screen or out of a PTY is data, never
 * instruction (`AGENT_BRIEF` D6, `00 R32`). It arrives through
 * {@link sanitizeRemoteText} and is carried in a type of its own, so a
 * component cannot mistake it for a string we wrote.
 */

// ---------------------------------------------------------------- contracts

/**
 * The app wide event carrying one session's lease and in flight intent.
 *
 * AGREED. The shell emits this app wide with `emit`, in the style of
 * `sessions://event`; the constant on that side is `crate::agent::AGENT_EVENT`
 * in `src-tauri/src/agent/mod.rs`. Its payloads are flat and carry a `type`
 * discriminator, which is a different shape from the one this module wants, so
 * {@link fromWire} translates and {@link parseActivityEvent} accepts either.
 * An unknown `type` is ignored rather than guessed at.
 */
export const AGENT_ACTIVITY_EVENT = "agent://event";

/**
 * Seed for a window that opened while agents were already driving, in the
 * style of `list_active_sessions` and for the same reason `pending_credential_request`
 * exists: Tauri events are fire and forget, so anything emitted before a
 * window's `listen()` registration completes is simply gone.
 *
 * AGREED. Returns `{ enabled, socket, attachments }` rather than a bare array,
 * so {@link seedRows} unwraps it.
 */
export const AGENT_LEASES_COMMAND = "agent_status";

/**
 * Take a lease off whoever holds it and give it to this person. ASSUMED.
 *
 * One command for both gestures, because from the plane's side clicking into a
 * pane and pressing stop are the same operation: a human outranks an agent by
 * default (`00 R11`, ladder `admin 900, owner 200, human 100, agent 50`), so
 * neither one is a request and neither one needs the agent's cooperation. The
 * reason rides along for the trace, not for the arbitration.
 */
export const AGENT_REVOKE_COMMAND = "agent_take_the_wheel";

/** Why a human took a lease. Recorded, never consulted before acting. */
export type RevokeReason = "took-the-wheel" | "stopped";

// ------------------------------------------------------------------- types

/**
 * Who holds a lease.
 *
 * `unknown` is NOT a synonym for `human` and must not be rendered as one: it
 * means the plane named a holder we have no roster entry for, and the only
 * honest thing to say about it is that something is driving.
 */
export type HolderKind = "human" | "agent" | "service" | "unknown";

export interface LeaseHolder {
  kind: HolderKind;
  /** What to call it on screen. The token subject, never the token. */
  name: string;
  /** The capability that authorised it, by name, or null when unstated. */
  capability: string | null;
  /** Plane wall clock (ms) when it took the lease. 0 when unstated. */
  since: number;
}

/** Enough to say which box, for a limb this window has never mounted. */
export interface MachineRef {
  label: string;
  address: string;
  port: number;
  /** Kept as a plain string: a limb may be a kind the viewer cannot show. */
  protocol: string;
}

/**
 * What became of an intent.
 *
 * `unknown` exists for the same reason {@link HolderKind} has one. An outcome
 * we cannot read is reported as unread rather than guessed at, because both
 * available guesses are wrong in a way somebody would act on.
 */
export type IntentOutcome = "in-flight" | "accepted" | "refused" | "failed" | "unknown";

export interface AgentIntent {
  /** The plane's span id. Our React key, and how a repeat is recognised. */
  id: string;
  /** The intent discriminant, e.g. `pointer.click`. Our vocabulary. */
  kind: string;
  /** A short line the plane wrote about it. Our text, safe to render. */
  summary: string;
  outcome: IntentOutcome;
  /** Plane wall clock (ms). */
  at: number;
  /**
   * What the far side showed, verbatim. UNTRUSTED, see the file header.
   * Never a string we wrote, and never rendered as anything but quoted text.
   */
  remote: RemoteText | null;
}

/** Text from a remote screen or terminal, already neutralised, still data. */
export interface RemoteText {
  /** Neutralised for display. The only form of this text the UI ever holds. */
  text: string;
  /** Which surface it was read off, so the label can say so. */
  source: "screen" | "terminal";
  /** True when the far side said more than we kept. */
  truncated: boolean;
}

/** A human taking a lease off an agent, remembered long enough to be seen. */
export interface Preemption {
  /** The agent that was driving. */
  agent: string;
  /** Our clock (ms). */
  at: number;
}

/** One session's worth of the above. */
export interface AgentActivity {
  sessionId: string;
  machine: MachineRef | null;
  holder: LeaseHolder | null;
  intent: AgentIntent | null;
  preempted: Preemption | null;
  /**
   * When this session first appeared here, and the wall's sort key.
   *
   * Deliberately not the current holder's `since`. Taking the wheel replaces
   * the holder, so ordering by that would send a card to the end of the row at
   * the exact moment a person is watching to see what their click did. This is
   * written once and survives every handover, so a card stays where the person
   * left it.
   */
  firstSeen: number;
  /**
   * Our clock (ms) at the last local handover, or 0.
   *
   * A revocation is applied here before the command is sent (`00 R13`), so an
   * event already on the wire when the button was pressed would otherwise put
   * the agent back on screen a moment later. See {@link applyActivityEvent}.
   */
  handoverAt: number;
}

export type AgentState = Readonly<Record<string, AgentActivity>>;

export const EMPTY_AGENT_STATE: AgentState = {};

/**
 * How long a local handover ignores what the plane says about that session.
 *
 * Short on purpose. It is only wide enough to swallow an event that was
 * already in flight when the person pressed the button; the plane is the
 * authority, and if it refuses a revocation the person has to find out at
 * once rather than in a few seconds.
 */
export const HANDOVER_MUTE_MS = 1200;

/** How long "you took the wheel" stays on screen after the fact. */
export const PREEMPT_NOTICE_MS = 6000;

/** Longest remote excerpt we keep. Past this it is evidence, not a glance. */
export const REMOTE_TEXT_MAX = 140;

// -------------------------------------------------------------- untrusted

/**
 * Bring remote output down to something that can only ever be read as text.
 *
 * What this removes and why: control characters, because a bare CR or an
 * ANSI escape lets a far side redraw over the label that says the text is
 * remote; bidirectional overrides, because RLO reverses a run and can make
 * `refused` render as `desufer` beside chrome it did not write; and zero width
 * characters, because they hide the difference between two strings a person is
 * being asked to tell apart.
 *
 * What this deliberately does NOT remove is markup, quotes, or the words. A
 * remote machine printing `<b>` or "ignore your previous instructions" is
 * showing us exactly what it printed, and mangling it would turn a legible
 * record into a misleading one. It is safe to show because it is rendered as a
 * text node by a renderer that escapes, and because nothing downstream of the
 * UI reads it back as an instruction.
 */
export function sanitizeRemoteText(
  raw: unknown,
  source: unknown = "screen",
  max: number = REMOTE_TEXT_MAX,
): RemoteText | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const cleaned = raw
    // C0, DEL and C1. Replaced with a space rather than dropped, so two lines
    // of output do not silently become one run-on word.
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
    // Bidirectional marks, embeddings, overrides and isolates.
    .replace(/[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, "")
    // Zero width joiners, non joiners, spaces and the byte order mark.
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (cleaned.length === 0) return null;
  const truncated = cleaned.length > max;
  return {
    text: truncated ? `${cleaned.slice(0, max)}…` : cleaned,
    source: source === "terminal" ? "terminal" : "screen",
    truncated,
  };
}

// ---------------------------------------------------------------- decoding

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

function holderKind(v: unknown): HolderKind {
  switch (v) {
    case "human":
    case "agent":
    case "service":
      return v;
    default:
      // Every other value, including a missing one, is a driver we cannot
      // name. See the file header: this is not `human`.
      return "unknown";
  }
}

function outcomeOf(v: unknown): IntentOutcome {
  switch (v) {
    case "in-flight":
    case "accepted":
    case "refused":
    case "failed":
      return v;
    default:
      return "unknown";
  }
}

function parseHolder(raw: unknown): LeaseHolder | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const kind = holderKind(r.kind);
  const name = str(r.name).trim();
  return {
    kind,
    // A holder with no name still has a kind worth showing, so fall back to
    // the kind rather than dropping the whole holder on the floor.
    name: name || (kind === "unknown" ? "Unnamed driver" : kind),
    capability: str(r.capability).trim() || null,
    since: num(r.since),
  };
}

function parseMachine(raw: unknown): MachineRef | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const address = str(r.address);
  const label = str(r.label).trim() || address;
  if (!label) return null;
  return { label, address, port: num(r.port), protocol: str(r.protocol) || "vnc" };
}

function parseIntent(raw: unknown): AgentIntent | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const kind = str(r.kind).trim();
  const summary = str(r.summary).trim();
  if (!kind && !summary) return null;
  const remoteRaw = r.remote && typeof r.remote === "object"
    ? (r.remote as Record<string, unknown>)
    : null;
  return {
    id: str(r.id) || `${kind}:${num(r.at)}`,
    kind: kind || "intent",
    summary,
    outcome: outcomeOf(r.outcome),
    at: num(r.at),
    remote: remoteRaw ? sanitizeRemoteText(remoteRaw.text, remoteRaw.source) : null,
  };
}

/** One session's lease and in flight intent, as the plane broadcasts it. */
export interface AgentActivityEvent {
  sessionId: string;
  /** Plane wall clock (ms) the event was minted at. */
  at: number;
  machine: MachineRef | null;
  /** null when nobody holds the lease, which is an ordinary session. */
  holder: LeaseHolder | null;
  intent: AgentIntent | null;
}

/**
 * Read a payload off the wire, or refuse it.
 *
 * Defensive in the same way `SessionsContext` is: a stray event, an older
 * shell, or a field that has moved must leave the UI showing what it showed
 * before rather than throwing inside a listener.
 */
/**
 * Translate one `agent://event` payload into the shape the rest of this module
 * speaks, or `null` for a payload this build has nothing to do with.
 *
 * The shell's vocabulary is flat and discriminated on `type`: `plane` reports
 * whether the socket is up, `attached` and `detached` bracket a client's hold
 * on a session, and `lease` is the one that moves a badge. Only the last two
 * change what is on screen.
 *
 * Two fields the shell does not send, and both absences are correct rather
 * than missing. There is no `machine`, because the shell already told this
 * window about its sessions and a second copy could disagree with the first;
 * the caller fills it from the session it already has. And there is no `at`,
 * because a wall clock minted on the sending side would be compared against
 * ours, so receipt time is the only clock both halves agree on.
 */
export function fromWire(raw: unknown): unknown | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const kind = str(r.type);
  const sessionId = str(r.sessionId);
  if (!sessionId) return null;

  // A client letting go, or being let go of, is an ordinary session again.
  if (kind === "detached") {
    return { sessionId, at: Date.now(), machine: null, holder: null, intent: null };
  }
  if (kind !== "lease" && kind !== "attached") return null;

  const at = Date.now();
  const held = r.held === true;
  // `held: false` is the whole of "nobody is driving". The badge goes away on
  // that alone, so a revoked lease needs no second signal to be believed.
  const holder = held
    ? {
        kind: str(r.holderKind) || "unknown",
        name: str(r.holderLabel) || str(r.client) || "",
        capability: null,
        since: 0,
      }
    : null;

  // `inflight` is already coalesced on the shell side, so a drag of two
  // hundred pointer events arrives as one name rather than two hundred.
  const flying = Array.isArray(r.inflight) ? r.inflight.map(str).filter(Boolean) : [];
  const intent =
    holder && flying.length > 0
      ? {
          id: `${str(r.attachmentId) || sessionId}:${flying[0]}`,
          kind: flying[0],
          summary: flying.length > 1 ? `${flying[0]} and ${flying.length - 1} more` : "",
          outcome: "in-flight",
          at,
          remote: null,
        }
      : null;

  return { sessionId, at, machine: null, holder, intent };
}

/**
 * Unwrap the seed. `agent_status` answers `{ enabled, socket, attachments }`
 * rather than a bare array, because a window also needs to know whether the
 * plane is on at all: no attachments and no plane look identical otherwise,
 * and only one of them is worth telling somebody about.
 */
export function seedRows(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (!raw || typeof raw !== "object") return [];
  const rows = (raw as Record<string, unknown>).attachments;
  return Array.isArray(rows) ? rows : [];
}

export function parseActivityEvent(raw: unknown): AgentActivityEvent | null {
  if (!raw || typeof raw !== "object") return null;
  // A payload carrying `type` came off the wire and needs translating first.
  // Anything else is already in this module's shape, which is what the tests
  // and the seed rows use.
  const shaped = "type" in (raw as Record<string, unknown>) ? fromWire(raw) : raw;
  if (!shaped || typeof shaped !== "object") return null;
  const r = shaped as Record<string, unknown>;
  const sessionId = str(r.sessionId);
  if (!sessionId) return null;
  return {
    sessionId,
    at: num(r.at),
    machine: parseMachine(r.machine),
    holder: parseHolder(r.holder),
    intent: parseIntent(r.intent),
  };
}

// ----------------------------------------------------------------- reducer

/**
 * Fold one event into the store.
 *
 * Returns the state unchanged where nothing moved, which is load-bearing
 * rather than an optimisation: this runs from a listener at whatever rate the
 * plane broadcasts, and a fresh object every time would re-render the pane
 * grid for an event that said the same thing twice.
 */
export function applyActivityEvent(
  state: AgentState,
  ev: AgentActivityEvent,
  now: number,
): AgentState {
  const prev = state[ev.sessionId];

  // A revocation is already on screen (see `AgentActivity.handoverAt`). An
  // event minted before the button was pressed cannot be allowed to put the
  // agent back, and the plane cannot know about the click yet.
  if (prev && prev.handoverAt > 0 && now - prev.handoverAt < HANDOVER_MUTE_MS) return state;

  // Nobody holds it and nothing is in flight: an ordinary session, which has
  // no entry at all rather than an entry saying nothing.
  if (!ev.holder && !ev.intent) {
    if (!prev) return state;
    // Keep a fresh preempt notice alive: the point of it is to be seen just
    // after the lease changed hands, which is exactly when this arrives.
    if (prev.preempted && now - prev.preempted.at < PREEMPT_NOTICE_MS) {
      if (prev.holder === null && prev.intent === null) return state;
      return { ...state, [ev.sessionId]: { ...prev, holder: null, intent: null } };
    }
    const next = { ...state };
    delete next[ev.sessionId];
    return next;
  }

  const entry: AgentActivity = {
    sessionId: ev.sessionId,
    // The plane repeats the machine on every event; keep the last good one so
    // a payload that omits it does not blank a card that was naming a box.
    machine: ev.machine ?? prev?.machine ?? null,
    holder: ev.holder,
    intent: ev.intent,
    // An agent holding it again means this is new work, not the handover the
    // notice was about.
    preempted: ev.holder?.kind === "agent" ? null : (prev?.preempted ?? null),
    firstSeen: prev?.firstSeen ?? (ev.holder?.since || ev.at || now),
    handoverAt: 0,
  };
  return sameActivity(prev, entry) ? state : { ...state, [ev.sessionId]: entry };
}

function sameHolder(a: LeaseHolder | null, b: LeaseHolder | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return a.kind === b.kind && a.name === b.name && a.capability === b.capability
    && a.since === b.since;
}

function sameIntent(a: AgentIntent | null, b: AgentIntent | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return a.id === b.id && a.outcome === b.outcome && a.summary === b.summary
    && a.kind === b.kind && (a.remote?.text ?? null) === (b.remote?.text ?? null);
}

function sameMachine(a: MachineRef | null, b: MachineRef | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  // By value, not by reference: the plane repeats the machine on every event
  // and each one is decoded into a fresh object, so a reference test would
  // report every repeat as a change and re-render the grid at broadcast rate.
  return a.label === b.label && a.address === b.address && a.port === b.port
    && a.protocol === b.protocol;
}

function sameActivity(a: AgentActivity | undefined, b: AgentActivity): boolean {
  if (!a) return false;
  return sameMachine(a.machine, b.machine) && a.preempted === b.preempted
    && a.handoverAt === b.handoverAt && a.firstSeen === b.firstSeen
    && sameHolder(a.holder, b.holder) && sameIntent(a.intent, b.intent);
}

/**
 * A person has taken this lease. Applied before the plane is told.
 *
 * This is the whole of "the stop button is a revocation rather than a request"
 * on the UI's side (`00 R13`). There is no pending flag and no spinner to
 * clear, because there is nothing to wait for: the state a person is shown is
 * the state they asked for, written synchronously, and the event that follows
 * can only confirm it. A UI that waited would be showing two seconds of
 * nothing happening under a button labelled stop, which is the exact failure
 * BrowserGlass measured at 2,008 ms.
 */
export function applyHandover(
  state: AgentState,
  sessionId: string,
  holderName: string,
  now: number,
): AgentState {
  const prev = state[sessionId];
  // Nothing was driving it, so taking the wheel is what clicking a pane has
  // always done and there is nothing to say about it.
  if (!prev || prev.holder?.kind !== "agent") return state;
  return {
    ...state,
    [sessionId]: {
      ...prev,
      holder: { kind: "human", name: holderName, capability: null, since: now },
      // Keys are released and dispatch stops synchronously on the plane's
      // side, so nothing the agent had in flight is still in flight.
      intent: null,
      preempted: { agent: prev.holder.name, at: now },
      handoverAt: now,
    },
  };
}

/**
 * Retire a handover notice once it has been on screen long enough.
 *
 * Scheduled by the store when the handover happens, rather than judged against
 * a clock that ticks: a notice then costs two state changes instead of one per
 * second across a grid of twelve panes, and nothing re-renders while an agent
 * is quietly working.
 */
export function clearNotice(state: AgentState, sessionId: string, now: number): AgentState {
  const prev = state[sessionId];
  if (!prev?.preempted) return state;
  if (now - prev.preempted.at < PREEMPT_NOTICE_MS) return state;
  // The notice was the only reason this entry was still here.
  if (!prev.holder && !prev.intent) return forgetSession(state, sessionId);
  return { ...state, [sessionId]: { ...prev, preempted: null } };
}

/** Drop a session that has gone, so a closed pane leaves no card behind. */
export function forgetSession(state: AgentState, sessionId: string): AgentState {
  if (!(sessionId in state)) return state;
  const next = { ...state };
  delete next[sessionId];
  return next;
}

// ----------------------------------------------------------------- reading

/** Is an agent driving this session right now? */
export function drivenByAgent(a: AgentActivity | undefined): boolean {
  return a?.holder?.kind === "agent";
}

/** Should the "you took the wheel" line still be on screen? */
export function noticeFresh(a: AgentActivity | undefined, now: number): boolean {
  return Boolean(a?.preempted && now - a.preempted.at < PREEMPT_NOTICE_MS);
}

/**
 * Everything the wall shows, in an order that does not move underneath a
 * person watching it.
 *
 * Sorted by when the limb first appeared, oldest first, and by nothing that
 * changes afterwards. Sorting by recent activity would reshuffle the row every
 * time a machine did something, which is precisely when somebody is looking at
 * it; sorting by the current holder would move a card the instant a person took
 * the wheel, which is the one moment they are watching that card. A new limb
 * appends to the end and the cards already there stay where they were.
 * `sessionId` breaks ties so the order is total.
 */
export function wallEntries(state: AgentState, now: number): AgentActivity[] {
  return Object.values(state)
    .filter((a) => drivenByAgent(a) || noticeFresh(a, now))
    .sort((a, b) => {
      if (a.firstSeen !== b.firstSeen) return a.firstSeen - b.firstSeen;
      return a.sessionId < b.sessionId ? -1 : a.sessionId > b.sessionId ? 1 : 0;
    });
}

/** How many machines an agent is driving. The wall's own headline. */
export function drivenCount(state: AgentState): number {
  return Object.values(state).filter(drivenByAgent).length;
}

/** What to call a holder on screen, making no claim we cannot support. */
export function holderLabel(holder: LeaseHolder | null): string {
  if (!holder) return "Nobody";
  switch (holder.kind) {
    case "agent":
      return `Agent ${holder.name}`;
    case "service":
      return `Service ${holder.name}`;
    case "human":
      return holder.name;
    default:
      // Said as plainly as it is known: something is driving, and we are not
      // going to guess what.
      return `Driver ${holder.name}`;
  }
}

/** One line for the strip: what is in flight, or what just happened. */
export function intentLine(intent: AgentIntent | null): string {
  if (!intent) return "";
  return intent.summary ? `${intent.kind} ${intent.summary}` : intent.kind;
}

/** How a remote excerpt is introduced, so its origin is never in doubt. */
export function remoteLabel(remote: RemoteText): string {
  return remote.source === "terminal" ? "remote terminal" : "remote screen";
}

// ------------------------------------------------------------------- plane
//
// Everything below is about the PLANE rather than about any one session: is it
// running, where is its socket, how many agents are attached to it, and how
// much of this computer they are driving between them.
//
// It is in this file for the same reason the lease payload is: the shell half
// of these numbers is being written in parallel with this half, so the names
// on the wire are read in exactly one place and reconciling them later is an
// edit to this section and to nothing else. Every component reads
// {@link planeView}.

/**
 * The store key that switches the plane on. AGREED.
 *
 * `crate::agent::AGENT_PLANE_ENABLED_KEY`, written with `set_app_setting`
 * exactly like `ALLOW_MULTIPLE_SESSIONS_KEY` is. Writing it binds or unlinks
 * the socket there and then, so switching the plane on is a switch rather than
 * a restart, and the shell answers with a `plane` event either way.
 *
 * The value is a word rather than a flag: `plane_enabled` accepts `true`, `1`,
 * `yes` and `on`, and treats everything else, a missing value included, as off.
 */
export const AGENT_PLANE_ENABLED_KEY = "agent_plane_enabled";
export const AGENT_PLANE_ON = "true";
export const AGENT_PLANE_OFF = "false";

/**
 * Hand back the HTTP bearer token, for one copy to the clipboard. ASSUMED.
 *
 * The HTTP half of the plane is being built alongside this screen, so this may
 * answer nothing at all, and nothing at all is a perfectly good answer: the
 * modal simply does not offer the button. A token is never rendered and never
 * held in React state, see `AgentConnect`.
 */
export const AGENT_HTTP_TOKEN_COMMAND = "agent_http_token";

/**
 * What the plane says about itself.
 *
 * `enabled` and `socket` are AGREED: `agent_status` answers both and the
 * `plane` event carries both, with `error` on the arm where the setting is on
 * and the socket would not bind.
 *
 * The three counts and the two setup fields are ASSUMED, and each is null
 * until the plane actually says it, never zero. The difference matters on
 * screen: "no agent is attached" and "this build does not report how many"
 * are different sentences and only one of them is a fact.
 */
export interface PlaneStatus {
  /**
   * Whether the socket is up, or null when this payload does not say.
   *
   * A `counts` event carries no `enabled`, and reading its absence as "off"
   * would blink the whole surface away every time a number moved. Null means
   * no news, and {@link planeView} keeps the last thing that did say.
   */
  enabled: boolean | null;
  socket: string | null;
  /** Why the socket did not bind, when the setting is on and it did not. */
  error: string | null;
  /** Distinct agents attached, driving or idle. AGREED: `agentsConnected`. */
  agents: number | null;
  /** Sessions an agent HOLDS THE LEASE on. AGREED: `sessionsDriven`. */
  driving: number | null;
  /** Live sessions in all, driven or not. AGREED: `sessionsLive`. */
  sessions: number | null;
  /** Absolute path of the `dvv` binary, if the shell knows one. ASSUMED. */
  binary: string | null;
  /** Where the HTTP half listens, when it is on at all. ASSUMED. */
  httpUrl: string | null;
}

/**
 * Field names accepted for each count, most likely first.
 *
 * A short list rather than a guess: the shell half of this is being named
 * right now, and a status bar that reads zero because a field was called
 * something reasonable is worse than one that accepts three reasonable names.
 * When the real name is known, the alternatives come out of this table.
 */
const COUNT_NAMES = {
  agents: ["agentsConnected"],
  driving: ["sessionsDriven"],
  sessions: ["sessionsLive"],
} as const;

/**
 * One count, by any of its accepted names.
 *
 * An array counts as its length, because a build that sends the attachments
 * themselves has told us the number just as plainly as one that sends a
 * number. Anything else, a missing field included, is "not reported".
 */
function count(raw: Record<string, unknown>, names: readonly string[]): number | null {
  for (const name of names) {
    const v = raw[name];
    if (typeof v === "number" && Number.isFinite(v)) return Math.max(0, Math.round(v));
    if (Array.isArray(v)) return v.length;
  }
  return null;
}

const strOrNull = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

/**
 * Read a plane payload, or refuse it.
 *
 * Accepts both things that carry this news: the `agent_status` answer, which
 * has `enabled` and no `type` at all, and the `type: "plane"` event. A lease
 * payload is refused here and a plane payload is refused by
 * {@link parseActivityEvent}, so one listener can offer each payload to both
 * and exactly one of them takes it.
 */
/**
 * Fold a newer payload onto what we already knew.
 *
 * Three payloads share {@link PlaneStatus} and none carries every field: the
 * `plane` event says whether the socket is up, the `counts` event says how many
 * of what, and only the `agent_status` seed says both. So a null in the newer
 * one means "no news about this", never "it went away", and replacing wholesale
 * would make a counts event read as the plane switching itself off.
 *
 * `enabled` is the one that matters most: it gates whether any agent chrome
 * renders at all, so losing it blinks the entire surface away and back on every
 * time an agent attaches.
 */
export function mergePlaneStatus(prev: PlaneStatus, next: PlaneStatus): PlaneStatus {
  const keep = <T>(fresh: T | null, held: T | null): T | null => (fresh === null ? held : fresh);
  return {
    enabled: keep(next.enabled, prev.enabled),
    socket: keep(next.socket, prev.socket),
    // The exception. An error is cleared by the payload that reports success,
    // so a bind failure does not outlive the bind that fixed it. `plane` always
    // states it, `counts` never does, which is why this follows `enabled`.
    error: next.enabled === null ? prev.error : next.error,
    agents: keep(next.agents, prev.agents),
    driving: keep(next.driving, prev.driving),
    sessions: keep(next.sessions, prev.sessions),
    binary: keep(next.binary, prev.binary),
    httpUrl: keep(next.httpUrl, prev.httpUrl),
  };
}

export function parsePlaneStatus(raw: unknown): PlaneStatus | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const kind = str(r.type);
  // Three carriers, one shape. `agent_status` answers with no `type` and an
  // `enabled` boolean; the shell emits `plane` when the socket comes up or goes
  // down, and `counts` when a number moves. They are two event types rather
  // than one deliberately: the plane's own state changes when somebody toggles
  // a setting, roughly never, while the counts move on every attach, detach and
  // lease change, so folding them together would wake every consumer that only
  // wants to know whether the socket exists.
  //
  // A `counts` payload carries no `enabled`, so it must not be read as the
  // plane switching itself off. `planeView` treats a null `enabled` as "no news"
  // and keeps whatever the last plane payload said.
  const isCounts = kind === "counts";
  if (kind ? kind !== "plane" && !isCounts : typeof r.enabled !== "boolean") return null;
  return {
    enabled: isCounts ? null : r.enabled === true,
    socket: strOrNull(r.socket),
    error: strOrNull(r.error),
    agents: count(r, COUNT_NAMES.agents),
    driving: count(r, COUNT_NAMES.driving),
    sessions: count(r, COUNT_NAMES.sessions),
    binary: strOrNull(r.binary),
    httpUrl: strOrNull(r.httpUrl),
  };
}

/** Everything a surface needs to say about the plane, with nothing left null. */
export interface PlaneView {
  /** Is there a plane at all? Nothing agent shaped renders while this is false. */
  on: boolean;
  /** Agents attached. */
  agents: number;
  /** Machines an agent holds the lease on right now. */
  driving: number;
  /** Live sessions in all, or 0 for "this build does not say". */
  sessions: number;
  socket: string | null;
  error: string | null;
  binary: string | null;
  httpUrl: string | null;
}

export const PLANE_OFF: PlaneView = {
  on: false,
  agents: 0,
  driving: 0,
  sessions: 0,
  socket: null,
  error: null,
  binary: null,
  httpUrl: null,
};

/**
 * What the plane reported, reconciled with what this window can see for itself.
 *
 * Three rules, and each one exists to stop the strip saying something that is
 * not so.
 *
 * A count this build does not report falls back to what the lease store knows,
 * which is a floor rather than a total: an agent attached to nothing holds no
 * lease and appears in no entry, so the derived agent count can only ever be
 * too low. It is used because "1 agent driving 1" while an agent is visibly
 * driving beats "no agent connected".
 *
 * Driving cannot exceed the sessions there are, and a reported total below it
 * would be a snapshot taken between two events rather than a fact, so the
 * total is raised to meet it. An unreported total stays 0, which
 * {@link planeStatusLine} renders as no total at all rather than as "of 0".
 *
 * And a lease held by an agent is proof the plane is on, whatever a stale
 * `enabled` says, because nothing can hold one otherwise.
 */
export function planeView(reported: PlaneStatus | null, state: AgentState): PlaneView {
  const driving = reported?.driving ?? drivenCount(state);
  const derived = new Set(
    Object.values(state)
      .filter(drivenByAgent)
      .map((a) => a.holder?.name ?? ""),
  );
  let agents = reported?.agents ?? derived.size;
  // An agent has to be attached to hold a lease, so a count of none beside a
  // machine being driven is a count we do not believe.
  if (driving > 0) agents = Math.max(agents, 1);
  const sessions = reported?.sessions === null || reported?.sessions === undefined
    ? 0
    : Math.max(reported.sessions, driving);
  return {
    on: reported?.enabled === true || driving > 0,
    agents,
    driving,
    sessions,
    socket: reported?.socket ?? null,
    error: reported?.error ?? null,
    binary: reported?.binary ?? null,
    httpUrl: reported?.httpUrl ?? null,
  };
}

const agentWord = (n: number): string => (n === 1 ? "1 agent" : `${n} agents`);

/**
 * The status line: agents, what they are driving, and out of how much.
 *
 * "2 agents driving 5 of 11". Driving is the lease and nothing else, so an
 * agent that is attached and idle is counted in the first number and in
 * neither of the others. That distinction is the whole reason this line is
 * three numbers rather than one.
 */
export function planeStatusLine(plane: PlaneView): string {
  if (!plane.on) return "";
  if (plane.agents === 0) return "No agent connected";
  if (plane.driving === 0) return `${agentWord(plane.agents)} connected, none driving`;
  const of = plane.sessions > 0 ? ` of ${plane.sessions}` : "";
  return `${agentWord(plane.agents)} driving ${plane.driving}${of}`;
}

/** The same thing at length, for the tooltip and the screen reader. */
export function planeStatusDetail(plane: PlaneView): string {
  if (!plane.on) return "";
  const total =
    plane.sessions > 0
      ? ` ${plane.sessions === 1 ? "1 session is" : `${plane.sessions} sessions are`} live in all.`
      : "";
  if (plane.agents === 0) {
    return `No agent is attached to this computer.${total}`;
  }
  const held =
    plane.driving === 0
      ? "None of them holds a lease, so nothing is being driven"
      : `${plane.driving === 1 ? "1 machine is" : `${plane.driving} machines are`} being driven`;
  return `${agentWord(plane.agents)} attached. ${held}.${total} Driving means an agent holds the lease; an attached agent that holds none is driving nothing.`;
}
