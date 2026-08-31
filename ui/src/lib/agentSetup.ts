/**
 * Connecting an agent: the button that does it, and the lines behind it.
 *
 * THE ORDER MATTERS. Registration is a button now, not a paste. The shell runs
 * `claude mcp add` itself and reports what happened, so the ordinary path
 * through the modal is one press and no terminal at all. The copyable lines
 * stay underneath, folded away, for somebody who wants to read what the button
 * did or who drives a different agent.
 *
 * They are built here rather than written into the modal for two reasons. A
 * command with a path in it has a quoting rule, and a quoting rule that lives
 * in JSX is a quoting rule nothing can test; and the honest handling of a path
 * this application does not know is a decision, not a template, so it is made
 * once and made visibly.
 *
 * Nothing here is React and nothing here reads the plane. The caller passes
 * what it has and gets back a string.
 *
 * WHEN THE PATH IS NOT KNOWN. An installed build ships `dvv` inside the bundle
 * and the plane reports its absolute path, so every line below is complete and
 * runnable with nothing left to edit. A development build has no bundle to read
 * it out of and reports nothing, truthfully, and the only honest answer to a
 * path we do not have is a placeholder that is obviously one: an invented
 * path would be right on the machine it was written on and wrong everywhere
 * else, which is the one failure a copy button must never have. When that
 * happens {@link binaryNote} says so in a sentence, rather than leaving
 * somebody to work out why a command has a hole in it.
 */

/** What stands in for a path we do not have. Obviously not a real path. */
export const DVV_PATH_PLACEHOLDER = "/path/to/dvv";

/** The MCP server's name, as `claude mcp add` will register it. */
export const MCP_SERVER_NAME = "deskvnc";

/**
 * The environment variable the HTTP line reads the token out of.
 *
 * The token stays out of the pasted command deliberately. A command line is
 * the least private place on a computer: it lands in shell history, in a
 * screen share and in whatever a person pastes it into next.
 */
export const TOKEN_ENV = "DESKVNC_TOKEN";

/**
 * Where an HTTP listener answers when nobody said otherwise.
 *
 * AGREED with the transport: `crates/dvv/src/http.rs` defaults to `127.0.0.1`
 * on port 7333 and serves the MCP endpoint at `/mcp`. Loopback is the default
 * and binding wider takes its own flag, which prints what was just exposed.
 *
 * The UI shows this rather than waiting to be told one, because the listener
 * runs in the `dvv` process and is started by the person reading the modal, so
 * the shell has no way to know whether one exists. Waiting for news that
 * cannot arrive would hide the whole transport.
 */
export const HTTP_DEFAULT_URL = "http://127.0.0.1:7333/mcp";

const WINDOWS_PATH = /^(?:[A-Za-z]:[\\/]|\\\\)/;

/**
 * Make a path safe to paste, and leave an ordinary one alone.
 *
 * Quoting everything would be safer still and reads worse: the overwhelmingly
 * common case is a path with nothing special in it, and a person comparing the
 * line with what `dvv doctor` printed should see the same characters in both.
 * A Windows path takes double quotes because a single quoted string is not a
 * thing in `cmd`, and it cannot contain a double quote in the first place.
 */
export function shellQuote(path: string): string {
  if (!/[\s"'$`\\&|;<>()*?]/.test(path)) return path;
  if (WINDOWS_PATH.test(path)) return `"${path.replace(/"/g, "")}"`;
  // The POSIX idiom: close the quote, escape the apostrophe, open it again.
  return `'${path.replace(/'/g, "'\\''")}'`;
}

/** True when the line below carries a real path rather than the placeholder. */
export function knowsBinary(binary: string | null): boolean {
  return typeof binary === "string" && binary.trim().length > 0;
}

/**
 * Register the stdio server with Claude Code.
 *
 * Byte for byte what `dvv doctor` prints, which is deliberate: a person who
 * runs both should not have to work out whether two different looking lines do
 * the same thing.
 */
export function mcpAddLine(binary: string | null): string {
  const path = knowsBinary(binary) ? shellQuote(binary!.trim()) : DVV_PATH_PLACEHOLDER;
  return `claude mcp add --scope user ${MCP_SERVER_NAME} -- ${path} mcp --stdio`;
}

/** The one line that says whether any of this is working. */
export function doctorLine(binary: string | null): string {
  return knowsBinary(binary) ? `${shellQuote(binary!.trim())} doctor` : "dvv doctor";
}

/**
 * The same registration over HTTP, with the token left out of it.
 *
 * The header is spelled with the variable rather than the secret, so the line
 * can be copied, pasted and shared without carrying anything private. Setting
 * the variable is the step above it, and the token reaches the clipboard from
 * the modal's own button without ever being drawn on screen.
 */
export function httpAddLine(url: string): string {
  return `claude mcp add --transport http ${MCP_SERVER_NAME} ${url} --header "Authorization: Bearer $${TOKEN_ENV}"`;
}

/** Put the token in the environment first, without typing it out. */
export function tokenExportLine(): string {
  return `read -rs ${TOKEN_ENV} && export ${TOKEN_ENV}`;
}

/**
 * Start the HTTP listener.
 *
 * It prints its own `claude mcp add` line at startup with the live token
 * already substituted, which is the copy anybody should actually use. The line
 * shown beside this one is the same command with the token left out, for
 * somebody who wants to read it before running anything.
 */
export function httpServeLine(binary: string | null): string {
  return knowsBinary(binary)
    ? `${shellQuote(binary!.trim())} mcp --http`
    : `${DVV_PATH_PLACEHOLDER} mcp --http`;
}

/**
 * Say why a line has a hole in it, or say nothing at all.
 *
 * Null in the ordinary case, which is an installed build: the plane reports
 * where `dvv` is, every line is complete, and a paragraph explaining that
 * nothing is wrong is a paragraph nobody should have to read. It speaks up
 * only when the placeholder is on screen, because a person looking at
 * `/path/to/dvv` deserves to know whose fault it is and what fills it in.
 */
export function binaryNote(binary: string | null): string | null {
  if (knowsBinary(binary)) return null;
  return (
    "This build is not reporting where dvv is. The path comes from inside the " +
    "application bundle, and a development build does not have one. Run dvv doctor " +
    "on a copy that does and it prints these lines with the real path already in them."
  );
}

/**
 * What an agent can do, and the one thing it will never do.
 *
 * Short, and honest in both directions. An agent that finds out where the edge
 * is by hitting it wastes a person's afternoon.
 *
 * The list moves as the socket grows: opening a saved machine and running a
 * command over SSH were both limits and are limits no longer, so they read as
 * capabilities here rather than sitting in a list of regrets nobody reread.
 *
 * WHAT DOES NOT MOVE, and is not waiting on anybody. An agent cannot answer a
 * password or a certificate prompt. That is a boundary rather than a gap
 * (`00 R16`, `09 §4`): a model that could type a secret it had read off a
 * screen would leave an audit trail saying a person authorised it, and an
 * audit trail that lies is worse than no audit trail. Opening a machine works
 * because the credential comes out of the keychain into the transport, where
 * the agent can neither supply one nor read one back.
 */
export const AGENT_CAN: readonly string[] = [
  "Open one of your saved machines. The credential comes from the keychain, and the agent neither supplies it nor sees it.",
  "Drive it and watch itself work: pointer, keyboard, clipboard, and the screen.",
  "Run a command over SSH and read the output back, with the exit code it really got.",
  "Hand control back the instant you want it. Clicking a pane, or pressing stop, takes the lease.",
];

export const AGENT_CANNOT: readonly string[] = [
  "Answer a password or a certificate prompt. Those stay yours.",
];

/** Why the line above is a boundary and not a feature somebody forgot. */
export const AGENT_BOUNDARY_WHY =
  "That one is deliberate and it is not going to change. An agent that could type " +
  "a secret it read off a screen would leave a record saying you approved it, and a " +
  "record that says the wrong thing is worse than none.";

// ---------------------------------------------------------------------------
// Registering, without a terminal
// ---------------------------------------------------------------------------
//
// The shell runs `claude mcp add` itself and says what came of it. This is the
// whole reason the modal has a button where it used to have a line to copy.
//
// The names below are read in exactly one place on purpose, so reconciling
// this half with the shell is an edit to this section and to nothing else.
// Every component reads {@link parseRegisterResult}.

/**
 * Register the stdio server with Claude Code, on the person's behalf. AGREED.
 *
 * `src-tauri/src/commands/agent.rs`. Takes no arguments, runs
 * `claude mcp add --scope user deskvnc -- <bundled dvv> mcp --stdio` on a
 * blocking thread and answers `agent::RegistrationOutcome`, which serializes
 * internally tagged on `status` with kebab-case arm names.
 *
 * A build that does not have this command answers nothing through
 * `safeInvoke`, which is not an error and is not treated as one: it becomes
 * `unsupported`, and the modal opens the copyable lines instead.
 */
export const AGENT_REGISTER_COMMAND = "agent_register_with_claude";

/**
 * What came of pressing the button.
 *
 * Seven arms rather than the obvious two, because "it did not work" is six
 * different situations with six different next steps, and a button that
 * flattens them into one message sends somebody looking in the wrong place.
 * Six of them come off the wire and the seventh is the absence of a wire.
 *
 * `registered`  it is registered now, this press did it.
 * `already`     it was registered before, and nothing changed.
 * `no-claude`   Claude Code is not on this computer, so there was nothing to
 *               register with. Not a failure of ours.
 * `no-binary`   this build has no `dvv` inside it to register, which is what a
 *               development build looks like. Nothing broken.
 * `timed-out`   `claude` was still running when the clock ran out and has been
 *               stopped.
 * `failed`      it ran and refused, and `detail` carries its own stderr.
 * `unsupported` this build has no such command at all, so `safeInvoke`
 *               answered its fallback. Falls back to the paste.
 */
export type RegisterOutcome =
  | "registered"
  | "already"
  | "no-claude"
  | "no-binary"
  | "timed-out"
  | "failed"
  | "unsupported";

export interface RegisterResult {
  outcome: RegisterOutcome;
  /** What the shell said for itself, tidied. Empty when it said nothing. */
  detail: string;
}

/** How much of a shell message is worth putting in a modal. */
const DETAIL_MAX = 240;

/**
 * Words that mean each outcome, folded to letters so spelling cannot matter.
 *
 * The six on the left of each group are the shell's own arm names, kebab-cased
 * on the wire and folded to letters here. The rest are spellings of the same
 * six that a rename would plausibly land on, kept because they cost one line
 * each and because a modal that says "it did not work" over an arm called
 * `AlreadyAdded` instead of `AlreadyRegistered` would be lying about a success.
 */
const REGISTER_WORDS: Readonly<Record<string, RegisterOutcome>> = {
  registered: "registered",
  added: "registered",
  ok: "registered",
  success: "registered",
  succeeded: "registered",
  installed: "registered",
  done: "registered",
  alreadyregistered: "already",
  already: "already",
  alreadyadded: "already",
  alreadyexists: "already",
  alreadypresent: "already",
  exists: "already",
  present: "already",
  unchanged: "already",
  claudenotfound: "no-claude",
  noclaude: "no-claude",
  claudemissing: "no-claude",
  notfound: "no-claude",
  missing: "no-claude",
  notinstalled: "no-claude",
  nocli: "no-claude",
  nobinary: "no-binary",
  nodvv: "no-binary",
  notbundled: "no-binary",
  timedout: "timed-out",
  timeout: "timed-out",
  failed: "failed",
  failure: "failed",
  error: "failed",
};

/** Fields that might carry the outcome word, most likely first. */
const WORD_KEYS = ["outcome", "status", "result", "kind", "type", "state"] as const;

/** Fields that might carry something the shell wants to say. */
const DETAIL_KEYS = ["message", "detail", "details", "error", "reason", "stderr", "output"] as const;

const fold = (s: string): string => s.toLowerCase().replace(/[^a-z]/g, "");

/**
 * Make a shell message fit in a modal without hiding what it said.
 *
 * Control characters out, whitespace collapsed, length capped. A build failure
 * can arrive as half a screen of stderr, and a paragraph that pushes the button
 * off the top of the dialog is a message nobody finishes reading anyway.
 */
function tidy(text: string): string {
  const flat = text
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return flat.length > DETAIL_MAX ? `${flat.slice(0, DETAIL_MAX - 1).trimEnd()}…` : flat;
}

function firstString(r: Record<string, unknown>, keys: readonly string[]): string {
  for (const key of keys) {
    const v = r[key];
    if (typeof v === "string" && v.trim()) return tidy(v);
  }
  return "";
}

/**
 * Read whatever the shell answered, and never throw.
 *
 * Deliberately generous. A boolean, a word, an object with a field, a serde
 * enum arriving as one key naming its arm: all of them are ways a Rust command
 * reasonably reports this, and which one it turns out to be should not decide
 * whether a person believes the button worked. Anything it genuinely cannot
 * place with a message attached is a failure carrying that message, and
 * anything it cannot place at all is `unsupported`, which sends the reader to
 * the lines they can run by hand.
 */
export function parseRegisterResult(raw: unknown): RegisterResult {
  if (raw === null || raw === undefined) return { outcome: "unsupported", detail: "" };
  if (typeof raw === "boolean") return { outcome: raw ? "registered" : "failed", detail: "" };
  if (typeof raw === "string") {
    const word = REGISTER_WORDS[fold(raw)];
    // A string we cannot place is the shell explaining itself in prose, which
    // it only bothers to do when something went wrong.
    return word ? { outcome: word, detail: "" } : { outcome: "failed", detail: tidy(raw) };
  }
  if (typeof raw !== "object") return { outcome: "unsupported", detail: "" };

  const r = raw as Record<string, unknown>;
  const detail = firstString(r, DETAIL_KEYS);

  for (const key of WORD_KEYS) {
    const v = r[key];
    if (typeof v !== "string") continue;
    const word = REGISTER_WORDS[fold(v)];
    if (word) return { outcome: word, detail };
  }

  for (const key of ["ok", "registered", "success"]) {
    const v = r[key];
    if (typeof v === "boolean") return { outcome: v ? "registered" : "failed", detail };
  }

  // An externally tagged serde enum: one key, named for the arm, wrapping
  // whatever that arm carries.
  const keys = Object.keys(r);
  if (keys.length === 1) {
    const word = REGISTER_WORDS[fold(keys[0])];
    if (word) {
      const inner = r[keys[0]];
      if (typeof inner === "string" && inner.trim()) return { outcome: word, detail: tidy(inner) };
      if (inner && typeof inner === "object") {
        return { outcome: word, detail: firstString(inner as Record<string, unknown>, DETAIL_KEYS) };
      }
      return { outcome: word, detail: "" };
    }
  }

  return detail ? { outcome: "failed", detail } : { outcome: "unsupported", detail: "" };
}

/**
 * The sentence the modal puts under the button.
 *
 * Every arm says what happened and, where there is one, what to do next. None
 * of them says "an error occurred", which tells a person only that they are on
 * their own.
 */
export function registerLine(result: RegisterResult): string {
  switch (result.outcome) {
    case "registered":
      return "Registered. If Claude Code is already running, restart it so it picks this up.";
    case "already":
      return "Already registered. There was nothing left to do.";
    case "no-claude":
      return "Claude Code is not on this computer, so there was nothing to register with. Install it, or copy the line below into whichever agent you use.";
    case "no-binary":
      return "This build has no dvv inside it to register, which is what a development build looks like. An installed copy carries one, and the line below does it by hand.";
    case "timed-out":
      return "Claude Code did not finish and has been stopped. Press it again, or run the line below yourself and watch what it says.";
    case "failed":
      return result.detail
        ? `It did not go through. ${result.detail}`
        : "It did not go through, and the shell did not say why. The line below does the same thing by hand.";
    case "unsupported":
      return "This build cannot do it for you. Copy the line below and run it instead.";
  }
}

/**
 * Which of the three colours the modal already owns this outcome deserves.
 *
 * `no-binary` is the interesting one: it is grey rather than amber, because
 * the shell is telling us this is a development build and nothing is broken.
 * Painting a warning over "you are running the app you just compiled" trains
 * somebody to ignore the colour when it eventually means something.
 */
export function registerTone(outcome: RegisterOutcome): "success" | "info" | "warning" {
  if (outcome === "registered") return "success";
  if (outcome === "already" || outcome === "no-binary") return "info";
  return "warning";
}

/**
 * True when the answer leaves a person with something to do by hand.
 *
 * Every arm but the two that finished the job. It opens the fold rather than
 * mentioning it, because a message that points at something folded away is a
 * message asking somebody to go and look for their own answer.
 */
export function needsManualSetup(outcome: RegisterOutcome): boolean {
  return outcome !== "registered" && outcome !== "already";
}
