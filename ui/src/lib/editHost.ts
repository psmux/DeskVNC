/**
 * "Open this computer's settings", asked for from somewhere that cannot open
 * a dialog itself.
 *
 * The host editor lives in the library window. A session may be in a window
 * of its own, so a disconnect panel that wants to send the user to a setting
 * broadcasts this instead of trying to render the editor where it is not.
 *
 * `section` says where to land. `"security"` opens Advanced with the Security
 * disclosure already expanded, which is the same "open it expanded" rule the
 * editor applies to a setting that is already on: a setting that changes how
 * the connection is made is never reachable only by people who remember it
 * exists.
 */
import type { OpenSessionOptions } from "./tauri";

export const EDIT_HOST_EVENT = "library://edit-host";

/**
 * The agent plane asking the library to open a machine the way a click does.
 *
 * The plane cannot build a tab: the tab strip lives in this webview, and the
 * tab-or-window preference (`settings.windowMode`) lives in browser storage
 * the shell cannot read. So instead of the shell guessing, it sends the same
 * request a click would make and this window runs its own `openSession`,
 * which honours the preference, de-duplicates, and mounts the viewer exactly
 * as it does for a person. The shell then finds the session by machine and
 * hands it to the agent. Before this, an agent open either dialled nothing at
 * all (0.23.0 to 0.26.0) or always opened a window (0.26.1).
 */
export const AGENT_OPEN_EVENT = "library://agent-open";

export interface AgentOpenRequest {
  hostId?: string | null;
  address: string;
  port: number;
  protocol: "vnc" | "rdp" | "ssh";
  /** Open behind what the person is looking at, without selecting it. */
  background?: boolean;
}

/**
 * What the library opens for an agent's request.
 *
 * A saved machine is opened by its id whether or not this window's host list
 * has it yet. The list is read when the window loads, so a machine saved
 * after that is missing from it. Opening that one by address registered the
 * session under its endpoint, the shell waiting for it under the profile id
 * never saw it claimed, and it opened a second connection to the same machine
 * that nothing ever closed.
 */
export function agentOpenOptions(ask: AgentOpenRequest): OpenSessionOptions {
  const background = ask.background === true;
  return ask.hostId
    ? { profileId: ask.hostId, background }
    : { address: ask.address, port: ask.port, protocol: ask.protocol, background };
}

export interface EditHostRequest {
  hostId: string;
  section?: "security";
}
