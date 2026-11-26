/**
 * Keeping a machine that was opened without a saved host.
 *
 * Quick connect, a typed address, a machine from Nearby, an agent's `dvv open`
 * by address: each one opens a session with no host behind it. Right clicking
 * that session's tab offers "Add to saved hosts", and the dialog it opens
 * turns the session into a saved host and the tab into a tab of that host.
 *
 * The rules (which tab qualifies, what the dialog starts with, what gets
 * saved) live here, away from the plumbing, so they can be tested.
 */
import type { SessionParams } from "../hooks/useSession";
import { autoSaveProfile, canAutoSave, findSavedHost, sameAddress } from "./autoSave";
import type { DiscoveredHost, HostProfile } from "./types";

/**
 * What the shell says about the credentials a session used, from
 * `session_credential_state`. Never the secret, only whether there is one.
 */
export interface SessionCredentialState {
  /** The session signed in with a password typed at the prompt, and the server took it. */
  used: boolean;
  /** That prompt also carried a user name. */
  hasUsername: boolean;
  /** "Remember" was ticked at that prompt. */
  remembered: boolean;
}

export const NO_CREDENTIALS: SessionCredentialState = {
  used: false,
  hasUsername: false,
  remembered: false,
};

/** Read whatever the shell sent defensively: an older shell sends nothing. */
export function parseCredentialState(raw: unknown): SessionCredentialState {
  if (!raw || typeof raw !== "object") return NO_CREDENTIALS;
  const r = raw as Record<string, unknown>;
  const used = r.used === true;
  return {
    used,
    hasUsername: used && r.hasUsername === true,
    remembered: used && r.remembered === true,
  };
}

/**
 * Whether a session can be offered as a new saved host.
 *
 * A session that already belongs to a saved host has nothing to add. Boundary
 * is left out for the same reason the automatic save leaves it out: a paired
 * computer is already saved, and one reached through an invitation is one
 * time help, not a machine to keep.
 */
export function canSaveAsHost(params: Pick<SessionParams, "profileId" | "address" | "protocol">): boolean {
  return (
    params.profileId === null &&
    (params.address ?? "").trim() !== "" &&
    canAutoSave(params.protocol)
  );
}

/**
 * The session a tab's "Add to saved hosts" acts on: the one in its focused
 * pane, which is also the one the tab is named after. Null when the tab
 * offers nothing.
 */
export function saveTargetOf<S extends { params: SessionParams }>(
  focusedSessionId: string | null,
  sessions: Readonly<Record<string, S>>,
): S | null {
  if (!focusedSessionId) return null;
  const session = sessions[focusedSessionId];
  return session && canSaveAsHost(session.params) ? session : null;
}

/**
 * The name the dialog starts with: what the server calls its desktop (which
 * is what the tab shows), and the address when that says nothing more.
 */
export function suggestedName(title: string, address: string): string {
  const name = title.trim();
  if (name === "" || name === "New pane" || sameAddress(name, address)) return address.trim();
  return name;
}

/**
 * The saved host the dialog should point at instead of making a second one.
 * Same address and port is the test, whatever protocol it was saved under:
 * two hosts on one endpoint is the duplicate the person would trip over.
 */
export function existingHostFor(
  hosts: readonly HostProfile[],
  params: Pick<SessionParams, "address" | "port">,
): HostProfile | null {
  return findSavedHost(hosts, {
    address: params.address ?? "",
    port: params.port,
    protocol: null,
    explicitPort: true,
  });
}

/** Whether "Also save" starts ticked: only when the person asked at the prompt. */
export function saveCredentialsByDefault(creds: SessionCredentialState): boolean {
  return creds.used && creds.remembered;
}

/** The checkbox's words, which say exactly what will be kept. */
export function credentialsLabel(creds: SessionCredentialState): string {
  return creds.hasUsername
    ? "Also save the user name and password used for this session"
    : "Also save the password used for this session";
}

/**
 * The new host, built the way the automatic save builds one, so the two never
 * disagree: same protocol, address and port as the session, and the default
 * settings an unsaved session connects with (a host with no settings stored
 * gets exactly those defaults). Discovery's hints come along when it saw the
 * machine. Only the name is the person's.
 */
export function newHostForSession(input: {
  params: Pick<SessionParams, "address" | "port" | "protocol">;
  name: string;
  discovered: DiscoveredHost | null;
}): HostProfile {
  const address = (input.params.address ?? "").trim();
  const profile = autoSaveProfile({
    protocol: input.params.protocol,
    address,
    port: input.params.port,
    desktopName: null,
    discovered: input.discovered,
  });
  const name = input.name.trim();
  return { ...profile, friendlyName: name === "" ? address : name };
}

/**
 * The existing host, renamed if the person changed the name. Every setting it
 * already has is kept: those were chosen on purpose, and this session only
 * ran on defaults.
 */
export function updatedHost(existing: HostProfile, name: string): HostProfile {
  const trimmed = name.trim();
  if (trimmed === "" || trimmed === existing.friendlyName) return existing;
  return { ...existing, friendlyName: trimmed };
}
