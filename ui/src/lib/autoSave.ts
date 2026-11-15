/**
 * Saving a computer to the Library once a connection to it succeeds.
 *
 * Quick connect, Recents and the Nearby list all open ad hoc sessions, which
 * leave no host behind. With the "Save computers I connect to" preference on,
 * the Library turns each one into a saved host the first time it connects,
 * unless a saved host already covers that endpoint. The rules that decide
 * whether and how are here, apart from the plumbing, so they can be tested.
 */
import {
  blankHostProfile,
  hostMac,
  hostProtocol,
  resolvedOsHint,
  type DiscoveredHost,
  type HostProfile,
  type ProtocolKind,
} from "./types";
import { discoveredEndpoint } from "./address";

/**
 * Session window to Library, once a session first reaches connected:
 * `{ sessionId, desktopName }`. The Library only acts on sessions it opened
 * ad hoc itself, so an agent's session or a saved host's never triggers a save.
 */
export const SESSION_CONNECTED_EVENT = "library://session-connected";

/**
 * Library to session window, after a host was saved for that session:
 * `{ sessionId, name }`. The session shows the notice; the Library does not,
 * so a session in a tab does not get it twice.
 */
export const HOST_AUTOSAVED_EVENT = "library://host-autosaved";

export interface SessionConnectedPayload {
  sessionId: string;
  desktopName: string;
}

export interface HostAutoSavedPayload {
  sessionId: string;
  name: string;
}

/** Matches the Rust side's `normalize_address`, so both agree on "same machine". */
export function sameAddress(a: string, b: string): boolean {
  const norm = (s: string): string =>
    s
      .trim()
      .replace(/\.+$/, "")
      .replace(/[A-Z]/g, (c) => c.toLowerCase()); // ASCII only, as Rust does
  return norm(a) === norm(b);
}

/**
 * The saved host that already covers an endpoint, or null.
 *
 * `protocol: null` means the caller does not know it (a bare typed address),
 * so any protocol matches. `explicitPort: false` means the port is only the
 * default for a bare hostname, so a host saved on another port of that
 * machine still counts, the way quick connect has always matched.
 */
export function findSavedHost(
  hosts: readonly HostProfile[],
  target: { address: string; port: number; protocol: ProtocolKind | null; explicitPort?: boolean },
): HostProfile | null {
  const explicitPort = target.explicitPort ?? true;
  return (
    hosts.find(
      (h) =>
        sameAddress(h.address, target.address) &&
        (!explicitPort || h.port === target.port) &&
        (target.protocol === null || hostProtocol(h) === target.protocol),
    ) ?? null
  );
}

/** The discovery row for the endpoint that was dialled, if discovery saw it. */
export function discoveredFor(
  discovered: readonly DiscoveredHost[],
  protocol: ProtocolKind,
  address: string,
  port: number,
): DiscoveredHost | null {
  return (
    discovered.find((d) => {
      const e = discoveredEndpoint(d);
      return e.protocol === protocol && e.port === port && sameAddress(e.address, address);
    }) ?? null
  );
}

/**
 * Which sessions may become saved hosts. Boundary is left out: a Boundary
 * computer the user paired is already saved by the shell, and one reached
 * through an invitation is one time help, not a machine to keep.
 */
export function canAutoSave(protocol: ProtocolKind): boolean {
  return protocol === "vnc" || protocol === "rdp" || protocol === "ssh";
}

/**
 * The name a saved host gets: what discovery called it, then what the server
 * calls itself, then the address. A name that is only the address again
 * tells nobody anything, so it is passed over.
 */
export function autoSaveName(names: {
  discoveredName: string | null | undefined;
  desktopName: string | null | undefined;
  address: string;
}): string {
  for (const raw of [names.discoveredName, names.desktopName]) {
    const name = raw?.trim() ?? "";
    if (name !== "" && !sameAddress(name, names.address)) return name;
  }
  return names.address.trim();
}

/** A complete new host profile for a session that just connected. */
export function autoSaveProfile(input: {
  protocol: ProtocolKind;
  address: string;
  port: number;
  desktopName: string | null;
  discovered: DiscoveredHost | null;
}): HostProfile {
  const d = input.discovered;
  const serverHint = d?.serverHint?.trim() ?? "";
  return {
    ...blankHostProfile(input.protocol),
    friendlyName: autoSaveName({
      discoveredName: d?.name,
      desktopName: input.desktopName,
      address: input.address,
    }),
    address: input.address.trim(),
    port: input.port,
    osHint: d ? resolvedOsHint(d) : "unknown",
    serverHint: serverHint === "" ? null : serverHint,
    wolMac: hostMac(d),
  };
}

/**
 * The host the shell saved for this endpoint, renamed, or null to leave it.
 *
 * Ticking Remember on the first connect makes the shell save the host before
 * the auto save runs, named by its bare address. That one takes the better
 * name and any hints it lacks. A host someone named is never touched.
 */
export function renameAdopted(existing: HostProfile, profile: HostProfile): HostProfile | null {
  const bare = existing.friendlyName.trim() === existing.address.trim();
  if (!bare || profile.friendlyName === existing.friendlyName) return null;
  return {
    ...existing,
    friendlyName: profile.friendlyName,
    osHint: (existing.osHint ?? "unknown") === "unknown" ? profile.osHint : existing.osHint,
    serverHint: existing.serverHint ?? profile.serverHint,
    wolMac: existing.wolMac ?? profile.wolMac,
  };
}
