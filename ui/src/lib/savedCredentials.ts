/**
 * Saved credentials (issue #98): a named user name and password, or a user
 * name and SSH key file, that any number of hosts sign in with. A host names
 * one by `credentialId`; changing the saved credential changes every host
 * that names it on its next connect.
 *
 * The webview never holds a saved password. `save_saved_credential` takes
 * one, the list says only `hasSecret`, exactly as a host's own password
 * works. The rules the editor and the manager share are pure functions here
 * so they can be tested without rendering.
 */
import { mustInvoke, safeInvoke } from "./tauri";
import { hostProtocol, type HostProfile, type ProtocolKind } from "./types";
import { isLockedError, type SaveOutcome } from "./credentialStore";
import { t, tn } from "../i18n";

export type SavedCredentialKind = "password" | "ssh-key";

/** Mirrors `vnc_store::CredentialProfile`. Never carries a secret. */
export interface SavedCredential {
  id: string;
  name: string;
  /** Plain string for the same reason `HostProfile.protocol` is one. */
  kind: string;
  username: string | null;
  domain: string | null;
  keyPath: string | null;
  hasSecret: boolean;
  createdAt: number;
  updatedAt: number;
}

export function blankSavedCredential(kind: SavedCredentialKind = "password"): SavedCredential {
  return {
    id: crypto.randomUUID(),
    name: "",
    kind,
    username: null,
    domain: null,
    keyPath: null,
    hasSecret: false,
    createdAt: 0,
    updatedAt: 0,
  };
}

/**
 * Whether a saved credential can sign in to a host speaking `protocol`. The
 * same rule as `CredentialProfile::fits` in Rust: a password works for VNC,
 * Remote Desktop and SSH, a key for SSH only, and nothing for Boundary.
 */
export function credentialFits(c: Pick<SavedCredential, "kind">, protocol: ProtocolKind): boolean {
  if (c.kind === "password") return protocol === "vnc" || protocol === "rdp" || protocol === "ssh";
  if (c.kind === "ssh-key") return protocol === "ssh";
  return false;
}

/** The credentials the editor offers for this protocol, by name. */
export function credentialsFor(all: SavedCredential[], protocol: ProtocolKind): SavedCredential[] {
  return all
    .filter((c) => credentialFits(c, protocol))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

/** The hosts that sign in with this credential, by name. */
export function hostsUsing(credentialId: string, hosts: HostProfile[]): HostProfile[] {
  return hosts
    .filter((h) => h.credentialId === credentialId)
    .sort((a, b) => a.friendlyName.localeCompare(b.friendlyName, undefined, { sensitivity: "base" }));
}

/**
 * The saved credential a host signs in with, or `null` when it keeps its own
 * or names one that is gone or no longer fits its protocol. Rust resolves
 * the same way, so the editor and the connect never disagree.
 */
export function linkedCredential(host: HostProfile, all: SavedCredential[]): SavedCredential | null {
  if (!host.credentialId) return null;
  const c = all.find((x) => x.id === host.credentialId);
  return c && credentialFits(c, hostProtocol(host)) ? c : null;
}

/** Whether a host will connect without asking: its own password, or a
 *  saved credential with a secret. Drives the key icon. */
export function hostHasSavedSecret(host: HostProfile, all: SavedCredential[]): boolean {
  return host.hasPassword || Boolean(linkedCredential(host, all)?.hasSecret);
}

/** One line under the picker saying what the host will sign in as. */
export function describeCredential(c: SavedCredential): string {
  const user = c.username?.trim()
    ? c.domain?.trim()
      ? `${c.domain.trim()}\\${c.username.trim()}`
      : c.username.trim()
    : null;
  if (c.kind === "ssh-key") {
    const key = c.keyPath?.split(/[\\/]/).pop();
    if (!key) return t("No key file is chosen yet.");
    return user
      ? t("Signs in as {user} with the key {key}.", { user, key })
      : t("Signs in as the same user as this computer with the key {key}.", { key });
  }
  if (user) {
    return c.hasSecret
      ? t("Signs in as {user} with its saved password.", { user })
      : t("Signs in as {user} and asks for the password when you connect.", { user });
  }
  return c.hasSecret
    ? t("Asks for the user name if the computer wants one, and uses its saved password.")
    : t("Asks for the user name and password when you connect.");
}

/**
 * What deleting a credential does, in words, for the confirm dialog. The
 * hosts are named so nobody finds out later which machines stopped
 * connecting.
 */
export function deleteSummary(c: SavedCredential, using: HostProfile[]): string {
  if (using.length === 0) {
    return t("No host uses {name}. Deleting it removes its saved password too.", { name: c.name });
  }
  const names = using.map((h) => h.friendlyName || h.address);
  const list =
    names.length <= 5
      ? names.join(", ")
      : t("{names} and {more} more", { names: names.slice(0, 5).join(", "), more: names.length - 5 });
  return `${tn(using.length, "1 host uses it: {list}.", "{count} hosts use it: {list}.", { list })} ${t(
    "Keep a copy on each host and they connect as before, each with its own copy that no longer follows changes. Otherwise they ask for a user name and password on their next connect.",
  )}`;
}

export function listSavedCredentials(): Promise<SavedCredential[]> {
  return safeInvoke<SavedCredential[]>("list_saved_credentials", undefined, []);
}

/**
 * Save a credential and, when `secret` is not empty, its password or key
 * passphrase. A locked encrypted file is not a failure: the shell keeps the
 * secret and the unlock dialog writes it.
 */
export async function saveSavedCredential(
  credential: SavedCredential,
  secret: string,
): Promise<{ saved: SavedCredential | null; outcome: SaveOutcome }> {
  try {
    const saved = await mustInvoke<SavedCredential>("save_saved_credential", {
      credential,
      secret: secret || null,
    });
    return { saved, outcome: "saved" };
  } catch (err) {
    if (isLockedError(err)) return { saved: null, outcome: "waiting-for-unlock" };
    throw err;
  }
}

export function deleteSavedCredential(credentialId: string, keepOnHosts: boolean): Promise<string[]> {
  return mustInvoke<string[]>("delete_saved_credential", { credentialId, keepOnHosts });
}
