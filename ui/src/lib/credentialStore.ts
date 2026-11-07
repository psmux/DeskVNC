/**
 * Where saved passwords live, and saving them without losing the error.
 *
 * On a desktop with no usable keychain (a Linux login with no default
 * keyring, or one where the person cancelled the "choose a password for the
 * new keyring" prompt) the shell keeps passwords in an encrypted file that
 * stays locked until the person gives its master password. Every save made
 * while it is locked is kept by the shell and announced with
 * `credential-store-locked`; `CredentialUnlockHost` asks for the master
 * password and the unlock writes them. A save that fails for any other
 * reason is shown to the person, never dropped.
 */
import { mustInvoke, safeInvoke } from "./tauri";

export type CredentialBackend = "OsKeychain" | "EncryptedFile" | "Locked";

export interface CredentialStatus {
  backend: CredentialBackend;
  /** The encrypted file exists, so unlocking checks a master password chosen before. */
  vaultExists: boolean;
  /** Saves waiting for the unlock. */
  parkedSaves: number;
}

export const CREDENTIAL_STORE_LOCKED = "credential-store-locked";

export async function credentialStatus(): Promise<CredentialStatus | null> {
  return safeInvoke<CredentialStatus | null>("credential_status", undefined, null);
}

/** Unlocks (or, the first time, creates) the encrypted file. Throws on a wrong password. */
export async function unlockCredentials(masterPassword: string): Promise<string[]> {
  return mustInvoke<string[]>("unlock_credentials", { masterPassword });
}

/** The shell's message for a save that is waiting for the master password. */
export function isLockedError(err: unknown): boolean {
  return /credential store is locked/i.test(String(err));
}

export type SaveOutcome = "saved" | "waiting-for-unlock";

/**
 * `save_password`, with its error kept. A locked store is not a failure: the
 * shell holds the password and the unlock dialog is already on its way, so
 * this resolves `"waiting-for-unlock"`. Anything else rejects, for the caller
 * to show.
 */
export async function saveCredentials(
  hostId: string,
  creds: object,
): Promise<SaveOutcome> {
  try {
    await mustInvoke("save_password", { hostId, creds });
    return "saved";
  } catch (err) {
    if (isLockedError(err)) return "waiting-for-unlock";
    throw err;
  }
}

/** One plain sentence about where passwords are kept, for Preferences. */
export function describeCredentialStore(status: CredentialStatus | null): string {
  if (!status) return "Passwords are stored in your operating system keychain, never in plain text.";
  switch (status.backend) {
    case "OsKeychain":
      return "Passwords are stored in your operating system keychain.";
    case "EncryptedFile":
      return "This computer has no usable keychain, so passwords are stored in an encrypted file protected by your master password. It is unlocked for now.";
    case "Locked":
      return status.vaultExists
        ? "This computer has no usable keychain, so passwords are stored in an encrypted file protected by your master password. Unlock it to use and save passwords."
        : "This computer has no usable keychain. Choose a master password to keep saved passwords in an encrypted file instead.";
  }
}
