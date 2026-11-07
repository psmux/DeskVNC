/**
 * Asks for the master password of the encrypted credential file, the store
 * DeskVNC uses when the computer has no usable keychain.
 *
 * `CredentialUnlockHost` is mounted once in the main window. It opens the
 * dialog when a save had to wait for the unlock (`credential-store-locked`),
 * once at start when a file from an earlier run is locked, and whenever
 * Preferences asks (`OPEN_CREDENTIAL_UNLOCK`). Closing it is respected for the
 * rest of the run: later saves that have to wait say so in a toast with an
 * Unlock action instead of opening it again.
 */
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Dialog } from "./primitives";
import { IconLock } from "./icons";
import { safeListen } from "../lib/tauri";
import {
  CREDENTIAL_STORE_LOCKED,
  credentialStatus,
  unlockCredentials,
  type CredentialStatus,
} from "../lib/credentialStore";
import { useToasts } from "../state/ToastContext";

/** A window event Preferences dispatches to open the dialog on request. */
export const OPEN_CREDENTIAL_UNLOCK = "deskvnc:open-credential-unlock";
/** Dispatched after a successful unlock, so open views can re-read the status. */
export const CREDENTIALS_UNLOCKED = "deskvnc:credentials-unlocked";

export const MIN_MASTER_PASSWORD = 8;

export type UnlockMode = "create" | "enter";

export function CredentialUnlockDialog({
  mode,
  waiting,
  onUnlock,
  onClose,
}: {
  mode: UnlockMode;
  /** Saves waiting for this unlock. */
  waiting: number;
  onUnlock: (masterPassword: string) => Promise<void>;
  onClose: () => void;
}): ReactNode {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const creating = mode === "create";
  const tooShort = creating && password.length > 0 && password.length < MIN_MASTER_PASSWORD;
  const mismatch = creating && confirm.length > 0 && confirm !== password;
  const ready =
    password.length > 0 &&
    !busy &&
    (!creating || (password.length >= MIN_MASTER_PASSWORD && confirm === password));

  const submit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await onUnlock(password);
    } catch (err) {
      setError(
        /master password/i.test(String(err))
          ? "That master password is not the one this file was locked with."
          : `Could not unlock the password file: ${String(err)}`,
      );
      setBusy(false);
    }
  };

  const waitingLine =
    waiting === 1
      ? "One password you asked to remember is waiting for this."
      : waiting > 1
        ? `${waiting} passwords you asked to remember are waiting for this.`
        : null;

  return (
    <Dialog
      title={creating ? "Choose a master password" : "Unlock saved passwords"}
      onClose={onClose}
      width={460}
    >
      <form className="space-y-4" onSubmit={(e) => void submit(e)}>
        <div className="flex items-start gap-3">
          <span className="mt-0.5 shrink-0 text-accent">
            <IconLock size={20} />
          </span>
          <p className="text-sm text-primary" data-testid="unlock-explainer">
            {creating
              ? "This computer has no keychain DeskVNC can use, so saved passwords are kept in an encrypted file instead. Choose a master password for it. You will be asked for it once each time DeskVNC starts."
              : "Saved passwords on this computer are kept in an encrypted file. Enter its master password to use them."}
            {waitingLine ? <span className="mt-1 block text-xs text-secondary">{waitingLine}</span> : null}
          </p>
        </div>

        <label className="block">
          <span className="mb-1 block text-xs font-medium text-secondary">Master password</span>
          <input
            data-autofocus
            className="field"
            type="password"
            name="master-password"
            autoComplete={creating ? "new-password" : "current-password"}
            spellCheck={false}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {tooShort ? (
          <p className="text-xs text-tertiary">Use at least {MIN_MASTER_PASSWORD} characters.</p>
        ) : null}

        {creating ? (
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-secondary">Type it again</span>
            <input
              className="field"
              type="password"
              name="master-password-confirm"
              autoComplete="new-password"
              spellCheck={false}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </label>
        ) : null}
        {mismatch ? <p className="text-xs text-danger">The two passwords differ.</p> : null}

        {error ? (
          <p className="rounded-md bg-danger-subtle p-2.5 text-xs text-primary" role="alert">
            {error}
          </p>
        ) : null}

        <div className="flex justify-end gap-2.5 pt-1">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Not now
          </button>
          <button type="submit" className="btn-primary disabled:opacity-40" disabled={!ready}>
            {creating ? "Create" : "Unlock"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function CredentialUnlockHost(): ReactNode {
  const [status, setStatus] = useState<CredentialStatus | null>(null);
  const [open, setOpen] = useState(false);
  const declined = useRef(false);
  const { push } = useToasts();

  const show = useCallback(async (): Promise<void> => {
    const now = await credentialStatus();
    if (!now || now.backend !== "Locked") return;
    setStatus(now);
    setOpen(true);
  }, []);

  // A file from an earlier run is asked for once at start; with no file
  // there is nothing to unlock until something is saved.
  useEffect(() => {
    void credentialStatus().then((now) => {
      if (now && now.backend === "Locked" && now.vaultExists) {
        setStatus(now);
        setOpen(true);
      }
    });
  }, []);

  useEffect(() => {
    const unlisten = safeListen<{ hostId: string }>(CREDENTIAL_STORE_LOCKED, () => {
      if (!declined.current) {
        void show();
        return;
      }
      push("warning", "A password is waiting to be saved until you unlock saved passwords.", {
        label: "Unlock",
        run: () => void show(),
      });
    });
    return () => {
      void unlisten.then((f) => f());
    };
  }, [push, show]);

  useEffect(() => {
    const onAsk = (): void => void show();
    window.addEventListener(OPEN_CREDENTIAL_UNLOCK, onAsk);
    return () => window.removeEventListener(OPEN_CREDENTIAL_UNLOCK, onAsk);
  }, [show]);

  if (!open || !status) return null;
  return (
    <CredentialUnlockDialog
      mode={status.vaultExists ? "enter" : "create"}
      waiting={status.parkedSaves}
      onUnlock={async (pw) => {
        const written = await unlockCredentials(pw);
        setOpen(false);
        window.dispatchEvent(new CustomEvent(CREDENTIALS_UNLOCKED, { detail: written }));
        push(
          "success",
          written.length > 0
            ? "Saved passwords are unlocked and the waiting password is saved."
            : "Saved passwords are unlocked.",
        );
      }}
      onClose={() => {
        declined.current = true;
        setOpen(false);
      }}
    />
  );
}
