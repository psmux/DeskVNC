/**
 * Interactive authentication prompt (PRD/10 §3.4).
 *
 * Raised by `session://event` `credentials-required` while the handshake is
 * PAUSED. Answering sends `provide_credentials`; dismissing sends
 * `cancel_credentials` and abandons the attempt.
 *
 * Notes that matter:
 * - The username field exists ONLY for identity-carrying methods
 *   (`kind === "username-and-password"`).
 * - "Remember" is opt-in and defaults to OFF. The checkbox is a *request*: the
 *   shell holds the value in memory and writes it to the keychain only after
 *   the server accepts it, so a wrong password is never persisted.
 * - The 8-character notice is a hard requirement for DES-based methods, which
 *   truncate silently, a 20-character password that "works" here would fail
 *   confusingly elsewhere.
 * - Nothing is echoed back out: this component is the only place the secret
 *   exists in JS, and it lives in state that unmounts with the dialog.
 */
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Dialog } from "./primitives";
import { IconAlert, IconLock } from "./icons";
import type { CredentialRequest } from "../lib/types";

/** DES truncation point for VncAuth / TLSVnc / X509Vnc. */
const VNC_PASSWORD_LIMIT = 8;

export function CredentialPrompt({
  request,
  hostName,
  onSubmit,
  onCancel,
}: {
  request: CredentialRequest;
  hostName: string;
  onSubmit: (username: string | null, password: string, save: boolean) => void;
  onCancel: () => void;
}): ReactNode {
  const needsUsername = request.kind === "username-and-password";
  const [username, setUsername] = useState(request.usernameHint ?? "");
  const [password, setPassword] = useState("");
  const [save, setSave] = useState(false); // opt-in, per PRD/10 §3.4
  const submitted = useRef(false);

  // A rejected attempt re-raises the prompt with a higher `attempt`. Clear the
  // password (it was wrong) and re-arm submission, but keep what the user
  // typed for the user name and their "remember" choice.
  useEffect(() => {
    submitted.current = false;
    setPassword("");
  }, [request.attempt]);

  const retry = request.attempt > 1;
  const truncating = request.truncatesPassword && password.length > VNC_PASSWORD_LIMIT;

  const submit = (e: FormEvent): void => {
    e.preventDefault();
    if (submitted.current || password.length === 0) return;
    submitted.current = true;
    onSubmit(needsUsername ? username : null, password, save);
  };

  return (
    <Dialog title="Authentication required" onClose={onCancel} width={460}>
      {/* A <form> so Enter submits from either field for free. Escape is
          handled by Dialog and maps to Cancel. */}
      <form className="space-y-4" onSubmit={submit}>
        <div className="flex items-start gap-3">
          <span className="mt-0.5 shrink-0 text-accent">
            <IconLock size={20} />
          </span>
          <div className="min-w-0">
            <p className="text-sm text-primary">
              <strong className="break-words">{hostName}</strong>{" "}
              {needsUsername
                ? "needs a user name and password before it will let you in."
                : "needs a password before it will let you in."}
            </p>
            <p className="mt-0.5 text-xs text-tertiary">{request.method}</p>
          </div>
        </div>

        {retry ? (
          <div
            className="flex items-start gap-2.5 rounded-md bg-danger-subtle p-3"
            role="alert"
            aria-live="assertive"
          >
            <span className="mt-0.5 shrink-0 text-danger">
              <IconAlert size={16} />
            </span>
            <p className="text-sm text-primary">
              {request.error?.trim() || "Incorrect password. Try again."}
              <span className="mt-0.5 block text-xs text-secondary">
                Attempt {request.attempt}
              </span>
            </p>
          </div>
        ) : null}

        {needsUsername ? (
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-secondary">User name</span>
            <input
              data-autofocus
              className="field"
              type="text"
              name="username"
              autoComplete="username"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
        ) : null}

        <label className="block">
          <span className="mb-1 block text-xs font-medium text-secondary">Password</span>
          <input
            data-autofocus={needsUsername ? undefined : true}
            className="field"
            type="password"
            name="password"
            autoComplete="current-password"
            spellCheck={false}
            aria-describedby={truncating ? "vnc-truncation-warning" : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>

        {truncating ? (
          <p
            id="vnc-truncation-warning"
            className="flex items-start gap-2 rounded-md bg-warning-subtle p-2.5 text-xs text-primary"
            role="status"
            aria-live="polite"
          >
            <span className="mt-px shrink-0 text-warning">
              <IconAlert size={14} />
            </span>
            <span>
              This server uses legacy VNC authentication, only the first {VNC_PASSWORD_LIMIT}{" "}
              characters are used.
            </span>
          </p>
        ) : null}

        <label className="flex items-start gap-2.5 text-sm text-primary">
          <input
            type="checkbox"
            className="mt-0.5 accent-(--accent)"
            checked={save}
            onChange={(e) => setSave(e.target.checked)}
          />
          <span>
            Remember for this computer
            <span className="block text-xs text-tertiary">
              Stored in your system keychain, never in a file. Saved only if this password works.
            </span>
          </span>
        </label>

        <div className="flex justify-end gap-2.5 pt-1">
          <button type="button" className="btn-secondary" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn-primary disabled:opacity-40" disabled={!password}>
            Connect
          </button>
        </div>
      </form>
    </Dialog>
  );
}
