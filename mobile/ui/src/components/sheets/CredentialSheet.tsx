/**
 * Asks for a password (and maybe a user name) when a computer wants one.
 * Answers a `credentials-required` session event; the session screen passes
 * the result to `api.sessionCredentials`.
 */
import { useEffect, useState } from "react";
import type { CredentialRequest } from "../../api/contract";
import { IconLock } from "../../art/Icons";
import { SceneKey } from "../../art/Scenes";
import { Button } from "../Button";
import { Field, Toggle } from "../Field";
import { Sheet } from "../Sheet";

/** Classic VNC passwords stop counting after 8 characters (DES). */
export const VNC_PASSWORD_LIMIT = 8;

interface Props {
  open: boolean;
  request: CredentialRequest | null;
  hostName?: string;
  onSubmit: (username: string | null, password: string, save: boolean) => void;
  onCancel: () => void;
}

export function CredentialSheet({ open, request, hostName, onSubmit, onCancel }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [save, setSave] = useState(true);
  useEffect(() => {
    if (open) {
      setUsername(request?.usernameHint ?? "");
      setPassword("");
    }
  }, [open, request]);
  const needsUser = request?.kind === "username-and-password";
  const ready = password !== "" && (!needsUser || username.trim() !== "");
  // Said before it bites: a longer password "works" here and then fails on
  // the computer, which only ever read the first 8 characters.
  const truncating = !!request?.truncatesPassword && Array.from(password).length > VNC_PASSWORD_LIMIT;
  return (
    <Sheet
      open={open}
      onClose={onCancel}
      art={<SceneKey />}
      title={hostName ? `${hostName}: sign in` : "Sign in"}
      subtitle={needsUser ? "Use the name and password you use on that computer." : "This computer asks for its screen sharing password."}
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) onSubmit(needsUser ? username.trim() : null, password, save);
        }}
      >
        {(request?.error || (request?.attempt ?? 1) > 1) && (
          <p role="alert" className="rounded-2xl bg-danger-soft px-4 py-3 text-center font-medium text-danger">
            That did not work. Check the {needsUser ? "name and password" : "password"} and try again.
          </p>
        )}
        {needsUser && <Field label="User name" autoComplete="username" autoCapitalize="none" autoCorrect="off" value={username} onChange={(e) => setUsername(e.target.value)} />}
        <Field
          label="Password"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-describedby={truncating ? "dv-trunc-warning" : undefined}
          hint={request?.truncatesPassword && !truncating ? `Only the first ${VNC_PASSWORD_LIMIT} characters count for this kind of computer.` : undefined}
        />
        {truncating && (
          <p id="dv-trunc-warning" className="rounded-2xl border border-boundary/40 bg-boundary-soft px-4 py-3 text-[15px] leading-snug">
            This computer only reads the first {VNC_PASSWORD_LIMIT} characters of a password. We send them all, but only the first{" "}
            {VNC_PASSWORD_LIMIT} count.
          </p>
        )}
        <div className="flex items-center gap-3 rounded-2xl bg-surface-2 px-4 py-3">
          <IconLock className="text-ok" />
          <div className="flex-1">
            <p className="font-semibold">Remember on this phone</p>
            <p className="text-sm text-ink-dim">Kept safely in the phone's keychain.</p>
          </div>
          <Toggle on={save} onChange={setSave} label="Remember on this phone" />
        </div>
        <Button type="submit" size="xl" block disabled={!ready}>
          Sign in
        </Button>
        <Button variant="ghost" size="md" block onClick={onCancel}>
          Cancel
        </Button>
      </form>
    </Sheet>
  );
}
