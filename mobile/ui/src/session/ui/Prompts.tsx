/**
 * Sign in and certificate questions, as bottom sheets with big fields.
 * Behaviour follows the desktop app's CredentialPrompt.tsx and CertPrompt.tsx:
 * the DES password limit is pointed out before it bites, and a changed
 * certificate is a clear warning whose safe answer is the big button.
 */
import { useState } from "react";
import type { CredentialRequest } from "../../api/contract";
import type { CertPromptData } from "../useRemoteSession";
import { Sheet } from "./Sheet";
import { IconEye, IconEyeOff, IconLock, IconShieldAlert, IconShieldCheck } from "./icons";

/** Classic VNC passwords stop counting after 8 characters (DES). */
export const VNC_PASSWORD_LIMIT = 8;

export function CredentialSheet({
  request,
  computerName,
  onSubmit,
  onCancel,
}: {
  request: CredentialRequest;
  computerName: string;
  onSubmit(username: string | null, password: string | null, save: boolean): void;
  onCancel(): void;
}) {
  const needsUser = request.kind === "username-and-password";
  const [username, setUsername] = useState(request.usernameHint ?? "");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [save, setSave] = useState(true);
  const truncating = request.truncatesPassword && Array.from(password).length > VNC_PASSWORD_LIMIT;
  const canGo = password.length > 0 && (!needsUser || username.trim().length > 0);

  return (
    <Sheet title={`Sign in to ${computerName}`} icon={<IconLock />} onClose={onCancel}>
      <form
        className="dv-s-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (canGo) onSubmit(needsUser ? username.trim() : null, password, save);
        }}
      >
        {request.error || request.attempt > 1 ? (
          <p className="dv-s-callout tone-danger" role="alert">
            {request.error ? "That did not work. " : ""}Please check the {needsUser ? "name and password" : "password"} and try again.
          </p>
        ) : (
          <p className="dv-s-lead">This computer asks for {needsUser ? "a name and password" : "its password"}.</p>
        )}
        {needsUser ? (
          <label className="dv-s-field">
            <span>Name</span>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              enterKeyHint="next"
              autoFocus
            />
          </label>
        ) : null}
        <label className="dv-s-field">
          <span>Password</span>
          <div className="dv-s-field-row">
            <input
              type={show ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              enterKeyHint="go"
              autoFocus={!needsUser}
              aria-describedby={truncating ? "dv-s-trunc" : undefined}
            />
            <button type="button" className="dv-s-eye" onClick={() => setShow((v) => !v)} aria-label={show ? "Hide password" : "Show password"}>
              {show ? <IconEyeOff size={22} /> : <IconEye size={22} />}
            </button>
          </div>
        </label>
        {truncating ? (
          <p id="dv-s-trunc" className="dv-s-callout tone-warn">
            This kind of computer only reads the first {VNC_PASSWORD_LIMIT} characters of a password. We will send all of
            them, but only the first {VNC_PASSWORD_LIMIT} count.
          </p>
        ) : null}
        <label className="dv-s-check">
          <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />
          <span>Remember on this phone</span>
        </label>
        <button type="submit" className="dv-s-big" disabled={!canGo}>
          Sign in
        </button>
        <button type="button" className="dv-s-plain" onClick={onCancel}>
          Cancel
        </button>
      </form>
    </Sheet>
  );
}

/** Groups a hex fingerprint into pairs so a person can compare it by eye. */
export function formatFingerprint(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  if (hex.length < 8) return fp;
  return (hex.match(/.{1,2}/g) ?? []).join(" ");
}

export function CertSheet({ data, computerName, onAnswer }: { data: CertPromptData; computerName: string; onAnswer(accept: boolean): void }) {
  const [showDetails, setShowDetails] = useState(false);
  if (data.isChange) {
    return (
      <Sheet title="This computer looks different" icon={<IconShieldAlert />} tone="warning" onClose={() => onAnswer(false)}>
        <div className="dv-s-form">
          <p className="dv-s-callout tone-danger">
            {computerName} is showing a different identity from last time. That can happen after it was reinstalled, but
            it can also mean someone is pretending to be it.
          </p>
          <p className="dv-s-lead">If you were not expecting a change, do not connect, and ask the person who looks after it.</p>
          <button type="button" className="dv-s-big" onClick={() => onAnswer(false)}>
            Do not connect
          </button>
          <button type="button" className="dv-s-link" onClick={() => setShowDetails((v) => !v)}>
            {showDetails ? "Hide details" : "Show details"}
          </button>
          {showDetails ? <CertDetails data={data} /> : null}
          <button type="button" className="dv-s-plain tone-danger" onClick={() => onAnswer(true)}>
            I know about the change, connect anyway
          </button>
        </div>
      </Sheet>
    );
  }
  return (
    <Sheet title="First time connecting" icon={<IconShieldCheck />} onClose={() => onAnswer(false)}>
      <div className="dv-s-form">
        <p className="dv-s-lead">
          This is the first time this phone has seen {computerName}. We will remember its identity and warn you if it ever
          changes.
        </p>
        <button type="button" className="dv-s-link" onClick={() => setShowDetails((v) => !v)}>
          {showDetails ? "Hide details" : "Show details"}
        </button>
        {showDetails ? <CertDetails data={data} /> : null}
        <button type="button" className="dv-s-big" onClick={() => onAnswer(true)}>
          Trust and connect
        </button>
        <button type="button" className="dv-s-plain" onClick={() => onAnswer(false)}>
          Cancel
        </button>
      </div>
    </Sheet>
  );
}

function CertDetails({ data }: { data: CertPromptData }) {
  return (
    <dl className="dv-s-details">
      {data.subject ? (
        <>
          <dt>Name on the certificate</dt>
          <dd>{data.subject}</dd>
        </>
      ) : null}
      <dt>Fingerprint</dt>
      <dd className="mono">{formatFingerprint(data.fingerprint)}</dd>
    </dl>
  );
}
