/**
 * "Is this the right computer?" Answers a `certificate-prompt` session event;
 * the session screen passes the answer to `api.sessionTrust`. The fingerprint
 * hides under More details, since most people only need the question.
 */
import { useState } from "react";
import { SceneIdCard } from "../../art/Scenes";
import { Button } from "../Button";
import { Sheet } from "../Sheet";

export interface CertificatePrompt {
  fingerprint: string;
  subject: string;
  isChange: boolean;
  scheme: string;
}

/** Groups a hex fingerprint into pairs so a person can compare it by eye. */
export function formatFingerprint(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  if (hex.length < 8) return fp;
  return (hex.match(/.{1,2}/g) ?? []).join(" ");
}

/**
 * RSA-AES (VNC security types 5 and 129) and macOS Screen Sharing send a
 * bare RSA key with no certificate around it. Their `subject` describes the
 * key, for example "RSA-AES server key (2048-bit)", and calling that a name
 * on a certificate was wrong.
 */
export function isRawKey(scheme: string): boolean {
  return scheme === "ra2" || scheme === "apple-rsa";
}

/**
 * The SSH computer a tunnel goes through (issue #91). Its key arrives before
 * any session exists: `session_connect` fails with SSH_HOST_KEY_PROMPT and a
 * yes dials again with the fingerprint, so the scheme only steers the words.
 */
export const SSH_SCHEME = "ssh";

/** The label over `subject` in More details. */
export function subjectLabel(scheme: string): string {
  if (scheme === SSH_SCHEME) return "SSH computer";
  return isRawKey(scheme) ? "Kind of key" : "Name on its certificate";
}

/** How the fingerprint is shown: SSH's own `SHA256:` form as is, a hex one in pairs. */
export function shownFingerprint(scheme: string, fp: string): string {
  return scheme === SSH_SCHEME ? fp : formatFingerprint(fp);
}

interface Props {
  open: boolean;
  prompt: CertificatePrompt | null;
  hostName?: string;
  onAnswer: (accept: boolean) => void;
}

export function CertificateSheet({ open, prompt, hostName, onAnswer }: Props) {
  const [details, setDetails] = useState(false);
  const change = prompt?.isChange ?? false;
  const name = hostName ?? "This computer";
  const ssh = prompt?.scheme === SSH_SCHEME;
  return (
    <Sheet
      open={open}
      onClose={() => onAnswer(false)}
      dismissible={false}
      art={<SceneIdCard warn={change} />}
      title={change ? `${name} looks different` : ssh ? "First time through this SSH computer" : "First time connecting"}
      subtitle={
        change
          ? "Its security ID changed since last time. That happens after a reinstall, but it can also mean something is in the way. If you did not expect this, stop."
          : ssh
            ? "The tunnel to this computer goes through an SSH computer your phone has not met before. If it is the one you meant, say yes and you will not be asked again."
            : "Your phone has not met this computer before. If it is the one you meant, say yes and you will not be asked again."
      }
    >
      <div className="flex flex-col gap-3">
        <button type="button" className="min-h-12 text-center text-subhead font-semibold text-accent" onClick={() => setDetails((v) => !v)}>
          {details ? "Hide details" : "More details"}
        </button>
        {details && prompt && (
          <div className="rounded-[10px] bg-surface-2 p-4 text-footnote">
            {prompt.subject ? (
              <>
                <p className="text-ink-dim">{subjectLabel(prompt.scheme)}</p>
                <p className="mb-3 break-all font-medium">{prompt.subject}</p>
              </>
            ) : null}
            <p className="text-ink-dim">Fingerprint</p>
            <p className="break-all font-mono text-caption leading-relaxed">{shownFingerprint(prompt.scheme, prompt.fingerprint)}</p>
          </div>
        )}
        {change ? (
          <>
            {/* A changed identity: the big, easy button is the safe one. */}
            <Button size="xl" block onClick={() => onAnswer(false)}>
              No, stop
            </Button>
            <button type="button" className="min-h-12 text-center text-subhead font-semibold text-danger" onClick={() => onAnswer(true)}>
              I expected this, connect anyway
            </button>
          </>
        ) : (
          <>
            <Button size="xl" block onClick={() => onAnswer(true)}>
              Yes, connect
            </Button>
            <Button variant="soft" size="lg" block onClick={() => onAnswer(false)}>
              No, stop
            </Button>
          </>
        )}
      </div>
    </Sheet>
  );
}
