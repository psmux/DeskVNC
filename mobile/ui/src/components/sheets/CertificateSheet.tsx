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

/** The label over `subject` in More details. */
export function subjectLabel(scheme: string): string {
  return isRawKey(scheme) ? "Kind of key" : "Name on its certificate";
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
  return (
    <Sheet
      open={open}
      onClose={() => onAnswer(false)}
      dismissible={false}
      art={<SceneIdCard warn={change} />}
      title={change ? `${name} looks different` : "First time connecting"}
      subtitle={
        change
          ? "Its security ID changed since last time. That happens after a reinstall, but it can also mean something is in the way. If you did not expect this, stop."
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
            <p className="break-all font-mono text-caption leading-relaxed">{formatFingerprint(prompt.fingerprint)}</p>
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
