/**
 * Certificate trust-on-first-use prompt, and the red hard-stop variant for a
 * CHANGED fingerprint. Focus defaults to Cancel in both; the changed variant
 * never defaults to accept and requires typed confirmation to proceed.
 */
import { useState, type ReactNode } from "react";
import { Dialog } from "./primitives";
import { fingerprintMnemonic, formatFingerprint } from "../lib/util";
import { IconAlert, IconLock } from "./icons";
import type { PinScheme } from "../lib/types";

export interface CertPromptData {
  fingerprint: string;
  subject: string;
  isChange: boolean;
  hostName: string;
  /**
   * Which key this fingerprint belongs to. Routing, not copy: it is handed
   * back to `trust_certificate` untouched. It reaches the copy only through
   * the one branch below, because what a user can usefully verify differs.
   */
  scheme: PinScheme;
}

export function CertPrompt({
  data,
  onTrust,
  onConnectOnce,
  onCancel,
}: {
  data: CertPromptData;
  onTrust: () => void;
  onConnectOnce: () => void;
  onCancel: () => void;
}): ReactNode {
  const mnemonic = fingerprintMnemonic(data.fingerprint);
  const [confirmText, setConfirmText] = useState("");

  if (data.isChange) {
    const confirmed = confirmText === "trust new identity";
    return (
      <Dialog
        title="Server identity has CHANGED"
        onClose={onCancel}
        danger
        width={560}
        initialFocusSelector="[data-cancel]"
      >
        <div className="space-y-4">
          <div className="flex items-start gap-3 rounded-md bg-danger-subtle p-3.5">
            <span className="mt-0.5 shrink-0 text-danger">
              <IconAlert size={20} />
            </span>
            <p className="text-sm text-primary">
              <strong>{data.hostName}</strong> is presenting a different certificate than the one
              you trusted before. This can mean the server was reinstalled, or that someone is
              intercepting your connection. <strong>Do not continue unless you know why this
              changed.</strong>
              {data.scheme === "rdp-tls" ? (
                <span className="mt-2 block">
                  A Windows reinstall, or a new machine certificate after a domain
                  change, both look exactly like this. So does an attacker. Do not
                  continue unless you know which it is.
                </span>
              ) : null}
            </p>
          </div>
          <FingerprintBlock fingerprint={data.fingerprint} mnemonic={mnemonic} subject={data.subject} />
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-secondary">
              To proceed anyway, type <span className="mono">trust new identity</span>
            </span>
            <input
              className="field mono"
              value={confirmText}
              spellCheck={false}
              autoComplete="off"
              onChange={(e) => setConfirmText(e.target.value)}
            />
          </label>
          <div className="flex justify-end gap-2.5">
            <button type="button" data-cancel className="btn-primary" onClick={onCancel}>
              Cancel (recommended)
            </button>
            <button
              type="button"
              className="btn-danger disabled:opacity-40"
              disabled={!confirmed}
              onClick={onTrust}
            >
              Trust new identity
            </button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      title={`Verify ${data.hostName}`}
      onClose={onCancel}
      width={560}
      initialFocusSelector="[data-cancel]"
    >
      <div className="space-y-4">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 shrink-0 text-warning">
            <IconLock size={20} />
          </span>
          <p className="text-sm text-secondary">
            {data.scheme === "rdp-tls" ? (
              <>
                Windows Remote Desktop normally identifies itself with a certificate
                it generated for itself, so on a fresh machine there is nothing to
                compare this against. Remembering it now means you will be told if
                it ever changes.
              </>
            ) : (
              <>
                This is the first time this computer has identified itself with the
                key below. Verify the fingerprint matches the one shown on the
                server, then choose how much to trust it.
              </>
            )}
          </p>
        </div>
        <FingerprintBlock fingerprint={data.fingerprint} mnemonic={mnemonic} subject={data.subject} />
        <div className="flex flex-wrap justify-end gap-2.5">
          <button type="button" data-cancel className="btn-secondary" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="btn-secondary" onClick={onConnectOnce}>
            Connect once
          </button>
          <button type="button" className="btn-primary" onClick={onTrust}>
            Trust this computer
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function FingerprintBlock({
  fingerprint,
  mnemonic,
  subject,
}: {
  fingerprint: string;
  mnemonic: string;
  subject: string;
}): ReactNode {
  return (
    <div className="space-y-2 rounded-md bg-inset p-3.5">
      {subject ? <div className="text-xs text-secondary">{subject}</div> : null}
      <div className="mono break-all text-xs leading-relaxed text-primary" aria-label="SHA-256 certificate fingerprint">
        {formatFingerprint(fingerprint)}
      </div>
      {mnemonic ? (
        <div className="text-sm">
          <span className="text-tertiary">Fingerprint words: </span>
          <span className="mono font-medium text-accent">{mnemonic}</span>
        </div>
      ) : null}
    </div>
  );
}
