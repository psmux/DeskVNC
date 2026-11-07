/**
 * Certificate trust-on-first-use prompt, and the red hard-stop variant for a
 * CHANGED fingerprint. Focus defaults to Cancel in both; the changed variant
 * never defaults to accept and requires typed confirmation to proceed.
 */
import { useState, type ReactNode } from "react";
import { Dialog } from "./primitives";
import { fingerprintMnemonic, formatFingerprint } from "../lib/util";
import { IconAlert, IconLock } from "./icons";
import type { CertificateDigests, PinScheme } from "../lib/types";

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
  /**
   * The whole certificate's thumbprint and SHA-256, when the key came in a
   * certificate. Display only, so the person can match what an admin reads
   * off the server; the pin stays `fingerprint`.
   */
  certificate?: CertificateDigests | null;
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
          <FingerprintBlock
            fingerprint={data.fingerprint}
            mnemonic={mnemonic}
            subject={data.subject}
            certificate={data.certificate}
          />
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
      title={
        data.scheme === "rdg-tls"
          ? `Verify the RD Gateway for ${data.hostName}`
          : `Verify ${data.hostName}`
      }
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
            {data.scheme === "rdg-tls" ? (
              <>
                This connection goes through an RD Gateway, and this is the
                certificate the gateway presented. Your password is sent to the
                gateway once you trust it, so check the fingerprint with whoever
                runs the gateway if it is not signed by an authority you know.
              </>
            ) : data.scheme === "rdp-tls" ? (
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
        <FingerprintBlock
            fingerprint={data.fingerprint}
            mnemonic={mnemonic}
            subject={data.subject}
            certificate={data.certificate}
          />
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

/**
 * What the hex string is. Every pin in this app is the SHA-256 of the
 * server's public key (the certificate's SubjectPublicKeyInfo), not of the
 * whole certificate, so somebody comparing it against a certificate
 * thumbprint has to be told which digest to compute or the two never match.
 */
export const FINGERPRINT_LABEL = "SHA-256 of the server's public key";

/**
 * Windows calls the certificate's SHA-1 its Thumbprint, in the certificate
 * dialog, certlm.msc and `Get-ChildItem Cert:`, and prints it as 40 hex
 * digits with no separators. Shown in that form so it can be read across
 * character by character.
 */
export const THUMBPRINT_LABEL = "Thumbprint";
export const CERTIFICATE_SHA256_LABEL = "Certificate SHA-256";

/** The Windows form of a thumbprint: upper case hex, no separators. */
export function windowsThumbprint(colonHex: string): string {
  return colonHex.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

export function FingerprintBlock({
  fingerprint,
  mnemonic,
  subject,
  certificate,
}: {
  fingerprint: string;
  mnemonic: string;
  subject: string;
  certificate?: CertificateDigests | null;
}): ReactNode {
  return (
    <div className="space-y-2 rounded-md bg-inset p-3.5">
      {subject ? <div className="text-xs text-secondary">{subject}</div> : null}
      <div className="text-2xs text-tertiary">{FINGERPRINT_LABEL}</div>
      <div className="mono break-all text-xs leading-relaxed text-primary" aria-label={FINGERPRINT_LABEL}>
        {formatFingerprint(fingerprint)}
      </div>
      {certificate ? (
        <>
          <div className="text-2xs text-tertiary">
            {THUMBPRINT_LABEL} <span className="text-tertiary">(SHA-1, as Windows shows it)</span>
          </div>
          <div className="mono break-all text-xs leading-relaxed text-primary" aria-label={THUMBPRINT_LABEL}>
            {windowsThumbprint(certificate.thumbprint)}
          </div>
          <div className="text-2xs text-tertiary">{CERTIFICATE_SHA256_LABEL}</div>
          <div
            className="mono break-all text-xs leading-relaxed text-primary"
            aria-label={CERTIFICATE_SHA256_LABEL}
          >
            {formatFingerprint(certificate.sha256)}
          </div>
        </>
      ) : null}
      {mnemonic ? (
        <div className="text-sm">
          <span className="text-tertiary">Fingerprint words: </span>
          <span className="mono font-medium text-accent">{mnemonic}</span>
        </div>
      ) : null}
    </div>
  );
}
