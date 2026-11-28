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
import { useT } from "../i18n";

/** A translated sentence with the host name set in bold where `{name}` stands. */
function withBoldName(text: string, name: string): ReactNode {
  return text.split("{name}").map((piece, i) => (
    <span key={i}>
      {i > 0 ? <strong>{name}</strong> : null}
      {piece}
    </span>
  ));
}

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

/**
 * RSA-AES (VNC security types 5 and 129) and macOS Screen Sharing send a
 * bare RSA key with no certificate around it, so the copy says key for
 * those. The phone app's CertificateSheet makes the same split.
 */
export function isRawKey(scheme: PinScheme): boolean {
  return scheme === "ra2" || scheme === "apple-rsa";
}

/** What a person types to trust a changed identity. Compared as typed, so not translated. */
const CONFIRM_PHRASE = "trust new identity";

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
  const t = useT();
  const mnemonic = fingerprintMnemonic(data.fingerprint);
  const [confirmText, setConfirmText] = useState("");

  if (data.isChange) {
    const confirmed = confirmText === CONFIRM_PHRASE;
    return (
      <Dialog
        title={t("Server identity has CHANGED")}
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
              {withBoldName(
                isRawKey(data.scheme)
                  ? t(
                      "{name} is presenting a different key than the one you trusted before. This can mean the server was reinstalled, or that someone is intercepting your connection.",
                    )
                  : t(
                      "{name} is presenting a different certificate than the one you trusted before. This can mean the server was reinstalled, or that someone is intercepting your connection.",
                    ),
                data.hostName,
              )}{" "}
              <strong>{t("Do not continue unless you know why this changed.")}</strong>
              {data.scheme === "rdp-tls" ? (
                <span className="mt-2 block">
                  {t(
                    "A Windows reinstall, or a new machine certificate after a domain change, both look exactly like this. So does an attacker. Do not continue unless you know which it is.",
                  )}
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
              {/* The phrase itself stays English: it is compared as typed. */}
              {t("To proceed anyway, type {phrase}")
                .split("{phrase}")
                .map((piece, i) => (
                  <span key={i}>
                    {i > 0 ? <span className="mono">{CONFIRM_PHRASE}</span> : null}
                    {piece}
                  </span>
                ))}
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
              {t("Cancel (recommended)")}
            </button>
            <button
              type="button"
              className="btn-danger disabled:opacity-40"
              disabled={!confirmed}
              onClick={onTrust}
            >
              {t("Trust new identity")}
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
          ? t("Verify the RD Gateway for {name}", { name: data.hostName })
          : t("Verify {name}", { name: data.hostName })
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
              t(
                "This connection goes through an RD Gateway, and this is the certificate the gateway presented. Your password is sent to the gateway once you trust it, so check the fingerprint with whoever runs the gateway if it is not signed by an authority you know.",
              )
            ) : data.scheme === "rdp-tls" ? (
              t(
                "Windows Remote Desktop normally identifies itself with a certificate it generated for itself, so on a fresh machine there is nothing to compare this against. Remembering it now means you will be told if it ever changes.",
              )
            ) : (
              t(
                "This is the first time this computer has identified itself with the key below. Verify the fingerprint matches the one shown on the server, then choose how much to trust it.",
              )
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
            {t("Cancel")}
          </button>
          <button type="button" className="btn-secondary" onClick={onConnectOnce}>
            {t("Connect once")}
          </button>
          <button type="button" className="btn-primary" onClick={onTrust}>
            {t("Trust this computer")}
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
  const t = useT();
  // The labels stay English constants for the tests; they are shown through t.
  const fingerprintLabel = t(FINGERPRINT_LABEL);
  const thumbprintLabel = t(THUMBPRINT_LABEL);
  const certificateLabel = t(CERTIFICATE_SHA256_LABEL);
  return (
    <div className="space-y-2 rounded-md bg-inset p-3.5">
      {subject ? <div className="text-xs text-secondary">{subject}</div> : null}
      <div className="text-2xs text-tertiary">{fingerprintLabel}</div>
      <div className="mono break-all text-xs leading-relaxed text-primary" aria-label={fingerprintLabel}>
        {formatFingerprint(fingerprint)}
      </div>
      {certificate ? (
        <>
          <div className="text-2xs text-tertiary">
            {thumbprintLabel} <span className="text-tertiary">{t("(SHA-1, as Windows shows it)")}</span>
          </div>
          <div className="mono break-all text-xs leading-relaxed text-primary" aria-label={thumbprintLabel}>
            {windowsThumbprint(certificate.thumbprint)}
          </div>
          <div className="text-2xs text-tertiary">{certificateLabel}</div>
          <div
            className="mono break-all text-xs leading-relaxed text-primary"
            aria-label={certificateLabel}
          >
            {formatFingerprint(certificate.sha256)}
          </div>
        </>
      ) : null}
      {mnemonic ? (
        <div className="text-sm">
          <span className="text-tertiary">{t("Fingerprint words:")} </span>
          <span className="mono font-medium text-accent">{mnemonic}</span>
        </div>
      ) : null}
    </div>
  );
}
