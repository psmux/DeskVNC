/**
 * Trust-on-first-use prompt for an SSH host key, and the red hard-stop
 * variant for a CHANGED key. Mirrors `CertPrompt`, but for the SSH layer:
 * this appears BEFORE any session exists, and the pin it writes is shared
 * with the Files panel and the terminal sidecar.
 *
 * Two machines can be behind it, and the words change accordingly. A tunnel
 * GATEWAY stands in front of the machine you asked for, and trusting it says
 * nothing about that machine. A direct SSH session's key IS the machine's.
 * Saying "gateway" in the second case would be describing something that is
 * not there, in a dialog whose entire job is to tell the user what they are
 * about to trust.
 *
 * SSH fingerprints are OpenSSH's `SHA256:...` base64 form, shown verbatim so
 * the user can compare against `ssh-keygen -lf` output on the server.
 */
import type { ReactNode } from "react";
import { Dialog } from "./primitives";
import type { SshHostKeyPromptState } from "../hooks/useSession";
import { IconAlert, IconLock } from "./icons";
import { Trans } from "./Trans";
import { useT } from "../lib/i18n";

export function SshHostKeyPrompt({
  data,
  onAccept,
  onCancel,
}: {
  data: SshHostKeyPromptState;
  onAccept: () => void;
  onCancel: () => void;
}): ReactNode {
  const tr = useT();
  const endpoint = `${data.host}:${data.port}`;
  const gateway = data.gateway;

  if (data.changed) {
    return (
      <Dialog
        title={
          gateway
            ? tr("SSH gateway identity has CHANGED")
            : tr("This machine's identity has CHANGED")
        }
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
            <p className="text-sm break-words text-primary">
              <Trans
                text="The SSH server at {endpoint} is presenting a different host key than the one you trusted before. This can mean the machine was reinstalled, or that someone is intercepting your connection. The connection was refused. If you know the key legitimately changed, remove the saved key for this machine and connect again."
                nodes={{ endpoint: <strong className="mono">{endpoint}</strong> }}
              />
            </p>
          </div>
          <KeyBlock label={tr("Previously trusted")} value={data.expected ?? ""} />
          <KeyBlock label={tr("Presented now")} value={data.fingerprint} />
          <div className="flex justify-end">
            <button type="button" data-cancel className="btn-primary" onClick={onCancel}>
              {tr("Close")}
            </button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      title={
        gateway
          ? tr("Verify SSH gateway {host}", { host: data.host })
          : tr("Verify {host}", { host: data.host })
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
          <p className="text-sm break-words text-secondary">
            {gateway ? (
              <Trans
                text="Your connection will be tunnelled through the SSH server at {endpoint}, and this is the first time it has identified itself."
                nodes={{ endpoint: <span className="mono">{endpoint}</span> }}
              />
            ) : (
              <Trans
                text="This is the first time {endpoint} has identified itself, so there is nothing saved to compare it against yet."
                nodes={{ endpoint: <span className="mono">{endpoint}</span> }}
              />
            )}{" "}
            <Trans
              text="Verify the fingerprint below matches the server's ({command}) before trusting it."
              nodes={{
                command: (
                  <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span>
                ),
              }}
            />
          </p>
        </div>
        <KeyBlock label={data.keyType ?? tr("host key")} value={data.fingerprint} />
        <div className="flex flex-wrap justify-end gap-2.5">
          <button type="button" data-cancel className="btn-secondary" onClick={onCancel}>
            {tr("Cancel")}
          </button>
          <button type="button" className="btn-primary" onClick={onAccept}>
            {tr("Trust and connect")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function KeyBlock({ label, value }: { label: string; value: string }): ReactNode {
  const tr = useT();
  return (
    <div className="space-y-1 rounded-md bg-inset p-3.5">
      <div className="text-xs text-secondary">{label}</div>
      <div
        className="mono break-all text-xs leading-relaxed text-primary"
        aria-label={tr("{label} SSH fingerprint", { label })}
      >
        {value}
      </div>
    </div>
  );
}
