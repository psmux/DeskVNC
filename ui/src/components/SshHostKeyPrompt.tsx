/**
 * Trust-on-first-use prompt for the SSH tunnel gateway's host key, and the
 * red hard-stop variant for a CHANGED key. Mirrors `CertPrompt`, but for the
 * SSH layer: this appears BEFORE any VNC session exists, and the pin it
 * writes is shared with the Files panel.
 *
 * SSH fingerprints are OpenSSH's `SHA256:...` base64 form, shown verbatim so
 * the user can compare against `ssh-keygen -lf` output on the server.
 */
import type { ReactNode } from "react";
import { Dialog } from "./primitives";
import type { SshHostKeyPromptState } from "../hooks/useSession";
import { IconAlert, IconLock } from "./icons";

export function SshHostKeyPrompt({
  data,
  onAccept,
  onCancel,
}: {
  data: SshHostKeyPromptState;
  onAccept: () => void;
  onCancel: () => void;
}): ReactNode {
  const endpoint = `${data.host}:${data.port}`;

  if (data.changed) {
    return (
      <Dialog
        title="SSH gateway identity has CHANGED"
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
              The SSH server at <strong className="mono">{endpoint}</strong> is presenting a
              different host key than the one you trusted before. This can mean the machine was
              reinstalled, or that someone is intercepting your connection. The connection was
              refused. If you know the key legitimately changed, remove the saved key for this
              machine and connect again.
            </p>
          </div>
          <KeyBlock label="Previously trusted" value={data.expected ?? ""} />
          <KeyBlock label="Presented now" value={data.fingerprint} />
          <div className="flex justify-end">
            <button type="button" data-cancel className="btn-primary" onClick={onCancel}>
              Close
            </button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      title={`Verify SSH gateway ${data.host}`}
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
            Your connection will be tunnelled through the SSH server at{" "}
            <span className="mono">{endpoint}</span>, and this is the first time it has
            identified itself. Verify the fingerprint below matches the server&apos;s
            (<span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span>)
            before trusting it.
          </p>
        </div>
        <KeyBlock label={data.keyType ?? "host key"} value={data.fingerprint} />
        <div className="flex flex-wrap justify-end gap-2.5">
          <button type="button" data-cancel className="btn-secondary" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="btn-primary" onClick={onAccept}>
            Trust and connect
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function KeyBlock({ label, value }: { label: string; value: string }): ReactNode {
  return (
    <div className="space-y-1 rounded-md bg-inset p-3.5">
      <div className="text-xs text-secondary">{label}</div>
      <div
        className="mono break-all text-xs leading-relaxed text-primary"
        aria-label={`${label} SSH fingerprint`}
      >
        {value}
      </div>
    </div>
  );
}
