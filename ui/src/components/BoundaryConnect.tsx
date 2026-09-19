import { useRef, useState } from "react";
import { mustInvoke } from "../lib/tauri";

/** Only the connection form lives here. Rust validates and owns the invitation. */
export function BoundaryConnect() {
  const dialog = useRef<HTMLDialogElement>(null);
  const [invitation, setInvitation] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const close = () => { setInvitation(""); setError(""); dialog.current?.close(); };
  const connect = async () => {
    setBusy(true);
    setError("");
    try {
      await mustInvoke("connect_boundary", { invitation: invitation.trim(), helperName: name.trim() });
      close();
    } catch (error) {
      setError(String(error));
    } finally { setBusy(false); }
  };
  return <>
    <button type="button" className="rounded-md border border-subtle px-3 py-1.5 text-sm text-primary hover:bg-inset" onClick={() => dialog.current?.showModal()}>Boundary support</button>
    <dialog ref={dialog} onCancel={() => { setInvitation(""); setError(""); }} className="m-auto w-full max-w-lg rounded-lg border border-subtle bg-raised p-6 text-primary shadow-lg backdrop:bg-black/40">
      <form onSubmit={(event) => { event.preventDefault(); void connect(); }} className="flex flex-col gap-4">
        <div><h2 className="text-lg font-semibold">Connect to Boundary</h2><p className="mt-2 text-sm text-secondary">Ask the person needing support to open Boundary and send you an invitation. They approve sharing on their computer.</p></div>
        <details className="rounded border border-subtle p-3 text-sm">
          <summary className="cursor-pointer">Use your own network or relay</summary>
          <ol className="mt-2 list-decimal space-y-2 pl-5 text-secondary">
            <li>On the recipient Mac, open Boundary and select “Set up my infrastructure”. Choose an existing Tailscale or private network, or a compatible relay.</li>
            <li>For a private network, connect this Mac to a network authorized to reach the recipient. Boundary does not enroll devices or change your network access rules.</li>
            <li>Create a new invitation after setup and paste it below. Private network invitations disable Boundary public relay fallback in the updated driver.</li>
          </ol>
          <p className="mt-2 text-xs text-secondary">Cloudflare account provisioning is not available yet. Free provider plans have usage and eligibility limits. A provider account does not enable unattended desktop access.</p>
        </details>
        <label className="text-sm">Your name<input autoFocus required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} className="mt-1 w-full rounded border border-subtle bg-inset p-2" /></label>
        <label className="text-sm">Invitation<textarea required spellCheck={false} autoComplete="off" maxLength={16384} rows={5} value={invitation} onChange={(event) => setInvitation(event.target.value)} placeholder="boundary1:…" className="mt-1 w-full rounded border border-subtle bg-inset p-2 font-mono text-xs" /></label>
        <p className="text-xs text-secondary">Invitations are temporary and are not saved in the host library or recent addresses.</p>
        {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
        <div className="flex justify-end gap-2"><button type="button" disabled={busy} onClick={close} className="rounded border border-subtle px-4 py-2">Cancel</button><button disabled={busy || !name.trim() || !invitation.trim()} type="submit" className="rounded bg-accent px-4 py-2 text-accent-fg disabled:opacity-50">{busy ? "Opening…" : "Connect"}</button></div>
      </form>
    </dialog>
  </>;
}
