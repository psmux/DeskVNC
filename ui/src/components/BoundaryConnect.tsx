import { useRef, useState } from "react";
import { BoundaryProviderSetup } from "./BoundaryProviderSetup";
import { mustInvoke } from "../lib/tauri";

/** Only the connection form lives here. Rust validates and owns the invitation. */
export function BoundaryConnect() {
  const dialog = useRef<HTMLDialogElement>(null);
  const [open, setOpen] = useState(false);
  const [invitation, setInvitation] = useState("");
  const [codeService, setCodeService] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const close = () => { setOpen(false); setInvitation(""); setError(""); dialog.current?.close(); };
  const connect = async () => {
    setBusy(true);
    setError("");
    try {
      await mustInvoke("connect_boundary", { invitation: invitation.trim(), helperName: name.trim(), codeService: codeService.trim() || null });
      close();
    } catch (error) {
      setError(String(error));
    } finally { setBusy(false); }
  };
  return <>
    <button type="button" className="rounded-md border border-subtle px-3 py-1.5 text-sm text-primary hover:bg-inset" onClick={() => { setOpen(true); dialog.current?.showModal(); }}>Boundary support</button>
    <dialog ref={dialog} onCancel={() => { setOpen(false); setInvitation(""); setError(""); }} className="m-auto max-h-[90vh] overflow-y-auto w-full max-w-lg rounded-lg border border-subtle bg-raised p-6 text-primary shadow-lg backdrop:bg-black/40">
      <form onSubmit={(event) => { event.preventDefault(); void connect(); }} className="flex flex-col gap-4">
        <div><h2 className="text-lg font-semibold">Connect to Boundary</h2><p className="mt-2 text-sm text-secondary">Ask the person needing support to open Boundary and send you an invitation. They approve sharing on their computer.</p></div>
        <BoundaryProviderSetup active={open} />
        <label className="text-sm">Your name<input autoFocus required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} className="mt-1 w-full rounded border border-subtle bg-inset p-2" /></label>
        <label className="text-sm">Support code or full invitation<textarea required spellCheck={false} autoComplete="off" maxLength={16384} rows={5} value={invitation} onChange={(event) => setInvitation(event.target.value)} placeholder="1234 5678 9012 or boundary1:…" className="mt-1 w-full rounded border border-subtle bg-inset p-2 font-mono text-xs" /></label>
        {!invitation.trim().startsWith("boundary1:") && <label className="text-sm">Private code service URL (optional override)<input type="url" value={codeService} onChange={(event) => setCodeService(event.target.value)} placeholder="https://codes.example.com" className="mt-1 w-full rounded border border-subtle bg-inset p-2" /><span className="mt-1 block text-xs text-secondary">Leave empty for the shared Boundary service. For private codes, use the same trusted service as the person sharing. That service can read and replace invitations.</span></label>}
        <p className="text-xs text-secondary">Invitations are temporary and are not saved in the host library or recent addresses.</p>
        {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
        <div className="flex justify-end gap-2"><button type="button" disabled={busy} onClick={close} className="rounded border border-subtle px-4 py-2">Cancel</button><button disabled={busy || !name.trim() || !invitation.trim()} type="submit" className="rounded bg-accent px-4 py-2 text-accent-fg disabled:opacity-50">{busy ? "Opening…" : "Connect"}</button></div>
      </form>
    </dialog>
  </>;
}
