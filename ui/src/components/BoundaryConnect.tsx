import { useRef, useState } from "react";
import { BoundaryProviderSetup } from "./BoundaryProviderSetup";
import { mustInvoke, openSessionWindow, readClipboard } from "../lib/tauri";
import { useHosts } from "../state/HostsContext";

const NAME_KEY = "deskvnc.boundary.helperName";

/** Read a remembered value, tolerating storage that is blocked. */
function remembered(key: string): string {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}
function remember(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // A private window or blocked storage: the name is asked for again.
  }
}

/** A machine ID: 64 hex characters, as DeskVNC Support shows it. */
function looksLikeMachineId(text: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(text.trim());
}

/**
 * Boundary support, both ways in.
 *
 * Help someone now: the person opens DeskVNC Support, presses Create
 * invitation and sends it; it is pasted here for you when it is already on the
 * clipboard. Connect to a computer: a machine with unattended access, by its
 * ID, saved to the Library so it opens like any other computer afterwards.
 * Rust validates and owns the invitation; it never enters a URL.
 */
export function BoundaryConnect() {
  const dialog = useRef<HTMLDialogElement>(null);
  const { saveHost, savePassword } = useHosts();
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"invite" | "machine">("invite");
  const [invitation, setInvitation] = useState("");
  const [codeService, setCodeService] = useState("");
  const [name, setName] = useState(remembered(NAME_KEY));
  const [machineId, setMachineId] = useState("");
  const [machineName, setMachineName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [pasted, setPasted] = useState(false);

  const reset = () => {
    setOpen(false);
    setInvitation("");
    setMachineId("");
    setMachineName("");
    setPassword("");
    setError("");
    setPasted(false);
  };
  const close = () => {
    reset();
    dialog.current?.close();
  };
  const show = async () => {
    setOpen(true);
    dialog.current?.showModal();
    // An invitation already copied is pasted for you, and a machine ID
    // switches to connecting by ID. Nothing else on the clipboard is touched.
    const clip = (await readClipboard())?.trim() ?? "";
    if (clip.startsWith("boundary1:")) {
      setMode("invite");
      setInvitation(clip);
      setPasted(true);
    } else if (looksLikeMachineId(clip)) {
      setMode("machine");
      setMachineId(clip);
      setPasted(true);
    }
  };

  const connectInvite = async () => {
    remember(NAME_KEY, name.trim());
    await mustInvoke("connect_boundary", {
      invitation: invitation.trim(),
      helperName: name.trim(),
      codeService: codeService.trim() || null,
    });
  };
  const connectMachine = async () => {
    remember(NAME_KEY, name.trim());
    const saved = await saveHost({
      friendlyName: machineName.trim() || "Boundary computer",
      address: machineId.trim().toLowerCase(),
      port: 0,
      protocol: "boundary",
    });
    if (!saved) throw new Error("The computer could not be saved to the Library");
    if (password) await savePassword(saved.id, password);
    await openSessionWindow({ profileId: saved.id });
  };
  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      if (mode === "invite") await connectInvite();
      else await connectMachine();
      close();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const numeric = mode === "invite" && invitation.trim() !== "" && /^[0-9\s-]+$/.test(invitation.trim());
  const ready =
    name.trim() !== "" &&
    (mode === "invite" ? invitation.trim() !== "" : looksLikeMachineId(machineId));
  const tab = (value: "invite" | "machine", label: string) => (
    <button
      type="button"
      onClick={() => { setMode(value); setError(""); }}
      className={`flex-1 rounded px-3 py-1.5 text-sm ${mode === value ? "bg-accent text-accent-fg" : "border border-subtle text-primary hover:bg-inset"}`}
    >
      {label}
    </button>
  );

  return <>
    <button type="button" className="rounded-md border border-subtle px-3 py-1.5 text-sm text-primary hover:bg-inset" onClick={() => void show()}>Boundary support</button>
    <dialog ref={dialog} onCancel={reset} className="m-auto max-h-[90vh] overflow-y-auto w-full max-w-lg rounded-lg border border-subtle bg-raised p-6 text-primary shadow-lg backdrop:bg-black/40">
      <form onSubmit={(event) => { event.preventDefault(); void submit(); }} className="flex flex-col gap-4">
        <div>
          <h2 className="text-lg font-semibold">Boundary support</h2>
          <p className="mt-2 text-sm text-secondary">Help someone over the internet, with nothing to set up on either network.</p>
        </div>
        <div className="flex gap-2">{tab("invite", "Help someone now")}{tab("machine", "Connect to a computer")}</div>
        <label className="text-sm">Your name, shown to the person<input autoFocus required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} className="mt-1 w-full rounded border border-subtle bg-inset p-2" /></label>
        {mode === "invite" ? <>
          <ol className="list-decimal space-y-1 pl-5 text-sm text-secondary">
            <li>They download <strong>DeskVNC Support</strong> from the DeskVNC releases page and open it. Nothing is installed.</li>
            <li>They press <strong>Create invitation</strong>, then <strong>Copy invitation</strong>, and send it to you in any chat.</li>
            <li>You copy it and open this window. It is pasted for you. They approve you on their screen.</li>
          </ol>
          <label className="text-sm">Their invitation<textarea required spellCheck={false} autoComplete="off" maxLength={16384} rows={4} value={invitation} onChange={(event) => { setInvitation(event.target.value); setPasted(false); }} placeholder="boundary1:…" className="mt-1 w-full rounded border border-subtle bg-inset p-2 font-mono text-xs" /></label>
          {pasted && <p className="-mt-2 text-xs text-secondary">Pasted from your clipboard.</p>}
          {numeric && <label className="text-sm">Code service URL<input type="url" value={codeService} onChange={(event) => setCodeService(event.target.value)} placeholder="https://codes.example.com" className="mt-1 w-full rounded border border-subtle bg-inset p-2" /><span className="mt-1 block text-xs text-secondary">A number needs the same code service the person used. Otherwise ask them for the invitation text.</span></label>}
          <p className="text-xs text-secondary">During the session they can choose to let you connect any time. The computer is then saved to your Library and opens unattended.</p>
          <BoundaryProviderSetup active={open} />
        </> : <>
          <p className="text-sm text-secondary">For a computer with unattended access switched on in DeskVNC Support. A computer that paired you is already in your Library.</p>
          <label className="text-sm">Computer ID<input required spellCheck={false} autoComplete="off" value={machineId} onChange={(event) => { setMachineId(event.target.value); setPasted(false); }} placeholder="64 letters and digits, from Copy ID" className="mt-1 w-full rounded border border-subtle bg-inset p-2 font-mono text-xs" /></label>
          {pasted && <p className="-mt-2 text-xs text-secondary">Pasted from your clipboard.</p>}
          {machineId.trim() !== "" && !looksLikeMachineId(machineId) && <p className="-mt-2 text-xs text-red-500">That is not a computer ID. Use Copy ID in DeskVNC Support.</p>}
          <label className="text-sm">Name in your Library<input maxLength={80} value={machineName} onChange={(event) => setMachineName(event.target.value)} placeholder="Mum's laptop" className="mt-1 w-full rounded border border-subtle bg-inset p-2" /></label>
          <label className="text-sm">Unattended password, if you were not paired<input type="password" autoComplete="off" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-1 w-full rounded border border-subtle bg-inset p-2" /><span className="mt-1 block text-xs text-secondary">Kept in your system keychain, never in the Library file.</span></label>
        </>}
        {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
        <div className="flex justify-end gap-2"><button type="button" disabled={busy} onClick={close} className="rounded border border-subtle px-4 py-2">Cancel</button><button disabled={busy || !ready} type="submit" className="rounded bg-accent px-4 py-2 text-accent-fg disabled:opacity-50">{busy ? "Opening…" : mode === "invite" ? "Connect" : "Save and connect"}</button></div>
      </form>
    </dialog>
  </>;
}
