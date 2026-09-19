import { useEffect, useState } from "react";
import { mustInvoke } from "../lib/tauri";

type Progress = { message: string; address: string | null; finished: boolean; failed: boolean };
export function BoundaryProviderSetup({ active }: { active: boolean }) {
  const [provider, setProvider] = useState("Tailscale");
  const [token, setToken] = useState("");
  const [team, setTeam] = useState("");
  const [account, setAccount] = useState("");
  const [emails, setEmails] = useState("");
  const [configure, setConfigure] = useState(false);
  const [consent, setConsent] = useState(false);
  const [remove, setRemove] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (!active) { setToken(""); return; }
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const state = await mustInvoke<Progress | null>("boundary_provider_status");
        if (!alive) return;
        if (state) { setMessage(state.message); setBusy(!state.finished); }
      } catch { if (alive) setMessage("Could not read setup status. Reopen this dialog to reconnect."); }
      if (alive) timer = setTimeout(() => { void poll(); }, 700);
    };
    void poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [active]);
  const start = async (removeResources = false) => {
    setBusy(true);
    const authKey = token;
    setToken("");
    try {
      await mustInvoke("boundary_provider_start", { request: {
        remove_resources: removeResources, provider, auth_key: authKey, account_id: account.trim(), team: team.trim(),
        emails: emails.split(",").map(value => value.trim()).filter(Boolean),
        configure_account: provider === "Cloudflare" && configure,
      } });
    } catch (error) { setMessage(String(error)); setBusy(false); }
  };
  const inputClass = "mt-1 w-full rounded border border-subtle bg-inset p-2";
  return <details className="rounded border border-subtle p-3 text-sm">
    <summary className="cursor-pointer">Set up my private infrastructure</summary>
    <div className="mt-3 flex flex-col gap-3">
      <p>Install and connect this helper device to your own provider account. Run setup in Boundary on the recipient device as well, then create a new invitation.</p>
      <fieldset disabled={busy} className="flex flex-col gap-3">
        <label>Provider<select className={inputClass} value={provider} onChange={event => { setProvider(event.target.value); setToken(""); setConsent(false); }}><option>Tailscale</option><option>Cloudflare</option></select></label>
        {provider === "Cloudflare" && <>
          <label>Cloudflare team name<input className={inputClass} value={team} onChange={event => setTeam(event.target.value)} /></label>
          <label><input type="checkbox" checked={configure} onChange={event => setConfigure(event.target.checked)} /> Configure my account through the Cloudflare API</label>
          {configure && <>
            <label>Account ID<input className={inputClass} value={account} onChange={event => setAccount(event.target.value)} /></label>
            <label>Enrollment emails, separated by commas<input className={inputClass} value={emails} onChange={event => setEmails(event.target.value)} /></label>
            <p>Creates an email enrollment policy and private Mesh device profile, and enables device connectivity for the account. Existing access policies still apply.</p>
          </>}
        </>}
        {(provider === "Tailscale" || configure) && <label>{provider === "Tailscale" ? "Device auth key (optional, leave empty for browser login)" : "Scoped Cloudflare API token"}<input type="password" autoComplete="off" spellCheck={false} className={inputClass} value={token} onChange={event => setToken(event.target.value)} /></label>}
        <p>The official client is installed if missing. Complete provider login and operating system permission prompts when they appear. Windows setup adds a UDP firewall rule limited to this app and the private provider network.</p>
        <label><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} /> Install the client and apply the setup described above</label>
        <button type="button" disabled={!consent || busy} onClick={() => void start()} className="rounded border border-subtle px-3 py-2 disabled:opacity-50">Install and connect</button>
      </fieldset>
      {provider === "Cloudflare" && configure && !busy && <>
        <label><input type="checkbox" checked={remove} onChange={event => setRemove(event.target.checked)} /> Remove this deployment's Cloudflare enrollment policy and device profile. This can interrupt access.</label>
        <button type="button" disabled={!remove} onClick={() => { setRemove(false); void start(true); }}>Remove Boundary account resources</button>
      </>}
      {busy && <button type="button" onClick={() => { void mustInvoke("boundary_provider_cancel").catch(error => setMessage(String(error))); }}>Cancel setup</button>}
      {message && <p role="status">{message}</p>}
      <p className="text-xs text-secondary">A local connection check is followed by an actual Boundary session to verify the complete route. Private invitations disable public relay fallback.</p>
    </div>
  </details>;
}
