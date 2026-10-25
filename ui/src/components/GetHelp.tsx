import { useEffect, useRef, useState, type ReactNode } from "react";
import { BoundaryProviderSetup } from "./BoundaryProviderSetup";
import { writeClipboard } from "../lib/tauri";
import {
  setCodeService,
  shortId,
  support,
  useSupport,
  type NetworkProfile,
  type SupportView,
} from "../lib/support";

/**
 * Get help: let someone see or control this computer, with nothing else to
 * download. Everything DeskVNC Support offers the person being helped is
 * here: a code or invitation, the approval, control and their tools as
 * separate choices, pairing, and unattended access.
 *
 * The approval itself and the banner shown while someone is connected live in
 * `SupportOverlay`, so they appear whether or not this window is open.
 */
export function GetHelp(): ReactNode {
  const dialog = useRef<HTMLDialogElement>(null);
  const [open, setOpen] = useState(false);
  const view = useSupport();
  const show = () => {
    setOpen(true);
    dialog.current?.showModal();
    void support.refreshDisplays().catch(() => undefined);
  };
  const close = () => {
    setOpen(false);
    dialog.current?.close();
  };
  const helping = (view?.unattended.active.length ?? 0) > 0;
  const busy = view?.sharing || helping;
  return (
    <>
      <button
        type="button"
        className={`rounded-md border px-3 py-1.5 text-sm hover:bg-inset ${busy ? "border-danger text-danger" : "border-subtle text-primary"}`}
        onClick={show}
        title="Let someone you trust see or control this computer"
      >
        {view?.connected || helping ? "Sharing" : "Get help"}
      </button>
      <dialog
        ref={dialog}
        onClose={() => setOpen(false)}
        className="m-auto max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-subtle bg-raised p-6 text-primary shadow-lg backdrop:bg-black/40"
      >
        {open && view ? <Body view={view} onClose={close} /> : null}
      </dialog>
    </>
  );
}

function Body({ view, onClose }: { view: SupportView; onClose: () => void }): ReactNode {
  const [error, setError] = useState("");
  const run = (action: () => Promise<unknown>) => {
    setError("");
    action().catch((err) => setError(String(err)));
  };
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start gap-3">
        <div>
          <h2 className="text-lg font-semibold">Get help</h2>
          <p className="mt-1 text-sm text-secondary">
            Let someone you trust see or control this computer. They see nothing until you approve
            them.
          </p>
        </div>
        <button type="button" className="btn-secondary ml-auto shrink-0" onClick={onClose}>
          Close
        </button>
      </div>
      <section className="rounded-lg border border-subtle bg-surface p-4">
        {view.connected ? <Sharing view={view} run={run} /> : <Share view={view} run={run} />}
      </section>
      {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
      <StatusLine view={view} />
      <details className="rounded-lg border border-subtle p-4">
        <summary className="cursor-pointer font-medium">Settings</summary>
        <div className="mt-4 flex flex-col gap-6">
          <ScreenSettings view={view} run={run} />
          <UnattendedSettings view={view} run={run} />
          <ConnectionSettings view={view} />
          <CodeSettings view={view} />
        </div>
      </details>
    </div>
  );
}

type Run = (action: () => Promise<unknown>) => void;

function Copy({ text, label }: { text: string; label: string }): ReactNode {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn-secondary px-3 py-1 text-xs"
      onClick={() => {
        void writeClipboard(text).then((ok) => {
          setDone(ok);
          if (ok) setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}

function ScreenPermission(): ReactNode {
  return (
    <div className="flex flex-col gap-2 text-sm">
      <p>Screen Recording permission is needed to share.</p>
      <div>
        <button type="button" className="btn-secondary" onClick={() => void support.requestScreenPermission()}>
          Allow screen recording
        </button>
      </div>
      <p className="text-xs text-secondary">After granting it, quit and reopen DeskVNC if sharing still fails.</p>
    </div>
  );
}

function DisplayPicker({ view, run }: { view: SupportView; run: Run }): ReactNode {
  return (
    <select
      className="field"
      value={view.display ?? ""}
      disabled={view.sharing}
      onChange={(event) => run(() => support.setDisplay(Number(event.target.value)))}
    >
      {view.displays.map((display) => (
        <option key={display.id} value={display.id}>
          {display.name}
        </option>
      ))}
    </select>
  );
}

/** Before anyone is connected: the code, or the button that makes one. */
function Share({ view, run }: { view: SupportView; run: Run }): ReactNode {
  const label = view.codesAvailable ? "Get a code" : "Create invitation";
  let body: ReactNode;
  if (!view.sharing) {
    if (!view.screenPermission) body = <ScreenPermission />;
    else if (view.displays.length === 0) body = <p className="text-sm text-danger">No display found to share.</p>;
    else
      body = (
        <>
          {view.displays.length > 1 ? (
            <label className="text-sm">
              Sharing
              <div className="mt-1">
                <DisplayPicker view={view} run={run} />
              </div>
            </label>
          ) : null}
          <button
            type="button"
            className="btn-primary w-full py-3 text-base"
            disabled={view.networkError !== null}
            onClick={() => run(support.share)}
          >
            {label}
          </button>
          <p className="text-xs text-secondary">One code per session. It expires after 10 minutes if nobody connects.</p>
        </>
      );
  } else if (!view.invitation || view.codeBusy) {
    body = (
      <>
        <p className="text-sm text-secondary">{view.invitation ? "Getting your code…" : "Creating your code…"}</p>
        {view.invitation ? (
          <div>
            <button type="button" className="btn-secondary px-3 py-1 text-xs" onClick={() => run(support.fullInvitation)}>
              Use the full invitation instead
            </button>
          </div>
        ) : null}
      </>
    );
  } else if (view.code) {
    body = (
      <>
        <p className="mono select-all text-center text-3xl font-semibold tracking-wider">{view.code}</p>
        <p className="text-xs text-secondary">Read it out or send it. Your helper enters it, and you approve them here.</p>
        <div className="flex gap-2">
          <Copy text={view.code} label="Copy code" />
          <Copy text={view.invitation} label="Copy the full invitation instead" />
        </div>
      </>
    );
  } else {
    body = (
      <>
        <textarea
          readOnly
          rows={4}
          value={view.invitation}
          className="mono w-full rounded border border-subtle bg-inset p-2 text-xs"
          onFocus={(event) => event.target.select()}
        />
        <div>
          <Copy text={view.invitation} label="Copy invitation" />
        </div>
        <p className="text-xs text-secondary">Send it in any chat and keep it private. It is valid for one session.</p>
        {view.codeMessage ? <p className="text-sm text-danger">{view.codeMessage}</p> : null}
      </>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <div>
        <h3 className="font-semibold">Allow remote control</h3>
        <p className="text-sm text-secondary">
          Give the person helping you {view.codesAvailable ? "this code" : "this invitation"}. They see nothing until you
          approve them.
        </p>
      </div>
      {body}
      {view.sharing ? (
        <div>
          <button type="button" className="btn-secondary" onClick={() => run(support.stop)}>
            Cancel
          </button>
        </div>
      ) : null}
      <UnattendedSummary view={view} />
    </div>
  );
}

function UnattendedSummary({ view }: { view: SupportView }): ReactNode {
  const u = view.unattended;
  return (
    <div className="mt-2 border-t border-subtle pt-3 text-sm">
      <p>
        Unattended access:{" "}
        {u.enabled ? (
          <span className="text-success">{u.reachable ? "On" : "Starting"}</span>
        ) : (
          <span className="text-secondary">Off. Change it under Settings.</span>
        )}
      </p>
      {u.enabled ? (
        <div className="mt-1 flex items-center gap-2">
          <span className="text-xs text-secondary">This computer's ID</span>
          <span className="mono text-xs">{shortId(u.machineId)}</span>
          <Copy text={u.machineId} label="Copy ID" />
        </div>
      ) : null}
    </div>
  );
}

/** While a helper is connected. */
function Sharing({ view, run }: { view: SupportView; run: Run }): ReactNode {
  const helper = view.helper;
  return (
    <div className="flex flex-col gap-3">
      <div>
        <h3 className="font-semibold">Your screen is being shared</h3>
        <p className="text-sm text-secondary">
          The helper can see the selected display, including notifications and this window.
        </p>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={view.control}
          disabled={!view.inputPermission}
          onChange={(event) => run(() => support.setControl(event.target.checked))}
        />
        Allow the helper to control my mouse and keyboard
      </label>
      {!view.inputPermission ? (
        <div className="text-sm">
          <p className="text-secondary">Control needs Accessibility permission. Viewing works without it.</p>
          <button type="button" className="btn-secondary mt-1" onClick={() => void support.openInputSettings()}>
            Open Accessibility settings
          </button>
        </div>
      ) : null}
      {view.toolsOffered ? (
        <>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={view.tools}
              onChange={(event) => run(() => support.setTools(event.target.checked))}
            />
            Allow the helper's tools to run commands and copy files
          </label>
          {view.activity.length > 0 ? (
            <div>
              <p className="text-xs text-secondary">What their tools did</p>
              {view.activity.map((line, index) => (
                <p key={index} className="mono truncate text-xs">
                  {line}
                </p>
              ))}
            </div>
          ) : null}
        </>
      ) : null}
      {helper ? (
        helper.paired ? (
          <p className="text-sm text-secondary">
            {helper.name} can connect to this computer any time. Remove them under Settings, Unattended access, to stop
            it.
          </p>
        ) : (
          <div>
            <button
              type="button"
              className="btn-secondary"
              title="They are remembered by their connection's key. You can remove them later under Settings."
              onClick={() => run(support.pair)}
            >
              Let {helper.name} connect any time, even when I am away
            </button>
          </div>
        )
      ) : null}
      <div>
        <button type="button" className="btn-danger" onClick={() => run(support.stop)}>
          End session
        </button>
      </div>
    </div>
  );
}

function StatusLine({ view }: { view: SupportView }): ReactNode {
  const color = view.error ? "bg-danger" : view.connected || !view.sharing ? "bg-success" : "bg-warning";
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className={`inline-block size-2 rounded-full ${color}`} />
      <span>{view.status}</span>
      {view.warning ? <span className="text-warning">{view.warning}</span> : null}
      {view.route ? <span className="text-secondary">{view.route}</span> : null}
      <span className="ml-auto text-secondary">{view.networkLabel}</span>
    </div>
  );
}

function ScreenSettings({ view, run }: { view: SupportView; run: Run }): ReactNode {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="font-semibold">Screen to share</h3>
      {view.displays.length > 0 ? (
        <div className="flex gap-2">
          <DisplayPicker view={view} run={run} />
          <button type="button" className="btn-secondary shrink-0" onClick={() => run(support.refreshDisplays)}>
            Refresh
          </button>
        </div>
      ) : (
        <p className="text-sm text-danger">No display found.</p>
      )}
      {!view.screenPermission ? <ScreenPermission /> : null}
      {!view.inputPermission ? (
        <div className="text-sm">
          <p className="text-secondary">
            Accessibility permission is needed for a helper to control this computer. Viewing works without it.
          </p>
          <button type="button" className="btn-secondary mt-1" onClick={() => void support.openInputSettings()}>
            Open Accessibility settings
          </button>
        </div>
      ) : null}
    </section>
  );
}

/**
 * The addresses a helper on the same network, or a VPN, can type instead of
 * the ID, and on Windows the one firewall change that lets them in.
 */
function DirectAddresses({ addresses, reachable, run }: { addresses: string[]; reachable: boolean; run: Run }): ReactNode {
  const [allowed, setAllowed] = useState<boolean | null>(null);
  useEffect(() => {
    if (!reachable) return;
    let live = true;
    void support
      .directAllowed()
      .then((answer) => live && setAllowed(answer))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [reachable]);
  if (addresses.length === 0) return null;
  return (
    <div className="mt-2">
      <p className="text-xs text-secondary">Or by address, on a network that reaches this computer</p>
      <ul className="flex flex-col gap-1">
        {addresses.map((address) => (
          <li key={address} className="flex items-center gap-2">
            <span className="mono text-xs">{address}</span>
            <Copy text={address} label="Copy" />
          </li>
        ))}
      </ul>
      {allowed === false ? (
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <p className="text-xs text-secondary">Windows Firewall turns these away until you allow DeskVNC in.</p>
          <button
            type="button"
            className="btn-secondary"
            onClick={() =>
              run(async () => {
                await support.allowDirect();
                setAllowed(await support.directAllowed());
              })
            }
          >
            Allow connections by address
          </button>
        </div>
      ) : null}
    </div>
  );
}

function UnattendedSettings({ view, run }: { view: SupportView; run: Run }): ReactNode {
  const u = view.unattended;
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [local, setLocal] = useState("");
  const setNewPassword = () => {
    setLocal("");
    if (password !== confirm) {
      setLocal("The two passwords differ");
      return;
    }
    run(() => support.setPassword(password));
    setPassword("");
    setConfirm("");
  };
  return (
    <section className="flex flex-col gap-2 text-sm">
      <h3 className="font-semibold">Unattended access</h3>
      <p className="text-secondary">
        Let people you trust connect to this computer when nobody is here to approve. Off unless you switch it on.
        DeskVNC must be running for it to work.
      </p>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={u.enabled} onChange={(event) => run(() => support.setUnattended(event.target.checked))} />
        Allow unattended access to this computer
      </label>
      {u.enabled ? (
        <div>
          <p className="text-xs text-secondary">{u.reachable ? "This computer's ID, reachable now" : "This computer's ID"}</p>
          <div className="flex items-center gap-2">
            <span className="mono break-all text-xs">{u.machineId}</span>
            <Copy text={u.machineId} label="Copy ID" />
          </div>
          <p className="mt-1 text-xs text-secondary">
            A helper enters it as the computer ID, with the unattended password unless they were paired here.
          </p>
          <DirectAddresses addresses={u.addresses} reachable={u.reachable} run={run} />
        </div>
      ) : null}
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={u.autostart} onChange={(event) => run(() => support.setAutostart(event.target.checked))} />
        Start DeskVNC when I sign in, so it is ready
      </label>
      <p className="mt-2 text-xs text-secondary">Paired helpers</p>
      {u.helpers.length === 0 ? (
        <p className="text-xs text-secondary">
          None yet. During a support session, choose Let them connect any time to pair the helper.
        </p>
      ) : (
        <ul className="flex flex-col gap-1">
          {u.helpers.map((helper) => (
            <li key={helper.id} className="flex flex-wrap items-center gap-3">
              <span className="font-medium">{helper.name}</span>
              <span className="mono text-xs text-secondary">{shortId(helper.id)}</span>
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={helper.control}
                  onChange={(event) => run(() => support.setHelper(helper.id, event.target.checked, helper.tools))}
                />
                may control
              </label>
              <label
                className="flex items-center gap-1 text-xs"
                title="For a helper whose tools, such as DeskVNC's agents, work on this computer while you are away. Commands run as you."
              >
                <input
                  type="checkbox"
                  checked={helper.tools}
                  onChange={(event) => run(() => support.setHelper(helper.id, helper.control, event.target.checked))}
                />
                may run commands and copy files
              </label>
              <button type="button" className="btn-secondary ml-auto px-2.5 py-1 text-xs" onClick={() => run(() => support.removeHelper(helper.id))}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-xs text-secondary">Unattended password</p>
      <p className="text-xs text-secondary">
        Optional. Lets a helper who was never paired connect with this computer's ID and the password. At least{" "}
        {u.minPassword} characters. Five wrong tries pause it for 15 minutes.
      </p>
      <div className="flex flex-wrap gap-2">
        <input
          type="password"
          autoComplete="new-password"
          placeholder="New password"
          className="field max-w-48"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        <input
          type="password"
          autoComplete="new-password"
          placeholder="Repeat it"
          className="field max-w-48"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
        />
        <button type="button" className="btn-secondary" disabled={password === ""} onClick={setNewPassword}>
          Set password
        </button>
        {u.hasPassword ? (
          <button type="button" className="btn-secondary" onClick={() => run(() => support.setPassword(null))}>
            Remove the password
          </button>
        ) : null}
      </div>
      {local ? <p className="text-danger">{local}</p> : null}
      {u.message ? <p className={u.error ? "text-danger" : "text-success"}>{u.message}</p> : null}
    </section>
  );
}

type Choice = "Automatic" | "Provider" | "Private" | "Relay";

function ConnectionSettings({ view }: { view: SupportView }): ReactNode {
  const [choice, setChoice] = useState<Choice>(view.network.mode);
  const [address, setAddress] = useState(view.network.mode === "Private" ? view.network.address : "");
  const [relay, setRelay] = useState(view.network.mode === "Relay" ? view.network.url : "");
  const [message, setMessage] = useState("");
  useEffect(() => setMessage(""), [choice]);
  const profile = (): NetworkProfile => {
    if (choice === "Automatic") return { mode: "Automatic" };
    if (choice === "Relay") return { mode: "Relay", url: relay.trim() };
    return { mode: "Private", address: address.trim() };
  };
  const save = () => {
    setMessage("");
    support
      .saveNetwork(profile())
      .then(() => setMessage("Saved. Get a code to try it with your helper."))
      .catch((err) => setMessage(String(err)));
  };
  const radio = (value: Choice, label: string) => (
    <label className="flex items-center gap-2">
      <input type="radio" name="support-network" checked={choice === value} onChange={() => setChoice(value)} />
      {label}
    </label>
  );
  const ready = choice === "Automatic" || (choice === "Relay" ? relay.trim() !== "" : address.trim() !== "");
  return (
    <section className="flex flex-col gap-2 text-sm">
      <h3 className="font-semibold">Connection</h3>
      <p className="text-secondary">Now: {view.networkLabel}</p>
      {view.networkError ? <p className="text-danger">{view.networkError}</p> : null}
      <fieldset disabled={view.sharing} className="flex flex-col gap-2">
        {radio("Automatic", "Automatic (recommended for a support call)")}
        {radio("Provider", "Set up my Tailscale or Cloudflare network")}
        {radio("Private", "Use another existing private network")}
        {radio("Relay", "Use my compatible relay server")}
        {choice === "Automatic" ? (
          <p className="text-xs text-secondary">
            Tries a direct connection with encrypted relay fallback. No provider account is needed. Public relays have
            capacity limits and no uptime guarantee.
          </p>
        ) : null}
        {choice === "Provider" ? (
          <>
            <BoundaryProviderSetup
              active
              intro="Install and connect this computer to your own provider account. Run setup on the helper's device too."
              onAddress={setAddress}
            />
            {address ? <p className="text-xs">This computer's address on that network: {address}</p> : null}
          </>
        ) : null}
        {choice === "Private" ? (
          <label>
            Local interface IP address
            <input className="field mt-1" value={address} onChange={(event) => setAddress(event.target.value)} />
            <span className="mt-1 block text-xs text-secondary">
              For an existing Headscale, WireGuard, Cloudflare private network or other routed network. Both machines
              need a permitted route. Entering an IP does not enroll either device.
            </span>
          </label>
        ) : null}
        {choice === "Relay" ? (
          <label>
            Relay URL
            <input className="field mt-1" value={relay} onChange={(event) => setRelay(event.target.value)} />
            <span className="mt-1 block text-xs text-secondary">
              A compatible iroh relay. The invitation carries it to your helper.
            </span>
          </label>
        ) : null}
        {choice === "Provider" || choice === "Private" ? (
          <p className="text-xs text-secondary">
            If this network is unavailable or the address changes, connecting fails instead of using a public relay.
          </p>
        ) : null}
        <div>
          <button type="button" className="btn-secondary" disabled={!ready} onClick={save}>
            Save connection settings
          </button>
        </div>
      </fieldset>
      {view.sharing ? <p className="text-xs text-secondary">End the session to change this.</p> : null}
      {message ? <p role="status">{message}</p> : null}
    </section>
  );
}

function CodeSettings({ view }: { view: SupportView }): ReactNode {
  const [url, setUrl] = useState(view.codeService);
  const [message, setMessage] = useState("");
  const save = () => {
    setMessage("");
    setCodeService(url)
      .then(() => setMessage("Saved"))
      .catch((err) => setMessage(String(err)));
  };
  return (
    <section className="flex flex-col gap-2 text-sm">
      <h3 className="font-semibold">Short codes</h3>
      <p className="text-secondary">
        A short code is easier to read out than a full invitation. Both people must use the same code service, and it
        can read the invitations it is given, so use one you trust.
      </p>
      <div className="flex gap-2">
        <input
          type="url"
          className="field"
          placeholder="https://codes.example.com"
          value={url}
          disabled={view.sharing}
          onChange={(event) => setUrl(event.target.value)}
        />
        <button type="button" className="btn-secondary shrink-0" disabled={view.sharing} onClick={save}>
          Save
        </button>
      </div>
      <p className="text-xs text-secondary">
        Leave empty for the shared Boundary service. Private infrastructure needs its own service here.
      </p>
      {message ? <p role="status">{message}</p> : null}
    </section>
  );
}
