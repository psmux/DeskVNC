/**
 * "Add to saved hosts", from the right-click menu of a tab whose session was
 * opened without one (quick connect, a typed address, Nearby, an agent).
 *
 * The same dialog is "Edit saved host" on a tab whose session already has a
 * host: often one the automatic save made and the person never named, opened
 * again from the Library or by an agent. It renames that host and can keep
 * the password the session signed in with, and points at the full editor.
 *
 * Saving makes a host with the session's protocol, address and port and the
 * defaults the session connected with, and the tab becomes a tab of that
 * host: it keeps the saved name, reconnects with the host's settings and
 * stored password, and the Library shows its activity on the host's tile.
 * The connection itself is not interrupted.
 *
 * A host already saved on the same address and port is pointed at rather
 * than duplicated: the person can open it, or update it with this name and
 * keep the tab with it.
 *
 * The password never passes through here. The shell kept the one the server
 * accepted, and only says whether there is one; `bind_session_to_host` writes
 * it into the credential store when the box is ticked.
 */
import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { emit } from "@tauri-apps/api/event";
import { useHosts } from "../state/HostsContext";
import { useDiscovery } from "../state/DiscoveryContext";
import { useTabs, type LiveSession } from "../state/TabsContext";
import { useToasts } from "../state/ToastContext";
import { discoveredFor } from "../lib/autoSave";
import { EDIT_HOST_EVENT, type EditHostRequest } from "../lib/editHost";
import { inTauri, mustInvoke, safeInvoke } from "../lib/tauri";
import { protocolLabel, type HostProfile } from "../lib/types";
import {
  NO_CREDENTIALS,
  credentialsLabel,
  existingHostFor,
  newHostForSession,
  parseCredentialState,
  saveCredentialsByDefault,
  suggestedName,
  updatedHost,
  type SessionCredentialState,
} from "../lib/saveTabHost";
import { Dialog } from "./primitives";

export function SaveTabHostDialog({
  session,
  host,
  onClose,
}: {
  session: LiveSession;
  /**
   * The saved host this session already belongs to, for "Edit saved host".
   * Null for "Add to saved hosts".
   */
  host: HostProfile | null;
  onClose: () => void;
}): ReactNode {
  const { hosts, saveHost, refresh } = useHosts();
  const { discovered } = useDiscovery();
  const { bindHost, select } = useTabs();
  const { push } = useToasts();
  const { params } = session;
  const address = (params.address ?? "").trim();
  const sessionId = params.sessionId ?? session.id;

  const editing = host !== null;
  const [name, setName] = useState(() => host?.friendlyName ?? suggestedName(session.title, address));
  const [creds, setCreds] = useState<SessionCredentialState>(NO_CREDENTIALS);
  const [saveCreds, setSaveCreds] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Worked out once, when the dialog opens: a host saved while it is open is
  // not the one the person was told about.
  const existing = useMemo(() => host ?? existingHostFor(hosts, params), []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    let cancelled = false;
    void safeInvoke<unknown>("session_credential_state", { sessionId }, null).then((raw) => {
      if (cancelled) return;
      const state = parseCredentialState(raw);
      setCreds(state);
      setSaveCreds(saveCredentialsByDefault(state));
    });
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  const save = async (): Promise<void> => {
    if (busy || name.trim() === "") return;
    setBusy(true);
    setError(null);
    try {
      let saved: HostProfile | null;
      if (existing) {
        const next = updatedHost(existing, name);
        saved = next === existing ? existing : await saveHost(next);
      } else {
        saved = await saveHost(
          newHostForSession({
            params,
            name,
            discovered: discoveredFor(discovered, params.protocol, address, params.port),
          }),
        );
      }
      if (!saved) {
        setError("This host could not be saved.");
        return;
      }
      if (inTauri()) {
        await mustInvoke("bind_session_to_host", {
          sessionId,
          hostId: saved.id,
          saveCredentials: creds.used && saveCreds,
        });
        // The connection this host came from is live, so it should not read
        // as never connected to, and Recents should list it.
        if (!existing) await safeInvoke("touch_connected", { hostId: saved.id }, null);
      }
      bindHost(session.id, saved.id, saved.friendlyName);
      void refresh();
      push(
        "success",
        existing
          ? `Updated ${saved.friendlyName} in your saved hosts`
          : `Saved ${saved.friendlyName} to your saved hosts`,
      );
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const openExisting = (): void => {
    if (!existing) return;
    onClose();
    // The editor lives in the Library, so the Library comes to the front.
    select(null);
    if (inTauri()) {
      const ask: EditHostRequest = { hostId: existing.id };
      void emit(EDIT_HOST_EVENT, ask).catch(() => {});
    }
  };

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    void save();
  };

  return (
    <Dialog title={editing ? "Edit saved host" : "Add to saved hosts"} onClose={onClose} width={440}>
      <form className="space-y-4" onSubmit={onSubmit}>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-secondary">Name</span>
          <input
            data-autofocus
            className="field"
            type="text"
            name="hostName"
            autoComplete="off"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <p className="text-xs text-secondary">
          {protocolLabel(params.protocol)} at {address}, port {params.port}
        </p>

        {editing ? (
          <p className="text-xs text-secondary">
            This tab is a host in your Library. Change its name here, or open it for every setting.
          </p>
        ) : existing ? (
          <div className="rounded-md bg-inset p-3 text-sm text-primary" role="status">
            {existing.friendlyName} is already saved for this address and port.
            <span className="mt-0.5 block text-xs text-secondary">
              Open it to see its settings, or update it to use this name and keep this tab with it.
            </span>
          </div>
        ) : null}

        {creds.used ? (
          <label className="flex items-start gap-2.5 text-sm text-primary">
            <input
              type="checkbox"
              className="mt-0.5 accent-(--accent)"
              checked={saveCreds}
              onChange={(e) => setSaveCreds(e.target.checked)}
            />
            <span>
              {credentialsLabel(creds)}
              <span className="block text-xs text-tertiary">
                Stored with your other saved passwords, never in the host list.
              </span>
            </span>
          </label>
        ) : null}

        {error ? (
          <p className="text-sm text-danger" role="alert">
            {error}
          </p>
        ) : null}

        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {editing ? (
            <>
              <button type="button" className="btn-secondary" onClick={openExisting}>
                All settings
              </button>
              <button
                type="submit"
                className="btn-primary disabled:opacity-40"
                disabled={busy || name.trim() === ""}
              >
                Save
              </button>
            </>
          ) : existing ? (
            <>
              <button type="button" className="btn-secondary" onClick={openExisting}>
                Open saved host
              </button>
              <button
                type="submit"
                className="btn-primary disabled:opacity-40"
                disabled={busy || name.trim() === ""}
              >
                Update saved host
              </button>
            </>
          ) : (
            <button
              type="submit"
              className="btn-primary disabled:opacity-40"
              disabled={busy || name.trim() === ""}
            >
              Save
            </button>
          )}
        </div>
      </form>
    </Dialog>
  );
}
