/**
 * The saved credentials list in Preferences > Security (issue #98): add,
 * edit and delete the user names and passwords, and SSH keys, that hosts
 * sign in with. Editing one here changes it for every host that uses it.
 */
import { useState, type ReactNode } from "react";
import { useHosts } from "../state/HostsContext";
import {
  blankSavedCredential,
  deleteSavedCredential,
  deleteSummary,
  describeCredential,
  hostsUsing,
  type SavedCredential,
} from "../lib/savedCredentials";
import { SavedCredentialDialog } from "./HostDialog";
import { Dialog } from "./primitives";

export function SavedCredentialsSection(): ReactNode {
  const { hosts, savedCredentials, refresh } = useHosts();
  const [editing, setEditing] = useState<SavedCredential | null>(null);
  const [deleting, setDeleting] = useState<SavedCredential | null>(null);
  const [error, setError] = useState<string | null>(null);
  const list = savedCredentials ?? [];

  const remove = async (c: SavedCredential, keepOnHosts: boolean): Promise<void> => {
    try {
      await deleteSavedCredential(c.id, keepOnHosts);
      setDeleting(null);
      setError(null);
    } catch (err) {
      setError(String(err));
    }
    await refresh();
  };

  const using = deleting ? hostsUsing(deleting.id, hosts) : [];

  return (
    <div>
      <p className="text-sm font-medium text-primary">Saved credentials</p>
      <p className="text-xs text-tertiary">
        A user name and password, or an SSH key, saved once and picked in any host&apos;s editor. Change it
        here and every host that uses it signs in with the new one.
      </p>
      {list.length === 0 ? (
        <p className="mt-2 text-xs text-secondary">
          None yet. Add one here, or choose &quot;New saved credential&quot; in a host&apos;s editor.
        </p>
      ) : (
        <ul className="mt-2 divide-y divide-subtle rounded-md border border-subtle" aria-label="Saved credentials">
          {list.map((c) => {
            const n = hostsUsing(c.id, hosts).length;
            return (
              <li key={c.id} className="flex items-center gap-3 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm text-primary">{c.name}</p>
                  <p className="truncate text-xs text-tertiary">
                    {describeCredential(c)} {n === 0 ? "No host uses it." : n === 1 ? "Used by 1 host." : `Used by ${n} hosts.`}
                  </p>
                </div>
                <button type="button" className="btn-secondary" onClick={() => setEditing(c)}>
                  Edit
                </button>
                <button type="button" className="btn-secondary" onClick={() => setDeleting(c)}>
                  Delete
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <button type="button" className="btn-secondary mt-2" onClick={() => setEditing(blankSavedCredential())}>
        Add saved credential
      </button>
      {error ? (
        <p className="mt-2 text-xs text-danger" role="alert">
          {error}
        </p>
      ) : null}

      {editing ? (
        <SavedCredentialDialog
          initial={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void refresh();
          }}
        />
      ) : null}

      {deleting ? (
        <Dialog title={`Delete ${deleting.name}?`} onClose={() => setDeleting(null)} danger width={460}>
          <p className="text-sm text-secondary" data-testid="delete-credential-summary">
            {deleteSummary(deleting, using)}
          </p>
          <div className="mt-4 flex flex-wrap justify-end gap-2">
            <button type="button" className="btn-secondary" onClick={() => setDeleting(null)}>
              Cancel
            </button>
            {using.length > 0 ? (
              <>
                <button type="button" className="btn-secondary" onClick={() => void remove(deleting, false)}>
                  Delete, hosts will ask
                </button>
                <button type="button" className="btn-danger" onClick={() => void remove(deleting, true)}>
                  Delete, keep a copy on each host
                </button>
              </>
            ) : (
              <button type="button" className="btn-danger" onClick={() => void remove(deleting, false)}>
                Delete
              </button>
            )}
          </div>
        </Dialog>
      ) : null}
    </div>
  );
}
