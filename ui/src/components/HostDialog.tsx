/** Add/Edit host dialog with progressive disclosure (PRD/11 §3.3). */
import { useMemo, useState, type ReactNode } from "react";
import type { HostGroup, HostProfile, HostTag, OsHint, QualityPreset, ScalingMode, SshTunnelSettings } from "../lib/types";
import { blankSshTunnel, parseSshTunnel } from "../lib/types";
import { parseConnectAddress } from "../lib/address";
import { Dialog, Select } from "./primitives";
import { IconChevronDown, IconChevronRight } from "./icons";
import { classNames } from "../lib/util";

export interface HostDraft {
  id?: string;
  friendlyName: string;
  address: string;
  port: number;
  groupId: string | null;
  tagIds: string[];
  osHint: OsHint;
  password: string;
  hasPassword: boolean;
  securityPref: string | null;
  qualityPref: QualityPreset;
  scalingMode: ScalingMode;
  keyboardMode: string;
  passthrough: boolean;
  /** Parsed `sshTunnel` blob; `null` when the host has never configured one. */
  sshTunnel: SshTunnelSettings | null;
  /**
   * SSH passphrase (or key passphrase) to save. Like `password`, write-only:
   * empty means "leave whatever is in the keychain alone", and nothing stored
   * is ever read back into the dialog.
   */
  sshPassphrase: string;
  wolMac: string | null;
  /**
   * UI-only: this MAC came from discovery, not from the stored profile. Drives
   * the "we filled this in for you" hint and opens the Advanced section, so an
   * auto-filled value is never applied out of sight. Never persisted.
   */
  macFromDiscovery?: boolean;
}

export function draftFromHost(h: HostProfile | null, prefill?: Partial<HostDraft>): HostDraft {
  return {
    id: h?.id,
    friendlyName: h?.friendlyName ?? prefill?.friendlyName ?? "",
    address: h?.address ?? prefill?.address ?? "",
    port: h?.port ?? prefill?.port ?? 5900,
    groupId: h?.groupId ?? null,
    tagIds: h?.tags ?? [],
    osHint: h?.osHint ?? prefill?.osHint ?? "unknown",
    password: "",
    hasPassword: h?.hasPassword ?? false,
    securityPref: h?.securityPref ?? null,
    qualityPref: h?.qualityPref ?? "auto",
    scalingMode: h?.scalingMode ?? "aspect-fit",
    keyboardMode: h?.keyboardMode ?? "auto",
    passthrough: h?.passthrough ?? false,
    sshTunnel: parseSshTunnel(h?.sshTunnel),
    sshPassphrase: "",
    // Falls through to the prefill so a MAC learned by discovery survives into
    // the draft, both for a brand-new host and for a saved one that has none.
    wolMac: h?.wolMac ?? prefill?.wolMac ?? null,
    macFromDiscovery: !h?.wolMac && Boolean(prefill?.wolMac),
  };
}

export function HostDialog({
  draft: initial,
  groups,
  tags,
  onSave,
  onClose,
}: {
  draft: HostDraft;
  groups: HostGroup[];
  tags: HostTag[];
  onSave: (draft: HostDraft) => void;
  onClose: () => void;
}): ReactNode {
  const [d, setD] = useState<HostDraft>(initial);
  // Open Advanced when the dialog arrives with a MAC the user never typed, // discovery filled it in, and a value silently folded away is one the user
  // can neither check nor correct. An enabled SSH tunnel opens it too: it
  // changes how every connection is made and should not be editable only for
  // those who remember it exists.
  const [advanced, setAdvanced] = useState(
    () => Boolean(initial.macFromDiscovery) || Boolean(initial.sshTunnel?.enabled),
  );
  const [touched, setTouched] = useState(false);

  const set = (patch: Partial<HostDraft>): void => setD((prev) => ({ ...prev, ...patch }));

  // The same parser the connection itself uses, so the dialog refuses exactly
  // what would fail to connect, and says why instead of just "invalid".
  const parsed = useMemo(() => parseConnectAddress(d.address), [d.address]);

  const addressError = touched && !parsed.ok ? parsed.error : null;

  const canSave = parsed.ok;

  const submit = (): void => {
    setTouched(true);
    if (!parsed.ok) return;
    // Saving straight from the keyboard skips the blur that normalizes the
    // address, so it is normalized here too rather than only on the way out
    // of the field.
    const address = parsed.endpoint.address;
    const name = d.friendlyName.trim() || address;
    onSave({ ...d, address, friendlyName: name });
  };

  return (
    <Dialog title={d.id ? "Edit Host" : "New Host"} onClose={onClose} width={540}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label="Friendly name" hint="How this computer appears in your library">
          <input
            data-autofocus
            className="field"
            value={d.friendlyName}
            placeholder="Living Room Mac"
            onChange={(e) => set({ friendlyName: e.target.value })}
          />
        </Field>

        <div className="grid grid-cols-[1fr_120px] gap-3">
          <Field label="Address" error={addressError}>
            <input
              className="field mono"
              value={d.address}
              placeholder="192.168.1.42 or hostname"
              spellCheck={false}
              onBlur={() => {
                setTouched(true);
                // Store what would actually be dialled, not what was typed:
                // `  office  ` and `[::1]` are accepted above but would be
                // saved verbatim and then never resolve, and an address that
                // does not match the canonical form cannot be recognised as
                // a saved host when it is typed into QuickConnect later.
                if (parsed.ok) set({ address: parsed.endpoint.address });
              }}
              onChange={(e) => {
                const typed = parseConnectAddress(e.target.value);
                // Only a port the user actually typed moves into the Port
                // field; a bare hostname leaves this profile's saved port
                // alone. Anything else stays as typed so the field stays
                // editable while it is still half-written.
                set(
                  typed.ok && typed.endpoint.explicitPort
                    ? { address: typed.endpoint.address, port: typed.endpoint.port }
                    : { address: e.target.value },
                );
              }}
            />
          </Field>
          <Field label="Port">
            <input
              className="field mono"
              type="number"
              min={1}
              max={65535}
              value={d.port}
              onChange={(e) => set({ port: parseInt(e.target.value, 10) || 5900 })}
            />
          </Field>
        </div>

        <Field
          label="Password"
          hint={
            d.hasPassword && !d.password
              ? "A password is saved in your system keychain. Leave blank to keep it."
              : "Stored in your system keychain, never in a file"
          }
        >
          <input
            className="field"
            type="password"
            value={d.password}
            placeholder={d.hasPassword ? "••••••••  (unchanged)" : "Optional"}
            autoComplete="off"
            onChange={(e) => set({ password: e.target.value })}
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Group">
            <Select
              value={d.groupId ?? ""}
              onChange={(e) => set({ groupId: e.target.value || null })}
            >
              <option value="">No group</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Operating system">
            <Select
              value={d.osHint}
              onChange={(e) => set({ osHint: e.target.value as OsHint })}
            >
              <option value="unknown">Unknown</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="qemu">QEMU / VM</option>
            </Select>
          </Field>
        </div>

        {tags.length > 0 ? (
          <Field label="Tags">
            <div className="flex flex-wrap gap-1.5">
              {tags.map((t) => {
                const on = d.tagIds.includes(t.id);
                return (
                  <button
                    key={t.id}
                    type="button"
                    aria-pressed={on}
                    className={classNames(
                      "rounded-pill border px-2.5 py-1 text-xs",
                      on ? "border-transparent font-medium text-white" : "border-subtle text-secondary",
                    )}
                    style={on ? { background: t.color } : undefined}
                    onClick={() =>
                      set({
                        tagIds: on ? d.tagIds.filter((x) => x !== t.id) : [...d.tagIds, t.id],
                      })
                    }
                  >
                    {t.name}
                  </button>
                );
              })}
            </div>
          </Field>
        ) : null}

        {/* Advanced accordion */}
        <div className="rounded-md border border-subtle">
          <button
            type="button"
            aria-expanded={advanced}
            className="flex w-full items-center gap-1.5 px-3 py-2.5 text-sm font-medium text-secondary hover:text-primary"
            onClick={() => setAdvanced((a) => !a)}
          >
            {advanced ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
            Advanced
          </button>
          {advanced ? (
            <div className="space-y-4 border-t border-subtle p-3">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Security type" hint="Auto negotiates the strongest supported">
                  <Select
                    value={d.securityPref ?? "auto"}
                    onChange={(e) => set({ securityPref: e.target.value === "auto" ? null : e.target.value })}
                  >
                    <option value="auto">Auto</option>
                    <option value="vencrypt-x509">VeNCrypt (TLS + X.509)</option>
                    <option value="ra2">RSA-AES (RA2)</option>
                    <option value="apple-dh">Apple Screen Sharing</option>
                    <option value="vncauth">VNC password only</option>
                    <option value="none">None</option>
                  </Select>
                </Field>
                <Field label="Quality" hint="Auto adapts to network conditions">
                  <Select
                    value={d.qualityPref}
                    onChange={(e) => set({ qualityPref: e.target.value as QualityPreset })}
                  >
                    <option value="auto">Auto</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="bw">Black &amp; White</option>
                  </Select>
                </Field>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Scaling" hint="How the remote screen fits the window">
                  <Select
                    value={d.scalingMode}
                    onChange={(e) => set({ scalingMode: e.target.value as ScalingMode })}
                  >
                    <option value="aspect-fit">Aspect fit</option>
                    <option value="fit">Fit to window</option>
                    <option value="actual">Actual size (1:1)</option>
                    <option value="remote-resize">Remote resize</option>
                  </Select>
                </Field>
                <Field label="Keyboard mode" hint="How keystrokes are translated">
                  <Select
                    value={d.keyboardMode}
                    onChange={(e) => set({ keyboardMode: e.target.value })}
                  >
                    <option value="auto">Auto</option>
                    <option value="keysym">Keysym</option>
                    <option value="unicode">Unicode</option>
                    <option value="scancode">Scancode</option>
                  </Select>
                </Field>
              </div>
              <Field
                label="MAC address (for Wake-on-LAN)"
                hint={
                  d.macFromDiscovery
                    ? "Filled in automatically, this is the address we saw when we found this machine on your network. Lets you wake it from the library."
                    : "Filled in automatically when the machine was discovered on your network. Lets you wake this computer from the library."
                }
              >
                <input
                  className="field mono"
                  value={d.wolMac ?? ""}
                  placeholder="aa:bb:cc:dd:ee:ff"
                  spellCheck={false}
                  aria-label="MAC address for Wake-on-LAN"
                  onChange={(e) => set({ wolMac: e.target.value || null, macFromDiscovery: false })}
                />
              </Field>
              <label className="flex items-start gap-2.5 text-sm text-primary">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-(--accent)"
                  checked={d.passthrough}
                  onChange={(e) => set({ passthrough: e.target.checked })}
                />
                <span>
                  Capture system shortcuts by default
                  <span className="block text-xs text-tertiary">
                    Sends shortcuts like Cmd+Tab / Alt+Tab to the remote computer
                  </span>
                </span>
              </label>
              <SshTunnelSection
                tunnel={d.sshTunnel}
                passphrase={d.sshPassphrase}
                onChange={(sshTunnel) => set({ sshTunnel })}
                onPassphrase={(sshPassphrase) => set({ sshPassphrase })}
              />
            </div>
          ) : null}
        </div>

        <div className="flex justify-end gap-2.5 pt-1">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={!canSave}>
            {d.id ? "Save Changes" : "Add Host"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * The SSH tunnel editor inside Advanced. The auth secret itself never
 * appears here: `stored` uses the passphrase saved in the keychain for this
 * host (the same one the Files panel uses), `agent` asks the running
 * ssh-agent, and `key-file` names a key on disk.
 */
function SshTunnelSection({
  tunnel,
  passphrase,
  onChange,
  onPassphrase,
}: {
  tunnel: SshTunnelSettings | null;
  passphrase: string;
  onChange: (tunnel: SshTunnelSettings) => void;
  onPassphrase: (passphrase: string) => void;
}): ReactNode {
  const t = tunnel ?? blankSshTunnel();
  const patch = (p: Partial<SshTunnelSettings>): void => onChange({ ...t, ...p });

  return (
    <div className="space-y-4 rounded-md border border-subtle p-3">
      <label className="flex items-start gap-2.5 text-sm text-primary">
        <input
          type="checkbox"
          className="mt-0.5 accent-(--accent)"
          checked={t.enabled}
          onChange={(e) => patch({ enabled: e.target.checked })}
        />
        <span>
          Tunnel over SSH
          <span className="block text-xs text-tertiary">
            Runs the VNC connection through an SSH login, so it works for servers that
            only listen on the remote computer&apos;s own loopback, and is encrypted end to end
          </span>
        </span>
      </label>
      {t.enabled ? (
        <>
          <div className="grid grid-cols-[1fr_120px] gap-3">
            <Field label="SSH host" hint="Leave blank to SSH to the VNC address above">
              <input
                className="field mono"
                value={t.host}
                placeholder="Same as the VNC address"
                spellCheck={false}
                onChange={(e) => patch({ host: e.target.value })}
              />
            </Field>
            <Field label="SSH port">
              <input
                className="field mono"
                type="number"
                min={1}
                max={65535}
                value={t.port}
                onChange={(e) => patch({ port: parseInt(e.target.value, 10) || 22 })}
              />
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="User" hint="Leave blank to use your local username">
              <input
                className="field mono"
                value={t.user}
                placeholder="Same as this computer"
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => patch({ user: e.target.value })}
              />
            </Field>
            <Field label="Authentication" hint="Secrets stay in your keychain / agent">
              <Select
                value={t.auth}
                onChange={(e) =>
                  patch({ auth: e.target.value as SshTunnelSettings["auth"] })
                }
              >
                <option value="stored">Saved passphrase (or agent)</option>
                <option value="agent">SSH agent</option>
                <option value="key-file">Private key file</option>
              </Select>
            </Field>
          </div>
          {t.auth === "key-file" ? (
            <Field label="Private key path" hint="An OpenSSH private key on this computer">
              <input
                className="field mono"
                value={t.keyPath ?? ""}
                placeholder="~/.ssh/id_ed25519"
                spellCheck={false}
                onChange={(e) => patch({ keyPath: e.target.value || null })}
              />
            </Field>
          ) : null}
          {t.auth !== "agent" ? (
            <Field
              label={t.auth === "key-file" ? "Key passphrase" : "SSH password"}
              hint="Stored in your system keychain, shared with the Files panel. Leave blank to keep what is already saved."
            >
              <input
                className="field"
                type="password"
                value={passphrase}
                placeholder="Optional"
                autoComplete="off"
                onChange={(e) => onPassphrase(e.target.value)}
              />
            </Field>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  children: ReactNode;
}): ReactNode {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-secondary">{label}</span>
      {children}
      {error ? (
        <span className="mt-1 block text-xs text-danger" role="alert">
          {error}
        </span>
      ) : hint ? (
        <span className="mt-1 block text-xs text-tertiary">{hint}</span>
      ) : null}
    </label>
  );
}
