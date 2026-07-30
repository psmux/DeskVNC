/** Add/Edit host dialog with progressive disclosure (PRD/11 §3.3). */
import { useMemo, useState, type ReactNode } from "react";
import type { HostGroup, HostProfile, HostTag, OsHint, QualityPreset, ScalingMode } from "../lib/types";
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
    // Falls through to the prefill so a MAC learned by discovery survives into
    // the draft, both for a brand-new host and for a saved one that has none.
    wolMac: h?.wolMac ?? prefill?.wolMac ?? null,
    macFromDiscovery: !h?.wolMac && Boolean(prefill?.wolMac),
  };
}

/** Accepts "host", "host:5901", or display-number shorthand "host:1" (-> 5901). */
function parseAddress(input: string): { address: string; port: number | null } {
  const m = /^(.*?):(\d+)$/.exec(input.trim());
  if (!m) return { address: input.trim(), port: null };
  const n = parseInt(m[2], 10);
  return { address: m[1], port: n < 100 ? 5900 + n : n };
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
  // can neither check nor correct.
  const [advanced, setAdvanced] = useState(() => Boolean(initial.macFromDiscovery));
  const [touched, setTouched] = useState(false);

  const set = (patch: Partial<HostDraft>): void => setD((prev) => ({ ...prev, ...patch }));

  const addressError = useMemo((): string | null => {
    if (!touched) return null;
    if (d.address.trim().length === 0) return "An address or hostname is required";
    if (/\s/.test(d.address.trim())) return "Addresses cannot contain spaces";
    return null;
  }, [d.address, touched]);

  const canSave = d.address.trim().length > 0 && !/\s/.test(d.address.trim());

  const submit = (): void => {
    setTouched(true);
    if (!canSave) return;
    const name = d.friendlyName.trim() || d.address.trim();
    onSave({ ...d, friendlyName: name });
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
              onBlur={() => setTouched(true)}
              onChange={(e) => {
                const { address, port } = parseAddress(e.target.value);
                set(port !== null ? { address, port } : { address: e.target.value });
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
