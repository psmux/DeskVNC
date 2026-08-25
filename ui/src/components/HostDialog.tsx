/** Add/Edit host dialog with progressive disclosure (PRD/11 §3.3). */
import { useMemo, useState, type ReactNode } from "react";
import type {
  HostGroup,
  HostProfile,
  HostTag,
  OsHint,
  ProtocolKind,
  QualityPreset,
  ScalingMode,
  SshTunnelSettings,
} from "../lib/types";
import {
  DEFAULT_PORT,
  PROTOCOLS,
  blankSshTunnel,
  hostProtocol,
  parseSshTunnel,
  protocolName,
} from "../lib/types";
import type { RdpResolution, RdpSettings } from "../lib/rdp";
import { rdpDefaults } from "../lib/rdpDefaults";
import {
  blankRdpSettings,
  parseRdpSettings,
  RDP_FIXED_SIZES,
  RDP_MAX_DIM,
  RDP_MIN_DIM,
} from "../lib/rdp";
import { portOnProtocolChange, portWasTouched } from "../lib/hostDraft";
import { parseConnectTarget } from "../lib/address";
import { Dialog, Select } from "./primitives";
import { IconChevronDown, IconChevronRight } from "./icons";
import { classNames } from "../lib/util";

export interface HostDraft {
  id?: string;
  friendlyName: string;
  protocol: ProtocolKind;
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

  /** Parsed `rdpSettings` blob; `null` for a VNC host. */
  rdp: RdpSettings | null;
  /**
   * RDP account name, written on save alongside the password.
   *
   * Seeded BLANK even for a saved host, like `password`: there is no
   * `get_password` and there is not going to be one, so this field carries
   * the same "leave blank to keep what is stored" affordance the password
   * field already has.
   */
  rdpUser: string;
  /** Logon domain, part of the stored credential rather than the profile
   *  blob's `domain`. Blank means "leave what is stored alone". */
  rdpDomain: string;
  /**
   * UI-only: the user has deliberately set the port, so switching protocol
   * must not move it. Never persisted.
   */
  portTouched?: boolean;
}

export function draftFromHost(h: HostProfile | null, prefill?: Partial<HostDraft>): HostDraft {
  const protocol: ProtocolKind = h ? hostProtocol(h) : (prefill?.protocol ?? "vnc");
  return {
    id: h?.id,
    friendlyName: h?.friendlyName ?? prefill?.friendlyName ?? "",
    protocol,
    address: h?.address ?? prefill?.address ?? "",
    port: h?.port ?? prefill?.port ?? DEFAULT_PORT[protocol],
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
    // A new host starts from the Preferences defaults; a saved one is read
    // back verbatim, because its own settings are the answer.
    rdp: protocol === "rdp" ? (parseRdpSettings(h?.rdpSettings) ?? newRdpSettings()) : null,
    rdpUser: "",
    rdpDomain: "",
    portTouched: portWasTouched(h),
  };
}

/** A blank set of RDP settings with the Preferences defaults applied. */
function newRdpSettings(): RdpSettings {
  return { ...blankRdpSettings(), ...rdpDefaults() };
}

/** Either of the Security disclosure's switches is already on. */
function securityIsOn(d: HostDraft): boolean {
  return d.protocol === "rdp" && (d.rdp?.nla === "allow-fallback" || d.rdp?.legacyTls === true);
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
    () =>
      Boolean(initial.macFromDiscovery) ||
      Boolean(initial.sshTunnel?.enabled) ||
      securityIsOn(initial),
  );
  // The Security disclosure opens by itself when either of its switches is
  // already on, for the same reason Advanced does: a setting that changes how
  // the connection is made must never be editable only by people who
  // remember it exists.
  const [security, setSecurity] = useState(() => securityIsOn(initial));
  const [touched, setTouched] = useState(false);

  const set = (patch: Partial<HostDraft>): void => setD((prev) => ({ ...prev, ...patch }));

  const isRdp = d.protocol === "rdp";
  const rdp = d.rdp ?? blankRdpSettings();
  const setRdp = (patch: Partial<RdpSettings>): void => set({ rdp: { ...rdp, ...patch } });

  /**
   * Switching protocol reorganises the form, so it also has to move the port,
   * but only when the port is still the outgoing protocol's default and the
   * user has not deliberately set it. The rule itself is a pure function in
   * `lib/hostDraft.ts` so it can be tested without rendering.
   */
  const changeProtocol = (to: ProtocolKind): void => {
    if (to === d.protocol) return;
    set({
      protocol: to,
      port: portOnProtocolChange(d.protocol, to, d.port, d.portTouched === true),
      rdp: to === "rdp" ? (d.rdp ?? newRdpSettings()) : d.rdp,
      // Prefilled, not forced: xrdp on Linux exists, and so does a Mac with
      // an RDP server on it.
      osHint: to === "rdp" && d.osHint === "unknown" ? "windows" : d.osHint,
    });
  };

  // The same parser the connection itself uses, so the dialog refuses exactly
  // what would fail to connect, and says why instead of just "invalid". It is
  // told which protocol to parse as, so `box:1` in an RDP host's address field
  // reads as port 1 rather than as display 1.
  const parsed = useMemo(
    () => parseConnectTarget(d.address, d.protocol),
    [d.address, d.protocol],
  );

  const addressError = touched && !parsed.ok ? parsed.error : null;

  const canSave = parsed.ok;

  const submit = (): void => {
    setTouched(true);
    if (!parsed.ok) return;
    // Saving straight from the keyboard skips the blur that normalizes the
    // address, so it is normalized here too rather than only on the way out
    // of the field.
    const address = parsed.target.address;
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

        {/*
          Above the address row, because it changes what the rest of the form
          means and a control that reorganises a form comes before the form.
        */}
        <Field label="Connect using">
          <div
            className="flex gap-1 rounded-md border border-subtle p-0.5"
            role="radiogroup"
            aria-label="Connection protocol"
          >
            {PROTOCOLS.map((p) => (
              <button
                key={p}
                type="button"
                role="radio"
                aria-checked={d.protocol === p}
                className={classNames(
                  "flex-1 rounded-sm px-3 py-1.5 text-sm",
                  d.protocol === p
                    ? "bg-accent/12 font-medium text-accent"
                    : "text-secondary hover:text-primary",
                )}
                onClick={() => changeProtocol(p)}
              >
                {protocolName(p)}
              </button>
            ))}
          </div>
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
                if (parsed.ok) set({ address: parsed.target.address });
              }}
              onChange={(e) => {
                const typed = parseConnectTarget(e.target.value, d.protocol);
                // Only a port the user actually typed moves into the Port
                // field; a bare hostname leaves this profile's saved port
                // alone. Anything else stays as typed so the field stays
                // editable while it is still half-written.
                //
                // A port that arrived this way counts as deliberately set,
                // so a later protocol switch leaves it where it is.
                set(
                  typed.ok && typed.target.explicitPort
                    ? {
                        address: typed.target.address,
                        port: typed.target.port,
                        portTouched: true,
                      }
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
              onChange={(e) =>
                set({
                  port: parseInt(e.target.value, 10) || DEFAULT_PORT[d.protocol],
                  portTouched: true,
                })
              }
            />
          </Field>
        </div>

        {/* An RDP logon is user first, so the name field sits above the
            password rather than beside the security type. */}
        {isRdp ? (
          <div className="grid grid-cols-2 gap-3">
            <Field
              label="User name"
              hint={
                d.hasPassword && !d.rdpUser
                  ? "Leave blank to keep the saved one."
                  : "The account to sign in with"
              }
            >
              <input
                className="field"
                value={d.rdpUser}
                placeholder={d.hasPassword ? "(unchanged)" : "Administrator"}
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                onChange={(e) => set({ rdpUser: e.target.value })}
              />
            </Field>
            {/*
              The hint is doing real work. Splitting a UPN into a domain is
              the classic way to break an Entra ID sign-in, and nothing in
              this app will do it for the user, so the field has to say when
              to leave itself empty.
            */}
            <Field
              label="Domain"
              hint="Leave blank for a local account, or if your user name is already an email-style name like you@company.com."
            >
              <input
                className="field"
                value={d.rdpDomain}
                placeholder="Optional"
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                onChange={(e) => set({ rdpDomain: e.target.value })}
              />
            </Field>
          </div>
        ) : null}

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
                {/* RFB security types mean nothing to RDP; the Security
                    disclosure below is what takes their place there. */}
                {isRdp ? null : (
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
                )}
                <Field
                  label="Quality"
                  hint={
                    isRdp
                      ? "Auto adapts to network conditions. Lower settings turn off wallpaper and effects on the remote desktop."
                      : "Auto adapts to network conditions"
                  }
                >
                  <Select
                    value={d.qualityPref}
                    onChange={(e) => set({ qualityPref: e.target.value as QualityPreset })}
                  >
                    <option value="auto">Auto</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    {/*
                      Black and White is a shader in this app, not a wire
                      setting, so the toolbar keeps offering it live for both
                      protocols. As a STORED default for an RDP host it would
                      quietly mean "low quality, plus a grey screen on every
                      connect", which is not what choosing a saved default is
                      for.
                    */}
                    {isRdp ? null : <option value="bw">Black &amp; White</option>}
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
                    {/* RDP has no concept of a keysym. */}
                    {isRdp ? null : <option value="keysym">Keysym</option>}
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
                    {isRdp
                      ? "Sends shortcuts like Alt+Tab and the Windows key to the remote computer"
                      : "Sends shortcuts like Cmd+Tab / Alt+Tab to the remote computer"}
                  </span>
                </span>
              </label>
              {isRdp ? <RdpOptionsSection rdp={rdp} onChange={setRdp} /> : null}
              {isRdp ? (
                <SecuritySection
                  rdp={rdp}
                  open={security}
                  onToggle={() => setSecurity((v) => !v)}
                  onChange={setRdp}
                />
              ) : null}
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
 * The RDP options that are ordinary preferences, inside Advanced.
 *
 * Everything that is a security decision lives in {@link SecuritySection}
 * below instead, so a person scanning Advanced for the resolution setting
 * does not meet a TLS downgrade switch on the way.
 */
function RdpOptionsSection({
  rdp,
  onChange,
}: {
  rdp: RdpSettings;
  onChange: (patch: Partial<RdpSettings>) => void;
}): ReactNode {
  const [codecs, setCodecs] = useState(false);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <Field label="Colour depth" hint="Auto follows the quality setting">
          <Select
            value={rdp.colorDepth}
            onChange={(e) => onChange({ colorDepth: e.target.value as RdpSettings["colorDepth"] })}
          >
            <option value="auto">Auto</option>
            <option value="bpp32">32-bit</option>
            <option value="bpp24">24-bit</option>
            <option value="bpp16">16-bit</option>
            <option value="bpp15">15-bit</option>
          </Select>
        </Field>
        <Field label="Sound">
          <Select
            value={rdp.audio}
            onChange={(e) => onChange({ audio: e.target.value as RdpSettings["audio"] })}
          >
            <option value="play-locally">Play here</option>
            <option value="leave-at-server">Play there</option>
            <option value="off">Do not play</option>
          </Select>
        </Field>
      </div>

      <Check
        checked={rdp.monitors === "all"}
        onChange={(on) => onChange({ monitors: on ? "all" : "primary" })}
        label="Use all of my monitors"
        hint="Makes the Displays menu list the remote monitors instead of just the one."
      />
      <ResolutionField value={rdp.resolution} onChange={(resolution) => onChange({ resolution })} />
      <Check
        checked={rdp.clipboard}
        onChange={(clipboard) => onChange({ clipboard })}
        label="Share my clipboard"
      />
      <Check
        checked={rdp.consoleSession}
        onChange={(consoleSession) => onChange({ consoleSession })}
        label="Connect to the console session"
      />

      <div className="rounded-md border border-subtle">
        <button
          type="button"
          aria-expanded={codecs}
          className="flex w-full items-center gap-1.5 px-3 py-2 text-sm font-medium text-secondary hover:text-primary"
          onClick={() => setCodecs((v) => !v)}
        >
          {codecs ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
          Codecs
        </button>
        {codecs ? (
          <div className="space-y-3 border-t border-subtle p-3">
            <p className="text-xs text-tertiary">
              Turn one of these off only to work around a server whose picture is
              wrong. They all make the connection faster.
            </p>
            {(
              [
                ["remotefx", "RemoteFX"],
                ["clearcodec", "ClearCodec"],
                ["planar", "Planar"],
                ["avc420", "H.264 (AVC 4:2:0)"],
              ] as const
            ).map(([key, label]) => (
              <Check
                key={key}
                checked={rdp.codecs[key]}
                onChange={(on) => onChange({ codecs: { ...rdp.codecs, [key]: on } })}
                label={label}
              />
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

/**
 * The two switches that make the connection less safe, behind one heading, in
 * the same bordered block the SSH tunnel section uses.
 *
 * They are together and set apart on purpose. Both are relaxations, both are
 * off by default, and neither should be met by accident while looking for
 * something else. The disclosure opens by itself when either is already on.
 */
function SecuritySection({
  rdp,
  open,
  onToggle,
  onChange,
}: {
  rdp: RdpSettings;
  open: boolean;
  onToggle: () => void;
  onChange: (patch: Partial<RdpSettings>) => void;
}): ReactNode {
  return (
    <div className="rounded-md border border-subtle">
      <button
        type="button"
        aria-expanded={open}
        className="flex w-full items-center gap-1.5 px-3 py-2 text-sm font-medium text-secondary hover:text-primary"
        onClick={onToggle}
      >
        {open ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
        Security
      </button>
      {open ? (
        <div className="space-y-4 border-t border-subtle p-3">
          <Check
            checked={rdp.nla === "allow-fallback"}
            onChange={(on) => onChange({ nla: on ? "allow-fallback" : "required" })}
            label="Allow connecting without network level authentication"
            hint="Some older or misconfigured servers refuse network level authentication. Without it your password is sent to a computer whose identity has not been checked yet."
          />
          <div>
            <Check
              checked={rdp.legacyTls}
              onChange={(legacyTls) => onChange({ legacyTls })}
              label="Allow legacy TLS (1.0 and 1.1)"
              hint="For Windows 7 and Server 2008 R2 era computers that were never updated. Those machines offer only TLS 1.0 or 1.1, which this app normally refuses. Leave this off unless a connection has already failed for that reason."
            />
            {/*
              Shown only while the box is ticked, in the same danger colour
              the address field uses for its error text.

              Five things about this copy are deliberate. It names the
              machines before the protocol versions, because somebody with a
              Server 2008 R2 box in a cupboard does not know which TLS
              versions it offers. It says what still holds, because "this is
              insecure" with nothing after it makes people either ignore the
              warning or abandon a connection they legitimately need, and the
              honest position is narrower than either. It does not promise
              safety. It is per host and says so by living in one host's
              editor. And it never appears for a VNC profile.
            */}
            {rdp.legacyTls ? (
              <p className="mt-2 text-xs text-danger" role="status">
                TLS 1.0 and 1.1 are old and weak. Someone who can sit between you
                and this computer has a better chance of reading or changing the
                traffic than they would over TLS 1.2. What still protects you is
                the certificate this app pinned the first time you connected,
                which is checked on every connection whichever version is used,
                and network level authentication, which proves the computer is
                the one you signed in to before your password is sent. Turn this
                on for one computer at a time, not as a habit.
              </p>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** A checkbox with the label-and-hint shape this dialog uses everywhere. */
function Check({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (on: boolean) => void;
  label: string;
  hint?: string;
}): ReactNode {
  return (
    <label className="flex items-start gap-2.5 text-sm text-primary">
      <input
        type="checkbox"
        className="mt-0.5 accent-(--accent)"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        {label}
        {hint ? <span className="block text-xs text-tertiary">{hint}</span> : null}
      </span>
    </label>
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
            Runs the connection through an SSH login, so it works for servers that
            only listen on the remote computer&apos;s own loopback, and is encrypted end to end
          </span>
        </span>
      </label>
      {t.enabled ? (
        <>
          <div className="grid grid-cols-[1fr_120px] gap-3">
            <Field label="SSH host" hint="Leave blank to SSH to the address above">
              <input
                className="field mono"
                value={t.host}
                placeholder="Same as the address above"
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

/**
 * The size of the remote desktop, as opposed to how it is scaled once it
 * arrives.
 *
 * One control rather than a size plus a "follow the window" checkbox: the two
 * are not independent, and a fixed size that also tracked the window would
 * stop being fixed as soon as the window moved.
 */
function ResolutionField({
  value,
  onChange,
}: {
  value: RdpResolution;
  onChange: (v: RdpResolution) => void;
}): ReactNode {
  const listed =
    value.mode === "fixed" &&
    RDP_FIXED_SIZES.some(([w, h]) => w === value.width && h === value.height);
  const selected =
    value.mode === "fixed" ? (listed ? `${value.width}x${value.height}` : "custom") : value.mode;

  const pick = (v: string): void => {
    if (v === "follow-window" || v === "window-at-connect") return onChange({ mode: v });
    if (v === "custom") {
      // Seed the boxes from whatever is on screen, so switching to Custom
      // does not blank the fields the user was just looking at.
      const [w, h] = value.mode === "fixed" ? [value.width, value.height] : [1920, 1080];
      return onChange({ mode: "fixed", width: w, height: h });
    }
    const [w, h] = v.split("x").map(Number);
    onChange({ mode: "fixed", width: w, height: h });
  };

  const custom = value.mode === "fixed" && !listed;
  // Held as a number so a half typed value does not snap; the profile is only
  // written when the dialog is saved, and the range is checked on read.
  const dim = (n: number, set: (v: number) => void, label: string): ReactNode => (
    <input
      className="field"
      type="number"
      min={RDP_MIN_DIM}
      max={RDP_MAX_DIM}
      value={n}
      aria-label={label}
      onChange={(e) => set(Number(e.target.value) || 0)}
    />
  );

  return (
    <Field
      label="Resolution"
      hint={
        value.mode === "follow-window"
          ? "The remote desktop resizes as you resize this window. Windows rearranges its icons each time."
          : value.mode === "window-at-connect"
            ? "The remote desktop is sized to this window when you connect, then left alone."
            : "The remote desktop is always this size. This window scales it to fit."
      }
    >
      <Select value={selected} onChange={(e) => pick(e.target.value)}>
        <option value="window-at-connect">Match this window when connecting</option>
        <option value="follow-window">Match this window, and keep matching</option>
        {RDP_FIXED_SIZES.map(([w, h]) => (
          <option key={`${w}x${h}`} value={`${w}x${h}`}>
            {w} x {h}
          </option>
        ))}
        <option value="custom">Custom...</option>
      </Select>
      {custom && value.mode === "fixed" ? (
        <div className="mt-2 grid grid-cols-2 gap-3">
          {dim(value.width, (width) => onChange({ ...value, width }), "Width in pixels")}
          {dim(value.height, (height) => onChange({ ...value, height }), "Height in pixels")}
        </div>
      ) : null}
    </Field>
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
