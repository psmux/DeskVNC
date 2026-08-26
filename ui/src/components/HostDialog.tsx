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
import type { MultiplexerKind, SshAuthKind, SshSettings } from "../lib/ssh";
import { blankSshSettings, parseSshSettings } from "../lib/ssh";
import { sshDefaults } from "../lib/sshDefaults";
import { sshListWslDistros } from "../lib/tauri";
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
  /** Parsed `sshSettings` blob; `null` for a non-SSH host. */
  ssh: SshSettings | null;
  /**
   * SSH account name, written on save alongside the password as
   * `StoredCredentials.sshUser`.
   *
   * Seeded BLANK even for a saved host, for the same reason `rdpUser` is:
   * there is no `get_password`, so blank carries the "leave what is stored
   * alone" affordance rather than "connect as nobody". An empty value here
   * is also a legitimate END state, not just a placeholder: the Rust side
   * reads a blank `sshUser` as "the same account as this computer", so a
   * host that never sets this field is not missing anything.
   */
  sshUser: string;
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
    ssh: protocol === "ssh" ? (parseSshSettings(h?.sshSettings) ?? newSshSettings()) : null,
    sshUser: "",
    portTouched: portWasTouched(h),
  };
}

/** A blank set of RDP settings with the Preferences defaults applied. */
function newRdpSettings(): RdpSettings {
  return { ...blankRdpSettings(), ...rdpDefaults() };
}

/** A blank set of SSH settings with the Preferences defaults applied. */
function newSshSettings(): SshSettings {
  return { ...blankSshSettings(), ...sshDefaults() };
}

/** Either of the Security disclosure's switches is already on. */
function securityIsOn(d: HostDraft): boolean {
  return d.protocol === "rdp" && (d.rdp?.nla === "allow-fallback" || d.rdp?.legacyTls === true);
}

/**
 * What a protocol offers, so a field can ask "does this protocol have
 * this?" instead of "is this RDP?".
 *
 * A gate built around one protocol reads correctly for two: `!isRdp` meant
 * "the VNC-only field" back when RDP was the only other option. It reads
 * wrong for three, because SSH is not RDP either, and `!isRdp` would let a
 * VNC-only control reappear for it. Keying the lookup on every member of
 * `ProtocolKind` means TypeScript checks it against the type, so a fourth
 * protocol added without a row here is a compile error rather than a field
 * that silently reappears for it.
 */
interface ProtocolCaps {
  /**
   * Has a remote desktop picture. Quality, scaling, keyboard mode, the RFB
   * security type, the "capture system shortcuts" default, and (through
   * `RdpOptionsSection`) the display and resolution settings all describe
   * how a picture is drawn or controlled. None of it means anything to a
   * terminal, which has neither a picture nor a cursor.
   */
  graphical: boolean;
  /** RFB security type negotiation, VNC's own. RDP negotiates its own
   *  security below (see `SecuritySection`), and SSH's transport security
   *  is not a setting this app exposes a knob for. */
  rfbSecurity: boolean;
  /** A logon account name field. */
  username: boolean;
  /** A separate logon domain field, alongside username. */
  domain: boolean;
}

const PROTOCOL_CAPS: Record<ProtocolKind, ProtocolCaps> = {
  vnc: { graphical: true, rfbSecurity: true, username: false, domain: false },
  rdp: { graphical: true, rfbSecurity: false, username: true, domain: true },
  ssh: { graphical: false, rfbSecurity: false, username: true, domain: false },
};

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

  // `isRdp` still names one protocol on purpose: it only selects between the
  // two GRAPHICAL protocols' own quirks (RdpOptionsSection, SecuritySection,
  // the wording of a shared hint), inside sections already gated on
  // `caps.graphical` so SSH never reaches them. Anything that decides
  // whether a field exists AT ALL for a protocol goes through `caps` instead.
  const isRdp = d.protocol === "rdp";
  const isSsh = d.protocol === "ssh";
  const caps = PROTOCOL_CAPS[d.protocol];
  const rdp = d.rdp ?? blankRdpSettings();
  const setRdp = (patch: Partial<RdpSettings>): void => set({ rdp: { ...rdp, ...patch } });
  const ssh = d.ssh ?? blankSshSettings();
  const setSsh = (patch: Partial<SshSettings>): void => set({ ssh: { ...ssh, ...patch } });

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
      ssh: to === "ssh" ? (d.ssh ?? newSshSettings()) : d.ssh,
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

        {/*
          The logon fields are driven by capability, not by protocol name:
          RDP needs a user name and, for a directory account, a domain; SSH
          needs only a user name, and treats a blank one as "the same account
          as this computer" rather than as something it has to guess; VNC has
          no concept of a logon account at all, so nothing renders here. A
          logon is user first, so the name field sits above the password
          rather than beside the security type.
        */}
        {caps.username ? (
          caps.domain ? (
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
          ) : (
            <Field
              label="User name"
              hint={
                d.hasPassword && !d.sshUser
                  ? "Leave blank to keep the saved one."
                  : "Leave blank to sign in as the same user as this computer"
              }
            >
              <input
                className="field"
                value={d.sshUser}
                placeholder={d.hasPassword ? "(unchanged)" : "Same as this computer"}
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                onChange={(e) => set({ sshUser: e.target.value })}
              />
            </Field>
          )
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
              {/*
                Security type, Quality, Scaling and Keyboard mode all describe
                a remote PICTURE: how it is negotiated, compressed, fitted to
                the window, and typed into. None of that exists for a
                terminal, so the whole block is gated on `caps.graphical`
                rather than repeating that gate on every field inside it.
              */}
              {caps.graphical ? (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    {/* RFB security types are VNC's own negotiation; RDP's
                        equivalent is the Security disclosure below. */}
                    {caps.rfbSecurity ? (
                      <Field label="Security type" hint="Auto negotiates the strongest supported">
                        <Select
                          value={d.securityPref ?? "auto"}
                          onChange={(e) =>
                            set({ securityPref: e.target.value === "auto" ? null : e.target.value })
                          }
                        >
                          <option value="auto">Auto</option>
                          <option value="vencrypt-x509">VeNCrypt (TLS + X.509)</option>
                          <option value="ra2">RSA-AES (RA2)</option>
                          <option value="apple-dh">Apple Screen Sharing</option>
                          <option value="vncauth">VNC password only</option>
                          <option value="none">None</option>
                        </Select>
                      </Field>
                    ) : null}
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
                          setting, so the toolbar keeps offering it live for
                          both graphical protocols. As a STORED default for an
                          RDP host it would quietly mean "low quality, plus a
                          grey screen on every connect", which is not what
                          choosing a saved default is for.
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
                </>
              ) : null}
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
              {/* Waking a sleeping machine is orthogonal to how you talk to it
                  once it is up, so this stays available for every protocol;
                  "capture system shortcuts" is not, since a terminal has no
                  window to steal a shortcut away from. */}
              {caps.graphical ? (
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
              ) : null}
              {isRdp ? <RdpOptionsSection rdp={rdp} onChange={setRdp} /> : null}
              {isRdp ? (
                <SecuritySection
                  rdp={rdp}
                  open={security}
                  onToggle={() => setSecurity((v) => !v)}
                  onChange={setRdp}
                />
              ) : null}
              {isSsh ? (
                <SshOptionsSection
                  ssh={ssh}
                  onChange={setSsh}
                  host={d.address}
                  port={d.port}
                  username={d.sshUser}
                  profileId={d.id ?? null}
                />
              ) : null}
              {/*
                This tunnel wraps a GRAPHICAL session (VNC or RDP) inside an
                SSH login, so it can reach a server that only listens on the
                remote machine's own loopback. On an SSH host profile that
                reads as tunnelling SSH through SSH, which is not a real
                setting, the profile IS the SSH connection already. The two
                features sharing the words "SSH tunnel" is a naming
                collision, not a relationship, so it is worth spelling out
                here rather than leaving the omission to look accidental.
              */}
              {!isSsh ? (
                <SshTunnelSection
                  tunnel={d.sshTunnel}
                  passphrase={d.sshPassphrase}
                  onChange={(sshTunnel) => set({ sshTunnel })}
                  onPassphrase={(sshPassphrase) => set({ sshPassphrase })}
                />
              ) : null}
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

/** `[A-Za-z0-9_-]`, 1 to 64 characters, matching the Rust side exactly.
 *  The name is pasted onto a remote command line to attach or create the
 *  multiplexer session, so anything else is a shell-injection surface, not
 *  a cosmetic preference, and this has to refuse what the Rust side refuses. */
const SESSION_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** `null` when the session name is fine to save. */
function sessionNameError(name: string): string | null {
  if (name.trim() === "") return "Required";
  if (name.length > 64) return "64 characters or fewer";
  if (!SESSION_NAME_RE.test(name)) return "Only letters, numbers, underscore and hyphen";
  return null;
}

/**
 * `is_safe_distro_name` in `crates/ssh-core/src/multiplexer.rs`, mirrored
 * exactly: real distro names carry dots (`Ubuntu-22.04`, `openSUSE-Leap-15.5`)
 * so this is looser than {@link SESSION_NAME_RE}, but the name still reaches
 * the remote inside a command line, so anything a shell would treat as
 * punctuation stays out.
 */
const DISTRO_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** `null` when a typed distribution name is fine to save. Empty is legal, it
 *  means the Windows default, so only a non-empty, invalid name is an error. */
function distroNameError(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed === "") return null;
  if (trimmed.length > 64) return "64 characters or fewer";
  if (!DISTRO_NAME_RE.test(trimmed)) return "Only letters, numbers, dot, underscore and hyphen";
  return null;
}

/**
 * ssh.ts's `SshAuthKind` has a `"password"` member because that is a real
 * choice in the host editor; the connect config's own `SshAuthKind` (in
 * tauri.ts) does not, because "password" and "key-file passphrase" are the
 * same thing to the Rust side once they are looked up: whatever is sitting
 * in this profile's keychain entry, which is what `"stored"` fetches. Without
 * this mapping the Detect button would send a value `ssh_list_wsl_distros`
 * does not know and the request would fail to deserialize.
 */
function toDetectAuth(auth: SshAuthKind): "stored" | "key-file" | "agent" {
  return auth === "password" ? "stored" : auth;
}

/**
 * The SSH-only options, inside Advanced, shown only for the SSH protocol.
 *
 * Mirrors {@link RdpOptionsSection}'s shape: everything here is an ordinary
 * preference, not a security decision, so it lives in one flat block rather
 * than behind its own disclosure.
 */
function SshOptionsSection({
  ssh,
  onChange,
  host,
  port,
  username,
  profileId,
}: {
  ssh: SshSettings;
  onChange: (patch: Partial<SshSettings>) => void;
  /** The draft's own connection fields, so Detect can ask about the machine
   *  this profile actually points at rather than a stale or saved one. */
  host: string;
  port: number;
  username: string;
  profileId: string | null;
}): ReactNode {
  // Touched on blur rather than checked from the first keystroke, the same
  // rule the address field uses: typing a fresh name a character at a time
  // must not flash red before the user has finished it.
  const [nameTouched, setNameTouched] = useState(false);
  const nameError = nameTouched ? sessionNameError(ssh.sessionName) : null;

  // `null` means Detect has never run this dialog session: show the free-text
  // field with no "could not read" line, since nothing has actually failed
  // yet. `[]` means it ran and came back empty, which is an ordinary answer,
  // not an error, so the free-text field stays but says why.
  const [distros, setDistros] = useState<string[] | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [distroTouched, setDistroTouched] = useState(false);
  const distroError = distroTouched ? distroNameError(ssh.wslDistro ?? "") : null;

  const detectDistros = async (): Promise<void> => {
    setDetecting(true);
    try {
      const found = await sshListWslDistros({
        host,
        port,
        username,
        auth: toDetectAuth(ssh.auth),
        keyPath: ssh.keyPath,
        profileId,
      });
      setDistros(found);
    } finally {
      setDetecting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/*
        Sits above the multiplexer, above everything else in this section,
        because it decides whether the connection works at all: the bug this
        control fixes was a host with a saved password and no running
        ssh-agent, which failed with an agent error even though a perfectly
        good password was sitting in the keychain, because nothing on this
        side ever told the Rust side to use it. Agent stays the default,
        because it is the only one that needs nothing stored here.
      */}
      <Field
        label="Authentication"
        hint={
          ssh.auth === "password"
            ? "Uses the Password field above, kept in your system keychain, never in a file."
            : ssh.auth === "key-file"
              ? "The key file is read at connect time and never sent to the interface."
              : "Uses your running ssh-agent, Pageant, or the Windows OpenSSH pipe. Stores nothing."
        }
      >
        <Select
          value={ssh.auth}
          onChange={(e) => onChange({ auth: e.target.value as SshAuthKind })}
        >
          <option value="agent">SSH agent (recommended)</option>
          <option value="password">Password</option>
          <option value="key-file">Key file</option>
        </Select>
      </Field>

      {ssh.auth === "key-file" ? (
        <Field label="Private key path" hint="An OpenSSH or PuTTY (.ppk) private key on this computer">
          <input
            className="field mono"
            value={ssh.keyPath ?? ""}
            placeholder="~/.ssh/id_ed25519"
            spellCheck={false}
            autoCapitalize="none"
            autoCorrect="off"
            onChange={(e) => onChange({ keyPath: e.target.value || null })}
          />
        </Field>
      ) : null}

      {/*
        Sits directly after Authentication and before the multiplexer below,
        because it decides WHERE the multiplexer is looked for, not just
        whether one is used: with this on, tmux/psmux/etc. are searched for
        inside the WSL distribution, not on Windows. The reader needs that
        before reading the multiplexer control, or the multiplexer choice
        looks like it is about the Windows side when it may not be.
      */}
      <Check
        checked={ssh.wsl}
        onChange={(wsl) => onChange({ wsl })}
        label="Connect inside WSL"
        hint="On a Windows host, land inside the Windows Subsystem for Linux instead of PowerShell, and look for the multiplexer there instead of on Windows."
      />

      {ssh.wsl ? (
        <Field
          label="Distribution"
          error={distroError}
          hint={
            distros !== null && distros.length === 0
              ? "The list of installed distributions could not be read, so type a name instead. Leave blank for the default distribution."
              : "Leave blank for the default distribution."
          }
        >
          <div className="flex gap-2">
            {distros !== null && distros.length > 0 ? (
              <Select
                value={ssh.wslDistro ?? ""}
                onChange={(e) => onChange({ wslDistro: e.target.value || null })}
              >
                <option value="">Default distribution</option>
                {distros.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </Select>
            ) : (
              <input
                className="field mono"
                value={ssh.wslDistro ?? ""}
                placeholder="Default distribution"
                maxLength={64}
                spellCheck={false}
                autoCapitalize="none"
                autoCorrect="off"
                onBlur={() => setDistroTouched(true)}
                onChange={(e) => onChange({ wslDistro: e.target.value || null })}
              />
            )}
            <button
              type="button"
              className="btn-secondary shrink-0 disabled:opacity-40"
              disabled={detecting}
              onClick={() => void detectDistros()}
            >
              {detecting ? "Detecting…" : "Detect"}
            </button>
          </div>
        </Field>
      ) : null}

      {/*
        This is the most consequential control in the section: it decides
        whether the remote work survives a dropped connection at all, so the
        hint says that in plain language rather than naming the mechanism
        and leaving the stakes implicit. psmux is named beside tmux, not
        after it, because it is not a fallback for tmux, it is the author's
        own tmux-compatible multiplexer for Windows and the one most likely
        to be the only option on a Windows box.
      */}
      <Field
        label="Terminal multiplexer"
        hint="Auto finds tmux or psmux on the remote machine, so your work survives a dropped connection. Without one, a disconnect ends your session."
      >
        <Select
          value={ssh.multiplexer}
          onChange={(e) => onChange({ multiplexer: e.target.value as MultiplexerKind })}
        >
          <option value="auto">Auto (recommended)</option>
          <option value="psmux">psmux</option>
          <option value="tmux">tmux</option>
          <option value="screen">screen</option>
          <option value="zellij">zellij</option>
          <option value="none">None, always a plain shell</option>
          <option value="custom">Custom command</option>
        </Select>
      </Field>

      <Field
        label="Session name"
        error={nameError}
        hint="This is placed on the remote command line to attach or create the session, so only letters, numbers, underscore and hyphen are accepted, up to 64 characters."
      >
        <input
          className="field mono"
          value={ssh.sessionName}
          maxLength={64}
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
          onBlur={() => setNameTouched(true)}
          onChange={(e) => onChange({ sessionName: e.target.value })}
        />
      </Field>

      {ssh.multiplexer === "custom" ? (
        <Field
          label="Custom command"
          hint="Runs on the remote machine instead of attaching to tmux, psmux or another multiplexer. {session} is replaced with the session name above."
        >
          <input
            className="field mono"
            value={ssh.customCommand ?? ""}
            placeholder="tmux new -A -s {session}"
            spellCheck={false}
            autoCapitalize="none"
            autoCorrect="off"
            onChange={(e) => onChange({ customCommand: e.target.value || null })}
          />
        </Field>
      ) : null}

      <Field
        label="Startup command"
        hint="Runs once connected, instead of your login shell. Leave blank to sign in normally."
      >
        <input
          className="field mono"
          value={ssh.startupCommand ?? ""}
          placeholder="Optional"
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
          onChange={(e) => onChange({ startupCommand: e.target.value || null })}
        />
      </Field>

      {/*
        Meaningless under Auto: Auto already treats "nothing installed" as an
        answer (fall back on its own) rather than a failure, so there is
        nothing here for this switch to decide. It only means something once
        the multiplexer is pinned to something that might not be there.
      */}
      {ssh.multiplexer !== "auto" ? (
        <Check
          checked={ssh.fallbackToShell}
          onChange={(fallbackToShell) => onChange({ fallbackToShell })}
          label="Fall back to a plain shell"
          hint="If the chosen multiplexer is not installed on the remote machine, connect with an ordinary shell instead of refusing to connect."
        />
      ) : null}

      <div className="grid grid-cols-2 gap-3">
        <Field label="Font size">
          <input
            className="field"
            type="number"
            min={8}
            max={32}
            value={ssh.fontSize}
            onChange={(e) => onChange({ fontSize: Number(e.target.value) || ssh.fontSize })}
          />
        </Field>
        <Field label="Scrollback" hint="Lines kept for scrolling back">
          <input
            className="field"
            type="number"
            min={0}
            max={1_000_000}
            value={ssh.scrollback}
            onChange={(e) => onChange({ scrollback: Number(e.target.value) || 0 })}
          />
        </Field>
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
            <Field label="Private key path" hint="An OpenSSH or PuTTY (.ppk) private key on this computer">
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
