/**
 * QuickConnect: the always-visible address bar. Type where to go, press Enter,
 * you are connected. Nothing is saved and nothing has to be set up first.
 *
 * It is deliberately a permanent strip rather than a dialog behind a shortcut,
 * because "I just want to reach this one machine once" is the single most
 * common thing a viewer is opened for, and a feature nobody can see is a
 * feature nobody uses.
 *
 * Typing an address that a saved host already covers connects through that
 * host, so its quality, view-only and stored password still apply. Anything
 * else connects ad-hoc.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { DiscoveredHost, HostProfile, ProtocolKind } from "../lib/types";
import { DEFAULT_PORT, PROTOCOLS, hostProtocol, protocolLabel, protocolName } from "../lib/types";
import { formatTarget, parseConnectTarget, presetProtocol } from "../lib/address";
import { classNames, fuzzyMatch, modKeyLabel } from "../lib/util";
import { IconArrowRight, IconClock, IconMonitor, IconZap } from "./icons";

/** Matches the Rust side's `normalize_address`, so both agree on "same machine". */
function sameAddress(a: string, b: string): boolean {
  const norm = (s: string): string =>
    s
      .trim()
      .replace(/\.+$/, "")
      .replace(/[A-Z]/g, (c) => c.toLowerCase()); // ASCII only, as Rust does
  return norm(a) === norm(b);
}

/**
 * The protocol the chip flips to on a click, wrapping through `PROTOCOLS` in
 * the order the protocol picker itself uses (vnc -> rdp -> ssh -> vnc).
 *
 * A two-state flip stopped making sense once a third protocol existed:
 * "the other protocol" is only well defined between two. A cycle keeps the
 * chip a single click-to-correct button rather than opening a second
 * floating panel next to the one the suggestion list already owns below the
 * field, so the fix is the tooltip, not the control: it names the SPECIFIC
 * protocol one more click lands on, rather than leaving "the other one"
 * ambiguous among three.
 */
function nextProtocol(p: ProtocolKind): ProtocolKind {
  const i = PROTOCOLS.indexOf(p);
  return PROTOCOLS[(i + 1) % PROTOCOLS.length];
}

interface Suggestion {
  key: string;
  kind: "address" | "host" | "nearby" | "recent";
  label: string;
  sub: string;
  /** Shown as a chip on the row, so "Connect to rdp://frontdesk" and
   *  "Connect to frontdesk" are visibly different things. */
  protocol: ProtocolKind;
  run: () => void;
}

const MAX_HOST_SUGGESTIONS = 4;
const MAX_NEARBY_SUGGESTIONS = 3;
const MAX_RECENT_SUGGESTIONS = 5;

export function QuickConnect({
  hosts,
  discovered,
  recents,
  inputRef,
  onConnectHost,
  onConnectAddress,
  onRemember,
}: {
  hosts: HostProfile[];
  discovered: DiscoveredHost[];
  /** Previously quick-connected addresses, most recent first. */
  recents: string[];
  inputRef: React.RefObject<HTMLInputElement | null>;
  onConnectHost: (host: HostProfile) => void;
  onConnectAddress: (protocol: ProtocolKind, address: string, port: number) => void;
  onRemember: (address: string) => void;
}): ReactNode {
  const [value, setValue] = useState("");
  const [open, setOpen] = useState(false);
  /** -1 is "nothing picked yet", so Enter uses the field, not a highlighted row. */
  const [selected, setSelected] = useState(-1);
  /** Only red after the user actually tried to connect; typing is not an error. */
  const [attempted, setAttempted] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const trimmed = value.trim();
  const parsed = useMemo(() => parseConnectTarget(value), [value]);
  /**
   * The user has overridden the chip for what is currently typed. Cleared on
   * every keystroke, so it applies to one address rather than becoming a
   * sticky mode the user cannot see.
   */
  const [flipped, setFlipped] = useState<ProtocolKind | null>(null);

  /**
   * Go through the saved host when the typed address is one we already know:
   * the alternative is an ad-hoc session that silently drops the password and
   * quality the user configured for exactly this machine.
   */
  const savedMatch = useMemo((): HostProfile | null => {
    if (!parsed.ok) return null;
    const { address, port, explicitPort, protocol } = parsed.target;
    // A bare hostname means "that machine", not "that machine on 5900", so it
    // should still find a host saved on 5901 rather than sit above it in the
    // list as a near-identical second row.
    //
    // When the input NAMED a protocol, only a host of that protocol matches:
    // typing `rdp://box` must not connect through a VNC profile saved at that
    // address, which would dial the wrong thing at the wrong port.
    return (
      hosts.find(
        (h) =>
          sameAddress(h.address, address) &&
          (!explicitPort || h.port === port) &&
          (protocol === null || hostProtocol(h) === protocol),
      ) ?? null
    );
  }, [parsed, hosts]);

  /**
   * The protocol this connect will use: what the input named, then a saved
   * host's, then the port preset.
   *
   * The hard rule this exists for is that ambiguity never resolves silently
   * to VNC against port 3389. Whatever it resolves to, the chip shows it
   * before Enter and one click flips it.
   */
  const resolved: ProtocolKind = useMemo(() => {
    if (!parsed.ok) return flipped ?? "vnc";
    return (
      flipped ??
      parsed.target.protocol ??
      (savedMatch ? hostProtocol(savedMatch) : presetProtocol(parsed.target))
    );
  }, [parsed, flipped, savedMatch]);

  const connectTyped = (): void => {
    if (!parsed.ok) {
      setAttempted(true);
      return;
    }
    const { address, port, username } = parsed.target;
    if (savedMatch) {
      onConnectHost(savedMatch);
    } else {
      onConnectAddress(resolved, address, port);
      onRemember(formatTarget(resolved, address, port, username));
    }
    setValue("");
    setAttempted(false);
    setFlipped(null);
    setOpen(false);
  };

  const suggestions = useMemo((): Suggestion[] => {
    const out: Suggestion[] = [];

    if (trimmed !== "" && parsed.ok) {
      const { address, port, username } = parsed.target;
      const typedLabel = formatTarget(resolved, address, port, username);
      out.push(
        savedMatch
          ? {
              key: "typed",
              kind: "host",
              label: `Connect to ${savedMatch.friendlyName}`,
              sub: "saved host",
              protocol: hostProtocol(savedMatch),
              run: () => {
                onConnectHost(savedMatch);
                setValue("");
                setFlipped(null);
                setOpen(false);
              },
            }
          : {
              key: "typed",
              kind: "address",
              label: `Connect to ${typedLabel}`,
              // Silent on a protocol's OWN default port (5900 for VNC, 3389
              // for RDP, 22 for SSH); named otherwise, which is the thing
              // worth reading there. `resolved === "rdp" ? "" : port === 5900`
              // used to special-case VNC's default by number, which read an
              // SSH target on its own default port 22 as "an odd port".
              sub: port === DEFAULT_PORT[resolved] ? "" : `port ${port}`,
              protocol: resolved,
              run: () => {
                onConnectAddress(resolved, address, port);
                onRemember(typedLabel);
                setValue("");
                setFlipped(null);
                setOpen(false);
              },
            },
      );
    }

    if (trimmed !== "") {
      const matches = hosts
        .filter((h) => h.id !== savedMatch?.id)
        .map((h) => ({ h, m: fuzzyMatch(trimmed, `${h.friendlyName} ${h.address}`) }))
        .filter((x): x is { h: HostProfile; m: NonNullable<typeof x.m> } => x.m !== null)
        .sort((a, b) => b.m.score - a.m.score)
        .slice(0, MAX_HOST_SUGGESTIONS);
      for (const { h } of matches) {
        out.push({
          key: `host-${h.id}`,
          kind: "host",
          label: h.friendlyName,
          sub: formatTarget(hostProtocol(h), h.address, h.port),
          protocol: hostProtocol(h),
          run: () => {
            onConnectHost(h);
            setValue("");
            setFlipped(null);
            setOpen(false);
          },
        });
      }

      const nearby = discovered
        .filter((d) => !hosts.some((h) => sameAddress(h.address, d.address) && h.port === d.port))
        .filter((d) => fuzzyMatch(trimmed, `${d.name} ${d.address}`) !== null)
        .slice(0, MAX_NEARBY_SUGGESTIONS);
      for (const d of nearby) {
        const kind = d.protocol ?? "vnc";
        const label = formatTarget(kind, d.address, d.port);
        out.push({
          key: `nearby-${d.id}`,
          kind: "nearby",
          label: d.name,
          sub: label,
          protocol: kind,
          run: () => {
            onConnectAddress(kind, d.address, d.port);
            onRemember(label);
            setValue("");
            setFlipped(null);
            setOpen(false);
          },
        });
      }
    }

    // With an empty field the recents ARE the menu; while typing they are just
    // one more source, and the address row above already covers an exact retype.
    const recentPool = recents.filter((r) => r !== trimmed);
    const recentMatches = (
      trimmed === "" ? recentPool : recentPool.filter((r) => fuzzyMatch(trimmed, r) !== null)
    ).slice(0, MAX_RECENT_SUGGESTIONS);
    for (const r of recentMatches) {
      const p = parseConnectTarget(r);
      if (!p.ok) continue;
      // A recent round trips through `formatTarget`, so its own text says
      // which protocol it was. Anything that does not re-parse to itself
      // would connect somewhere the user never went.
      const kind = p.target.protocol ?? presetProtocol(p.target);
      out.push({
        key: `recent-${r}`,
        kind: "recent",
        label: r,
        sub: "recent",
        protocol: kind,
        run: () => {
          onConnectAddress(kind, p.target.address, p.target.port);
          onRemember(r);
          setValue("");
          setFlipped(null);
          setOpen(false);
        },
      });
    }

    return out;
  }, [trimmed, parsed, resolved, savedMatch, hosts, discovered, recents, onConnectHost, onConnectAddress, onRemember]);

  useEffect(() => {
    setSelected(-1);
    // The override is for one typed address, not a mode.
    setFlipped(null);
  }, [value]);

  // Discovery arriving or a host being saved can shorten the list under a
  // highlight that is already past its new end, which would leave Enter
  // pointing at nothing while a row still looked chosen.
  useEffect(() => {
    setSelected((s) => Math.min(s, suggestions.length - 1));
  }, [suggestions]);

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${selected}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  const showList = open && suggestions.length > 0;

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setOpen(true);
      setSelected((s) => Math.min(suggestions.length - 1, s + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelected((s) => Math.max(0, s - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const entry = showList && selected >= 0 ? suggestions[selected] : undefined;
      if (entry) entry.run();
      else if (trimmed !== "") connectTyped();
    } else if (e.key === "Escape") {
      e.preventDefault();
      // First Escape dismisses the list, a second one abandons the address.
      if (showList) setOpen(false);
      else {
        setValue("");
        setAttempted(false);
        inputRef.current?.blur();
      }
    }
  };

  const invalid = trimmed !== "" && !parsed.ok;

  return (
    <div className="flex items-center gap-2 border-b border-subtle bg-surface/40 px-4 py-2">
      <div className="relative min-w-0 flex-1 md:max-w-xl">
        <IconMonitor
          size={15}
          className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-tertiary"
        />
        <input
          ref={inputRef}
          className="field mono !pl-8"
          placeholder={`Connect to an address, e.g. 192.168.1.20:1 or rdp://frontdesk  (${modKeyLabel}T)`}
          aria-label="Address to connect to"
          spellCheck={false}
          autoComplete="off"
          role="combobox"
          aria-expanded={showList}
          aria-controls="quick-connect-list"
          aria-autocomplete="list"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setAttempted(false);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setOpen(false)}
          onKeyDown={onKeyDown}
        />
        {showList ? (
          <div
            ref={listRef}
            id="quick-connect-list"
            role="listbox"
            aria-label="Connection suggestions"
            className="fade-in absolute left-0 right-0 top-full z-30 mt-1 max-h-80 overflow-y-auto rounded-md border border-subtle bg-raised p-1.5 shadow-(--shadow-pop)"
          >
            {suggestions.map((s, i) => (
              <button
                key={s.key}
                type="button"
                data-index={i}
                role="option"
                aria-selected={i === selected}
                className={classNames(
                  "flex w-full items-center gap-3 rounded-md px-3 py-2 text-left",
                  i === selected ? "bg-accent text-accent-fg" : "text-primary hover:bg-inset",
                )}
                onPointerMove={() => setSelected(i)}
                // Keeping focus in the field means the blur that closes this
                // list cannot land before the click that uses it, which would
                // unmount this button mid-gesture and swallow the click.
                // Both events are suppressed because WebKit, which is what
                // this ships on, has not always honoured the pointer one.
                onPointerDown={(e) => e.preventDefault()}
                onMouseDown={(e) => e.preventDefault()}
                onClick={s.run}
              >
                <span className={i === selected ? "opacity-90" : "text-tertiary"}>
                  <SuggestionIcon kind={s.kind} />
                </span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{s.label}</span>
                <span
                  className={classNames(
                    "mono shrink-0 rounded-sm px-1.5 py-0.5 text-[10px] font-semibold tracking-wide",
                    i === selected ? "bg-black/15" : "bg-inset text-tertiary",
                  )}
                >
                  {protocolLabel(s.protocol)}
                </span>
                {s.sub ? (
                  <span
                    className={classNames(
                      "mono truncate text-xs",
                      i === selected ? "opacity-75" : "text-tertiary",
                    )}
                  >
                    {s.sub}
                  </span>
                ) : null}
              </button>
            ))}
          </div>
        ) : null}
      </div>
      {/*
        The chip is the answer to "which protocol is this about to speak", and
        it is a button because the answer is sometimes a guess. `box:3389` with
        no saved host is the case it exists for: the guess is visible before
        Enter and one click corrects it. With three protocols the button
        cycles rather than flips, and the tooltip names the protocol one more
        click reaches, so "the other protocol" never has to mean one of two
        unnamed alternatives.
      */}
      {trimmed !== "" && parsed.ok ? (
        <button
          type="button"
          className="mono shrink-0 rounded-md border border-subtle px-2 py-1 text-xs font-semibold text-secondary hover:text-primary"
          title={
            savedMatch
              ? `${savedMatch.friendlyName} is saved as ${protocolLabel(resolved)}`
              : `Click to connect with ${protocolName(nextProtocol(resolved))} instead`
          }
          disabled={savedMatch !== null}
          onPointerDown={(e) => e.preventDefault()}
          onClick={() => setFlipped(nextProtocol(resolved))}
        >
          {protocolLabel(resolved)}
        </button>
      ) : null}
      <button
        type="button"
        className="btn-secondary shrink-0"
        disabled={trimmed === ""}
        onClick={connectTyped}
      >
        Connect
      </button>
      {invalid ? (
        <span
          className={classNames("truncate text-xs", attempted ? "text-danger" : "text-tertiary")}
          role={attempted ? "alert" : undefined}
        >
          {parsed.error}
        </span>
      ) : (
        <span className="truncate text-xs text-tertiary">Connects without saving anything</span>
      )}
    </div>
  );
}

function SuggestionIcon({ kind }: { kind: Suggestion["kind"] }): ReactNode {
  switch (kind) {
    case "address":
      return <IconArrowRight size={16} />;
    case "nearby":
      return <IconZap size={16} />;
    case "recent":
      return <IconClock size={16} />;
    default:
      return <IconMonitor size={16} />;
  }
}
