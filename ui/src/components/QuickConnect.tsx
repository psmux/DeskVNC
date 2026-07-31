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
import type { DiscoveredHost, HostProfile } from "../lib/types";
import { formatEndpoint, parseConnectAddress } from "../lib/address";
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

interface Suggestion {
  key: string;
  kind: "address" | "host" | "nearby" | "recent";
  label: string;
  sub: string;
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
  onConnectAddress: (address: string, port: number) => void;
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
  const parsed = useMemo(() => parseConnectAddress(value), [value]);

  /**
   * Go through the saved host when the typed address is one we already know:
   * the alternative is an ad-hoc session that silently drops the password and
   * quality the user configured for exactly this machine.
   */
  const savedMatch = useMemo((): HostProfile | null => {
    if (!parsed.ok) return null;
    const { address, port, explicitPort } = parsed.endpoint;
    // A bare hostname means "that machine", not "that machine on 5900", so it
    // should still find a host saved on 5901 rather than sit above it in the
    // list as a near-identical second row.
    return (
      hosts.find((h) => sameAddress(h.address, address) && (!explicitPort || h.port === port)) ??
      null
    );
  }, [parsed, hosts]);

  const connectTyped = (): void => {
    if (!parsed.ok) {
      setAttempted(true);
      return;
    }
    const { address, port } = parsed.endpoint;
    if (savedMatch) {
      onConnectHost(savedMatch);
    } else {
      onConnectAddress(address, port);
      onRemember(formatEndpoint(address, port));
    }
    setValue("");
    setAttempted(false);
    setOpen(false);
  };

  const suggestions = useMemo((): Suggestion[] => {
    const out: Suggestion[] = [];

    if (trimmed !== "" && parsed.ok) {
      const { address, port } = parsed.endpoint;
      out.push(
        savedMatch
          ? {
              key: "typed",
              kind: "host",
              label: `Connect to ${savedMatch.friendlyName}`,
              sub: "saved host",
              run: () => {
                onConnectHost(savedMatch);
                setValue("");
                setOpen(false);
              },
            }
          : {
              key: "typed",
              kind: "address",
              label: `Connect to ${formatEndpoint(address, port)}`,
              sub: port === 5900 ? "" : `port ${port}`,
              run: () => {
                onConnectAddress(address, port);
                onRemember(formatEndpoint(address, port));
                setValue("");
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
          sub: formatEndpoint(h.address, h.port),
          run: () => {
            onConnectHost(h);
            setValue("");
            setOpen(false);
          },
        });
      }

      const nearby = discovered
        .filter((d) => !hosts.some((h) => sameAddress(h.address, d.address) && h.port === d.port))
        .filter((d) => fuzzyMatch(trimmed, `${d.name} ${d.address}`) !== null)
        .slice(0, MAX_NEARBY_SUGGESTIONS);
      for (const d of nearby) {
        out.push({
          key: `nearby-${d.id}`,
          kind: "nearby",
          label: d.name,
          sub: formatEndpoint(d.address, d.port),
          run: () => {
            onConnectAddress(d.address, d.port);
            onRemember(formatEndpoint(d.address, d.port));
            setValue("");
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
      const p = parseConnectAddress(r);
      if (!p.ok) continue;
      out.push({
        key: `recent-${r}`,
        kind: "recent",
        label: r,
        sub: "recent",
        run: () => {
          onConnectAddress(p.endpoint.address, p.endpoint.port);
          onRemember(r);
          setValue("");
          setOpen(false);
        },
      });
    }

    return out;
  }, [trimmed, parsed, savedMatch, hosts, discovered, recents, onConnectHost, onConnectAddress, onRemember]);

  useEffect(() => setSelected(-1), [value]);

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
          placeholder={`Connect to an address, e.g. 192.168.1.20:1  (${modKeyLabel}T)`}
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
