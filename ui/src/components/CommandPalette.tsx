/** Cmd/Ctrl+K command palette: fuzzy-matches hosts AND actions (PRD/03 §2.3). */
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { fuzzyMatch } from "../lib/util";
import type { HostProfile } from "../lib/types";
import { IconMonitor, IconZap } from "./icons";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

interface Entry {
  key: string;
  label: string;
  sub: string;
  kind: "host" | "action";
  score: number;
  run: () => void;
}

export function CommandPalette({
  hosts,
  actions,
  onConnect,
  onClose,
}: {
  hosts: HostProfile[];
  actions: PaletteAction[];
  onConnect: (host: HostProfile) => void;
  onClose: () => void;
}): ReactNode {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => inputRef.current?.focus(), []);

  const entries = useMemo((): Entry[] => {
    const out: Entry[] = [];
    for (const h of hosts) {
      const hay = `${h.friendlyName} ${h.address}`;
      const m = fuzzyMatch(query, hay);
      if (m) {
        out.push({
          key: `host-${h.id}`,
          label: h.friendlyName,
          sub: `${h.address}:${h.port}`,
          kind: "host",
          score: m.score + 10, // hosts get a slight edge
          run: () => onConnect(h),
        });
      }
    }
    for (const a of actions) {
      const m = fuzzyMatch(query, a.label);
      if (m) {
        out.push({
          key: `action-${a.id}`,
          label: a.label,
          sub: a.hint ?? "",
          kind: "action",
          score: m.score,
          run: a.run,
        });
      }
    }
    out.sort((a, b) => b.score - a.score);
    return out.slice(0, 12);
  }, [query, hosts, actions, onConnect]);

  useEffect(() => setSelected(0), [query]);

  useEffect(() => {
    listRef.current
      ?.querySelector(`[data-index="${selected}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  const onKeyDown = (e: React.KeyboardEvent): void => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelected((s) => Math.min(entries.length - 1, s + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelected((s) => Math.max(0, s - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const entry = entries[selected];
      if (entry) {
        onClose();
        entry.run();
      }
    }
  };

  return (
    <div
      className="fade-in fixed inset-0 z-40 flex justify-center bg-scrim pt-[18vh]"
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="h-fit w-[560px] max-w-[calc(100vw-32px)] overflow-hidden rounded-lg border border-subtle bg-raised shadow-(--shadow-pop)">
        <input
          ref={inputRef}
          className="w-full border-b border-subtle bg-transparent px-4 py-3.5 text-base text-primary outline-none placeholder:text-tertiary"
          placeholder="Connect to a host or run a command…"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-label="Command palette"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <div ref={listRef} id="palette-list" role="listbox" className="max-h-80 overflow-y-auto p-1.5">
          {entries.length === 0 ? (
            <div className="px-3 py-6 text-center text-sm text-tertiary">
              No matches for “{query}”
            </div>
          ) : (
            entries.map((entry, i) => (
              <button
                key={entry.key}
                type="button"
                data-index={i}
                role="option"
                aria-selected={i === selected}
                className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left ${
                  i === selected ? "bg-accent text-accent-fg" : "text-primary hover:bg-inset"
                }`}
                onPointerMove={() => setSelected(i)}
                onClick={() => {
                  onClose();
                  entry.run();
                }}
              >
                <span className={i === selected ? "opacity-90" : "text-tertiary"}>
                  {entry.kind === "host" ? <IconMonitor size={16} /> : <IconZap size={16} />}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{entry.label}</span>
                {entry.sub ? (
                  <span
                    className={`mono truncate text-xs ${i === selected ? "opacity-75" : "text-tertiary"}`}
                  >
                    {entry.sub}
                  </span>
                ) : null}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
