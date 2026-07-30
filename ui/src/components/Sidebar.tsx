/** Library left sidebar: Nearby / All Hosts / Favorites / Recents / Groups / Tags. */
import { useState, type ReactNode } from "react";
import type { HostGroup, HostProfile, HostTag } from "../lib/types";
import { classNames } from "../lib/util";
import {
  IconChevronDown,
  IconChevronRight,
  IconClock,
  IconFolder,
  IconMonitor,
  IconStar,
  IconZap,
  IconGear,
  IconPlus,
} from "./icons";

export type SidebarSelection =
  | { kind: "all" }
  | { kind: "nearby" }
  | { kind: "favorites" }
  | { kind: "recents" }
  | { kind: "group"; id: string }
  | { kind: "tags" };

export function Sidebar({
  hosts,
  groups,
  tags,
  nearbyCount,
  selection,
  onSelect,
  activeTagIds,
  tagMode,
  onToggleTag,
  onToggleTagMode,
  onNewGroup,
  onNewTag,
  onOpenPreferences,
}: {
  hosts: HostProfile[];
  groups: HostGroup[];
  tags: HostTag[];
  nearbyCount: number;
  selection: SidebarSelection;
  onSelect: (s: SidebarSelection) => void;
  activeTagIds: Set<string>;
  tagMode: "and" | "or";
  onToggleTag: (id: string) => void;
  onToggleTagMode: () => void;
  onNewGroup: () => void;
  onNewTag: () => void;
  onOpenPreferences: () => void;
}): ReactNode {
  const groupCount = (gid: string): number => {
    const childIds = groups.filter((g) => g.parentId === gid).map((g) => g.id);
    return hosts.filter((h) => h.groupId === gid || (h.groupId !== null && childIds.includes(h.groupId))).length;
  };

  const rootGroups = groups.filter((g) => g.parentId === null).sort((a, b) => a.sort - b.sort);

  return (
    <nav
      className="flex w-56 shrink-0 flex-col gap-1 overflow-y-auto border-r border-subtle bg-surface/60 px-2.5 py-3"
      aria-label="Library sections"
    >
      <SidebarRow
        icon={<IconZap size={16} />}
        label="Nearby"
        count={nearbyCount}
        active={selection.kind === "nearby"}
        onClick={() => onSelect({ kind: "nearby" })}
      />
      <SidebarRow
        icon={<IconMonitor size={16} />}
        label="All Hosts"
        count={hosts.length}
        active={selection.kind === "all"}
        onClick={() => onSelect({ kind: "all" })}
      />
      <SidebarRow
        icon={<IconStar size={16} />}
        label="Favorites"
        count={hosts.filter((h) => h.favorite).length}
        active={selection.kind === "favorites"}
        onClick={() => onSelect({ kind: "favorites" })}
      />
      <SidebarRow
        icon={<IconClock size={16} />}
        label="Recents"
        active={selection.kind === "recents"}
        onClick={() => onSelect({ kind: "recents" })}
      />

      <Section title="Groups" onAdd={onNewGroup} addLabel="New group">
        {rootGroups.length === 0 ? (
          <p className="px-2 py-1 text-xs text-tertiary">No groups yet</p>
        ) : (
          rootGroups.map((g) => (
            <GroupRow
              key={g.id}
              group={g}
              depth={0}
              groups={groups}
              count={groupCount}
              selection={selection}
              onSelect={onSelect}
            />
          ))
        )}
      </Section>

      <Section
        title="Tags"
        onAdd={onNewTag}
        addLabel="New tag"
        extra={
          tags.length > 1 ? (
            <button
              type="button"
              className="rounded-sm px-1.5 py-0.5 text-2xs font-semibold tracking-wide text-tertiary hover:bg-inset hover:text-primary"
              title="Toggle whether hosts must match ALL selected tags (AND) or ANY (OR)"
              aria-label={`Tag filter mode: ${tagMode.toUpperCase()}. Click to toggle.`}
              onClick={onToggleTagMode}
            >
              {tagMode.toUpperCase()}
            </button>
          ) : null
        }
      >
        {tags.length === 0 ? (
          <p className="px-2 py-1 text-xs text-tertiary">No tags yet</p>
        ) : (
          <div className="flex flex-wrap gap-1.5 px-2 py-1">
            {tags.map((t) => {
              const active = activeTagIds.has(t.id);
              return (
                <button
                  key={t.id}
                  type="button"
                  aria-pressed={active}
                  className={classNames(
                    "flex items-center gap-1.5 rounded-pill border px-2 py-0.5 text-xs",
                    active
                      ? "border-transparent font-medium text-white"
                      : "border-subtle text-secondary hover:border-strong",
                  )}
                  style={active ? { background: t.color } : undefined}
                  onClick={() => onToggleTag(t.id)}
                >
                  <span
                    className="inline-block h-2 w-2 rounded-full"
                    style={{ background: active ? "rgba(255,255,255,0.85)" : t.color }}
                  />
                  {t.name}
                </button>
              );
            })}
          </div>
        )}
      </Section>

      <div className="mt-auto pt-2">
        <SidebarRow
          icon={<IconGear size={16} />}
          label="Preferences"
          active={false}
          onClick={onOpenPreferences}
        />
      </div>
    </nav>
  );
}

function SidebarRow({
  icon,
  label,
  count,
  active,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
}): ReactNode {
  return (
    <button
      type="button"
      aria-current={active ? "true" : undefined}
      className={classNames(
        "flex w-full items-center gap-2.5 rounded-sm px-2 py-1.5 text-sm",
        active ? "bg-accent/15 font-medium text-primary" : "text-secondary hover:bg-inset hover:text-primary",
      )}
      onClick={onClick}
    >
      <span className={active ? "text-accent" : "text-tertiary"}>{icon}</span>
      <span className="min-w-0 flex-1 truncate text-left">{label}</span>
      {count !== undefined && count > 0 ? (
        <span className="text-xs text-tertiary">{count}</span>
      ) : null}
    </button>
  );
}

function Section({
  title,
  children,
  onAdd,
  addLabel,
  extra,
}: {
  title: string;
  children: ReactNode;
  onAdd?: () => void;
  addLabel?: string;
  extra?: ReactNode;
}): ReactNode {
  const [open, setOpen] = useState(true);
  return (
    <div className="mt-3">
      <div className="flex items-center gap-1 px-2">
        <button
          type="button"
          className="flex flex-1 items-center gap-1 text-2xs font-semibold uppercase tracking-wider text-tertiary hover:text-secondary"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? <IconChevronDown size={12} /> : <IconChevronRight size={12} />}
          {title}
        </button>
        {extra}
        {onAdd ? (
          <button
            type="button"
            aria-label={addLabel}
            title={addLabel}
            className="rounded-sm p-0.5 text-tertiary hover:bg-inset hover:text-primary"
            onClick={onAdd}
          >
            <IconPlus size={13} />
          </button>
        ) : null}
      </div>
      {open ? <div className="mt-1">{children}</div> : null}
    </div>
  );
}

function GroupRow({
  group,
  depth,
  groups,
  count,
  selection,
  onSelect,
}: {
  group: HostGroup;
  depth: number;
  groups: HostGroup[];
  count: (gid: string) => number;
  selection: SidebarSelection;
  onSelect: (s: SidebarSelection) => void;
}): ReactNode {
  const children = groups.filter((g) => g.parentId === group.id).sort((a, b) => a.sort - b.sort);
  const active = selection.kind === "group" && selection.id === group.id;
  return (
    <div>
      <button
        type="button"
        aria-current={active ? "true" : undefined}
        className={classNames(
          "flex w-full items-center gap-2 rounded-sm py-1.5 pr-2 text-sm",
          active ? "bg-accent/15 font-medium text-primary" : "text-secondary hover:bg-inset hover:text-primary",
        )}
        style={{ paddingLeft: 8 + depth * 14 }}
        onClick={() => onSelect({ kind: "group", id: group.id })}
      >
        <IconFolder size={15} className={active ? "text-accent" : "text-tertiary"} />
        <span className="min-w-0 flex-1 truncate text-left">{group.name}</span>
        <span className="text-xs text-tertiary">{count(group.id) || ""}</span>
      </button>
      {children.map((c) => (
        <GroupRow
          key={c.id}
          group={c}
          depth={depth + 1}
          groups={groups}
          count={count}
          selection={selection}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}
