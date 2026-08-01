/**
 * The tab strip across the top of the library window (tabbed view).
 *
 * Reads like browser tabs on purpose: the library is the pinned first tab and
 * cannot be closed, every session after it carries a status dot, the desktop's
 * own name, and a close button. Middle-click closes, matching the same habit.
 */
import { useEffect, useRef, type ReactNode, type Ref } from "react";
import { classNames } from "../lib/util";
import type { SessionState } from "../lib/types";
import type { SessionTab } from "../state/TabsContext";
import { IconGrid, IconX } from "./icons";

/** DOM id of the pane a tab controls. `null` is the library. */
export function tabPanelId(id: string | null): string {
  return `pane-${id ?? "library"}`;
}

/** Colour of a tab's status dot, and what a screen reader hears for it. */
function statusOf(state: SessionState): { className: string; label: string } {
  switch (state.state) {
    case "connected":
      return { className: "bg-success", label: "Connected" };
    case "disconnected":
      return { className: "bg-danger", label: "Disconnected" };
    case "reconnecting":
      return { className: "bg-warning animate-pulse", label: "Reconnecting" };
    default:
      return { className: "bg-accent animate-pulse", label: "Connecting" };
  }
}

export function TabStrip({
  tabs,
  activeId,
  onSelect,
  onClose,
  onSelectRelative,
}: {
  tabs: readonly SessionTab[];
  activeId: string | null;
  onSelect: (id: string | null) => void;
  onClose: (id: string) => void;
  /** Left/right arrow within the strip, the ARIA tablist keyboard contract. */
  onSelectRelative: (delta: number) => void;
}): ReactNode {
  const activeRef = useRef<HTMLDivElement>(null);

  // Keep the selected tab in view when it was chosen with the keyboard, or
  // when a new session lands off the right-hand end of a full strip.
  useEffect(() => {
    activeRef.current?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [activeId, tabs.length]);

  const onKeyDown = (e: React.KeyboardEvent): void => {
    if (e.key === "ArrowRight") {
      e.preventDefault();
      onSelectRelative(1);
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      onSelectRelative(-1);
    }
  };

  return (
    <div
      role="tablist"
      aria-label="Open sessions"
      className="flex shrink-0 items-stretch gap-1 overflow-x-auto border-b border-subtle bg-inset/50 px-2 pt-1.5"
      onKeyDown={onKeyDown}
    >
      <Tab
        ref={activeId === null ? activeRef : undefined}
        selected={activeId === null}
        onSelect={() => onSelect(null)}
        panelId={tabPanelId(null)}
        icon={<IconGrid size={13} />}
        label="Library"
      />
      {tabs.map((tab) => {
        const selected = tab.id === activeId;
        const status = statusOf(tab.state);
        return (
          <Tab
            key={tab.id}
            ref={selected ? activeRef : undefined}
            selected={selected}
            onSelect={() => onSelect(tab.id)}
            onClose={() => onClose(tab.id)}
            panelId={tabPanelId(tab.id)}
            // The dot is decorative here: its meaning is already in the tab's
            // own accessible name, and announcing it twice is just noise.
            icon={
              <span
                aria-hidden="true"
                className={classNames("h-1.5 w-1.5 shrink-0 rounded-full", status.className)}
              />
            }
            label={tab.title}
            status={status.label}
          />
        );
      })}
    </div>
  );
}

function Tab({
  ref,
  selected,
  onSelect,
  onClose,
  panelId,
  icon,
  label,
  status,
}: {
  ref?: Ref<HTMLDivElement>;
  selected: boolean;
  onSelect: () => void;
  onClose?: () => void;
  panelId: string;
  icon: ReactNode;
  label: string;
  status?: string;
}): ReactNode {
  return (
    <div
      ref={ref}
      role="tab"
      aria-selected={selected}
      aria-controls={panelId}
      // Named explicitly rather than from its contents: the close button is a
      // focusable descendant, so otherwise every tab would announce itself as
      // "my-desktop, Close my-desktop".
      aria-label={status ? `${label}, ${status}` : label}
      // Roving tabindex: Tab reaches the strip, then Left/Right move within it.
      tabIndex={selected ? 0 : -1}
      title={label}
      className={classNames(
        "group flex min-w-0 shrink-0 cursor-default items-center gap-2 rounded-t-md border border-b-0 px-3 py-1.5 text-xs",
        selected
          ? "border-subtle bg-surface text-primary"
          : "border-transparent text-secondary hover:bg-surface/60",
      )}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
      // Middle-click to close, the habit every tabbed app has taught.
      onAuxClick={(e) => {
        if (e.button === 1 && onClose) {
          e.preventDefault();
          onClose();
        }
      }}
    >
      {icon}
      <span className={classNames("max-w-40 truncate", selected && "font-medium")}>{label}</span>
      {onClose ? (
        <button
          type="button"
          aria-label={`Close ${label}`}
          // Always visible on the tab in front: a close button that only shows
          // on hover cannot be found without a pointer.
          className={classNames(
            "-mr-1 shrink-0 rounded-sm p-0.5 text-tertiary hover:bg-inset hover:text-primary",
            selected ? "" : "opacity-0 group-hover:opacity-100 focus-visible:opacity-100",
          )}
          onClick={(e) => {
            e.stopPropagation();
            onClose();
          }}
        >
          <IconX size={12} />
        </button>
      ) : null}
    </div>
  );
}
