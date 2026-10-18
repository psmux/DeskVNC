/**
 * The tab strip across the top of the library window (tabbed view).
 *
 * Reads like browser tabs on purpose: the library is the pinned first tab and
 * cannot be closed, every session after it carries a status dot, the desktop's
 * own name, and a close button. Middle-click closes, matching the same habit.
 *
 * The rest of the browser habits come along too. Right-clicking a tab offers
 * Close, Close other tabs, Close tabs to the left or right, and Close all
 * tabs. When the tabs no longer fit, arrows appear at both ends of the strip,
 * and an ordinary mouse wheel over it scrolls it sideways.
 */
import { useCallback, useEffect, useRef, useState, type ReactNode, type Ref } from "react";
import { tabsToClose, type CloseScope } from "../lib/tabClose";
import { classNames } from "../lib/util";
import type { SessionState } from "../lib/types";
import type { TabSummary } from "../state/TabsContext";
import { SESSION_PANEL_ID } from "./SplitView";
import { ContextMenu, type MenuItem } from "./primitives";
import { IconChevronLeft, IconChevronRight, IconGrid, IconX } from "./icons";

/**
 * DOM id of the surface a tab controls.
 *
 * There are two, not one per tab: the library, and the one every session is
 * laid out on. `SplitView` mounts every tab's sessions at once in a single
 * element so that moving one between panes cannot re-parent its canvas, so a
 * per-tab panel element does not exist to point at. One panel whose contents
 * follow the selected tab is the shape this actually has.
 */
export function tabPanelId(id: string | null): string {
  return id === null ? "pane-library" : SESSION_PANEL_ID;
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

const NO_TABS_DRIVEN: ReadonlySet<string> = new Set();

export function TabStrip({
  tabs,
  activeId,
  onSelect,
  onClose,
  onCloseMany,
  onSelectRelative,
  drivenTabIds = NO_TABS_DRIVEN,
}: {
  tabs: readonly TabSummary[];
  activeId: string | null;
  onSelect: (id: string | null) => void;
  onClose: (id: string) => void;
  /** Close several tabs at once, for the right-click menu's commands. */
  onCloseMany: (ids: readonly string[]) => void;
  /** Left/right arrow within the strip, the ARIA tablist keyboard contract. */
  onSelectRelative: (delta: number) => void;
  /**
   * Tabs holding at least one session an agent is driving.
   *
   * Empty until the agent plane is on, at which point every tab looks exactly
   * as it always has.
   */
  drivenTabIds?: ReadonlySet<string>;
}): ReactNode {
  const activeRef = useRef<HTMLDivElement>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);
  const [overflow, setOverflow] = useState({ left: false, right: false });
  /** The tab the menu was opened on (null for the library), and where. */
  const [menu, setMenu] = useState<{ id: string | null; x: number; y: number } | null>(null);

  // Whether anything is hidden off either end. Measured rather than computed,
  // since tab widths follow their titles and the window's width.
  const measure = useCallback((): void => {
    const el = scrollerRef.current;
    if (!el) return;
    // A pixel of slack: fractional widths leave scrollLeft a hair short of the
    // end, which would otherwise keep the right arrow lit with nothing to show.
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setOverflow((prev) => (prev.left === left && prev.right === right ? prev : { left, right }));
  }, []);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    for (const child of Array.from(el.children)) observer.observe(child);
    el.addEventListener("scroll", measure, { passive: true });
    return () => {
      observer.disconnect();
      el.removeEventListener("scroll", measure);
    };
  }, [measure, tabs]);

  // A plain mouse wheel only moves up and down, which a strip of tabs cannot
  // do, so turn it into sideways movement the way browsers do. A trackpad's
  // own sideways swipe is left alone. Native and not passive, because React's
  // wheel handler cannot cancel the event.
  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent): void => {
      if (el.scrollWidth <= el.clientWidth) return;
      if (Math.abs(e.deltaY) <= Math.abs(e.deltaX)) return;
      e.preventDefault();
      // Some Windows mice report whole lines rather than pixels.
      el.scrollLeft += e.deltaMode === WheelEvent.DOM_DELTA_LINE ? e.deltaY * 40 : e.deltaY;
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const scrollByPage = (direction: -1 | 1): void => {
    const el = scrollerRef.current;
    if (!el) return;
    el.scrollBy({ left: direction * Math.max(120, el.clientWidth * 0.75), behavior: "smooth" });
  };

  const menuItems = (id: string | null): MenuItem[] => {
    const ids = tabs.map((t) => t.id);
    const item = (label: string, scope: CloseScope, separatorAbove = false): MenuItem => {
      const closing = tabsToClose(ids, id, scope);
      return {
        label,
        separatorAbove,
        disabled: closing.length === 0,
        onSelect: () => onCloseMany(closing),
      };
    };
    // The library cannot close, so all it can offer is clearing the strip.
    if (id === null) return [item("Close all tabs", "all")];
    return [
      item("Close tab", "this"),
      item("Close other tabs", "others", true),
      item("Close tabs to the left", "left"),
      item("Close tabs to the right", "right"),
      item("Close all tabs", "all", true),
    ];
  };

  const scrolls = overflow.left || overflow.right;

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
    <div className="flex shrink-0 items-stretch border-b border-subtle bg-inset/50">
      {scrolls ? (
        <ScrollButton
          label="Scroll tabs left"
          disabled={!overflow.left}
          onClick={() => scrollByPage(-1)}
          icon={<IconChevronLeft size={14} />}
        />
      ) : null}
      <div
        ref={scrollerRef}
        role="tablist"
        aria-label="Open sessions"
        className={classNames(
          "tab-scroller flex min-w-0 flex-1 items-stretch gap-1 overflow-x-auto pt-1.5",
          scrolls ? "px-0.5" : "px-2",
        )}
        onKeyDown={onKeyDown}
      >
        <Tab
          ref={activeId === null ? activeRef : undefined}
          selected={activeId === null}
          onSelect={() => onSelect(null)}
          onMenu={(x, y) => setMenu({ id: null, x, y })}
          panelId={tabPanelId(null)}
          icon={<IconGrid size={13} />}
          label="Library"
        />
        {tabs.map((tab) => {
          const selected = tab.id === activeId;
          const status = statusOf(tab.state);
          const driven = drivenTabIds.has(tab.id);
          return (
            <Tab
              key={tab.id}
              ref={selected ? activeRef : undefined}
              selected={selected}
              onSelect={() => onSelect(tab.id)}
              onClose={() => onClose(tab.id)}
              onMenu={(x, y) => setMenu({ id: tab.id, x, y })}
              panelId={tabPanelId(tab.id)}
              // Both glyphs are decorative here: their meaning is already in the
              // tab's own accessible name, and announcing it twice is just noise.
              // The square is the same one the pane header uses, so a tab in the
              // background reads the same way as a pane in front does.
              icon={
                <span className="flex shrink-0 items-center gap-1">
                  <span
                    aria-hidden="true"
                    className={classNames("h-1.5 w-1.5 shrink-0 rounded-full", status.className)}
                  />
                  {driven ? (
                    <span
                      aria-hidden="true"
                      className="h-1.5 w-1.5 shrink-0 rounded-[1px] bg-warning"
                    />
                  ) : null}
                </span>
              }
              label={tab.title}
              // Said in words rather than left to a shape, because a shape is
              // exactly what a screen reader cannot pass on.
              status={driven ? `${status.label}, agent driving` : status.label}
            />
          );
        })}
      </div>
      {scrolls ? (
        <ScrollButton
          label="Scroll tabs right"
          disabled={!overflow.right}
          onClick={() => scrollByPage(1)}
          icon={<IconChevronRight size={14} />}
        />
      ) : null}
      {menu ? (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={menuItems(menu.id)}
          onClose={() => setMenu(null)}
        />
      ) : null}
    </div>
  );
}

/**
 * One of the arrows at the ends of a strip too full to show every tab.
 *
 * Both appear together, the one at an end with nothing past it dimmed, so the
 * tabs do not jump sideways every time an arrow comes or goes.
 */
function ScrollButton({
  label,
  disabled,
  onClick,
  icon,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
  icon: ReactNode;
}): ReactNode {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      // Out of the Tab order: the arrow keys already move along the strip and
      // bring the selected tab into view.
      tabIndex={-1}
      className={classNames(
        "my-1 flex w-6 shrink-0 items-center justify-center rounded-sm",
        disabled
          ? "text-tertiary opacity-40"
          : "text-secondary hover:bg-surface/60 hover:text-primary",
      )}
      onClick={onClick}
    >
      {icon}
    </button>
  );
}

function Tab({
  ref,
  selected,
  onSelect,
  onClose,
  onMenu,
  panelId,
  icon,
  label,
  status,
}: {
  ref?: Ref<HTMLDivElement>;
  selected: boolean;
  onSelect: () => void;
  onClose?: () => void;
  /** Open the tab's right-click menu at this point in the window. */
  onMenu: (x: number, y: number) => void;
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
        } else if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
          // The keyboard's way to the same menu, opened under the tab.
          e.preventDefault();
          const r = e.currentTarget.getBoundingClientRect();
          onMenu(r.left, r.bottom);
        }
      }}
      onContextMenu={(e) => {
        e.preventDefault();
        onMenu(e.clientX, e.clientY);
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
