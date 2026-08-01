/** Small shared UI primitives: toasts, context menu, empty state, skeletons, dialog shell. */
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
  type SelectHTMLAttributes,
} from "react";
import { useToasts, type Toast } from "../state/ToastContext";
import { usePaneVisible } from "./Pane";
import { classNames } from "../lib/util";
import { IconCheck, IconAlert, IconX, IconChevronDown } from "./icons";

// ------------------------------------------------------------------- select

/**
 * Themed dropdown.
 *
 * Deliberately still a native `<select>`: the browser keeps the whole keyboard
 * and screen-reader contract (type-ahead, arrow keys, Escape, platform popup)
 * that a hand-rolled listbox would have to re-earn. We only remove the native
 * bezel via `appearance: none` (see `select.field` in index.css) and draw the
 * chevron ourselves so it matches the icon set.
 */
export function Select({
  className,
  wrapperClassName,
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { wrapperClassName?: string }): ReactNode {
  return (
    <span className={classNames("relative block", wrapperClassName)}>
      <select className={classNames("field", className)} {...rest}>
        {children}
      </select>
      <IconChevronDown
        size={14}
        className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-tertiary"
      />
    </span>
  );
}

// ------------------------------------------------------------------- toasts

export function ToastShelf(): ReactNode {
  const { toasts, dismiss } = useToasts();
  return (
    <div
      className="pointer-events-none fixed bottom-4 left-1/2 z-50 flex w-full max-w-sm -translate-x-1/2 flex-col gap-2"
      role="status"
      aria-live="polite"
    >
      {toasts.map((t) => (
        <ToastCard key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
      ))}
    </div>
  );
}

function ToastCard({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }): ReactNode {
  const color =
    toast.kind === "success"
      ? "text-success"
      : toast.kind === "warning"
        ? "text-warning"
        : toast.kind === "danger"
          ? "text-danger"
          : "text-secondary";
  return (
    <div className="toast-in pointer-events-auto flex items-center gap-2.5 rounded-md border border-subtle bg-raised px-3.5 py-2.5 shadow-(--shadow-pop)">
      <span className={color}>
        {toast.kind === "success" ? (
          <IconCheck size={16} />
        ) : toast.kind === "info" ? (
          <IconCheck size={16} />
        ) : (
          <IconAlert size={16} />
        )}
      </span>
      <span className="min-w-0 flex-1 text-sm text-primary">{toast.message}</span>
      {toast.actionLabel ? (
        <button
          type="button"
          className="shrink-0 text-sm font-medium text-accent hover:underline"
          onClick={() => {
            toast.onAction?.();
            onDismiss();
          }}
        >
          {toast.actionLabel}
        </button>
      ) : null}
      <button
        type="button"
        aria-label="Dismiss notification"
        className="shrink-0 text-tertiary hover:text-primary"
        onClick={onDismiss}
      >
        <IconX size={14} />
      </button>
    </div>
  );
}

// ------------------------------------------------------------- context menu

export interface MenuItem {
  label: string;
  danger?: boolean;
  disabled?: boolean;
  separatorAbove?: boolean;
  onSelect: () => void;
}

export function ContextMenu({
  x,
  y,
  items,
  onClose,
}: {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
}): ReactNode {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x, y });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos({
      x: Math.min(x, window.innerWidth - r.width - 8),
      y: Math.min(y, window.innerHeight - r.height - 8),
    });
  }, [x, y]);

  useEffect(() => {
    const close = (): void => onClose();
    const key = (e: KeyboardEvent): void => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("pointerdown", close);
    window.addEventListener("keydown", key);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("pointerdown", close);
      window.removeEventListener("keydown", key);
      window.removeEventListener("blur", close);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      role="menu"
      className="fade-in fixed z-50 min-w-44 rounded-md border border-subtle bg-raised p-1 shadow-(--shadow-pop)"
      style={{ left: pos.x, top: pos.y }}
      onPointerDown={(e) => e.stopPropagation()}
    >
      {items.map((item, i) => (
        <div key={`${item.label}-${i}`}>
          {item.separatorAbove ? <div className="mx-2 my-1 border-t border-subtle" /> : null}
          <button
            type="button"
            role="menuitem"
            disabled={item.disabled}
            className={classNames(
              "block w-full rounded-sm px-2.5 py-1.5 text-left text-sm",
              item.disabled
                ? "cursor-default text-tertiary"
                : item.danger
                  ? "text-danger hover:bg-danger-subtle"
                  : "text-primary hover:bg-inset",
            )}
            onClick={() => {
              if (item.disabled) return;
              onClose();
              item.onSelect();
            }}
          >
            {item.label}
          </button>
        </div>
      ))}
    </div>
  );
}

// --------------------------------------------------------------- empty state

export function EmptyState({
  icon,
  title,
  body,
  primary,
  secondary,
}: {
  icon?: ReactNode;
  title: string;
  body?: string;
  primary?: { label: string; onClick: () => void };
  secondary?: { label: string; onClick: () => void };
}): ReactNode {
  return (
    <div className="flex h-full min-h-64 flex-col items-center justify-center gap-3 px-8 text-center">
      {icon ? <div className="text-tertiary">{icon}</div> : null}
      <h2 className="text-lg font-semibold text-primary">{title}</h2>
      {body ? <p className="max-w-md text-sm text-secondary">{body}</p> : null}
      <div className="mt-2 flex items-center gap-3">
        {primary ? (
          <button type="button" className="btn-primary" onClick={primary.onClick}>
            {primary.label}
          </button>
        ) : null}
        {secondary ? (
          <button type="button" className="btn-secondary" onClick={secondary.onClick}>
            {secondary.label}
          </button>
        ) : null}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------- skeleton

export function TileSkeleton(): ReactNode {
  return (
    <div className="overflow-hidden rounded-md border border-subtle bg-surface">
      <div className="skeleton aspect-[16/10]" />
      <div className="space-y-2 p-3">
        <div className="skeleton h-3.5 w-2/3 rounded" />
        <div className="skeleton h-3 w-1/2 rounded" />
      </div>
    </div>
  );
}

// -------------------------------------------------------------- dialog shell

export function Dialog({
  title,
  onClose,
  children,
  width = 520,
  danger = false,
  initialFocusSelector,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
  danger?: boolean;
  initialFocusSelector?: string;
}): ReactNode {
  const ref = useRef<HTMLDivElement>(null);
  // A dialog on a background tab is not on screen, and must neither take the
  // focus nor answer the keyboard. Both effects below listen outside this
  // subtree, where hiding the pane does not reach them.
  const onScreen = usePaneVisible();

  useEffect(() => {
    const el = ref.current;
    if (!el || !onScreen) return;
    const target = initialFocusSelector
      ? el.querySelector<HTMLElement>(initialFocusSelector)
      : el.querySelector<HTMLElement>("[data-autofocus]") ??
        el.querySelector<HTMLElement>("input, select, button");
    target?.focus();
  }, [initialFocusSelector, onScreen]);

  useEffect(() => {
    if (!onScreen) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
      if (e.key === "Tab" && ref.current) {
        // simple focus trap
        const focusables = ref.current.querySelectorAll<HTMLElement>(
          'button, input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose, onScreen]);

  const style: CSSProperties = { width, maxWidth: "calc(100vw - 32px)" };

  return (
    <div
      className="fade-in fixed inset-0 z-40 flex items-center justify-center bg-scrim"
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={classNames(
          "max-h-[85vh] overflow-y-auto rounded-lg border bg-surface shadow-(--shadow-pop)",
          danger ? "border-danger" : "border-subtle",
        )}
        style={style}
      >
        <div className="flex items-center justify-between border-b border-subtle px-5 py-3.5">
          <h2 className={classNames("text-base font-semibold", danger ? "text-danger" : "text-primary")}>
            {title}
          </h2>
          <button
            type="button"
            aria-label="Close dialog"
            className="rounded-sm p-1 text-tertiary hover:text-primary"
            onClick={onClose}
          >
            <IconX size={16} />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}
