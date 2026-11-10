/** A menu of big actions, each with an icon. */
import type { ReactNode } from "react";
import { haptic } from "../../lib/haptics";
import { Sheet } from "../Sheet";

export interface Action {
  label: string;
  icon: ReactNode;
  danger?: boolean;
  onPick: () => void;
}

export function ActionSheet({ open, title, art, actions, onClose }: { open: boolean; title?: ReactNode; art?: ReactNode; actions: Action[]; onClose: () => void }) {
  return (
    <Sheet open={open} onClose={onClose} title={title} art={art}>
      <div className="flex flex-col gap-2">
        {actions.map((a) => (
          <button
            key={a.label}
            type="button"
            onClick={() => {
              haptic(a.danger ? "warning" : "tap");
              onClose();
              a.onPick();
            }}
            className={`flex min-h-[3.25rem] items-center gap-3 rounded-[10px] px-4 text-left text-body font-medium active:scale-[0.98] ${a.danger ? "bg-danger-soft text-danger" : "bg-surface-2 text-ink"}`}
          >
            <span className="flex h-10 w-10 items-center justify-center rounded-full bg-surface">{a.icon}</span>
            {a.label}
          </button>
        ))}
        <button type="button" onClick={onClose} className="mt-1 min-h-12 rounded-[10px] text-body font-semibold text-ink-dim">
          Cancel
        </button>
      </div>
    </Sheet>
  );
}

/** Are you sure? For deleting. */
export function ConfirmSheet({
  open,
  title,
  subtitle,
  confirm,
  art,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: ReactNode;
  subtitle?: ReactNode;
  confirm: string;
  art?: ReactNode;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Sheet open={open} onClose={onClose} title={title} subtitle={subtitle} art={art}>
      <div className="flex flex-col gap-2">
        <button
          type="button"
          onClick={() => {
            onClose();
            onConfirm();
          }}
          className="min-h-[3.125rem] rounded-xl bg-danger text-headline text-white active:scale-[0.98]"
        >
          {confirm}
        </button>
        <button type="button" onClick={onClose} className="min-h-[3.125rem] rounded-xl bg-surface-2 text-headline">
          Keep it
        </button>
      </div>
    </Sheet>
  );
}
