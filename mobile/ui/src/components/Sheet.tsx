/**
 * A bottom sheet: slides up, drags down to close, dims what is behind it.
 * On a tablet it floats in the middle as a card. Used for prompts, menus and
 * anything that asks one question.
 */
import { AnimatePresence, motion, useDragControls } from "motion/react";
import { useEffect, type ReactNode } from "react";

interface Props {
  open: boolean;
  onClose?: () => void;
  children: ReactNode;
  /** Optional picture shown above the title. */
  art?: ReactNode;
  title?: ReactNode;
  subtitle?: ReactNode;
  /** When false the sheet cannot be dismissed by dragging or tapping outside. */
  dismissible?: boolean;
  labelledBy?: string;
}

export function Sheet({ open, onClose, children, art, title, subtitle, dismissible = true }: Props) {
  const drag = useDragControls();
  useEffect(() => {
    if (!open || !dismissible) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, dismissible, onClose]);
  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex items-end justify-center tab:items-center" role="dialog" aria-modal>
          <motion.div
            className="absolute inset-0 bg-black/45"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => dismissible && onClose?.()}
          />
          <motion.div
            className="relative max-h-[92dvh] w-full overflow-y-auto rounded-t-[18px] bg-surface px-5 pb-safe shadow-lift tab:max-w-lg tab:rounded-[18px] tab:pb-0"
            initial={{ y: "100%" }}
            animate={{ y: 0 }}
            exit={{ y: "100%" }}
            transition={{ type: "spring", stiffness: 380, damping: 36 }}
            drag={dismissible ? "y" : false}
            dragListener={false}
            dragControls={drag}
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0, bottom: 0.6 }}
            onDragEnd={(_, info) => {
              if (info.offset.y > 120 || info.velocity.y > 600) onClose?.();
            }}
          >
            <div className="flex justify-center pb-1 pt-3" onPointerDown={(e) => dismissible && drag.start(e)} style={{ touchAction: "none" }}>
              <div className="h-1.5 w-12 rounded-full bg-line" />
            </div>
            <div className="pb-6">
              {art && <div className="mx-auto mb-2 w-44">{art}</div>}
              {title && <h2 className="text-balance text-center text-title2">{title}</h2>}
              {subtitle && <p className="mx-auto mt-2 max-w-sm text-center text-subhead text-ink-dim">{subtitle}</p>}
              <div className={title ? "mt-5" : ""}>{children}</div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
