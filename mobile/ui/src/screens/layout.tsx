/**
 * Screen scaffolding: a big title that respects the notch, and a scroll area
 * with pull to refresh that leaves room for the tab bar.
 */
import { motion, useMotionValue, useTransform, animate } from "motion/react";
import { useRef, useState, type ReactNode } from "react";
import { IconRefresh } from "../art/Icons";
import { haptic } from "../lib/haptics";

export function ScreenHeader({ title, subtitle, action }: { title: string; subtitle?: ReactNode; action?: ReactNode }) {
  return (
    <header className="flex items-end gap-3 px-5 pb-3 pt-3 tab:px-8 tab:pt-8">
      <div className="min-w-0 flex-1">
        <h1 className="text-large-title">{title}</h1>
        {subtitle && <p className="mt-1 text-subhead text-ink-dim">{subtitle}</p>}
      </div>
      {action}
    </header>
  );
}

const PULL = 80;

export function ScreenScroll({ children, onRefresh, className = "" }: { children: ReactNode; onRefresh?: () => Promise<void>; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const start = useRef<number | null>(null);
  const pull = useMotionValue(0);
  const [busy, setBusy] = useState(false);
  const rotate = useTransform(pull, [0, PULL], [0, 270]);
  const opacity = useTransform(pull, [0, PULL * 0.4, PULL], [0, 0.6, 1]);

  const end = async () => {
    const was = pull.get();
    start.current = null;
    if (was >= PULL && onRefresh && !busy) {
      haptic("success");
      setBusy(true);
      animate(pull, PULL * 0.75);
      try {
        await onRefresh();
      } finally {
        setBusy(false);
        animate(pull, 0);
      }
    } else {
      animate(pull, 0);
    }
  };

  return (
    <div
      ref={ref}
      className={`pt-safe relative h-full overflow-y-auto overscroll-contain pb-[calc(6rem+env(safe-area-inset-bottom))] tab:pb-10 ${className}`}
      onTouchStart={(e) => {
        if (onRefresh && ref.current && ref.current.scrollTop <= 0) start.current = e.touches[0].clientY;
      }}
      onTouchMove={(e) => {
        if (start.current === null) return;
        const d = e.touches[0].clientY - start.current;
        if (d <= 0) return pull.set(0);
        const next = Math.min(PULL * 1.4, d * 0.5);
        if (pull.get() < PULL && next >= PULL) haptic("select");
        pull.set(next);
      }}
      onTouchEnd={() => void end()}
    >
      {onRefresh && (
        <motion.div className="pointer-events-none absolute inset-x-0 top-[env(safe-area-inset-top)] z-10 flex justify-center" style={{ height: pull, opacity }}>
          <motion.span
            className={`mt-3 flex h-11 w-11 items-center justify-center rounded-full bg-surface text-accent shadow-card ${busy ? "dv-spin" : ""}`}
            style={busy ? undefined : { rotate }}
          >
            <IconRefresh />
          </motion.span>
        </motion.div>
      )}
      <motion.div style={{ y: pull }}>{children}</motion.div>
    </div>
  );
}
