/**
 * Buttons. md is 40 px, lg 44 px (the touch minimum) and xl 50 px, the
 * height of a full width call to action on iOS. Each gives a small haptic tap.
 * `variant`: primary (the one obvious action), soft, ghost, danger.
 */
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { haptic } from "../lib/haptics";

type Variant = "primary" | "soft" | "ghost" | "danger" | "plain";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "md" | "lg" | "xl";
  icon?: ReactNode;
  /** A colour to use instead of the accent, as any CSS colour. */
  tone?: string;
  block?: boolean;
}

const SIZES = {
  md: "min-h-10 px-4 text-subhead gap-1.5 rounded-[9px]",
  lg: "min-h-11 px-5 text-subhead gap-2 rounded-[10px]",
  xl: "min-h-[3.125rem] px-6 text-headline gap-2 rounded-xl",
};

export function Button({ variant = "primary", size = "lg", icon, tone, block, className = "", children, onClick, style, ...rest }: Props) {
  const look: Record<Variant, string> = {
    primary: "text-accent-ink active:brightness-95",
    soft: "border border-line bg-surface-2 text-ink active:brightness-95",
    ghost: "bg-transparent text-accent active:bg-surface-2",
    danger: "bg-danger-soft text-danger active:brightness-95",
    plain: "border border-line bg-surface text-ink active:brightness-95",
  };
  const bg = variant === "primary" ? { background: tone ?? "var(--dv-accent-fill)" } : undefined;
  return (
    <button
      type="button"
      className={`inline-flex select-none items-center justify-center font-semibold transition-[transform,filter] duration-150 active:scale-[0.97] disabled:opacity-45 disabled:active:scale-100 ${SIZES[size]} ${look[variant]} ${block ? "w-full" : ""} ${className}`}
      style={{ ...bg, ...style }}
      onClick={(e) => {
        haptic("tap");
        onClick?.(e);
      }}
      {...rest}
    >
      {/* Icons follow the label size, so a 24 px glyph never shouts beside 15 px text. */}
      {icon && <span className="inline-flex shrink-0 [&>svg]:h-[1.15em] [&>svg]:w-[1.15em]">{icon}</span>}
      {children}
    </button>
  );
}

/** A round icon button, 44 px. */
export function IconButton({ label, children, className = "", onClick, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={`inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-line bg-surface text-ink transition-transform active:scale-90 ${className}`}
      onClick={(e) => {
        haptic("tap");
        onClick?.(e);
      }}
      {...rest}
    >
      {children}
    </button>
  );
}
