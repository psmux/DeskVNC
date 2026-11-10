/**
 * Buttons. Every one is at least 48 px tall and gives a small haptic tap.
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
  md: "min-h-12 px-5 text-base gap-2 rounded-[10px]",
  lg: "min-h-14 px-6 text-lg gap-2.5 rounded-[10px]",
  xl: "min-h-14 px-7 text-lg gap-3 rounded-xl",
};

export function Button({ variant = "primary", size = "lg", icon, tone, block, className = "", children, onClick, style, ...rest }: Props) {
  const look: Record<Variant, string> = {
    primary: "text-accent-ink active:brightness-95",
    soft: "border border-line bg-surface-2 text-ink active:brightness-95",
    ghost: "bg-transparent text-accent active:bg-surface-2",
    danger: "bg-danger-soft text-danger active:brightness-95",
    plain: "border border-line bg-surface text-ink active:brightness-95",
  };
  const bg = variant === "primary" ? { background: tone ?? "var(--dv-accent)" } : undefined;
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
      {icon}
      {children}
    </button>
  );
}

/** A round icon button, 48 px. */
export function IconButton({ label, children, className = "", onClick, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={`inline-flex h-12 w-12 shrink-0 items-center justify-center rounded-full border border-line bg-surface text-ink transition-transform active:scale-90 ${className}`}
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
