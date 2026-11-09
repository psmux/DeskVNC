/**
 * Shared bits for every illustration: one line colour and weight, so the art
 * reads as a single hand drew it.
 */
import type { SVGProps } from "react";

export const LINE = "var(--dv-art-line)";
export const PAPER = "var(--dv-art-paper)";
export const SHADE = "var(--dv-art-shade)";
export const W = 3; // line weight in a 160 wide view box

export const stroke = {
  stroke: LINE,
  strokeWidth: W,
  strokeLinejoin: "round" as const,
  strokeLinecap: "round" as const,
};

export type ArtProps = Omit<SVGProps<SVGSVGElement>, "children"> & { size?: number | string };

/** A soft ground shadow under an object. */
export function Ground({ cx, cy, rx, opacity = 0.14 }: { cx: number; cy: number; rx: number; opacity?: number }) {
  return <ellipse cx={cx} cy={cy} rx={rx} ry={rx * 0.12} fill={LINE} opacity={opacity} />;
}

/** A four point sparkle. */
export function Sparkle({ x, y, r = 6, fill = "#ffc145", className }: { x: number; y: number; r?: number; fill?: string; className?: string }) {
  const k = r * 0.28;
  return (
    <path
      className={className}
      d={`M${x} ${y - r} Q${x + k} ${y - k} ${x + r} ${y} Q${x + k} ${y + k} ${x} ${y + r} Q${x - k} ${y + k} ${x - r} ${y} Q${x - k} ${y - k} ${x} ${y - r}Z`}
      fill={fill}
      stroke={LINE}
      strokeWidth={2}
      strokeLinejoin="round"
    />
  );
}
