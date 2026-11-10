/**
 * Shared bits for every illustration: one line colour and weight, so the art
 * reads as one set. Gray line work on paper, the accent for the one thing
 * that matters in each picture, nothing else.
 */
import type { SVGProps } from "react";

export const LINE = "var(--dv-art-line)";
export const PAPER = "var(--dv-art-paper)";
export const SHADE = "var(--dv-art-shade)";
export const MID = "var(--dv-art-mid)";
export const BACKDROP = "var(--dv-art-backdrop)";
export const ACCENT = "var(--dv-accent)";
export const ACCENT_SOFT = "var(--dv-accent-soft)";
export const W = 2; // line weight in a 160 wide view box

export const stroke = {
  stroke: LINE,
  strokeWidth: W,
  strokeLinejoin: "round" as const,
  strokeLinecap: "round" as const,
};

export type ArtProps = Omit<SVGProps<SVGSVGElement>, "children"> & { size?: number | string };

/** A soft ground shadow under an object. */
export function Ground({ cx, cy, rx, opacity = 0.1 }: { cx: number; cy: number; rx: number; opacity?: number }) {
  return <ellipse cx={cx} cy={cy} rx={rx} ry={rx * 0.1} fill={LINE} opacity={opacity} />;
}

/** The screen of a device: a quiet blue gray wash, the same in every picture. */
export function ScreenGradient({ id }: { id: string }) {
  return (
    <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stopColor="var(--dv-art-screen-top)" />
      <stop offset="1" stopColor="var(--dv-art-screen-bottom)" />
    </linearGradient>
  );
}

/** A small window on a screen: a title strip and a few gray text lines. */
export function MiniWindow({ x, y, w, h, lines = 3, accent = false }: { x: number; y: number; w: number; h: number; lines?: number; accent?: boolean }) {
  const gap = (h - 8) / (lines + 1);
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={2.5} fill={PAPER} />
      <rect x={x} y={y} width={w} height={5} rx={2.5} fill={SHADE} />
      {Array.from({ length: lines }, (_, i) => (
        <rect
          key={i}
          x={x + 4}
          y={y + 6 + gap * (i + 0.6)}
          width={(w - 8) * (i === 0 ? 0.7 : i % 2 ? 0.9 : 0.55)}
          height={2.2}
          rx={1.1}
          fill={accent && i === 0 ? ACCENT : MID}
        />
      ))}
    </g>
  );
}
