/**
 * The Nearby radar. Rings, a sweep that turns while a scan runs, the phone in
 * the middle, and a blip for every computer found, placed by its address so
 * the same computer always lands in the same spot.
 */
import { AnimatePresence, motion } from "motion/react";
import type { HostOs, Protocol } from "../api/contract";
import { LINE, PAPER, stroke } from "./common";
import { protocolColor } from "./ProtocolArt";

export interface Blip {
  key: string;
  protocol: Protocol;
  os: HostOs;
}

/** A stable angle and distance from a string. */
export function blipSpot(key: string): { angle: number; dist: number } {
  let h = 2166136261;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const u = (h >>> 0) / 4294967295;
  const v = ((h >>> 8) & 0xffff) / 0xffff;
  return { angle: u * Math.PI * 2, dist: 0.42 + v * 0.48 };
}

export function Radar({ blips, scanning, onBlip, className }: { blips: Blip[]; scanning: boolean; onBlip?: (key: string) => void; className?: string }) {
  const R = 140;
  const C = 150;
  return (
    <svg viewBox="0 0 300 300" className={className} role="img" aria-label={scanning ? "Looking for computers" : "Radar"}>
      <defs>
        <radialGradient id="radar-bg" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor="var(--dv-accent)" stopOpacity={0.22} />
          <stop offset="1" stopColor="var(--dv-accent)" stopOpacity={0.05} />
        </radialGradient>
        <linearGradient id="radar-sweep" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="var(--dv-accent)" stopOpacity={0} />
          <stop offset="1" stopColor="var(--dv-accent)" stopOpacity={0.55} />
        </linearGradient>
      </defs>
      <circle cx={C} cy={C} r={R} fill="url(#radar-bg)" stroke="var(--dv-accent)" strokeOpacity={0.35} strokeWidth={2} />
      {[0.33, 0.66].map((f) => (
        <circle key={f} cx={C} cy={C} r={R * f} fill="none" stroke="var(--dv-accent)" strokeOpacity={0.25} strokeWidth={2} strokeDasharray="4 8" />
      ))}
      {scanning && (
        <g className="dv-spin" style={{ transformOrigin: `${C}px ${C}px`, transformBox: "view-box" }}>
          <path d={`M${C} ${C} L${C + R} ${C} A${R} ${R} 0 0 0 ${C + R * Math.cos(-0.9)} ${C + R * Math.sin(-0.9)} Z`} fill="url(#radar-sweep)" />
          <path d={`M${C} ${C} L${C + R} ${C}`} stroke="var(--dv-accent)" strokeWidth={3} strokeLinecap="round" />
        </g>
      )}
      {scanning &&
        [0, 0.6, 1.2].map((d) => (
          <circle
            key={d}
            cx={C}
            cy={C}
            r={40}
            fill="none"
            stroke="var(--dv-accent)"
            strokeWidth={2}
            className="dv-pulse"
            style={{ animationDelay: `${d}s` }}
          />
        ))}
      {/* You are here. */}
      <g transform={`translate(${C - 15} ${C - 26})`}>
        <rect x="0" y="0" width="30" height="52" rx="7" fill={PAPER} {...stroke} />
        <rect x="4" y="7" width="22" height="38" rx="3" fill="var(--dv-accent)" />
        <rect x="11" y="2.5" width="8" height="2" rx="1" fill={LINE} />
      </g>
      <AnimatePresence>
        {blips.map((b) => {
          const { angle, dist } = blipSpot(b.key);
          const x = C + Math.cos(angle) * R * dist;
          const y = C + Math.sin(angle) * R * dist;
          return (
            <motion.g
              key={b.key}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0, opacity: 0 }}
              transition={{ type: "spring", stiffness: 420, damping: 18 }}
              style={{ originX: `${x}px`, originY: `${y}px`, cursor: onBlip ? "pointer" : undefined }}
              onClick={() => onBlip?.(b.key)}
            >
              <circle cx={x} cy={y} r={20} fill={protocolColor(b.protocol)} opacity={0.22} />
              <circle cx={x} cy={y} r={12} fill={protocolColor(b.protocol)} stroke={LINE} strokeWidth={2.5} />
              <circle cx={x - 3.5} cy={y - 3.5} r={3} fill="#fff" opacity={0.7} />
            </motion.g>
          );
        })}
      </AnimatePresence>
    </svg>
  );
}
