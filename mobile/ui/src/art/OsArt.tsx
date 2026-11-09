/**
 * A friendly picture of each kind of computer, used when there is no live
 * screenshot yet. Drawn from scratch in a generic style: no real logos.
 */
import type { HostOs } from "../api/contract";
import { swatch } from "../theme/palette";
import { Ground, LINE, PAPER, Sparkle, stroke, type ArtProps } from "./common";

interface Props extends ArtProps {
  os: HostOs | "demo";
  /** A palette key from theme/palette.ts, tints the wallpaper. */
  color?: string;
  /** Draw the backdrop blob behind the device. */
  backdrop?: boolean;
}

export function OsArt({ os, color, backdrop = true, size, ...rest }: Props) {
  const sw = swatch(color);
  const id = `os-${os}-${sw.key}`;
  return (
    <svg viewBox="0 0 160 120" width={size} role="img" aria-label={label(os)} {...rest}>
      <defs>
        <linearGradient id={`${id}-sky`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={sw.main} />
          <stop offset="1" stopColor={sw.soft} />
        </linearGradient>
      </defs>
      {backdrop && <path d="M22 70c-6-30 22-52 56-54 34-2 66 12 66 46 0 34-30 46-64 46S28 100 22 70Z" fill={sw.soft} opacity={0.9} />}
      {os === "windows" && <Windows id={id} />}
      {os === "mac" && <Mac id={id} />}
      {os === "linux" && <Linux id={id} />}
      {os === "raspberry" && <Raspberry />}
      {os === "unknown" && <Unknown id={id} />}
      {os === "demo" && <Demo id={id} />}
    </svg>
  );
}

function label(os: Props["os"]): string {
  switch (os) {
    case "windows":
      return "A Windows PC";
    case "mac":
      return "A Mac";
    case "linux":
      return "A Linux computer";
    case "raspberry":
      return "A Raspberry Pi";
    case "demo":
      return "The demo computer";
    default:
      return "A computer";
  }
}

function Hills({ x, y, w, h }: { x: number; y: number; w: number; h: number }) {
  return (
    <g>
      <path d={`M${x} ${y + h * 0.72} q${w * 0.25} ${-h * 0.3} ${w * 0.5} ${-h * 0.08} t${w * 0.5} ${-h * 0.06} V${y + h} H${x}Z`} fill="#ffffff" opacity={0.55} />
      <path d={`M${x} ${y + h * 0.86} q${w * 0.3} ${-h * 0.22} ${w * 0.6} ${-h * 0.04} t${w * 0.4} ${-h * 0.1} V${y + h} H${x}Z`} fill="#ffffff" opacity={0.8} />
    </g>
  );
}

function Windows({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={108} rx={36} />
      <path d="M70 92h20l4 14H66Z" fill={PAPER} {...stroke} />
      <rect x="22" y="22" width="116" height="74" rx="9" fill={PAPER} {...stroke} />
      <rect x="29" y="29" width="102" height="57" rx="4" fill={`url(#${id}-sky)`} />
      <Hills x={29} y={29} w={102} h={57} />
      {/* A floating bar with four little app tiles in the middle. */}
      <rect x="52" y="76" width="56" height="8" rx="4" fill="#ffffff" opacity={0.9} />
      {["#2f78f0", "#20b26b", "#ffc145", "#f0508c"].map((c, i) => (
        <rect key={c} x={60 + i * 11} y={78} width={6} height={4} rx={1.5} fill={c} />
      ))}
      <rect x="40" y="38" width="38" height="26" rx="3" fill="#ffffff" opacity={0.95} />
      <rect x="44" y="44" width="22" height="3" rx="1.5" fill={LINE} opacity={0.3} />
      <rect x="44" y="50" width="28" height="3" rx="1.5" fill={LINE} opacity={0.2} />
      <rect x="44" y="56" width="16" height="3" rx="1.5" fill={LINE} opacity={0.2} />
    </g>
  );
}

function Mac({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={108} rx={34} />
      <path d="M68 94h24l3 12H65Z" fill={PAPER} {...stroke} />
      <rect x="20" y="18" width="120" height="80" rx="10" fill={PAPER} {...stroke} />
      <rect x="27" y="25" width="106" height="58" rx="4" fill={`url(#${id}-sky)`} />
      <Hills x={27} y={25} w={106} h={58} />
      <rect x="27" y="25" width="106" height="6" fill="#ffffff" opacity={0.7} />
      <circle cx="32" cy="28" r="1.6" fill={LINE} />
      <rect x="54" y="72" width="52" height="9" rx="4.5" fill="#ffffff" opacity={0.75} />
      {["#ff8a65", "#ffc145", "#4fc3f7", "#81c784", "#ba68c8"].map((c, i) => (
        <rect key={c} x={58 + i * 9.5} y={74} width={6.5} height={5} rx={1.6} fill={c} />
      ))}
      {/* The chin, with a little face that suits a friendly app. */}
      <path d="M21 83h118v5a10 10 0 0 1-10 10H31a10 10 0 0 1-10-10Z" fill="#e9e5f7" {...stroke} />
      <circle cx="80" cy="90.5" r="2.4" fill={LINE} opacity={0.5} />
    </g>
  );
}

function Linux({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={108} rx={36} />
      <path d="M70 92h20l4 14H66Z" fill={PAPER} {...stroke} />
      <rect x="22" y="26" width="116" height="70" rx="9" fill={PAPER} {...stroke} />
      <rect x="29" y="33" width="102" height="53" rx="4" fill="#232a40" />
      <rect x="29" y="33" width="102" height="53" rx="4" fill={`url(#${id}-sky)`} opacity={0.25} />
      <path d="M38 46l8 6-8 6" fill="none" stroke="#3ddc8f" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round" />
      <rect x="50" y="56" width="14" height="3.5" rx="1.75" fill="#3ddc8f" className="dv-blink" />
      <rect x="38" y="66" width="44" height="3" rx="1.5" fill="#ffffff" opacity={0.35} />
      <rect x="38" y="73" width="30" height="3" rx="1.5" fill="#ffffff" opacity={0.25} />
      {/* A small penguin friend sitting on the corner of the screen. */}
      <g transform="translate(104 4)">
        <ellipse cx="14" cy="22" rx="11" ry="13" fill="#2b2d42" {...stroke} />
        <ellipse cx="14" cy="25" rx="7" ry="9" fill="#ffffff" />
        <circle cx="10.5" cy="15" r="2.6" fill="#ffffff" />
        <circle cx="17.5" cy="15" r="2.6" fill="#ffffff" />
        <circle cx="11" cy="15.4" r="1.2" fill={LINE} />
        <circle cx="17" cy="15.4" r="1.2" fill={LINE} />
        <path d="M11 19.5l3 2.6 3-2.6Z" fill="#ffb02e" stroke={LINE} strokeWidth={1.4} strokeLinejoin="round" />
        <path d="M6 33.5h6M16 33.5h6" stroke="#ffb02e" strokeWidth={3.4} strokeLinecap="round" />
      </g>
    </g>
  );
}

function Raspberry() {
  return (
    <g>
      <Ground cx={80} cy={106} rx={44} />
      {/* A little green board. */}
      <rect x="24" y="44" width="112" height="56" rx="7" fill="#3fbf5f" {...stroke} />
      {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((i) => (
        <rect key={i} x={36 + i * 7} y={48} width={3.6} height={6} rx={1} fill="#ffd36b" />
      ))}
      <rect x="44" y="64" width="26" height="22" rx="3" fill="#2b2d42" />
      <rect x="78" y="70" width="18" height="12" rx="2" fill="#2b2d42" opacity={0.85} />
      <rect x="104" y="60" width="26" height="16" rx="2" fill="#c9d1dc" stroke={LINE} strokeWidth={2} />
      <rect x="104" y="80" width="26" height="14" rx="2" fill="#c9d1dc" stroke={LINE} strokeWidth={2} />
      <circle cx="31" cy="51" r="2.5" fill={PAPER} stroke={LINE} strokeWidth={1.5} />
      <circle cx="31" cy="93" r="2.5" fill={PAPER} stroke={LINE} strokeWidth={1.5} />
      {/* A raspberry sitting on top, with leaves and a smile. */}
      <g transform="translate(62 2)" className="dv-float">
        <path d="M18 8c-6-6-14-4-15 1 6 0 10 2 15 5 5-3 9-5 15-5-1-5-9-7-15-1Z" fill="#3fa45b" {...stroke} />
        <path d="M18 12c12 0 17 9 15 18-2 10-9 16-15 16S5 40 3 30C1 21 6 12 18 12Z" fill="#e8436f" {...stroke} />
        {[
          [11, 20],
          [18, 18],
          [25, 20],
          [8, 28],
          [28, 28],
          [12, 36],
          [24, 36],
        ].map(([x, y]) => (
          <circle key={`${x}-${y}`} cx={x} cy={y} r={2.3} fill="#ff8fb0" />
        ))}
        <circle cx="14" cy="27" r="1.6" fill={LINE} />
        <circle cx="22" cy="27" r="1.6" fill={LINE} />
        <path d="M15 31.5q3 2.5 6 0" fill="none" stroke={LINE} strokeWidth={1.6} strokeLinecap="round" />
      </g>
    </g>
  );
}

function Unknown({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={108} rx={36} />
      <path d="M70 92h20l4 14H66Z" fill={PAPER} {...stroke} />
      <rect x="22" y="22" width="116" height="74" rx="9" fill={PAPER} {...stroke} />
      <rect x="29" y="29" width="102" height="57" rx="4" fill={`url(#${id}-sky)`} />
      <circle cx="68" cy="52" r="3.4" fill={LINE} />
      <circle cx="92" cy="52" r="3.4" fill={LINE} />
      <path d="M68 64q12 10 24 0" fill="none" stroke={LINE} strokeWidth={3.2} strokeLinecap="round" />
      <circle cx="60" cy="61" r="4" fill="#ff8fb0" opacity={0.6} />
      <circle cx="100" cy="61" r="4" fill="#ff8fb0" opacity={0.6} />
    </g>
  );
}

function Demo({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={108} rx={36} />
      <path d="M70 92h20l4 14H66Z" fill={PAPER} {...stroke} />
      <rect x="22" y="22" width="116" height="74" rx="9" fill={PAPER} {...stroke} />
      <rect x="29" y="29" width="102" height="57" rx="4" fill={`url(#${id}-sky)`} />
      <Hills x={29} y={29} w={102} h={57} />
      <circle cx="80" cy="55" r="15" fill="#ffffff" {...stroke} />
      <path d="M75 47.5v15l12-7.5Z" fill="#7c5cff" stroke={LINE} strokeWidth={2.2} strokeLinejoin="round" />
      <Sparkle x={30} y={20} r={7} />
      <Sparkle x={140} y={34} r={5} fill="#7cd8ff" />
      <Sparkle x={134} y={98} r={4} fill="#ff8fb0" />
    </g>
  );
}
