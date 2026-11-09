/**
 * The three ways to connect, as a small badge icon and as a larger scene for
 * the wizard's first step.
 *
 *   rdp       Windows Remote Desktop: a window with an arrow reaching in
 *   vnc       VNC screen sharing: a screen sending out waves
 *   boundary  a help code: a ticket with three groups of dots and a heart
 */
import type { Protocol } from "../api/contract";
import { Ground, LINE, PAPER, Sparkle, stroke, type ArtProps } from "./common";

export const PROTOCOL_LABEL: Record<Protocol, string> = {
  rdp: "Remote Desktop",
  vnc: "Screen sharing",
  boundary: "Boundary code",
};

export const PROTOCOL_TITLE: Record<Protocol, string> = {
  rdp: "Windows Remote Desktop",
  vnc: "VNC screen sharing",
  boundary: "Boundary code",
};

export const PROTOCOL_HINT: Record<Protocol, string> = {
  rdp: "For a Windows PC with Remote Desktop turned on. Usually at work or a home Pro PC.",
  vnc: "For a Mac, a Linux box or a Raspberry Pi with screen sharing on.",
  boundary: "For a computer running DeskVNC, anywhere. They give you a code.",
};

/** The protocol's colour, as a CSS variable. */
export function protocolColor(p: Protocol): string {
  return `var(--dv-${p})`;
}
export function protocolSoft(p: Protocol): string {
  return `var(--dv-${p}-soft)`;
}

/** A small icon on a coloured circle, for badges and lists. White strokes. */
export function ProtocolIcon({ protocol, size = 24, ...rest }: ArtProps & { protocol: Protocol }) {
  const s = { stroke: "#fff", strokeWidth: 2.2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, fill: "none" };
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} aria-hidden {...rest}>
      <circle cx="12" cy="12" r="12" fill={protocolColor(protocol)} />
      {protocol === "rdp" && (
        <g {...s}>
          <rect x="5.5" y="6.5" width="13" height="10" rx="1.8" />
          <path d="M5.5 9.5h13" />
          <path d="M9 19h6" />
          <path d="M10 13.2l2-1.8 2 1.8" />
        </g>
      )}
      {protocol === "vnc" && (
        <g {...s}>
          <rect x="7" y="8" width="10" height="7.5" rx="1.6" />
          <path d="M10 18.5h4" />
          <path d="M4.6 7.2a6 6 0 0 0 0 9.6M19.4 7.2a6 6 0 0 1 0 9.6" />
        </g>
      )}
      {protocol === "boundary" && (
        <g {...s}>
          <path d="M5 8.5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v1.5a2 2 0 0 0 0 4v1.5a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V14a2 2 0 0 0 0-4Z" />
          <path d="M9 12h.01M12 12h.01M15 12h.01" strokeWidth={2.8} />
        </g>
      )}
    </svg>
  );
}

/** A bigger picture for the wizard tiles: a phone reaching each kind of computer. */
export function ProtocolScene({ protocol, ...rest }: ArtProps & { protocol: Protocol }) {
  return (
    <svg viewBox="0 0 160 110" aria-hidden {...rest}>
      <circle cx="80" cy="56" r="50" fill={protocolSoft(protocol)} />
      {protocol === "rdp" && <RdpScene />}
      {protocol === "vnc" && <VncScene />}
      {protocol === "boundary" && <BoundaryScene />}
    </svg>
  );
}

function Phone({ x, y, screen }: { x: number; y: number; screen: string }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <rect x="0" y="0" width="30" height="54" rx="7" fill={PAPER} {...stroke} />
      <rect x="4" y="7" width="22" height="40" rx="3" fill={screen} />
      <rect x="11" y="3" width="8" height="2" rx="1" fill={LINE} />
    </g>
  );
}

function RdpScene() {
  return (
    <g>
      <Ground cx={80} cy={100} rx={56} />
      <rect x="58" y="22" width="84" height="58" rx="7" fill={PAPER} {...stroke} />
      <rect x="64" y="28" width="72" height="44" rx="3" fill="var(--dv-rdp)" />
      <rect x="64" y="28" width="72" height="44" rx="3" fill="#fff" opacity={0.15} />
      <rect x="72" y="35" width="30" height="20" rx="2" fill="#fff" />
      <rect x="72" y="35" width="30" height="5" rx="2" fill={LINE} opacity={0.25} />
      <rect x="106" y="44" width="22" height="20" rx="2" fill="#fff" opacity={0.85} />
      <rect x="86" y="66" width="28" height="4" rx="2" fill="#fff" opacity={0.9} />
      <path d="M92 80h16l3 12H89Z" fill={PAPER} {...stroke} />
      <Phone x={18} y={40} screen="var(--dv-rdp-soft)" />
      <path d="M50 62c6-10 10-16 18-20" fill="none" stroke="var(--dv-rdp)" strokeWidth={3} strokeDasharray="1 6" strokeLinecap="round" />
      <path d="M62 38l7 3-4 6" fill="none" stroke="var(--dv-rdp)" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round" />
    </g>
  );
}

function VncScene() {
  return (
    <g>
      <Ground cx={80} cy={100} rx={56} />
      <rect x="62" y="20" width="80" height="56" rx="7" fill={PAPER} {...stroke} />
      <rect x="68" y="26" width="68" height="42" rx="3" fill="var(--dv-vnc)" />
      <path d="M68 58q16-12 34-4t34-2v16H68Z" fill="#fff" opacity={0.45} />
      <circle cx="120" cy="38" r="6" fill="#fff" opacity={0.9} />
      <path d="M94 76h16l3 14H91Z" fill={PAPER} {...stroke} />
      <Phone x={16} y={38} screen="var(--dv-vnc)" />
      <path d="M20 62q11-6 22 0" fill="none" stroke="#fff" strokeWidth={2} opacity={0.7} />
      {/* Waves going from the computer to the phone. */}
      {[0, 1, 2].map((i) => (
        <path
          key={i}
          d={`M${56 - i * 6} ${44 - i * 4}q${-6 - i * 2} ${10 + i * 4} 0 ${20 + i * 8}`}
          fill="none"
          stroke="var(--dv-vnc)"
          strokeWidth={3}
          strokeLinecap="round"
          opacity={1 - i * 0.25}
        />
      ))}
    </g>
  );
}

function BoundaryScene() {
  return (
    <g>
      <Ground cx={80} cy={100} rx={56} />
      {/* A code ticket floating between two friendly speech bubbles. */}
      <g transform="rotate(-6 80 56)">
        <path
          d="M34 36a6 6 0 0 1 6-6h80a6 6 0 0 1 6 6v8a8 8 0 0 0 0 16v8a6 6 0 0 1-6 6H40a6 6 0 0 1-6-6v-8a8 8 0 0 0 0-16Z"
          fill="var(--dv-boundary)"
          {...stroke}
        />
        <path d="M54 32v42" stroke="#fff" strokeWidth={2} strokeDasharray="3 4" opacity={0.7} />
        {[0, 1, 2].map((g) => (
          <g key={g}>
            {[0, 1, 2, 3].map((d) => (
              <circle key={d} cx={64 + g * 20 + d * 4.5} cy={52} r={1.8} fill="#fff" />
            ))}
          </g>
        ))}
        <path d="M44 48c-2.5-3-7-1-5.5 2.5L44 56l4.5-5.5C50 47 46.5 45 44 48Z" fill="#fff" />
      </g>
      <Sparkle x={130} y={24} r={7} />
      <Sparkle x={28} y={84} r={5} fill="#ff8fb0" />
      <Sparkle x={138} y={86} r={4} fill="#7cd8ff" />
    </g>
  );
}
