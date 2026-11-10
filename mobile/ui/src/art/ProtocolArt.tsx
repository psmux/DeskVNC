/**
 * The three ways to connect, as a small badge icon and as a larger scene for
 * the wizard's first step. All three share the accent: the drawing tells
 * them apart, not the colour.
 *
 *   rdp       Windows Remote Desktop: a window with an arrow reaching in
 *   vnc       VNC screen sharing: a screen sending out waves
 *   boundary  a help code: a ticket with three groups of digits
 */
import type { Protocol } from "../api/contract";
import { ACCENT, ACCENT_SOFT, BACKDROP, Ground, LINE, MID, MiniWindow, PAPER, ScreenGradient, stroke, type ArtProps } from "./common";

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

/** The protocol's colour, as a CSS variable. The accent, for all three. */
export function protocolColor(p: Protocol): string {
  return `var(--dv-${p})`;
}
export function protocolSoft(p: Protocol): string {
  return `var(--dv-${p}-soft)`;
}

/** A small icon on an accent circle, for badges and lists. */
export function ProtocolIcon({ protocol, size = 24, ...rest }: ArtProps & { protocol: Protocol }) {
  const s = { stroke: "var(--dv-accent-ink)", strokeWidth: 2.2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, fill: "none" };
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
  const id = `proto-${protocol}`;
  return (
    <svg viewBox="0 0 160 110" aria-hidden {...rest}>
      <defs>
        <ScreenGradient id={`${id}-screen`} />
      </defs>
      <circle cx="80" cy="56" r="50" fill={BACKDROP} />
      {protocol === "rdp" && <RdpScene id={id} />}
      {protocol === "vnc" && <VncScene id={id} />}
      {protocol === "boundary" && <BoundaryScene />}
    </svg>
  );
}

function Phone({ x, y, screen }: { x: number; y: number; screen: string }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <rect x="0" y="0" width="30" height="54" rx="6" fill={PAPER} {...stroke} />
      <rect x="4" y="7" width="22" height="40" rx="2.5" fill={screen} />
      <rect x="11" y="3" width="8" height="1.6" rx="0.8" fill={LINE} opacity={0.6} />
    </g>
  );
}

function Computer({ id, x, y }: { id: string; x: number; y: number }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <path d="M34 58h16l3 12H31Z" fill={PAPER} {...stroke} />
      <rect x="0" y="0" width="84" height="58" rx="5" fill={PAPER} {...stroke} />
      <rect x="5" y="5" width="74" height="46" rx="2" fill={`url(#${id}-screen)`} />
    </g>
  );
}

function RdpScene({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={100} rx={56} />
      <Computer id={id} x={58} y={20} />
      <MiniWindow x={68} y={30} w={36} h={26} lines={2} accent />
      <MiniWindow x={100} y={40} w={28} h={22} lines={2} />
      <Phone x={18} y={40} screen={ACCENT_SOFT} />
      <rect x="25" y="56" width="16" height="11" rx="1.5" fill={PAPER} stroke={MID} strokeWidth={1} />
      <path d="M50 62c6-10 10-16 18-20" fill="none" stroke={ACCENT} strokeWidth={2.4} strokeDasharray="1 5" strokeLinecap="round" />
      <path d="M62 38.5l6.5 3-3.5 6" fill="none" stroke={ACCENT} strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round" />
    </g>
  );
}

function VncScene({ id }: { id: string }) {
  return (
    <g>
      <Ground cx={80} cy={100} rx={56} />
      <Computer id={id} x={60} y={20} />
      <MiniWindow x={74} y={32} w={46} h={28} lines={3} accent />
      <Phone x={16} y={38} screen={ACCENT_SOFT} />
      <rect x="22" y="54" width="18" height="12" rx="1.5" fill={PAPER} stroke={MID} strokeWidth={1} />
      {/* Waves going from the computer to the phone. */}
      {[0, 1, 2].map((i) => (
        <path
          key={i}
          d={`M${54 - i * 5} ${46 - i * 4}q${-5 - i * 2} ${9 + i * 4} 0 ${18 + i * 8}`}
          fill="none"
          stroke={ACCENT}
          strokeWidth={2.4}
          strokeLinecap="round"
          opacity={1 - i * 0.3}
        />
      ))}
    </g>
  );
}

function BoundaryScene() {
  return (
    <g>
      <Ground cx={80} cy={100} rx={56} />
      {/* A code ticket: a notch on each side, a tear line, three groups of digits. */}
      <path
        d="M30 34a5 5 0 0 1 5-5h90a5 5 0 0 1 5 5v12a8 8 0 0 0 0 16v12a5 5 0 0 1-5 5H35a5 5 0 0 1-5-5V62a8 8 0 0 0 0-16Z"
        fill={PAPER}
        {...stroke}
      />
      <path d="M52 32v44" stroke={MID} strokeWidth={1.5} strokeDasharray="3 3" />
      <rect x="36" y="46" width="10" height="16" rx="2" fill={ACCENT} />
      {[0, 1, 2].map((g) => (
        <g key={g}>
          {[0, 1, 2, 3].map((d) => (
            <rect key={d} x={60 + g * 22 + d * 4.6} y={50} width={3.4} height={8} rx={1} fill={g === 0 ? ACCENT : MID} />
          ))}
        </g>
      ))}
    </g>
  );
}
