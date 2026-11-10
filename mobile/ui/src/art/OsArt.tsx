/**
 * A plain picture of each kind of computer, used when there is no live
 * screenshot yet. Gray line work, a blue gray screen, one window. The kind
 * shows in the shape and the furniture (a taskbar, a menu bar and dock, a
 * terminal, a board), never in a logo or a colour.
 */
import type { HostOs } from "../api/contract";
import { ACCENT, BACKDROP, Ground, LINE, MID, MiniWindow, PAPER, SHADE, ScreenGradient, stroke, type ArtProps } from "./common";

interface Props extends ArtProps {
  os: HostOs | "demo";
  /** Draw the soft backdrop circle behind the device. */
  backdrop?: boolean;
}

export function OsArt({ os, backdrop = true, size, ...rest }: Props) {
  const id = `os-${os}`;
  return (
    <svg viewBox="0 0 160 120" width={size} role="img" aria-label={label(os)} {...rest}>
      <defs>
        <ScreenGradient id={`${id}-screen`} />
      </defs>
      {backdrop && <circle cx="80" cy="60" r="54" fill={BACKDROP} />}
      {os === "windows" && <Windows id={id} />}
      {os === "mac" && <Mac id={id} />}
      {os === "linux" && <Linux />}
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

/** A monitor on a stand, with whatever is on its screen drawn by the caller. */
function Monitor({ id, children, chin = false }: { id: string; children?: React.ReactNode; chin?: boolean }) {
  return (
    <g>
      <Ground cx={80} cy={108} rx={38} />
      <path d="M70 94h20l3 12H67Z" fill={PAPER} {...stroke} />
      <rect x="20" y="20" width="120" height={chin ? 80 : 76} rx="6" fill={PAPER} {...stroke} />
      <rect x="26" y="26" width="108" height="62" rx="2" fill={`url(#${id}-screen)`} />
      {children}
    </g>
  );
}

function Windows({ id }: { id: string }) {
  return (
    <Monitor id={id}>
      <MiniWindow x={36} y={34} w={48} h={34} lines={3} accent />
      <MiniWindow x={78} y={44} w={44} h={30} lines={2} />
      {/* A taskbar along the bottom, a few square buttons in the middle. */}
      <rect x="26" y="81" width="108" height="7" fill={PAPER} opacity={0.85} />
      {[0, 1, 2, 3].map((i) => (
        <rect key={i} x={66 + i * 8} y={83} width={5} height={3} rx={1} fill={i === 0 ? ACCENT : MID} />
      ))}
    </Monitor>
  );
}

function Mac({ id }: { id: string }) {
  return (
    <Monitor id={id} chin>
      {/* Menu bar, a window, and a dock. */}
      <rect x="26" y="26" width="108" height="5" fill={PAPER} opacity={0.85} />
      <MiniWindow x={42} y={37} w={60} h={34} lines={3} accent />
      <rect x="58" y="77" width="44" height="7" rx="3" fill={PAPER} opacity={0.85} />
      {[0, 1, 2, 3, 4].map((i) => (
        <rect key={i} x={61 + i * 8} y={79} width={5} height={3} rx={1} fill={i === 2 ? ACCENT : MID} />
      ))}
      <path d="M21 88h118" stroke={LINE} strokeWidth={1.5} opacity={0.5} />
    </Monitor>
  );
}

function Linux() {
  return (
    <g>
      <Ground cx={80} cy={108} rx={38} />
      <path d="M70 94h20l3 12H67Z" fill={PAPER} {...stroke} />
      <rect x="20" y="20" width="120" height="76" rx="6" fill={PAPER} {...stroke} />
      <rect x="26" y="26" width="108" height="62" rx="2" fill="#1f242d" />
      <path d="M36 40l6 4.5-6 4.5" fill="none" stroke={ACCENT} strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round" />
      <rect x="46" y="47" width="10" height="2.6" rx="1.3" fill={ACCENT} className="dv-blink" />
      <rect x="36" y="58" width="56" height="2.4" rx="1.2" fill="#ffffff" opacity={0.35} />
      <rect x="36" y="65" width="40" height="2.4" rx="1.2" fill="#ffffff" opacity={0.25} />
      <rect x="36" y="72" width="64" height="2.4" rx="1.2" fill="#ffffff" opacity={0.25} />
    </g>
  );
}

function Raspberry() {
  return (
    <g>
      <Ground cx={80} cy={104} rx={46} />
      {/* A small single board computer, seen from above. */}
      <rect x="26" y="36" width="108" height="62" rx="5" fill={PAPER} {...stroke} />
      {Array.from({ length: 13 }, (_, i) => (
        <rect key={i} x={40 + i * 6.6} y={40} width={3.4} height={5} rx={0.8} fill={MID} />
      ))}
      <rect x="44" y="56" width="26" height="24" rx="2.5" fill={SHADE} stroke={LINE} strokeWidth={1.5} />
      <rect x="51" y="63" width="12" height="10" rx="1.5" fill={ACCENT} />
      <rect x="78" y="62" width="18" height="12" rx="2" fill={SHADE} stroke={LINE} strokeWidth={1.5} />
      <rect x="106" y="52" width="24" height="16" rx="2" fill={SHADE} stroke={LINE} strokeWidth={1.5} />
      <rect x="106" y="74" width="24" height="16" rx="2" fill={SHADE} stroke={LINE} strokeWidth={1.5} />
      <circle cx="33" cy="43" r="2.2" fill="none" stroke={LINE} strokeWidth={1.5} />
      <circle cx="33" cy="91" r="2.2" fill="none" stroke={LINE} strokeWidth={1.5} />
    </g>
  );
}

function Unknown({ id }: { id: string }) {
  return (
    <Monitor id={id}>
      <MiniWindow x={50} y={38} w={60} h={38} lines={3} />
    </Monitor>
  );
}

function Demo({ id }: { id: string }) {
  return (
    <Monitor id={id}>
      <MiniWindow x={34} y={34} w={44} h={30} lines={2} />
      <circle cx="98" cy="58" r="13" fill={PAPER} />
      <path d="M94 51.5v13l10.5-6.5Z" fill={ACCENT} />
    </Monitor>
  );
}
