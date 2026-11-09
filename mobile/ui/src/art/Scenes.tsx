/**
 * The bigger illustrations: onboarding, empty states and the help steps.
 * Same line weight and palette as the OS artwork.
 */
import { Ground, LINE, PAPER, SHADE, Sparkle, stroke, type ArtProps } from "./common";

function PhoneBody({ x, y, w = 44, h = 80, children }: { x: number; y: number; w?: number; h?: number; children?: React.ReactNode }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <rect x="0" y="0" width={w} height={h} rx="9" fill={PAPER} {...stroke} />
      <rect x="4.5" y="9" width={w - 9} height={h - 18} rx="4" fill={SHADE} />
      <rect x={w / 2 - 6} y="3.5" width="12" height="2.6" rx="1.3" fill={LINE} />
      {children}
    </g>
  );
}

function Monitor({ x, y, w, h, screen, children }: { x: number; y: number; w: number; h: number; screen: string; children?: React.ReactNode }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <path d={`M${w / 2 - 12} ${h}h24l4 14h-32Z`} fill={PAPER} {...stroke} />
      <rect x="0" y="0" width={w} height={h} rx="8" fill={PAPER} {...stroke} />
      <rect x="6" y="6" width={w - 12} height={h - 12} rx="3" fill={screen} />
      {children}
    </g>
  );
}

/** Onboarding 1: a phone reaching across to a desktop. */
export function SceneReach(props: ArtProps) {
  return (
    <svg viewBox="0 0 240 180" aria-hidden {...props}>
      <circle cx="120" cy="92" r="78" fill="var(--dv-accent-soft)" />
      <Ground cx={120} cy={166} rx={90} />
      <Monitor x={104} y={36} w={112} h={78} screen="var(--dv-rdp)">
        <path d="M6 58q26-18 50-6t50-4v24H6Z" fill="#fff" opacity={0.4} />
        <rect x="16" y="16" width="44" height="30" rx="3" fill="#fff" />
        <rect x="16" y="16" width="44" height="6" rx="3" fill={LINE} opacity={0.2} />
        <rect x="21" y="28" width="28" height="3" rx="1.5" fill={LINE} opacity={0.3} />
        <rect x="21" y="35" width="20" height="3" rx="1.5" fill={LINE} opacity={0.2} />
        <circle cx="86" cy="24" r="8" fill="#ffd36b" />
      </Monitor>
      <g className="dv-float">
        <PhoneBody x={30} y={64} w={52} h={92}>
          <rect x="4.5" y="9" width="43" height="74" rx="4" fill="var(--dv-rdp)" />
          <rect x="9" y="22" width="22" height="16" rx="2" fill="#fff" />
          <path d="M4.5 66q12-8 22-3t21-2v22h-43Z" fill="#fff" opacity={0.4} />
          {/* A finger tapping the little screen. */}
          <circle cx="34" cy="52" r="7" fill="#fff" opacity={0.5} className="dv-pulse" />
          <circle cx="34" cy="52" r="4" fill="#fff" />
        </PhoneBody>
      </g>
      <path d="M86 92C98 74 108 62 122 54" fill="none" stroke="var(--dv-accent)" strokeWidth={4} strokeDasharray="1 9" strokeLinecap="round" />
      <Sparkle x={98} y={40} r={8} />
      <Sparkle x={222} y={30} r={6} fill="#7cd8ff" />
      <Sparkle x={34} y={40} r={5} fill="#ff8fb0" />
    </svg>
  );
}

/** Onboarding 2: the three ways, as three cards fanned out over the phone. */
export function SceneThreeWays(props: ArtProps) {
  const card = (x: number, y: number, rot: number, color: string, kind: "rdp" | "vnc" | "boundary") => (
    <g transform={`rotate(${rot} ${x + 32} ${y + 40})`}>
      <rect x={x} y={y} width="64" height="80" rx="12" fill={PAPER} {...stroke} />
      <rect x={x + 6} y={y + 6} width="52" height="40" rx="7" fill={color} />
      {kind === "rdp" && (
        <g transform={`translate(${x + 16} ${y + 12})`}>
          <rect x="0" y="0" width="32" height="22" rx="3" fill="#fff" />
          <rect x="0" y="0" width="32" height="6" rx="3" fill={LINE} opacity={0.2} />
          <path d="M12 26h8" stroke="#fff" strokeWidth={3} strokeLinecap="round" />
        </g>
      )}
      {kind === "vnc" && (
        <g transform={`translate(${x + 32} ${y + 26})`} fill="none" stroke="#fff" strokeWidth={3} strokeLinecap="round">
          <rect x="-9" y="-7" width="18" height="13" rx="2" fill="#fff" stroke="none" />
          <path d="M-15 -10a14 14 0 0 0 0 20M15 -10a14 14 0 0 1 0 20" />
        </g>
      )}
      {kind === "boundary" && (
        <g transform={`translate(${x + 32} ${y + 26})`} fill="#fff">
          {[-12, -4, 4, 12].map((dx) => (
            <circle key={dx} cx={dx} cy={-4} r={3} />
          ))}
          <path d="M0 13c-6-4-9-7-9-10a4.5 4.5 0 0 1 9-1 4.5 4.5 0 0 1 9 1c0 3-3 6-9 10Z" opacity={0.9} />
        </g>
      )}
      <rect x={x + 10} y={y + 54} width="36" height="5" rx="2.5" fill={LINE} opacity={0.75} />
      <rect x={x + 10} y={y + 64} width="26" height="4" rx="2" fill={LINE} opacity={0.25} />
    </g>
  );
  return (
    <svg viewBox="0 0 240 180" aria-hidden {...props}>
      <circle cx="120" cy="92" r="78" fill="var(--dv-boundary-soft)" />
      <Ground cx={120} cy={166} rx={90} />
      {card(28, 56, -14, "var(--dv-rdp)", "rdp")}
      {card(146, 56, 14, "var(--dv-vnc)", "vnc")}
      <g className="dv-float">{card(88, 36, 0, "var(--dv-boundary)", "boundary")}</g>
      <Sparkle x={42} y={34} r={7} />
      <Sparkle x={206} y={28} r={6} fill="#ff8fb0" />
    </svg>
  );
}

/** Onboarding 3: safety. A shield, and a screen asking the other person first. */
export function SceneSafety(props: ArtProps) {
  return (
    <svg viewBox="0 0 240 180" aria-hidden {...props}>
      <circle cx="120" cy="92" r="78" fill="var(--dv-ok-soft)" />
      <Ground cx={120} cy={166} rx={90} />
      <Monitor x={92} y={34} w={120} h={82} screen="var(--dv-vnc-soft)">
        <rect x="22" y="16" width="76" height="50" rx="7" fill={PAPER} {...stroke} />
        <circle cx="38" cy="33" r="7" fill="#ffb4a2" stroke={LINE} strokeWidth={2} />
        <path d="M28 48a10 8 0 0 1 20 0" fill="#7c5cff" stroke={LINE} strokeWidth={2} />
        <rect x="52" y="27" width="36" height="4" rx="2" fill={LINE} opacity={0.6} />
        <rect x="52" y="35" width="26" height="3.5" rx="1.75" fill={LINE} opacity={0.25} />
        <rect x="52" y="45" width="18" height="11" rx="5.5" fill="var(--dv-ok)" />
        <rect x="73" y="45" width="18" height="11" rx="5.5" fill={SHADE} />
        <path d="M57 50.5l2.5 2.5 4.5-4.5" fill="none" stroke="#fff" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
      </Monitor>
      <g className="dv-float">
        <path d="M58 46l34 12v26c0 22-16 36-34 44-18-8-34-22-34-44V58Z" fill="var(--dv-ok)" {...stroke} />
        <path d="M58 56l24 9v19c0 15-11 26-24 32Z" fill="#fff" opacity={0.25} />
        <path d="M44 86l10 10 20-22" fill="none" stroke="#fff" strokeWidth={6} strokeLinecap="round" strokeLinejoin="round" />
      </g>
      <Sparkle x={210} y={26} r={7} />
      <Sparkle x={30} y={36} r={5} fill="#7cd8ff" />
    </svg>
  );
}

/** Empty library: a cosy desk waiting for its first computer. */
export function SceneEmptyDesk(props: ArtProps) {
  return (
    <svg viewBox="0 0 240 170" aria-hidden {...props}>
      <circle cx="120" cy="86" r="74" fill="var(--dv-accent-soft)" />
      <rect x="24" y="128" width="192" height="10" rx="5" fill={PAPER} {...stroke} />
      <path d="M40 138v22M200 138v22" {...stroke} />
      {/* A screen drawn in dashes, with a plus: the computer to add. */}
      <rect x="74" y="44" width="92" height="64" rx="9" fill={PAPER} stroke="var(--dv-accent)" strokeWidth={3} strokeDasharray="7 7" />
      <circle cx="120" cy="76" r="14" fill="var(--dv-accent)" className="dv-float" />
      <path d="M120 69v14M113 76h14" stroke="#fff" strokeWidth={3.5} strokeLinecap="round" />
      <path d="M110 108h20l3 20h-26Z" fill={PAPER} stroke="var(--dv-accent)" strokeWidth={3} strokeDasharray="5 5" />
      {/* Plant. */}
      <path d="M44 128l-4-24h28l-4 24Z" fill="#f97a3c" {...stroke} />
      <path d="M54 104c-2-12-12-18-20-18 0 10 8 16 20 18Zm0 0c2-14 10-22 20-22 0 12-8 20-20 22Zm0 0c0-12 0-20 0-26" fill="#3fbf5f" {...stroke} />
      {/* Mug. */}
      <rect x="176" y="106" width="22" height="22" rx="4" fill="#ffc145" {...stroke} />
      <path d="M198 111a6 6 0 0 1 0 12" fill="none" {...stroke} />
      <path d="M182 98q3-4 0-8M190 98q3-4 0-8" fill="none" stroke={LINE} strokeWidth={2.4} strokeLinecap="round" opacity={0.5} />
      <Sparkle x={196} y={40} r={7} />
      <Sparkle x={42} y={48} r={5} fill="#ff8fb0" />
    </svg>
  );
}

/** A scan that found nothing: a sleepy radar dish. */
export function SceneSleepyRadar(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="78" r="62" fill="var(--dv-surface-2)" />
      <Ground cx={100} cy={136} rx={60} />
      <path d="M86 128l14-34 14 34Z" fill={PAPER} {...stroke} />
      <path d="M52 76a48 48 0 0 0 80-34Z" fill={PAPER} {...stroke} />
      <path d="M92 59l20-20" {...stroke} />
      <circle cx="114" cy="37" r="5" fill="var(--dv-accent)" {...stroke} />
      <path d="M78 66q4 3 8 0M98 66q4 3 8 0" fill="none" stroke={LINE} strokeWidth={2.4} strokeLinecap="round" />
      <text x="140" y="42" fontSize="18" fontWeight="800" fill="var(--dv-ink-dim)" fontFamily="inherit">z</text>
      <text x="152" y="28" fontSize="14" fontWeight="800" fill="var(--dv-ink-dim)" fontFamily="inherit" opacity={0.7}>z</text>
      <text x="162" y="17" fontSize="11" fontWeight="800" fill="var(--dv-ink-dim)" fontFamily="inherit" opacity={0.5}>z</text>
    </svg>
  );
}

/** Help step 1: looking the code up. */
export function SceneLookup(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="76" r="62" fill="var(--dv-boundary-soft)" />
      <Ground cx={100} cy={136} rx={60} />
      <rect x="40" y="50" width="110" height="56" rx="10" fill="var(--dv-boundary)" {...stroke} />
      {[0, 1, 2].map((g) =>
        [0, 1, 2, 3].map((d) => <circle key={`${g}${d}`} cx={56 + g * 32 + d * 6} cy={78} r={2.4} fill="#fff" />),
      )}
      <g className="dv-float">
        <circle cx="128" cy="66" r="24" fill="#ffffff" fillOpacity={0.55} {...stroke} strokeWidth={5} />
        <path d="M145 83l18 18" {...stroke} strokeWidth={8} />
        <path d="M116 56a14 14 0 0 1 12-4" fill="none" stroke="#fff" strokeWidth={3} strokeLinecap="round" />
      </g>
    </svg>
  );
}

/** Help step 2: the other person approving on their screen. */
export function SceneApprove(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="76" r="62" fill="var(--dv-accent-soft)" />
      <Ground cx={100} cy={136} rx={60} />
      <Monitor x={40} y={30} w={120} h={82} screen="var(--dv-vnc-soft)">
        <rect x="18" y="14" width="84" height="54" rx="8" fill={PAPER} {...stroke} />
        <circle cx="38" cy="34" r="9" fill="#ffd0b5" stroke={LINE} strokeWidth={2} />
        <path d="M30 31q8-8 16 0" fill="#6b4226" />
        <path d="M24 56a14 10 0 0 1 28 0" fill="var(--dv-boundary)" stroke={LINE} strokeWidth={2} />
        <rect x="58" y="26" width="34" height="4.5" rx="2.25" fill={LINE} opacity={0.6} />
        <rect x="58" y="36" width="24" height="3.5" rx="1.75" fill={LINE} opacity={0.25} />
        <rect x="58" y="46" width="34" height="13" rx="6.5" fill="var(--dv-ok)" className="dv-blink" />
        <path d="M70 52.5l3 3 6-6" fill="none" stroke="#fff" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round" />
      </Monitor>
      {/* Three dots of waiting. */}
      {[0, 1, 2].map((i) => (
        <circle key={i} cx={86 + i * 14} cy={20} r={4.5} fill="var(--dv-accent)" className="dv-blink" style={{ animationDelay: `${i * 0.25}s` }} />
      ))}
    </svg>
  );
}

/** Help step 3: connected, phone and computer with a heart between them. */
export function SceneConnected(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="76" r="62" fill="var(--dv-ok-soft)" />
      <Ground cx={100} cy={136} rx={70} />
      <Monitor x={96} y={40} w={80} h={58} screen="var(--dv-ok)">
        <path d="M6 40q16-12 34-4t34-2v18H6Z" fill="#fff" opacity={0.4} />
      </Monitor>
      <PhoneBody x={26} y={52} w={40} h={72}>
        <rect x="4.5" y="9" width="31" height="54" rx="4" fill="var(--dv-ok)" />
      </PhoneBody>
      <g className="dv-float">
        <path d="M81 72c-9-6-14-11-14-17a7 7 0 0 1 14-2 7 7 0 0 1 14 2c0 6-5 11-14 17Z" fill="#f0508c" {...stroke} />
      </g>
      <Sparkle x={160} y={26} r={7} />
      <Sparkle x={30} y={36} r={5} fill="#7cd8ff" />
    </svg>
  );
}

/** Saved: a big friendly tick with confetti. */
export function SceneSaved(props: ArtProps) {
  const bits = [
    [30, 40, "#f0508c"],
    [170, 34, "#ffc145"],
    [44, 112, "#7cd8ff"],
    [160, 110, "#7c5cff"],
    [100, 18, "#3fbf5f"],
  ] as const;
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="76" r="52" fill="var(--dv-ok)" {...stroke} />
      <path d="M76 77l16 16 32-34" fill="none" stroke="#fff" strokeWidth={10} strokeLinecap="round" strokeLinejoin="round" />
      {bits.map(([x, y, c], i) => (
        <rect key={i} x={x} y={y} width="10" height="6" rx="2" fill={c} transform={`rotate(${i * 37} ${x} ${y})`} />
      ))}
      <Sparkle x={150} y={60} r={6} />
      <Sparkle x={48} y={74} r={5} fill="#ff8fb0" />
    </svg>
  );
}

/** Touch modes in Settings: a trackpad pointer, or a finger right on the screen. */
export function SceneTouchMode({ mode, ...props }: ArtProps & { mode: "trackpad" | "direct" }) {
  return (
    <svg viewBox="0 0 120 90" aria-hidden {...props}>
      <rect x="18" y="6" width="84" height="78" rx="12" fill={PAPER} {...stroke} />
      <rect x="24" y="14" width="72" height="62" rx="6" fill="var(--dv-rdp-soft)" />
      {mode === "trackpad" ? (
        <g>
          <path d="M44 28v20l5-5 4 9 4-2-4-9h7Z" fill="#fff" stroke={LINE} strokeWidth={2} strokeLinejoin="round" />
          <circle cx="76" cy="60" r="9" fill="var(--dv-accent)" opacity={0.25} />
          <circle cx="76" cy="60" r="5" fill="var(--dv-accent)" />
          <path d="M70 54l-12-10" stroke="var(--dv-accent)" strokeWidth={2.5} strokeDasharray="2 4" strokeLinecap="round" />
        </g>
      ) : (
        <g>
          <rect x="34" y="24" width="30" height="20" rx="3" fill="#fff" />
          <circle cx="56" cy="40" r="10" fill="var(--dv-accent)" opacity={0.25} className="dv-pulse" />
          <path
            d="M56 40v-8a3 3 0 0 1 6 0v12l3-2a3 3 0 0 1 4 4l-7 10H52l-4-10a3 3 0 0 1 5-3l3 3"
            fill="#ffd0b5"
            stroke={LINE}
            strokeWidth={2}
            strokeLinejoin="round"
          />
        </g>
      )}
    </svg>
  );
}

/** Sign in: a padlock with a key ready to turn. */
export function SceneKey(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 140" aria-hidden {...props}>
      <circle cx="100" cy="72" r="58" fill="var(--dv-accent-soft)" />
      <Ground cx={100} cy={128} rx={54} />
      <path d="M78 62V48a22 22 0 0 1 44 0v14" fill="none" {...stroke} strokeWidth={7} />
      <path d="M78 62V48a22 22 0 0 1 44 0v14" fill="none" stroke="#c9d1dc" strokeWidth={3} strokeLinecap="round" />
      <rect x="66" y="60" width="68" height="58" rx="12" fill="#ffc145" {...stroke} />
      <circle cx="100" cy="84" r="7" fill={LINE} />
      <path d="M100 88v12" stroke={LINE} strokeWidth={5} strokeLinecap="round" />
      <g className="dv-float">
        <circle cx="156" cy="44" r="12" fill="var(--dv-accent)" {...stroke} />
        <circle cx="156" cy="44" r="4" fill={PAPER} />
        <path d="M146 52l-18 18M134 64l5 5M129 69l5 5" fill="none" {...stroke} strokeWidth={4} />
      </g>
      <Sparkle x={44} y={36} r={6} />
    </svg>
  );
}

/** A certificate question: a little ID card for the computer. */
export function SceneIdCard({ warn, ...props }: ArtProps & { warn?: boolean }) {
  return (
    <svg viewBox="0 0 200 140" aria-hidden {...props}>
      <circle cx="100" cy="72" r="58" fill={warn ? "var(--dv-danger-soft)" : "var(--dv-rdp-soft)"} />
      <Ground cx={100} cy={128} rx={54} />
      <rect x="44" y="40" width="112" height="74" rx="10" fill={PAPER} {...stroke} />
      <rect x="44" y="40" width="112" height="18" rx="10" fill={warn ? "var(--dv-danger)" : "var(--dv-rdp)"} {...stroke} />
      <rect x="56" y="68" width="32" height="34" rx="5" fill={SHADE} />
      <rect x="64" y="74" width="16" height="11" rx="2" fill={warn ? "var(--dv-danger)" : "var(--dv-rdp)"} />
      <path d="M68 89h8" stroke={LINE} strokeWidth={3} strokeLinecap="round" />
      <rect x="96" y="70" width="48" height="5" rx="2.5" fill={LINE} opacity={0.6} />
      <rect x="96" y="81" width="38" height="4" rx="2" fill={LINE} opacity={0.25} />
      <rect x="96" y="91" width="44" height="4" rx="2" fill={LINE} opacity={0.25} />
      <g className="dv-float">
        <circle cx="152" cy="40" r="15" fill={warn ? "var(--dv-danger)" : "var(--dv-ok)"} {...stroke} />
        {warn ? (
          <path d="M152 32v9M152 47v.01" stroke="#fff" strokeWidth={4} strokeLinecap="round" />
        ) : (
          <path d="M145 40l5 5 9-10" fill="none" stroke="#fff" strokeWidth={4} strokeLinecap="round" strokeLinejoin="round" />
        )}
      </g>
    </svg>
  );
}
