/**
 * The bigger illustrations: onboarding, empty states and the help steps.
 * Same line weight and palette as the OS artwork: gray line drawings on a
 * soft backdrop, with the accent for the one thing each picture is about.
 * Status colours appear only where the picture shows a status.
 */
import { ACCENT, ACCENT_SOFT, BACKDROP, Ground, LINE, MID, MiniWindow, PAPER, SHADE, ScreenGradient, stroke, type ArtProps } from "./common";

function PhoneBody({ x, y, w = 44, h = 80, screen = SHADE, children }: { x: number; y: number; w?: number; h?: number; screen?: string; children?: React.ReactNode }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <rect x="0" y="0" width={w} height={h} rx="8" fill={PAPER} {...stroke} />
      <rect x="4.5" y="9" width={w - 9} height={h - 18} rx="3.5" fill={screen} />
      <rect x={w / 2 - 6} y="4" width="12" height="2" rx="1" fill={LINE} opacity={0.6} />
      {children}
    </g>
  );
}

function Monitor({ x, y, w, h, screen, children }: { x: number; y: number; w: number; h: number; screen: string; children?: React.ReactNode }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <path d={`M${w / 2 - 12} ${h}h24l4 14h-32Z`} fill={PAPER} {...stroke} />
      <rect x="0" y="0" width={w} height={h} rx="6" fill={PAPER} {...stroke} />
      <rect x="6" y="6" width={w - 12} height={h - 12} rx="2" fill={screen} />
      {children}
    </g>
  );
}

/** A dialog asking the other person to allow, with an accent Allow button. */
function AllowDialog({ x, y, w, h }: { x: number; y: number; w: number; h: number }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="4" fill={PAPER} stroke={LINE} strokeWidth={1.5} />
      <circle cx={x + 13} cy={y + 14} r="6" fill={SHADE} stroke={LINE} strokeWidth={1.2} />
      <rect x={x + 24} y={y + 10} width={w - 34} height="3" rx="1.5" fill={LINE} opacity={0.55} />
      <rect x={x + 24} y={y + 17} width={(w - 34) * 0.7} height="2.6" rx="1.3" fill={MID} />
      <rect x={x + w - 46} y={y + h - 15} width="18" height="9" rx="2.5" fill={SHADE} />
      <rect x={x + w - 25} y={y + h - 15} width="18" height="9" rx="2.5" fill={ACCENT} />
    </g>
  );
}

/** Onboarding 1: a phone reaching across to a desktop. */
export function SceneReach(props: ArtProps) {
  return (
    <svg viewBox="0 0 240 180" aria-hidden {...props}>
      <defs>
        <ScreenGradient id="reach-screen" />
      </defs>
      <circle cx="120" cy="92" r="78" fill={BACKDROP} />
      <Ground cx={120} cy={166} rx={90} />
      <Monitor x={104} y={36} w={112} h={78} screen="url(#reach-screen)">
        <MiniWindow x={16} y={14} w={50} h={36} lines={3} accent />
        <MiniWindow x={56} y={28} w={42} h={30} lines={2} />
      </Monitor>
      <PhoneBody x={30} y={64} w={52} h={92} screen="url(#reach-screen)">
        <rect x="9" y="22" width="26" height="19" rx="2" fill={PAPER} />
        <rect x="9" y="22" width="26" height="4" rx="2" fill={SHADE} />
        <rect x="12" y="30" width="16" height="2" rx="1" fill={ACCENT} />
        <rect x="12" y="35" width="12" height="2" rx="1" fill={MID} />
        {/* A touch on the little screen. */}
        <circle cx="34" cy="56" r="8" fill={ACCENT} opacity={0.18} className="dv-pulse" />
        <circle cx="34" cy="56" r="4" fill={ACCENT} />
      </PhoneBody>
      <path d="M88 96C100 78 108 66 120 58" fill="none" stroke={ACCENT} strokeWidth={2.5} strokeDasharray="1 7" strokeLinecap="round" />
    </svg>
  );
}

/** Onboarding 2: the three ways, as three cards fanned out. */
export function SceneThreeWays(props: ArtProps) {
  const card = (x: number, y: number, rot: number, kind: "rdp" | "vnc" | "boundary", front = false) => (
    <g transform={`rotate(${rot} ${x + 32} ${y + 40})`}>
      <rect x={x} y={y} width="64" height="80" rx="8" fill={PAPER} {...stroke} />
      <rect x={x + 6} y={y + 6} width="52" height="40" rx="4" fill={front ? ACCENT_SOFT : SHADE} />
      {kind === "rdp" && (
        <g transform={`translate(${x + 16} ${y + 12})`} fill="none" stroke={ACCENT} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <rect x="0" y="0" width="32" height="22" rx="2.5" fill={PAPER} />
          <path d="M0 6h32" />
          <path d="M12 27h8" />
        </g>
      )}
      {kind === "vnc" && (
        <g transform={`translate(${x + 32} ${y + 26})`} fill="none" stroke={ACCENT} strokeWidth={2} strokeLinecap="round">
          <rect x="-9" y="-7" width="18" height="13" rx="2" fill={PAPER} />
          <path d="M-15 -10a14 14 0 0 0 0 20M15 -10a14 14 0 0 1 0 20" />
        </g>
      )}
      {kind === "boundary" && (
        <g transform={`translate(${x + 32} ${y + 26})`}>
          <path
            d="M-20 -9a3 3 0 0 1 3-3h34a3 3 0 0 1 3 3v5a4 4 0 0 0 0 8v5a3 3 0 0 1-3 3h-34a3 3 0 0 1-3-3v-5a4 4 0 0 0 0-8Z"
            fill={PAPER}
            stroke={ACCENT}
            strokeWidth={2}
            strokeLinejoin="round"
          />
          {[-10, -3, 4, 11].map((dx) => (
            <rect key={dx} x={dx - 1.6} y={-3} width={3.2} height={6} rx={1} fill={ACCENT} />
          ))}
        </g>
      )}
      <rect x={x + 10} y={y + 54} width="36" height="4" rx="2" fill={LINE} opacity={0.55} />
      <rect x={x + 10} y={y + 64} width="26" height="3.4" rx="1.7" fill={MID} />
    </g>
  );
  return (
    <svg viewBox="0 0 240 180" aria-hidden {...props}>
      <circle cx="120" cy="92" r="78" fill={BACKDROP} />
      <Ground cx={120} cy={166} rx={90} />
      {card(28, 56, -12, "rdp")}
      {card(146, 56, 12, "vnc")}
      {card(88, 40, 0, "boundary", true)}
    </svg>
  );
}

/** Onboarding 3: safety. A shield, and a screen asking the other person first. */
export function SceneSafety(props: ArtProps) {
  return (
    <svg viewBox="0 0 240 180" aria-hidden {...props}>
      <defs>
        <ScreenGradient id="safety-screen" />
      </defs>
      <circle cx="120" cy="92" r="78" fill={BACKDROP} />
      <Ground cx={120} cy={166} rx={90} />
      <Monitor x={92} y={34} w={120} h={82} screen="url(#safety-screen)">
        <AllowDialog x={20} y={18} w={80} h={46} />
      </Monitor>
      <path d="M58 48l32 11v24c0 21-15 34-32 42-17-8-32-21-32-42V59Z" fill={PAPER} {...stroke} />
      <path d="M58 58l22 7.6v17c0 14.5-10 24-22 30-12-6-22-15.5-22-30v-17Z" fill={ACCENT_SOFT} />
      <path d="M46 86l8 8 16-17" fill="none" stroke={ACCENT} strokeWidth={4} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Empty library: a desk waiting for its first computer. */
export function SceneEmptyDesk(props: ArtProps) {
  return (
    <svg viewBox="0 0 240 170" aria-hidden {...props}>
      <circle cx="120" cy="86" r="74" fill={BACKDROP} />
      <rect x="24" y="128" width="192" height="8" rx="3" fill={PAPER} {...stroke} />
      <path d="M40 136v22M200 136v22" {...stroke} />
      {/* A screen drawn in dashes, with a plus: the computer to add. */}
      <rect x="74" y="44" width="92" height="64" rx="6" fill={PAPER} stroke={ACCENT} strokeWidth={2} strokeDasharray="6 5" />
      <circle cx="120" cy="76" r="13" fill={ACCENT_SOFT} />
      <path d="M120 69v14M113 76h14" stroke={ACCENT} strokeWidth={2.6} strokeLinecap="round" />
      <path d="M110 108h20l3 20h-26Z" fill={PAPER} stroke={ACCENT} strokeWidth={2} strokeDasharray="4 4" />
      {/* A closed laptop and a cup, in plain line. */}
      <path d="M38 128l4-8h40l4 8Z" fill={PAPER} {...stroke} />
      <path d="M58 124h8" stroke={MID} strokeWidth={2} strokeLinecap="round" />
      <rect x="178" y="108" width="20" height="20" rx="3" fill={PAPER} {...stroke} />
      <path d="M198 112a5 5 0 0 1 0 11" fill="none" {...stroke} />
    </svg>
  );
}

/** A scan that found nothing: a quiet radar with no blips. */
export function SceneSleepyRadar(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="75" r="62" fill={BACKDROP} />
      <circle cx="100" cy="75" r="46" fill="none" stroke={MID} strokeWidth={1.5} />
      <circle cx="100" cy="75" r="28" fill="none" stroke={MID} strokeWidth={1.5} strokeDasharray="3 5" />
      <path d="M100 75L132 42" stroke={LINE} strokeWidth={2} strokeLinecap="round" opacity={0.5} />
      <g transform="translate(89 56)">
        <rect x="0" y="0" width="22" height="38" rx="5" fill={PAPER} {...stroke} />
        <rect x="3" y="5" width="16" height="28" rx="2" fill={ACCENT_SOFT} />
      </g>
    </svg>
  );
}

/** Help step 1: looking the code up. */
export function SceneLookup(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="76" r="62" fill={BACKDROP} />
      <Ground cx={100} cy={136} rx={60} />
      <rect x="36" y="50" width="114" height="54" rx="6" fill={PAPER} {...stroke} />
      {[0, 1, 2].map((g) =>
        [0, 1, 2, 3].map((d) => <rect key={`${g}${d}`} x={50 + g * 32 + d * 6} y={72} width={3.6} height={9} rx={1} fill={g === 0 ? ACCENT : MID} />),
      )}
      <g className="dv-float">
        <circle cx="130" cy="64" r="22" fill={PAPER} fillOpacity={0.7} stroke={ACCENT} strokeWidth={3} />
        <path d="M146 80l16 16" stroke={ACCENT} strokeWidth={5} strokeLinecap="round" />
      </g>
    </svg>
  );
}

/** Help step 2: the other person approving on their screen. */
export function SceneApprove(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <defs>
        <ScreenGradient id="approve-screen" />
      </defs>
      <circle cx="100" cy="76" r="62" fill={BACKDROP} />
      <Ground cx={100} cy={136} rx={60} />
      <Monitor x={40} y={30} w={120} h={82} screen="url(#approve-screen)">
        <AllowDialog x={18} y={16} w={84} h={48} />
      </Monitor>
      {/* Three dots of waiting. */}
      {[0, 1, 2].map((i) => (
        <circle key={i} cx={86 + i * 14} cy={18} r={3.5} fill={ACCENT} className="dv-blink" style={{ animationDelay: `${i * 0.25}s` }} />
      ))}
    </svg>
  );
}

/** Help step 3: connected, phone and computer showing the same screen. */
export function SceneConnected(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <defs>
        <ScreenGradient id="connected-screen" />
      </defs>
      <circle cx="100" cy="76" r="62" fill={BACKDROP} />
      <Ground cx={100} cy={136} rx={70} />
      <Monitor x={96} y={40} w={80} h={58} screen="url(#connected-screen)">
        <MiniWindow x={14} y={12} w={40} h={28} lines={2} accent />
      </Monitor>
      <PhoneBody x={26} y={52} w={40} h={72} screen="url(#connected-screen)">
        <rect x="8" y="22" width="24" height="17" rx="2" fill={PAPER} />
        <rect x="11" y="29" width="14" height="2" rx="1" fill={ACCENT} />
      </PhoneBody>
      <path d="M72 80h18" stroke={ACCENT} strokeWidth={2.5} strokeLinecap="round" />
      <circle cx="72" cy="80" r="3" fill={ACCENT} />
      <circle cx="90" cy="80" r="3" fill={ACCENT} />
      <circle cx="160" cy="34" r="11" fill="var(--dv-ok)" />
      <path d="M155 34l3.5 3.5 6.5-7" fill="none" stroke="#fff" strokeWidth={2.6} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Saved: a calm tick. */
export function SceneSaved(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 150" aria-hidden {...props}>
      <circle cx="100" cy="76" r="62" fill={BACKDROP} />
      <circle cx="100" cy="76" r="40" fill="var(--dv-ok-soft)" />
      <circle cx="100" cy="76" r="28" fill="var(--dv-ok)" />
      <path d="M87 77l9 9 18-19" fill="none" stroke="#fff" strokeWidth={6} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Touch modes in Settings: a trackpad pointer, or a finger right on the screen. */
export function SceneTouchMode({ mode, ...props }: ArtProps & { mode: "trackpad" | "direct" }) {
  return (
    <svg viewBox="0 0 120 90" aria-hidden {...props}>
      <rect x="18" y="6" width="84" height="78" rx="9" fill={PAPER} {...stroke} />
      <rect x="24" y="14" width="72" height="62" rx="4" fill={SHADE} />
      {mode === "trackpad" ? (
        <g>
          <path d="M44 28v20l5-5 4 9 4-2-4-9h7Z" fill={PAPER} stroke={LINE} strokeWidth={1.6} strokeLinejoin="round" />
          <circle cx="76" cy="60" r="9" fill={ACCENT} opacity={0.18} />
          <circle cx="76" cy="60" r="4.5" fill={ACCENT} />
          <path d="M70 54l-12-10" stroke={ACCENT} strokeWidth={2} strokeDasharray="2 4" strokeLinecap="round" />
        </g>
      ) : (
        <g>
          <rect x="34" y="24" width="30" height="20" rx="2.5" fill={PAPER} stroke={MID} strokeWidth={1} />
          <circle cx="58" cy="40" r="10" fill={ACCENT} opacity={0.18} className="dv-pulse" />
          <circle cx="58" cy="40" r="4.5" fill={ACCENT} />
        </g>
      )}
    </svg>
  );
}

/** Sign in: a padlock with a key beside it. */
export function SceneKey(props: ArtProps) {
  return (
    <svg viewBox="0 0 200 140" aria-hidden {...props}>
      <circle cx="100" cy="72" r="58" fill={BACKDROP} />
      <Ground cx={100} cy={128} rx={54} />
      <path d="M80 62V48a20 20 0 0 1 40 0v14" fill="none" stroke={LINE} strokeWidth={5} strokeLinecap="round" />
      <rect x="66" y="60" width="68" height="56" rx="8" fill={PAPER} {...stroke} />
      <circle cx="100" cy="84" r="6" fill={ACCENT} />
      <path d="M100 88v11" stroke={ACCENT} strokeWidth={4} strokeLinecap="round" />
      <g className="dv-float">
        <circle cx="156" cy="44" r="11" fill={PAPER} stroke={ACCENT} strokeWidth={3} />
        <circle cx="156" cy="44" r="3.5" fill={ACCENT} />
        <path d="M148 52l-18 18M136 64l5 5M131 69l5 5" fill="none" stroke={ACCENT} strokeWidth={3} strokeLinecap="round" />
      </g>
    </svg>
  );
}

/** A certificate question: an ID card for the computer. */
export function SceneIdCard({ warn, ...props }: ArtProps & { warn?: boolean }) {
  const tone = warn ? "var(--dv-danger)" : ACCENT;
  return (
    <svg viewBox="0 0 200 140" aria-hidden {...props}>
      <circle cx="100" cy="72" r="58" fill={BACKDROP} />
      <Ground cx={100} cy={128} rx={54} />
      <rect x="44" y="40" width="112" height="74" rx="7" fill={PAPER} {...stroke} />
      <path d="M44 56h112" stroke={LINE} strokeWidth={1.5} opacity={0.5} />
      <rect x="54" y="46" width="30" height="4" rx="2" fill={tone} />
      <rect x="56" y="66" width="32" height="34" rx="4" fill={SHADE} />
      <rect x="64" y="73" width="16" height="11" rx="2" fill={PAPER} stroke={LINE} strokeWidth={1.2} />
      <path d="M68 89h8" stroke={LINE} strokeWidth={2} strokeLinecap="round" />
      <rect x="96" y="70" width="48" height="4" rx="2" fill={LINE} opacity={0.55} />
      <rect x="96" y="80" width="38" height="3.4" rx="1.7" fill={MID} />
      <rect x="96" y="90" width="44" height="3.4" rx="1.7" fill={MID} />
      <circle cx="152" cy="40" r="13" fill={warn ? "var(--dv-danger)" : "var(--dv-ok)"} />
      {warn ? (
        <path d="M152 33v8M152 46.5v.01" stroke="#fff" strokeWidth={3.4} strokeLinecap="round" />
      ) : (
        <path d="M146 40l4 4 8-9" fill="none" stroke="#fff" strokeWidth={3.4} strokeLinecap="round" strokeLinejoin="round" />
      )}
    </svg>
  );
}
