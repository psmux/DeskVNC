/**
 * Illustrations for the session screen: the connecting scene, the hands of
 * the gesture coach and the pictures of the two touch modes. All inline SVG,
 * animated with CSS (see session.css, the `dv-a-` classes) and SMIL motion,
 * both of which WKWebView and Android System WebView play.
 */
import type { TouchMode } from "../input/gestures";

/** A right hand, index finger out, drawn with its fingertip at (x, y). */
export function Hand({ x = 0, y = 0, scale = 1, className }: { x?: number; y?: number; scale?: number; className?: string }) {
  return (
    <g transform={`translate(${x - 18 * scale} ${y - 4 * scale}) scale(${scale})`}>
      <g className={className}>
        <path
          d="M14 32 L14 8 A4 4 0 0 1 22 8 L22 22 A3.2 3.2 0 0 1 28.4 22.5 L28.4 25 A3 3 0 0 1 34.2 25.8 L34.2 28 A2.8 2.8 0 0 1 39.6 29 L39.6 40 C39.6 48 34 54 26 54 L22 54 C17 54 14 51 11 47 L5.5 38.5 A3 3 0 0 1 10.5 35 L14 39 Z"
          fill="var(--s-hand)"
          stroke="var(--s-hand-line)"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path d="M16 11.5h4" stroke="var(--s-hand-line)" strokeWidth="1.2" strokeLinecap="round" opacity="0.5" />
      </g>
    </g>
  );
}

function Pointer({ x, y, className }: { x: number; y: number; className?: string }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <g className={className}>
        <path d="M0 0 L0 13 L3.4 9.8 L6 15.2 L8.2 14.2 L5.7 8.9 L10.2 8.9 Z" fill="#fff" stroke="#111" strokeWidth="1.1" strokeLinejoin="round" />
      </g>
    </g>
  );
}

/** The miniature screen every coach scene draws on. */
function MiniScreen({ children }: { children: React.ReactNode }) {
  return (
    <svg viewBox="0 0 120 96" className="dv-s-scene" aria-hidden="true">
      <rect x="6" y="6" width="108" height="70" rx="8" fill="var(--s-surface-2)" stroke="var(--s-line)" strokeWidth="1.5" />
      <rect x="14" y="14" width="40" height="26" rx="3" fill="var(--s-accent)" opacity="0.22" />
      <rect x="60" y="14" width="46" height="8" rx="2" fill="var(--s-ink-dim)" opacity="0.25" />
      <rect x="60" y="26" width="34" height="8" rx="2" fill="var(--s-ink-dim)" opacity="0.18" />
      <rect x="14" y="46" width="92" height="22" rx="3" fill="var(--s-ink-dim)" opacity="0.12" />
      {children}
    </svg>
  );
}

function Dots({ n, x, y, className }: { n: number; x: number; y: number; className?: string }) {
  const xs = n === 1 ? [0] : n === 2 ? [-6, 6] : [-11, 0, 11];
  return (
    <g transform={`translate(${x} ${y})`}>
      <g className={className}>
        {xs.map((dx) => (
          <circle key={dx} cx={dx} cy={0} r="5" fill="var(--s-accent)" opacity="0.85" />
        ))}
      </g>
    </g>
  );
}

function Ripple({ x, y, delay = 0 }: { x: number; y: number; delay?: number }) {
  return (
    <circle
      cx={x}
      cy={y}
      r="9"
      fill="none"
      stroke="var(--s-accent)"
      strokeWidth="2.5"
      className="dv-a-ripple"
      style={{ animationDelay: `${delay}ms`, transformOrigin: `${x}px ${y}px` }}
    />
  );
}

export type CoachGesture =
  | "tp-move"
  | "tp-click"
  | "tp-right"
  | "tp-drag"
  | "scroll"
  | "pinch"
  | "keyboard"
  | "dt-click"
  | "dt-right"
  | "dt-zoom";

/** One animated gesture, the hand acting it out on a tiny screen. */
export function GestureScene({ kind }: { kind: CoachGesture }) {
  switch (kind) {
    case "tp-move":
      return (
        <MiniScreen>
          <Pointer x={40} y={30} className="dv-a-slide" />
          <Dots n={1} x={52} y={84} className="dv-a-slide" />
          <Hand x={52} y={84} scale={0.55} className="dv-a-slide" />
        </MiniScreen>
      );
    case "tp-click":
      return (
        <MiniScreen>
          <Pointer x={30} y={24} />
          <Ripple x={30} y={24} />
          <Dots n={1} x={62} y={84} className="dv-a-tap" />
          <Hand x={62} y={84} scale={0.55} className="dv-a-tap" />
        </MiniScreen>
      );
    case "tp-right":
      return (
        <MiniScreen>
          <Pointer x={30} y={24} />
          <g className="dv-a-menu">
            <rect x="38" y="30" width="34" height="30" rx="3" fill="var(--s-surface)" stroke="var(--s-line)" />
            <rect x="42" y="35" width="24" height="4" rx="1" fill="var(--s-ink-dim)" opacity="0.5" />
            <rect x="42" y="43" width="20" height="4" rx="1" fill="var(--s-ink-dim)" opacity="0.5" />
            <rect x="42" y="51" width="22" height="4" rx="1" fill="var(--s-ink-dim)" opacity="0.5" />
          </g>
          <Dots n={2} x={62} y={84} className="dv-a-tap" />
          <Hand x={62} y={84} scale={0.55} className="dv-a-tap" />
        </MiniScreen>
      );
    case "tp-drag":
      return (
        <MiniScreen>
          <rect x="22" y="48" width="0" height="8" fill="var(--s-accent)" opacity="0.45" className="dv-a-select" />
          <Pointer x={22} y={48} className="dv-a-slide-x" />
          <Dots n={1} x={40} y={84} className="dv-a-tapdrag" />
          <Hand x={40} y={84} scale={0.55} className="dv-a-tapdrag" />
        </MiniScreen>
      );
    case "scroll":
      return (
        <MiniScreen>
          <g className="dv-a-scroll-content">
            <rect x="60" y="40" width="46" height="5" rx="2" fill="var(--s-ink-dim)" opacity="0.3" />
            <rect x="60" y="49" width="38" height="5" rx="2" fill="var(--s-ink-dim)" opacity="0.3" />
          </g>
          <Dots n={2} x={60} y={70} className="dv-a-scroll" />
          <Hand x={60} y={70} scale={0.55} className="dv-a-scroll" />
        </MiniScreen>
      );
    case "pinch":
      return (
        <MiniScreen>
          <rect x="14" y="14" width="40" height="26" rx="3" fill="var(--s-accent)" opacity="0.35" className="dv-a-grow" style={{ transformOrigin: "34px 27px" }} />
          <circle cx="50" cy="56" r="5" fill="var(--s-accent)" className="dv-a-pinch-a" />
          <circle cx="70" cy="44" r="5" fill="var(--s-accent)" className="dv-a-pinch-b" />
          <Hand x={70} y={44} scale={0.55} className="dv-a-pinch-b" />
        </MiniScreen>
      );
    case "keyboard":
      return (
        <MiniScreen>
          <g className="dv-a-kbd">
            <rect x="10" y="52" width="100" height="22" rx="3" fill="var(--s-surface)" stroke="var(--s-line)" />
            {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
              <rect key={i} x={15 + i * 11.6} y="56" width="9" height="6" rx="1.5" fill="var(--s-ink-dim)" opacity="0.4" />
            ))}
            <rect x="30" y="65" width="60" height="5" rx="1.5" fill="var(--s-ink-dim)" opacity="0.4" />
          </g>
          <Dots n={3} x={60} y={36} className="dv-a-tap" />
          <Hand x={60} y={36} scale={0.55} className="dv-a-tap" />
        </MiniScreen>
      );
    case "dt-click":
      return (
        <MiniScreen>
          <Ripple x={34} y={27} delay={300} />
          <Hand x={34} y={27} scale={0.55} className="dv-a-tap" />
        </MiniScreen>
      );
    case "dt-right":
      return (
        <MiniScreen>
          <circle cx="34" cy="27" r="11" fill="none" stroke="var(--s-accent)" strokeWidth="3" strokeDasharray="69.1" className="dv-a-ring" style={{ transformOrigin: "34px 27px" }} />
          <g className="dv-a-menu-late">
            <rect x="44" y="30" width="34" height="30" rx="3" fill="var(--s-surface)" stroke="var(--s-line)" />
            <rect x="48" y="35" width="24" height="4" rx="1" fill="var(--s-ink-dim)" opacity="0.5" />
            <rect x="48" y="43" width="20" height="4" rx="1" fill="var(--s-ink-dim)" opacity="0.5" />
          </g>
          <Hand x={34} y={27} scale={0.55} className="dv-a-hold" />
        </MiniScreen>
      );
    case "dt-zoom":
      return (
        <MiniScreen>
          <rect x="14" y="14" width="40" height="26" rx="3" fill="var(--s-accent)" opacity="0.35" className="dv-a-grow-late" style={{ transformOrigin: "34px 27px" }} />
          <Ripple x={34} y={27} />
          <Ripple x={34} y={27} delay={260} />
          <Hand x={34} y={27} scale={0.55} className="dv-a-doubletap" />
        </MiniScreen>
      );
  }
}

/** The connecting scene: a phone, a computer, pulses running between them. */
export function ConnectArt({ step, failed }: { step: number; failed: boolean }) {
  const path = "M64 92 C 100 40, 160 40, 196 84";
  return (
    <svg viewBox="0 0 260 160" className="dv-s-connect-art" aria-hidden="true">
      {/* phone */}
      <g className={failed ? "" : "dv-a-bob"}>
        <rect x="24" y="60" width="44" height="80" rx="9" fill="var(--s-surface)" stroke="var(--s-ink)" strokeWidth="2.5" />
        <rect x="30" y="70" width="32" height="56" rx="3" fill="var(--s-accent)" opacity="0.25" />
        <circle cx="46" cy="132" r="2.5" fill="var(--s-ink)" />
      </g>
      {/* computer */}
      <g>
        <rect x="170" y="60" width="74" height="54" rx="6" fill="var(--s-surface)" stroke="var(--s-ink)" strokeWidth="2.5" />
        <rect x="177" y="67" width="60" height="40" rx="2" fill={failed ? "var(--s-danger)" : "var(--s-accent)"} opacity={failed ? 0.25 : 0.18 + step * 0.07} />
        <path d="M198 114 l-4 14 h26 l-4 -14" fill="var(--s-surface)" stroke="var(--s-ink)" strokeWidth="2.5" strokeLinejoin="round" />
        <path d="M188 128 h38" stroke="var(--s-ink)" strokeWidth="2.5" strokeLinecap="round" />
        <g transform="translate(207 87)">
          {failed ? (
            <path d="M-8 -8 L8 8 M8 -8 L-8 8" stroke="var(--s-danger)" strokeWidth="4" strokeLinecap="round" />
          ) : step >= 3 ? (
            <path d="M-9 0 L-3 6 L9 -7" stroke="var(--s-ok)" strokeWidth="4" fill="none" strokeLinecap="round" strokeLinejoin="round" className="dv-a-pop" />
          ) : step === 2 ? (
            <g className="dv-a-pop">
              <circle cx="-4" cy="0" r="5" fill="none" stroke="var(--s-ink)" strokeWidth="2.6" />
              <path d="M1 0 h10 M8 0 v4" stroke="var(--s-ink)" strokeWidth="2.6" strokeLinecap="round" />
            </g>
          ) : step === 1 ? (
            <path d="M0 -10 L8 -7 V-1 C8 4 4.5 8 0 10 C-4.5 8 -8 4 -8 -1 V-7 Z" fill="none" stroke="var(--s-ink)" strokeWidth="2.6" strokeLinejoin="round" className="dv-a-pop" />
          ) : (
            <g className="dv-a-search">
              <circle cx="-2" cy="-2" r="6" fill="none" stroke="var(--s-ink)" strokeWidth="2.6" />
              <path d="M2.5 2.5 L8 8" stroke="var(--s-ink)" strokeWidth="2.6" strokeLinecap="round" />
            </g>
          )}
        </g>
      </g>
      {/* the link */}
      <path d={path} fill="none" stroke="var(--s-line)" strokeWidth="3" strokeDasharray="2 9" strokeLinecap="round" />
      {failed ? (
        <g transform="translate(130 50)">
          <circle r="13" fill="var(--s-danger)" />
          <path d="M-5 -5 L5 5 M5 -5 L-5 5" stroke="#fff" strokeWidth="3" strokeLinecap="round" />
        </g>
      ) : (
        [0, 1, 2].map((i) => (
          <circle key={i} r="6" fill="var(--s-accent)">
            <animateMotion dur="1.8s" repeatCount="indefinite" path={path} begin={`${i * 0.6}s`} keyPoints="0;1" keyTimes="0;1" calcMode="linear" />
            <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.15;0.8;1" dur="1.8s" begin={`${i * 0.6}s`} repeatCount="indefinite" />
          </circle>
        ))
      )}
    </svg>
  );
}

/** Pictures for the touch mode chooser. */
export function ModePicture({ mode }: { mode: TouchMode }) {
  if (mode === "trackpad") {
    return (
      <svg viewBox="0 0 120 96" className="dv-s-scene" aria-hidden="true">
        <rect x="10" y="8" width="100" height="56" rx="6" fill="var(--s-surface-2)" stroke="var(--s-line)" strokeWidth="1.5" />
        <Pointer x={40} y={26} className="dv-a-slide" />
        <rect x="30" y="68" width="60" height="22" rx="5" fill="var(--s-surface-2)" stroke="var(--s-line)" strokeWidth="1.5" />
        <Dots n={1} x={52} y={80} className="dv-a-slide-small" />
        <Hand x={52} y={80} scale={0.4} className="dv-a-slide-small" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 120 96" className="dv-s-scene" aria-hidden="true">
      <rect x="10" y="8" width="100" height="70" rx="6" fill="var(--s-surface-2)" stroke="var(--s-line)" strokeWidth="1.5" />
      <rect x="22" y="20" width="34" height="22" rx="3" fill="var(--s-accent)" opacity="0.3" />
      <Ripple x={39} y={31} delay={300} />
      <Hand x={39} y={31} scale={0.55} className="dv-a-tap" />
    </svg>
  );
}
