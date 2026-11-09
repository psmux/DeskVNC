/** Line icons for the session screen, inline SVG, 24 unit grid, currentColor. */
import type { ReactNode } from "react";

function Svg({ children, size = 26 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.9}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

type P = { size?: number };

export const IconKeyboard = ({ size }: P) => (
  <Svg size={size}>
    <rect x="2.5" y="6" width="19" height="12" rx="2.5" />
    <path d="M6 10h.01M9.5 10h.01M13 10h.01M16.5 10h.01M6.5 14h11" />
  </Svg>
);

export const IconTrackpad = ({ size }: P) => (
  <Svg size={size}>
    <rect x="3" y="4" width="18" height="16" rx="3" />
    <path d="M3 15.5h18M12 15.5V20" />
    <path d="M9 9.5l2.2 1 1.1 2.4 1-4.4z" fill="currentColor" strokeWidth={1.2} />
  </Svg>
);

export const IconTouch = ({ size }: P) => (
  <Svg size={size}>
    <path d="M9 11V5.5a1.5 1.5 0 0 1 3 0V11" />
    <path d="M12 10.5V9.2a1.5 1.5 0 0 1 3 0v1.8" />
    <path d="M15 10.8a1.5 1.5 0 0 1 3 0V15a6 6 0 0 1-6 6h-.6a6 6 0 0 1-4.8-2.4l-2.8-3.8a1.6 1.6 0 0 1 2.4-2.1L9 14.4" />
  </Svg>
);

export const IconKeys = ({ size }: P) => (
  <Svg size={size}>
    <rect x="2.5" y="8" width="5.5" height="5.5" rx="1.3" />
    <rect x="9.3" y="8" width="5.5" height="5.5" rx="1.3" />
    <rect x="16" y="8" width="5.5" height="5.5" rx="1.3" />
    <path d="M4.5 17h15" />
  </Svg>
);

export const IconQuality = ({ size }: P) => (
  <Svg size={size}>
    <path d="M4 17.5c0-5 3.6-9 8-9s8 4 8 9" />
    <path d="M12 17.5l3.5-5" />
    <circle cx="12" cy="17.5" r="1.3" fill="currentColor" />
  </Svg>
);

export const IconClipboard = ({ size }: P) => (
  <Svg size={size}>
    <rect x="5" y="4.5" width="14" height="16.5" rx="2.5" />
    <path d="M9 4.5h6v2.5H9z" />
    <path d="M8.5 12h7M8.5 15.5h5" />
  </Svg>
);

export const IconCamera = ({ size }: P) => (
  <Svg size={size}>
    <path d="M4 8.5h3l1.6-2.5h6.8L17 8.5h3a1 1 0 0 1 1 1V18a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9.5a1 1 0 0 1 1-1z" />
    <circle cx="12" cy="13.3" r="3.4" />
  </Svg>
);

export const IconPower = ({ size }: P) => (
  <Svg size={size}>
    <path d="M12 3.5v8" />
    <path d="M6.8 6.6a7.5 7.5 0 1 0 10.4 0" />
  </Svg>
);

export const IconChevronDown = ({ size }: P) => (
  <Svg size={size}>
    <path d="M6 9.5l6 6 6-6" />
  </Svg>
);

export const IconChevronUp = ({ size }: P) => (
  <Svg size={size}>
    <path d="M6 14.5l6-6 6 6" />
  </Svg>
);

export const IconClose = ({ size }: P) => (
  <Svg size={size}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Svg>
);

export const IconExpand = ({ size }: P) => (
  <Svg size={size}>
    <path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" />
  </Svg>
);

export const IconRefresh = ({ size }: P) => (
  <Svg size={size}>
    <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
    <path d="M19.5 4v4h-4" />
  </Svg>
);

export const IconLock = ({ size }: P) => (
  <Svg size={size}>
    <rect x="5" y="10.5" width="14" height="10" rx="2.5" />
    <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
  </Svg>
);

export const IconShieldAlert = ({ size }: P) => (
  <Svg size={size}>
    <path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.1-7.5 9.5-4.4-1.4-7.5-4.9-7.5-9.5V6z" />
    <path d="M12 8v5M12 16.2h.01" />
  </Svg>
);

export const IconShieldCheck = ({ size }: P) => (
  <Svg size={size}>
    <path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.1-7.5 9.5-4.4-1.4-7.5-4.9-7.5-9.5V6z" />
    <path d="M8.8 12.2l2.2 2.2 4.3-4.6" />
  </Svg>
);

export const IconSend = ({ size }: P) => (
  <Svg size={size}>
    <path d="M4 12l15-7-5 15-2.5-6z" />
  </Svg>
);

export const IconCopy = ({ size }: P) => (
  <Svg size={size}>
    <rect x="8" y="8" width="12" height="12" rx="2.3" />
    <path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8" />
  </Svg>
);

export const IconPaste = ({ size }: P) => (
  <Svg size={size}>
    <rect x="5" y="4.5" width="14" height="16.5" rx="2.5" />
    <path d="M9 4.5h6v2.5H9z" />
    <path d="M12 10.5v6M9.5 14l2.5 2.5 2.5-2.5" />
  </Svg>
);

export const IconWifi = ({ size }: P) => (
  <Svg size={size}>
    <path d="M3 9a13 13 0 0 1 18 0M6 12.5a8.5 8.5 0 0 1 12 0M9 16a4 4 0 0 1 6 0" />
    <circle cx="12" cy="19" r="1" fill="currentColor" />
  </Svg>
);

export const IconEye = ({ size }: P) => (
  <Svg size={size}>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
    <circle cx="12" cy="12" r="3" />
  </Svg>
);

export const IconEyeOff = ({ size }: P) => (
  <Svg size={size}>
    <path d="M4 4l16 16" />
    <path d="M9.9 6A9.7 9.7 0 0 1 12 5.5C18 5.5 21.5 12 21.5 12a17 17 0 0 1-3 3.7M6.3 7.6A17 17 0 0 0 2.5 12S6 18.5 12 18.5a9 9 0 0 0 3.5-.7" />
  </Svg>
);

export const IconZoomOut = ({ size }: P) => (
  <Svg size={size}>
    <circle cx="11" cy="11" r="6.5" />
    <path d="M16 16l4.5 4.5M8 11h6" />
  </Svg>
);

export const IconHelp = ({ size }: P) => (
  <Svg size={size}>
    <circle cx="12" cy="12" r="9" />
    <path d="M9.6 9.3a2.5 2.5 0 0 1 4.8.9c0 1.8-2.4 2.2-2.4 3.8M12 17h.01" />
  </Svg>
);

export const IconArrow = ({ dir, size }: P & { dir: "up" | "down" | "left" | "right" }) => {
  const rot = { up: 0, right: 90, down: 180, left: 270 }[dir];
  return (
    <Svg size={size}>
      <g transform={`rotate(${rot} 12 12)`}>
        <path d="M12 19V5M6 11l6-6 6 6" />
      </g>
    </Svg>
  );
};

export const IconRotate = ({ size }: P) => (
  <Svg size={size}>
    <rect x="7" y="2.5" width="10" height="16" rx="2" className="dv-a-tilt" />
    <path d="M3.5 14.5a9 9 0 0 0 7 7M20.5 9.5a9 9 0 0 0-7-7" />
    <path d="M10.5 21.5l-2.3.4.6-2.4M13.5 2.5l2.3-.4-.6 2.4" />
  </Svg>
);
