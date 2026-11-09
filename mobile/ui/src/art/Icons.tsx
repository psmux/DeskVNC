/**
 * Small line icons for buttons and fields, plus the four illustrated tab bar
 * icons. All inline SVG, nothing fetched at runtime.
 */
import type { ReactNode, SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 24, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={2.2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconSearch = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="11" cy="11" r="6.5" />
    <path d="M16 16l4.5 4.5" />
  </Icon>
);
export const IconPlus = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 5v14M5 12h14" />
  </Icon>
);
export const IconBack = (p: IconProps) => (
  <Icon {...p}>
    <path d="M15 5l-7 7 7 7" />
  </Icon>
);
export const IconClose = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Icon>
);
export const IconChevron = (p: IconProps) => (
  <Icon {...p}>
    <path d="M9 5l7 7-7 7" />
  </Icon>
);
export const IconCheck = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  </Icon>
);
export const IconStar = ({ filled, ...p }: IconProps & { filled?: boolean }) => (
  <Icon {...p} fill={filled ? "currentColor" : "none"}>
    <path d="M12 3.8l2.5 5.1 5.6.8-4 4 .9 5.6-5-2.6-5 2.6.9-5.6-4-4 5.6-.8Z" />
  </Icon>
);
export const IconPaste = (p: IconProps) => (
  <Icon {...p}>
    <rect x="6" y="5" width="12" height="16" rx="2.5" />
    <path d="M9 5V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1" />
    <path d="M9.5 11h5M9.5 15h3.5" />
  </Icon>
);
export const IconBackspace = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 5h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H8l-6-7Z" />
    <path d="M11 9.5l5 5M16 9.5l-5 5" />
  </Icon>
);
export const IconMore = (p: IconProps) => (
  <Icon {...p} strokeWidth={3}>
    <path d="M6 12h.01M12 12h.01M18 12h.01" />
  </Icon>
);
export const IconLock = (p: IconProps) => (
  <Icon {...p}>
    <rect x="5" y="10.5" width="14" height="10" rx="2.5" />
    <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
  </Icon>
);
export const IconEye = ({ off, ...p }: IconProps & { off?: boolean }) => (
  <Icon {...p}>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
    <circle cx="12" cy="12" r="3" />
    {off && <path d="M4 4l16 16" />}
  </Icon>
);
export const IconRefresh = (p: IconProps) => (
  <Icon {...p}>
    <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
    <path d="M19.5 4.5v4.5H15" />
  </Icon>
);
export const IconTrash = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4.5 7h15M10 7V5h4v2M6.5 7l1 12.5a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5l1-12.5" />
  </Icon>
);
export const IconEdit = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14.5 5.5l4 4L8 20H4v-4Z" />
  </Icon>
);
export const IconPlay = (p: IconProps) => (
  <Icon {...p} fill="currentColor" strokeWidth={1.5}>
    <path d="M8 5.5v13l10.5-6.5Z" />
  </Icon>
);
export const IconLink = (p: IconProps) => (
  <Icon {...p}>
    <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1" />
    <path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />
  </Icon>
);
export const IconExternal = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14 4h6v6M20 4l-9 9M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />
  </Icon>
);

// ------------------------------------------------------------------ tab bar

export type TabKey = "computers" | "nearby" | "help" | "settings";

/** The illustrated tab icons: a soft filled shape behind a line drawing. */
export function TabIcon({ tab, active, size = 30 }: { tab: TabKey; active: boolean; size?: number }) {
  const line = active ? "var(--dv-accent)" : "var(--dv-ink-dim)";
  const fill = active ? "var(--dv-accent-soft)" : "transparent";
  const p = { stroke: line, strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden>
      {tab === "computers" && (
        <g>
          <rect x="4" y="6" width="24" height="16" rx="3" fill={fill} {...p} />
          {active && <path d="M8 18q4-5 8-2t8-2v4H8Z" fill="var(--dv-accent)" opacity={0.5} />}
          <path d="M12 27h8M16 22v5" fill="none" {...p} />
        </g>
      )}
      {tab === "nearby" && (
        <g>
          <circle cx="16" cy="16" r="12" fill={fill} {...p} />
          <circle cx="16" cy="16" r="6.5" fill="none" {...p} opacity={0.6} />
          <path d="M16 16L25 9" fill="none" {...p} />
          <circle cx="21" cy="21" r="2" fill={line} />
          <circle cx="16" cy="16" r="1.6" fill={line} />
        </g>
      )}
      {tab === "help" && (
        <g>
          <path d="M16 27C9 22 4 17.5 4 12.2A6 6 0 0 1 16 9a6 6 0 0 1 12 3.2C28 17.5 23 22 16 27Z" fill={fill} {...p} />
          <path d="M11 15h2.5l1.5-3 2.5 6 1.5-3H21" fill="none" {...p} />
        </g>
      )}
      {tab === "settings" && (
        <g>
          <rect x="4" y="4" width="24" height="24" rx="7" fill={fill} {...p} />
          <path d="M10 11h12M10 21h12" fill="none" {...p} />
          <circle cx="13" cy="11" r="2.6" fill={active ? "var(--dv-accent)" : "var(--dv-surface)"} {...p} />
          <circle cx="19" cy="21" r="2.6" fill={active ? "var(--dv-accent)" : "var(--dv-surface)"} {...p} />
        </g>
      )}
    </svg>
  );
}
