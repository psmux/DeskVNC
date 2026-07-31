/** Inline icon set, single coherent style, 1.5px stroke, 20px default (PRD/11 §8). */
import type { ReactNode, SVGProps } from "react";

export interface IconProps extends SVGProps<SVGSVGElement> {
  size?: number;
}

function Icon({ size = 20, children, ...rest }: IconProps & { children: ReactNode }): ReactNode {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconSearch = (p: IconProps): ReactNode => (
  <Icon {...p}><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></Icon>
);
export const IconGrid = (p: IconProps): ReactNode => (
  <Icon {...p}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></Icon>
);
export const IconList = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M8 6h13M8 12h13M8 18h13" /><path d="M3 6h.01M3 12h.01M3 18h.01" /></Icon>
);
export const IconPlus = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M12 5v14M5 12h14" /></Icon>
);
export const IconMonitor = (p: IconProps): ReactNode => (
  <Icon {...p}><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" /></Icon>
);
export const IconKey = (p: IconProps): ReactNode => (
  <Icon {...p}><circle cx="7.5" cy="15.5" r="4.5" /><path d="m11 12 9-9M17 6l3 3" /></Icon>
);
export const IconZap = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z" /></Icon>
);
export const IconStar = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.9L12 17.8 5.8 21l1.2-6.9-5-4.9 6.9-1L12 2z" /></Icon>
);
export const IconClock = (p: IconProps): ReactNode => (
  <Icon {...p}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 3" /></Icon>
);
export const IconFolder = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9L9.2 3.9A2 2 0 0 0 7.5 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z" /></Icon>
);
export const IconTag = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M12.6 2.9 21 11.4a2 2 0 0 1 0 2.8l-6.8 6.8a2 2 0 0 1-2.8 0L2.9 12.6A2 2 0 0 1 2.3 11V4.3a2 2 0 0 1 2-2H11a2 2 0 0 1 1.6.6z" /><circle cx="7.5" cy="7.5" r="1" fill="currentColor" /></Icon>
);
export const IconX = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M18 6 6 18M6 6l12 12" /></Icon>
);
export const IconArrowRight = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M5 12h14M13 6l6 6-6 6" /></Icon>
);
export const IconChevronDown = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="m6 9 6 6 6-6" /></Icon>
);
export const IconChevronRight = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="m9 6 6 6-6 6" /></Icon>
);
export const IconGear = (p: IconProps): ReactNode => (
  <Icon {...p}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.2a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.2a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.2a1.7 1.7 0 0 0 1 1.5h.1a1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5 1h.2a2 2 0 1 1 0 4h-.2a1.7 1.7 0 0 0-1.5 1z" /></Icon>
);
export const IconKeyboard = (p: IconProps): ReactNode => (
  <Icon {...p}><rect x="2" y="6" width="20" height="12" rx="2" /><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M6 14h.01M18 14h.01M9 14h6" /></Icon>
);
export const IconClipboard = (p: IconProps): ReactNode => (
  <Icon {...p}><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2" /></Icon>
);
export const IconFile = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7l-5-5z" /><path d="M14 2v5h5" /></Icon>
);
export const IconMaximize = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M8 3H5a2 2 0 0 0-2 2v3M16 3h3a2 2 0 0 1 2 2v3M8 21H5a2 2 0 0 1-2-2v-3M16 21h3a2 2 0 0 0 2-2v-3" /></Icon>
);
export const IconEye = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" /><circle cx="12" cy="12" r="3" /></Icon>
);
export const IconCamera = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M4 7h3l2-3h6l2 3h3a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z" /><circle cx="12" cy="13" r="3.5" /></Icon>
);
export const IconPower = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M12 2v10" /><path d="M18.4 6.6a9 9 0 1 1-12.8 0" /></Icon>
);
export const IconPin = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M12 17v5" /><path d="M9 3h6l-1 7 3 2v3H7v-3l3-2-1-7z" /></Icon>
);
export const IconActivity = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M22 12h-4l-3 8L9 4l-3 8H2" /></Icon>
);
export const IconRefresh = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M21 12a9 9 0 1 1-2.6-6.4" /><path d="M21 3v6h-6" /></Icon>
);
export const IconEdit = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M17 3a2.8 2.8 0 0 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" /></Icon>
);
export const IconTrash = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" /></Icon>
);
export const IconCheck = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="m4 12.5 5.5 5.5L20 6.5" /></Icon>
);
export const IconLock = (p: IconProps): ReactNode => (
  <Icon {...p}><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></Icon>
);
export const IconAlert = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /><path d="M12 9v4M12 17h.01" /></Icon>
);
export const IconChevronsUp = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="m17 11-5-5-5 5M17 18l-5-5-5 5" /></Icon>
);
export const IconGripVertical = (p: IconProps): ReactNode => (
  <Icon {...p}><circle cx="9" cy="6" r="1" fill="currentColor" /><circle cx="9" cy="12" r="1" fill="currentColor" /><circle cx="9" cy="18" r="1" fill="currentColor" /><circle cx="15" cy="6" r="1" fill="currentColor" /><circle cx="15" cy="12" r="1" fill="currentColor" /><circle cx="15" cy="18" r="1" fill="currentColor" /></Icon>
);
export const IconCommand = (p: IconProps): ReactNode => (
  <Icon {...p}><path d="M9 9V6a3 3 0 1 0-3 3h3zm0 0v6m0-6h6m-6 6v3a3 3 0 1 1-3-3h3zm6-6h3a3 3 0 1 0-3-3v3zm0 0v6m0 0h3a3 3 0 1 1-3 3v-3z" /></Icon>
);
