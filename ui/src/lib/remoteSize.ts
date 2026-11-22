/**
 * What size to ask a remote desktop for when the window changes, and how to
 * tell whether the server went along with it.
 *
 * Issue #60: on a Retina Mac the window is measured in physical pixels, two
 * to the point. Asking for that many pixels with nothing else said gets a
 * Windows desktop drawn at 100 percent on a surface twice as wide as the
 * window looks, so every word on it is half size.
 *
 * The two protocols answer that differently because only one of them can.
 * Remote Desktop carries a scale factor beside the size (`desktopScaleFactor`
 * in the Client Core Data and in every MS-RDPEDISP monitor layout), so it
 * keeps the physical size, which stays sharp, and the shell sends the
 * screen's scale with it. RFB's SetDesktopSize has no such field, so a VNC
 * desktop is asked for in points and drawn scaled up, which is what every
 * other VNC viewer on a Mac does.
 */

import type { ProtocolKind } from "./types";

export interface Size {
  w: number;
  h: number;
}

/**
 * The size to send in a resize request for a canvas of `physW` by `physH`
 * physical pixels on a screen of `dpr` physical pixels to the point.
 */
export function remoteResizeTarget(
  protocol: ProtocolKind,
  physW: number,
  physH: number,
  dpr: number,
): Size {
  if (protocol === "rdp") return { w: Math.round(physW), h: Math.round(physH) };
  const ratio = Number.isFinite(dpr) && dpr > 1 ? dpr : 1;
  return {
    w: Math.max(1, Math.round(physW / ratio)),
    h: Math.max(1, Math.round(physH / ratio)),
  };
}

/**
 * How far a server may land from the size asked for and still count as
 * having done it. RDP aligns the width down to a multiple of eight before it
 * leaves (MS-RDPEDISP 2.2.2.2.1), and servers of both kinds round to what
 * their display driver allows.
 */
export const RESIZE_TOLERANCE = 16;

/** How long a server gets to rebuild its desktop before we call it a no. */
export const RESIZE_GRACE_MS = 6000;

export function closeEnough(a: Size, b: Size): boolean {
  return Math.abs(a.w - b.w) <= RESIZE_TOLERANCE && Math.abs(a.h - b.h) <= RESIZE_TOLERANCE;
}

/**
 * Watches resize requests for a server that never answers them.
 *
 * Neither protocol says no in a way that reaches the window. An RDP server
 * without the display control channel never opens it and the request waits
 * forever; a Windows guest whose display driver refuses the layout accepts
 * the PDU and keeps its size; a VNC server without ExtendedDesktopSize is
 * not asked at all. What they have in common is that no new desktop size
 * arrives, so that is what this measures.
 *
 * `onRefused` fires once per run of refusals, and again only after a resize
 * has worked in between, so a window dragged about on a server that cannot
 * resize says so once rather than on every edge move.
 */
export class ResizeWatch {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private reported = false;

  constructor(
    private readonly onRefused: (asked: Size, got: Size) => void,
    private readonly graceMs = RESIZE_GRACE_MS,
  ) {}

  /** A request for `asked` just went out while the desktop was `current`. */
  requested(asked: Size, current: Size | null): void {
    this.cancel();
    // Nothing to compare against yet (not connected), or nothing to change.
    if (!current || closeEnough(asked, current)) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      if (this.reported) return;
      this.reported = true;
      this.onRefused(asked, current);
    }, this.graceMs);
  }

  /** The server sent a new desktop size: it is listening. */
  resized(): void {
    this.cancel();
    this.reported = false;
  }

  cancel(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }
}
