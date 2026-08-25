/**
 * Mock data used ONLY when running in a plain browser (`npm run dev` without
 * the Tauri shell), so the UI is explorable while the backend is being built.
 */
import {
  blankHostProfile,
  type CredentialKind,
  type CredentialRequest,
  type DiscoveredHost,
  type HostGroup,
  type HostProfile,
  type HostTag,
} from "./types";
import { inTauri } from "./tauri";

export function useMockData(): boolean {
  return import.meta.env.DEV && !inTauri();
}

const now = Math.floor(Date.now() / 1000);

export const MOCK_GROUPS: HostGroup[] = [
  { id: "g-home", name: "Home", parentId: null, sort: 0 },
  { id: "g-office", name: "Office", parentId: null, sort: 1 },
  { id: "g-lab", name: "Lab", parentId: "g-office", sort: 0 },
];

export const MOCK_TAGS: HostTag[] = [
  { id: "t-prod", name: "prod", color: "#e5544b" },
  { id: "t-dev", name: "dev", color: "#4f8ef7" },
  { id: "t-media", name: "media", color: "#34c26b" },
];

export const MOCK_HOSTS: HostProfile[] = [
  {
    ...blankHostProfile(),
    id: "h-studio", friendlyName: "Studio Mac", address: "192.168.1.42", port: 5900,
    groupId: "g-home", osHint: "macos", serverHint: "macOS Screen Sharing",
    qualityPref: "auto", scalingMode: "aspect-fit",
    hasPassword: true, favorite: true, tags: ["t-media"],
    lastConnected: now - 3600, connectCount: 42, online: true,
  },
  {
    ...blankHostProfile(),
    id: "h-proxmox", friendlyName: "Proxmox node 2", address: "10.0.0.7", port: 5901,
    groupId: "g-lab", osHint: "qemu", serverHint: "QEMU",
    qualityPref: "high", scalingMode: "aspect-fit",
    wolMac: "aa:bb:cc:dd:ee:ff", hasPassword: true,
    tags: ["t-prod", "t-dev"], lastConnected: now - 86400,
    connectCount: 17, online: true,
  },
  {
    ...blankHostProfile(),
    id: "h-win", friendlyName: "Front-desk PC", address: "office-pc.local", port: 5900,
    groupId: "g-office", osHint: "windows", serverHint: "TightVNC",
    qualityPref: "auto", scalingMode: "fit",
    online: false,
  },
  // One RDP profile is enough to exercise the whole of the RDP interface with
  // no backend: the protocol badge and the protocol column both appear (the
  // library now holds two protocols), the address label hides 3389 rather than
  // 5900, the editor opens on the RDP side of the selector, and the parsed
  // blob fills Advanced.
  {
    ...blankHostProfile("rdp"),
    id: "h-rdp", friendlyName: "Reception PC", address: "10.0.0.31", port: 3389,
    rdpSettings: JSON.stringify({
      v: 1,
      clipboard: true, microphone: false, consoleSession: false, restrictedAdmin: false,
      domain: "CORP", nla: "required", legacyTls: false, colorDepth: "bpp32",
      audio: "play-locally", monitors: "all", resolution: { mode: "window-at-connect" },
    }),
    groupId: "g-office", osHint: "windows", serverHint: "Windows Remote Desktop",
    qualityPref: "auto", scalingMode: "aspect-fit",
    hasPassword: true, tags: ["t-prod"],
    lastConnected: now - 7200, connectCount: 9, online: true,
  },
];

/**
 * Covers every branch of the discovery metadata the tiles have to survive:
 * a name from mDNS with no MAC, an event with neither field present at all
 * (older shell build), a NetBIOS name that PROVES Windows while `osHint` is
 * still guessing "unknown", and a Windows proof with no MAC to carry.
 */
export const MOCK_DISCOVERED: DiscoveredHost[] = [
  {
    id: "192.168.1.55:5900", name: "iMac-Kitchen", address: "192.168.1.55", port: 5900,
    osHint: "macos", serverHint: "macOS Screen Sharing", securityHint: "Apple auth",
    security: "unverified", securityTypes: [30], source: "mdns",
    mac: null, nameSource: "mdns",
    savedHostId: null,
  },
  {
    // Deliberately missing `mac` and `nameSource` entirely, an event from a
    // shell that predates them. Must render, and must not say "undefined".
    id: "192.168.1.60:5900", name: "192.168.1.60", address: "192.168.1.60", port: 5900,
    osHint: "unknown", serverHint: "VNC server (RFB 3.8)", securityHint: "VncAuth",
    security: "unencrypted", securityTypes: [2], source: "scan",
    savedHostId: null,
  },
  {
    // The interesting one: only Windows answers NetBIOS, so the badge must say
    // Windows even though `osHint` came back "unknown".
    id: "192.168.1.70:5900", name: "FRONTDESK-01", address: "192.168.1.70", port: 5900,
    osHint: "unknown", serverHint: "VNC server (RFB 3.8)", securityHint: "VncAuth",
    security: "unencrypted", securityTypes: [2], source: "scan",
    mac: "9c:53:22:6a:36:7c", nameSource: "netbios",
    savedHostId: null,
  },
  {
    // Same endpoint as the saved "Studio Mac", so it never shows in the Nearby
    // band, it is here to drive the other half of the feature: opening that
    // host's editor offers the MAC discovery has since learned for it.
    id: "192.168.1.42:5900", name: "Studio Mac", address: "192.168.1.42", port: 5900,
    osHint: "macos", serverHint: "macOS Screen Sharing", securityHint: "Apple auth",
    security: "unverified", securityTypes: [30], source: "mdns",
    mac: "3c:22:fb:81:04:9d", nameSource: "mdns",
    savedHostId: null,
  },
  {
    id: "192.168.1.71:5901", name: "LAB-WS-04", address: "192.168.1.71", port: 5901,
    osHint: "unknown", serverHint: "TightVNC", securityHint: "VncAuth",
    security: "unencrypted", securityTypes: [2], source: "scan",
    mac: null, nameSource: "rdp-cert",
    savedHostId: null,
  },
  // An RDP-only machine, which is what the Nearby band shows for a Windows
  // box that runs no VNC server at all. `nlaRequired` is null because one
  // negotiation cannot answer it; only the on-demand deep probe can.
  {
    id: "10.0.0.88:3389", name: "WAREHOUSE-01", address: "10.0.0.88", port: 3389,
    osHint: "windows", serverHint: "Windows Remote Desktop", securityHint: null,
    security: "unverified", securityTypes: [], source: "scan",
    mac: null, nameSource: "rdp-cert",
    protocol: "rdp",
    rdp: {
      tls: true, nla: true, nlaRequired: null, gfx: true,
      extendedClientData: true, restrictedAdmin: false, redirectedAuth: false,
      standardOnly: false, failureCode: null, selectedProtocol: 3,
    },
    savedHostId: null,
  },
];

// ---------------------------------------------------------------------------
// Thumbnails (PRD/03 §3)
// ---------------------------------------------------------------------------

/**
 * Stand-in for `capture_thumbnail` / `get_thumbnail` + the `library://thumbnail`
 * broadcast, so the whole tile-thumbnail chain is exercisable in a plain
 * browser: the mock session really reads its WebGL framebuffer back, really
 * downscales it, and the Library really re-reads it on the event.
 *
 * Backed by `sessionStorage` because the browser dev build navigates (rather
 * than opening a second window) between the Library and a session, and keyed by
 * host id exactly like the on-disk PNG cache is.
 */
const MOCK_THUMB_KEY = "deskvnc.mock.thumbnails";

/** DOM equivalent of the Tauri `library://thumbnail` event. */
export const MOCK_THUMBNAIL_EVENT = "mock://thumbnail";

export interface ThumbnailUpdate {
  hostId: string;
  capturedAt: number;
}

interface MockThumb extends ThumbnailUpdate {
  /** PNG data: URL, no blob to revoke, unlike the real ArrayBuffer path. */
  url: string;
}

function readMockThumbs(): Record<string, MockThumb> {
  try {
    const raw = window.sessionStorage.getItem(MOCK_THUMB_KEY);
    return raw ? (JSON.parse(raw) as Record<string, MockThumb>) : {};
  } catch {
    return {};
  }
}

/** The stored mock PNG for a host, or null. */
export function mockThumbnail(hostId: string): MockThumb | null {
  return readMockThumbs()[hostId] ?? null;
}

/**
 * Mock `capture_thumbnail`: downscale the raw RGBA to the same 480px-wide cap
 * the Rust store uses, keep it as a PNG data URL, and announce it.
 *
 * Rows are copied straight into an ImageData, so an upside-down framebuffer
 * read would show up as an upside-down tile, which is the point.
 */
export function saveMockThumbnail(
  hostId: string,
  width: number,
  height: number,
  rgba: Uint8Array,
): void {
  const source = document.createElement("canvas");
  source.width = width;
  source.height = height;
  const sctx = source.getContext("2d");
  if (!sctx) return;
  sctx.putImageData(new ImageData(new Uint8ClampedArray(rgba), width, height), 0, 0);

  const outW = Math.min(480, width);
  const outH = Math.max(1, Math.round((height * outW) / width));
  const target = document.createElement("canvas");
  target.width = outW;
  target.height = outH;
  const tctx = target.getContext("2d");
  if (!tctx) return;
  tctx.drawImage(source, 0, 0, outW, outH);

  const entry: MockThumb = {
    hostId,
    capturedAt: Math.floor(Date.now() / 1000),
    url: target.toDataURL("image/png"),
  };
  const all = readMockThumbs();
  all[hostId] = entry;
  try {
    window.sessionStorage.setItem(MOCK_THUMB_KEY, JSON.stringify(all));
  } catch {
    /* quota, the event below still updates the live tile */
  }
  window.dispatchEvent(
    new CustomEvent<ThumbnailUpdate>(MOCK_THUMBNAIL_EVENT, {
      detail: { hostId, capturedAt: entry.capturedAt },
    }),
  );
}

/**
 * Thumbnail key for a machine that is not in the library.
 *
 * Mirrors `discoveredThumbKey` in `components/HostTile.tsx` and
 * `discovered_key` in `src-tauri/src/thumbnail.rs`; duplicated here so the
 * seeding below has no import cycle with the components.
 */
function discoveredKey(address: string, port: number): string {
  return `discovered:${address}:${port}`;
}

/**
 * Which key a capture is stored under, browser-dev edition.
 *
 * Mirrors what the shell resolves from its session registry
 * (`AppState::claim_thumbnail`): a saved host uses its profile id, and a
 * session started from the Nearby list, which has no profile, is keyed by
 * endpoint so it still gets a picture. Null only when there is nothing at all
 * to file it under.
 */
export function mockThumbnailKey(
  profileId: string | null,
  address: string | null,
  port: number,
): string | null {
  if (profileId) return profileId;
  return address ? discoveredKey(address, port) : null;
}

/** A recognisable fake desktop: gradient wallpaper with a window on top. */
function fakeDesktopRGBA(width: number, height: number, hue: number): Uint8Array {
  const px = new Uint8Array(width * height * 4);
  const win = {
    x: Math.round(width * 0.18),
    y: Math.round(height * 0.16),
    w: Math.round(width * 0.64),
    h: Math.round(height * 0.62),
  };
  const hsl = (h: number, s: number, l: number): [number, number, number] => {
    const k = (n: number): number => (n + h / 30) % 12;
    const a = s * Math.min(l, 1 - l);
    const f = (n: number): number =>
      Math.round(255 * (l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)))));
    return [f(0), f(8), f(4)];
  };
  for (let y = 0; y < height; y++) {
    const t = y / height;
    const [br, bg, bb] = hsl(hue, 0.55, 0.22 + t * 0.28);
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      let r = br;
      let g = bg;
      let b = bb;
      const inWin = x >= win.x && x < win.x + win.w && y >= win.y && y < win.y + win.h;
      if (inWin) {
        const titleBar = y < win.y + Math.round(height * 0.06);
        [r, g, b] = titleBar ? hsl(hue, 0.2, 0.72) : hsl(hue, 0.08, 0.93);
        // "text" lines in the window body
        const row = y - win.y - Math.round(height * 0.1);
        if (!titleBar && row > 0 && row % 22 < 7 && x < win.x + win.w * 0.8) {
          [r, g, b] = hsl(hue, 0.3, 0.45);
        }
      }
      px[i] = r;
      px[i + 1] = g;
      px[i + 2] = b;
      px[i + 3] = 255;
    }
  }
  return px;
}

/**
 * Seed the mock cache from the URL, so the *discovered* half of the thumbnail
 * chain is drivable in a plain browser.
 *
 * A Nearby tile gets its picture from an earlier ad-hoc session, which the
 * browser dev build cannot really run (there is no VNC server and no shell to
 * hold the session registry). This stands in for "you connected to this
 * machine once already": it writes a real PNG under the same
 * `discovered:<address>:<port>` key the Rust store uses and fires the same
 * update event, so everything downstream, request, fetch, blob, render, is
 * the production path.
 *
 *   `?mockThumbs=discovered`  every host in the Nearby band
 *   `?mockThumbs=all`         …and the saved hosts too
 *   `?mockThumb=<key>`        one explicit key, repeatable
 *
 * Returns the keys seeded.
 */
export function seedMockThumbnails(): string[] {
  if (!useMockData()) return [];
  const q = new URLSearchParams(window.location.search);
  const which = q.get("mockThumbs");
  const keys = [...q.getAll("mockThumb")];
  if (which === "discovered" || which === "all") {
    for (const d of MOCK_DISCOVERED) keys.push(discoveredKey(d.address, d.port));
  }
  if (which === "all") {
    for (const h of MOCK_HOSTS) keys.push(h.id);
  }
  const seeded: string[] = [];
  for (const key of keys) {
    if (!key || seeded.includes(key)) continue;
    let hash = 0;
    for (const ch of key) hash = (hash * 31 + ch.charCodeAt(0)) % 360;
    saveMockThumbnail(key, 640, 400, fakeDesktopRGBA(640, 400, hash));
    seeded.push(key);
  }
  return seeded;
}

/**
 * Apply captured mock thumbnails onto the seed host list, so `thumbnailAt`
 * behaves like the SQLite column does after a reload.
 */
export function withMockThumbnails(hosts: HostProfile[]): HostProfile[] {
  const all = readMockThumbs();
  return hosts.map((h) =>
    all[h.id] ? { ...h, thumbnailAt: all[h.id].capturedAt } : h,
  );
}

// ---------------------------------------------------------------------------
// Interactive auth prompt (PRD/10 §3.4)
// ---------------------------------------------------------------------------

/**
 * Build a synthetic `credentials-required` request from the URL, so the auth
 * dialog is reachable in the browser dev build (no Tauri, no VNC server).
 *
 * `?mockCreds=<kind>` turns it on; the rest are optional knobs:
 *   `mockCreds`     `password-only` (default) | `username-and-password` | `rdp`
 *   `mockAttempt`   1-based attempt number; >1 renders the retry banner
 *   `mockError`     rejection reason shown in that banner
 *   `mockTruncates` `0` to suppress the 8-character legacy-VNC warning
 *   `mockMethod`    override the method label
 *   `mockUser`      username prefill
 *   `mockDomain`    domain prefill, only meaningful with `mockCreds=rdp`
 *
 * `mockCreds=rdp` is what makes the domain field, the `CORP\alice` splitter
 * and the Windows-flavoured introduction reviewable in a plain browser. The
 * domain field itself is driven by the SESSION's protocol rather than by
 * anything on the request, so the mock session reads `?protocol=rdp` for
 * that; this flag supplies the rest of the prompt's shape.
 *
 * Returns null in a real Tauri session or when the flag is absent, so this can
 * never shadow a genuine prompt.
 */
export function mockCredentialRequest(): CredentialRequest | null {
  if (!useMockData()) return null;
  const q = new URLSearchParams(window.location.search);
  const flag = q.get("mockCreds");
  if (!flag) return null;

  const rdp = flag === "rdp";
  const kind: CredentialKind =
    rdp || flag === "username-and-password" ? "username-and-password" : "password-only";
  const attempt = Math.max(1, parseInt(q.get("mockAttempt") ?? "1", 10) || 1);
  const truncates = q.get("mockTruncates") !== "0" && kind === "password-only";

  return {
    method:
      q.get("mockMethod") ??
      (rdp
        ? "CredSSP (NTLM)"
        : kind === "username-and-password"
          ? "VeNCrypt (X509Plain)"
          : "VNC Authentication"),
    kind,
    attempt,
    error:
      attempt > 1 ? (q.get("mockError") ?? "The server rejected that password.") : null,
    // Never fires for RDP: nothing in CredSSP truncates a password at eight
    // characters, so there is nothing to warn about.
    truncatesPassword: rdp ? false : truncates,
    usernameHint:
      q.get("mockUser") ?? (rdp ? "alice" : kind === "username-and-password" ? "admin" : null),
  };
}

/**
 * A synthetic terminal failure, so the disconnect copy can be read and
 * reviewed in a plain browser.
 *
 * `?mockError=ntlm-policy` is the one that matters: it is the message a
 * domain user under a Kerberos-only policy will hit, it names two Group
 * Policy settings in the words an administrator sees in `gpedit`, and it
 * cannot be produced without a domain controller configured that way.
 *
 *   `ntlm-policy`           the domain refuses NTLM
 *   `nla-refused`           the server refuses network level authentication
 *   `legacy-tls`            the server offers nothing above TLS 1.1
 *   `legacy-tls-unavailable` this build cannot use those versions
 */
export function mockDisconnectReason(): string | null {
  if (!useMockData()) return null;
  const q = new URLSearchParams(window.location.search);
  switch (q.get("mockError")) {
    case "ntlm-policy":
      return "ntlm-refused-by-policy";
    case "nla-refused":
      return "nla-refused";
    case "legacy-tls":
      return "legacy-tls-required";
    case "legacy-tls-unavailable":
      return "legacy-tls-unavailable";
    default:
      return null;
  }
}
