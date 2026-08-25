/** Host tiles for the Library grid: saved hosts and the discovered-but-unsaved band. */
import { useEffect, useState, type ReactNode } from "react";
import type { DiscoveredHost, HostProfile, OsHint } from "../lib/types";
import {
  DEFAULT_PORT,
  hostMac,
  hostProtocol,
  isWindowsNameSource,
  nameSourceLabel,
  protocolLabel,
  resolvedOsHint,
} from "../lib/types";
import { classNames, colorFromId, formatBps } from "../lib/util";
import { useHosts } from "../state/HostsContext";
import { useSessions, type TileActivity } from "../state/SessionsContext";
import { IconKey, IconMonitor, IconZap, IconEdit, IconLock, IconAlert, IconPlus } from "./icons";

/**
 * The OS badge.
 *
 * "Remote" is the honest fallback: we do not know the operating system, and
 * the old fallback said "VNC", which is a protocol name standing in for one.
 * That became wrong the moment a Windows machine reached over RDP had no OS
 * hint, and the protocol has its own badge now.
 */
export function osLabel(os: OsHint | null): string {
  switch (os) {
    case "macos":
      return "macOS";
    case "windows":
      return "Windows";
    case "linux":
      return "Linux";
    case "qemu":
      return "QEMU";
    default:
      return "Remote";
  }
}

/** The address, with the port hidden when it is this protocol's default. */
export function addressLabel(host: {
  address: string;
  port: number;
  protocol?: string | null;
}): string {
  const dflt = DEFAULT_PORT[hostProtocol(host)];
  return host.port === dflt ? host.address : `${host.address}:${host.port}`;
}

/**
 * The protocol badge, shown on every tile once the library holds more than
 * one protocol and on none at all before that.
 *
 * One rule, no surprises, and it disappears entirely for the VNC-only user
 * who is the majority today. A per tile "only badge the unusual one" rule
 * reads as cleverness and leaves the user guessing what the unbadged tiles
 * are.
 */
export function ProtocolBadge({ protocol }: { protocol: string }): ReactNode {
  return (
    <span className="shrink-0 rounded-sm bg-inset px-1.5 py-px text-2xs font-medium text-tertiary">
      {protocolLabel(protocol)}
    </span>
  );
}

function OnlineDot({ online }: { online: boolean | null | undefined }): ReactNode {
  const cls = online ? "bg-success" : "bg-tertiary/60";
  const label = online ? "Online" : online === false ? "Unreachable" : "Status unknown";
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${cls}`} role="img" aria-label={label} />;
}

// ------------------------------------------------------------- live overlays
//
// The strip and sparkline sit over the thumbnail image, so their backdrop is
// effectively always dark (a black gradient scrim) whatever the app theme, // the series colors are chosen against that scrim, not against the surface.
// RX is the prominent series in the app's accent-blue family (a lighter step
// so it clears the dark backdrop); TX is the de-emphasized companion in
// translucent white. Values and labels stay in white text ink; identity comes
// from the key-dot beside each value and the ↓/↑ glyphs, never color alone.

/** RX series, lighter step of the app accent blue, legible on the scrim. */
const RX_COLOR = "#7fb0f9";
/**
 * TX series, de-emphasis white, secondary by design. At 50% over the scrim
 * (≈ #808080) it sits ΔE ≈ 19 from the blue for normal and CVD vision alike,
 * and identity never rides on color alone: the ↓/↑ glyphs, the key-dots and
 * the stroke weights all restate which line is which.
 */
const TX_COLOR = "rgba(255, 255, 255, 0.5)";

const SPARK_W = 56;
const SPARK_H = 16;
/**
 * Scale floor in bits/sec. The y-scale is linear against the 60 s window max,
 * but an idle link's max is a few kb/s, without a floor those samples would
 * be stretched to full height and read as violent noise.
 */
const SPARK_FLOOR_BPS = 256_000;

interface BandwidthInfo {
  rx: number;
  tx: number;
  samples: readonly { rx: number; tx: number }[];
}

/** Right-aligned polyline: newest sample at the right edge, history grows left. */
function sparkPoints(
  samples: readonly { rx: number; tx: number }[],
  pick: (s: { rx: number; tx: number }) => number,
  max: number,
): string {
  // 1px inset on every side so the stroke and its round caps never clip.
  const step = (SPARK_W - 2) / 59; // fixed per-sample step for the 60-sample window
  const points: string[] = [];
  for (let i = 0; i < samples.length; i++) {
    const x = SPARK_W - 1 - (samples.length - 1 - i) * step;
    const v = Math.min(Math.max(pick(samples[i]), 0), max);
    const y = SPARK_H - 1 - (v / max) * (SPARK_H - 2);
    points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  }
  return points.join(" ");
}

/** ~Last 60 s of throughput as two thin lines; rx prominent, tx secondary. */
function Sparkline({ samples }: { samples: BandwidthInfo["samples"] }): ReactNode {
  if (samples.length < 2) return null; // one point draws nothing
  let max = SPARK_FLOOR_BPS;
  for (const s of samples) max = Math.max(max, s.rx, s.tx);
  return (
    <svg
      width={SPARK_W}
      height={SPARK_H}
      viewBox={`0 0 ${SPARK_W} ${SPARK_H}`}
      className="shrink-0"
      aria-hidden="true"
    >
      <polyline
        points={sparkPoints(samples, (s) => s.tx, max)}
        fill="none"
        stroke={TX_COLOR}
        strokeWidth={1}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <polyline
        points={sparkPoints(samples, (s) => s.rx, max)}
        fill="none"
        stroke={RX_COLOR}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * Bottom strip over the thumbnail: `↓ rx ↑ tx` plus the sparkline, on a
 * gradient scrim so it reads on both the image and the placeholder color.
 * Shown whenever fresh stats exist, independent of the live-previews toggle.
 */
function BandwidthStrip({
  bandwidth,
  className,
}: {
  bandwidth: BandwidthInfo;
  className?: string;
}): ReactNode {
  return (
    <div
      className={classNames(
        "pointer-events-none absolute inset-x-0 bottom-0 flex items-end justify-between gap-2 px-2 pb-1.5 pt-5",
        "bg-linear-to-t from-black/65 to-transparent",
        className,
      )}
      // NOT a live region: these values tick every second, and a role="status"
      // would have a screen reader announce each tick.
      aria-label={`Bandwidth: down ${formatBps(bandwidth.rx)}, up ${formatBps(bandwidth.tx)}`}
    >
      {/* tabular figures: the values change every second and must not jitter */}
      <div className="flex min-w-0 items-center gap-2 text-2xs font-medium text-white/90 [font-variant-numeric:tabular-nums]">
        <span className="flex items-center gap-1 whitespace-nowrap">
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full"
            style={{ background: RX_COLOR }}
            aria-hidden="true"
          />
          ↓ {formatBps(bandwidth.rx)}
        </span>
        <span className="flex items-center gap-1 whitespace-nowrap">
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full"
            style={{ background: TX_COLOR }}
            aria-hidden="true"
          />
          ↑ {formatBps(bandwidth.tx)}
        </span>
      </div>
      <Sparkline samples={bandwidth.samples} />
    </div>
  );
}

/** Small "this picture is live" marker for tiles showing a preview stream. */
function LiveBadge(): ReactNode {
  return (
    <span className="pointer-events-none absolute right-1.5 top-1.5 flex items-center gap-1 rounded-pill bg-black/55 px-1.5 py-0.5 text-2xs font-semibold tracking-wide text-white/90">
      <span className="h-1.5 w-1.5 rounded-full bg-success motion-safe:animate-pulse" aria-hidden="true" />
      LIVE
    </span>
  );
}

/** The preview frame to show, or null (toggle off / none published yet). */
function livePreviewOf(activity: TileActivity, enabled: boolean): string | null {
  return enabled && activity.preview ? activity.preview.dataUrl : null;
}

export function HostTile({
  host,
  selected,
  flash,
  onConnect,
  onEdit,
  onWake,
  onContextMenu,
  showProtocol,
}: {
  host: HostProfile;
  selected: boolean;
  flash?: boolean;
  onConnect: () => void;
  onEdit: () => void;
  onWake: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
  /** True when the library holds more than one protocol; see
   *  {@link ProtocolBadge} for why it is all-or-nothing. */
  showProtocol?: boolean;
}): ReactNode {
  const { thumbnailUrl, requestThumbnail } = useHosts();
  const { forKey, livePreviews } = useSessions();
  const [hover, setHover] = useState(false);

  // Ask unconditionally rather than only when `thumbnailAt` is set. The PNG on
  // disk, not the column, is what decides whether there is a picture, and
  // the two drift apart easily (an ad-hoc session writes a file against no
  // profile row at all). A host without one costs a single empty IPC reply,
  // whereas trusting a stale null leaves a tile permanently blank.
  useEffect(() => {
    requestThumbnail(host.id);
  }, [host.id, host.thumbnailAt, requestThumbnail]);

  const thumb = thumbnailUrl(host.id);
  const activity = forKey(host.id);
  const preview = livePreviewOf(activity, livePreviews);

  return (
    <div
      // The Library's pointer pipeline reads this to know which tile a press,
      // a marquee sweep or a drag is about (see useHostDragSelect), so it must
      // stay on the outermost element of the tile.
      data-host-id={host.id}
      role="button"
      tabIndex={0}
      aria-label={`${host.friendlyName}, ${osLabel(host.osHint)}, ${host.address}. Press Enter to connect.`}
      className={classNames(
        "group relative cursor-default select-none overflow-hidden rounded-md border bg-surface text-left outline-none",
        "transition-[transform,box-shadow,border-color] duration-120 motion-reduce:transition-none",
        selected ? "border-accent ring-2 ring-accent/40" : "border-subtle",
        hover && "-translate-y-0.5 shadow-(--shadow-tile-lift)",
        !hover && "shadow-(--shadow-tile)",
        "active:scale-[0.98]",
      )}
      onPointerEnter={() => setHover(true)}
      onPointerLeave={() => setHover(false)}
      onDoubleClick={onConnect}
      onContextMenu={onContextMenu}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          onConnect();
        }
      }}
    >
      {/* 16:10 live preview, thumbnail, or hashed-color placeholder */}
      <div className="relative aspect-[16/10] w-full overflow-hidden bg-inset">
        {preview ? (
          <img src={preview} alt="" className="h-full w-full object-cover" draggable={false} />
        ) : thumb ? (
          <img src={thumb} alt="" className="h-full w-full object-cover" draggable={false} />
        ) : (
          <div
            className="flex h-full w-full items-center justify-center"
            style={{ background: colorFromId(host.id) }}
          >
            <IconMonitor size={40} className="text-white/80" />
          </div>
        )}
        {preview ? <LiveBadge /> : null}
        {activity.bandwidth ? (
          // Yields to the hover quick actions below, which land in the same spot.
          <BandwidthStrip
            bandwidth={activity.bandwidth}
            className="transition-opacity duration-120 group-hover:opacity-0 group-focus-within:opacity-0 motion-reduce:transition-none"
          />
        ) : null}
        {flash ? <div className="shutter-flash pointer-events-none absolute inset-0 bg-white" /> : null}
        {/* hover quick actions */}
        <div
          className={classNames(
            "absolute inset-x-0 bottom-0 flex items-center justify-center gap-1.5 p-2",
            "translate-y-2 opacity-0 transition-[transform,opacity] duration-120 motion-reduce:transition-none",
            "group-hover:translate-y-0 group-hover:opacity-100 group-focus-within:translate-y-0 group-focus-within:opacity-100",
          )}
        >
          <QuickAction label={`Connect to ${host.friendlyName}`} onClick={onConnect}>
            <IconZap size={14} /> Connect
          </QuickAction>
          <QuickAction label={`Edit ${host.friendlyName}`} onClick={onEdit}>
            <IconEdit size={14} /> Edit
          </QuickAction>
          {host.wolMac ? (
            <QuickAction label={`Wake ${host.friendlyName}`} onClick={onWake}>
              <IconZap size={14} /> Wake
            </QuickAction>
          ) : null}
        </div>
      </div>

      <div className="space-y-0.5 px-3 py-2.5">
        <div className="flex items-center gap-2">
          <OnlineDot online={host.online} />
          <span
            className="min-w-0 flex-1 truncate text-sm font-medium text-primary"
            title={host.friendlyName}
          >
            {host.friendlyName}
          </span>
          {host.hasPassword ? (
            <span className="shrink-0 text-tertiary" role="img" aria-label="Password saved">
              <IconKey size={14} />
            </span>
          ) : null}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-secondary">
          <span className="shrink-0 rounded-sm bg-inset px-1.5 py-px text-2xs font-medium text-tertiary">
            {osLabel(host.osHint)}
          </span>
          {showProtocol ? <ProtocolBadge protocol={host.protocol} /> : null}
          {/* Non-default ports are shown here as they are in the list view, two hosts on one machine are otherwise indistinguishable. */}
          <span className="mono min-w-0 flex-1 truncate" title={addressLabel(host)}>
            {addressLabel(host)}
          </span>
        </div>
      </div>
    </div>
  );
}

function QuickAction({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
}): ReactNode {
  return (
    <button
      type="button"
      aria-label={label}
      className="flex items-center gap-1 rounded-pill border border-subtle bg-raised/95 px-2.5 py-1 text-xs font-medium text-primary shadow-(--shadow-tile) hover:bg-raised"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      onDoubleClick={(e) => e.stopPropagation()}
    >
      {children}
    </button>
  );
}

/**
 * Thumbnail key for a host that is not in the library.
 *
 * MUST match `discovered_key` in `src-tauri/src/thumbnail.rs`: connecting to a
 * machine straight from the Nearby list is an ad-hoc session with no profile
 * UUID, so its screenshot is stored against the endpoint instead. Without this
 * the tile you most need to recognise, an unfamiliar machine, is the one that
 * never gets a picture.
 */
export function discoveredThumbKey(address: string, port: number): string {
  return `discovered:${address}:${port}`;
}

/**
 * Discovered-but-unsaved host: dashed border, distinct band (PRD/11 §3.1).
 *
 * Shows the screenshot from an earlier ad-hoc connect when there is one, and
 * the colour-hash placeholder when there genuinely is not.
 */
export function DiscoveredTile({
  host,
  onAdd,
  onConnect,
  thumb,
}: {
  host: DiscoveredHost;
  onAdd: () => void;
  onConnect: () => void;
  /**
   * blob: URL of a screenshot captured on a previous ad-hoc connect.
   * Optional override; by default the tile fetches its own, exactly as a
   * saved-host tile does.
   */
  thumb?: string | null;
}): ReactNode {
  const { thumbnailUrl, requestThumbnail } = useHosts();
  const { forKey, livePreviews } = useSessions();
  const key = discoveredThumbKey(host.address, host.port);

  // The tile asks for its own image. Leaving this to the Library was the
  // reason a Nearby machine never showed one: the grid read the cache but
  // nothing ever populated it for an endpoint key, so the lookup was null on
  // every render no matter how many screenshots were on disk.
  useEffect(() => {
    requestThumbnail(key);
  }, [key, requestThumbnail]);

  const image = thumb ?? thumbnailUrl(key);
  const activity = forKey(key);
  const preview = livePreviewOf(activity, livePreviews);

  // What the machine actually is, and why we believe it: a name answered over
  // NetBIOS / MS-RPC / RDP is proof of Windows and outranks the `osHint`
  // substring guess. Both inputs may be missing entirely (older event, mDNS-only
  // host), which resolves to the neutral "Remote" badge rather than crashing.
  const os = resolvedOsHint(host);
  const proven = isWindowsNameSource(host.nameSource);
  const via = nameSourceLabel(host.nameSource);
  const osTitle = proven
    ? `Windows, name resolved via ${via}, which only a Windows machine answers`
    : os === "unknown"
      ? "Operating system not identified"
      // Protocol neutral, and more accurate than it was: the inference has
      // always used NetBIOS and RDP certificates as well as the RFB banner.
      : `${osLabel(os)}, inferred from what it answers on the network`;

  // The MAC is not tile furniture: it is unreadable at a glance and only
  // matters at the moment you save the host (it becomes the Wake-on-LAN
  // address). So it rides along in the address tooltip, where someone
  // wondering "can I wake this?" will look, and nowhere else.
  const mac = hostMac(host);
  const address = addressLabel(host);
  const addressTitle = mac
    ? `${address}\nMAC ${mac}, saved as the Wake-on-LAN address when you add this host`
    : address;

  const secIcon =
    host.security === "unencrypted" ? (
      <span className="flex shrink-0 items-center gap-1 whitespace-nowrap text-warning">
        <IconAlert size={13} className="shrink-0" /> {host.securityHint ?? "Unencrypted"}
      </span>
    ) : (
      <span className="flex shrink-0 items-center gap-1 whitespace-nowrap text-secondary">
        <IconLock size={13} className="shrink-0" /> {host.securityHint ?? "Encrypted"}
      </span>
    );
  return (
    <div className="flex flex-col overflow-hidden rounded-md border border-dashed border-strong bg-transparent">
      <div
        className="relative flex aspect-[16/10] items-center justify-center overflow-hidden"
        style={{ background: `color-mix(in srgb, ${colorFromId(host.address)} 22%, transparent)` }}
      >
        {preview ? (
          <img src={preview} alt="" className="h-full w-full object-cover" draggable={false} />
        ) : image ? (
          <img
            src={image}
            alt=""
            className="h-full w-full object-cover"
            draggable={false}
          />
        ) : (
          <IconMonitor size={36} className="text-tertiary" />
        )}
        {preview ? <LiveBadge /> : null}
        {activity.bandwidth ? <BandwidthStrip bandwidth={activity.bandwidth} /> : null}
      </div>
      <div className="space-y-1.5 px-3 py-2.5">
        <div className="truncate text-sm font-medium text-primary" title={host.name}>
          {host.name}
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <span
            className="shrink-0 rounded-sm bg-inset px-1.5 py-px text-2xs font-medium text-tertiary"
            title={osTitle}
          >
            {osLabel(os)}
          </span>
          {host.protocol && host.protocol !== "vnc" ? (
            <ProtocolBadge protocol={host.protocol} />
          ) : null}
          <span
            className="mono min-w-0 flex-1 truncate text-secondary"
            title={addressTitle}
            aria-label={mac ? `${address}, MAC address ${mac}` : address}
          >
            {address}
          </span>
          {secIcon}
        </div>
        <div className="flex gap-1.5 pt-1">
          {/* "Add host" is the primary intent here, so it takes the leftover
              width; Connect stays at its natural size. */}
          <button
            type="button"
            className="btn-secondary min-w-0 flex-1 justify-center !px-2.5 !py-1 !text-xs"
            onClick={onAdd}
          >
            <IconPlus size={13} className="shrink-0" /> Add host
          </button>
          <button
            type="button"
            className="btn-secondary shrink-0 !px-2.5 !py-1 !text-xs"
            onClick={onConnect}
          >
            <IconZap size={13} className="shrink-0" /> Connect
          </button>
        </div>
      </div>
    </div>
  );
}
