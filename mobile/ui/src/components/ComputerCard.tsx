/**
 * A saved computer as a big card: its picture, name, how to reach it and one
 * Connect button. Long press or the dots open the menu.
 */
import { motion } from "motion/react";
import { useRef } from "react";
import type { Host } from "../api/contract";
import { IconMore, IconPlay, IconStar } from "../art/Icons";
import { OsArt } from "../art/OsArt";
import { haptic } from "../lib/haptics";
import { usedAgo } from "../lib/time";
import { swatch } from "../theme/palette";
import { ProtocolBadge } from "./ProtocolBadge";

interface Props {
  host: Host;
  thumb: string | null | undefined;
  online: boolean | null;
  onConnect: () => void;
  onMenu: () => void;
  onFavorite: () => void;
}

export function ComputerCard({ host, thumb, online, onConnect, onMenu, onFavorite }: Props) {
  const sw = swatch(host.color);
  const press = useRef<ReturnType<typeof setTimeout> | null>(null);
  const startPress = () => {
    press.current = setTimeout(() => {
      haptic("select");
      onMenu();
    }, 550);
  };
  const cancelPress = () => press.current && clearTimeout(press.current);
  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="@container overflow-hidden rounded-[14px] border border-line bg-surface shadow-card"
      onContextMenu={(e) => {
        e.preventDefault();
        onMenu();
      }}
    >
      <div className="relative aspect-[16/9] w-full overflow-hidden border-b border-line bg-surface-2">
        <button
          type="button"
          className="absolute inset-0 block h-full w-full"
          onClick={onConnect}
          onPointerDown={startPress}
          onPointerUp={cancelPress}
          onPointerLeave={cancelPress}
          aria-label={`Connect to ${host.name}`}
        >
          {thumb ? (
            <img src={thumb} alt="" className="h-full w-full object-cover" draggable={false} />
          ) : (
            <OsArt os={host.os} className="mx-auto h-full py-4" backdrop={false} />
          )}
        </button>
        <span className="pointer-events-none absolute left-3 top-3">
          <ProtocolBadge protocol={host.protocol} solid />
        </span>
        {online !== null && (
          <span className="pointer-events-none absolute bottom-3 left-3 inline-flex items-center gap-2 rounded-full bg-black/60 px-2.5 py-1 text-[13px] font-medium text-white backdrop-blur">
            <span className={`h-2 w-2 rounded-full ${online ? "bg-[#3fc873]" : "bg-white/50"}`} />
            {online ? "Nearby now" : "Not seen nearby"}
          </span>
        )}
        <button
          type="button"
          onClick={onFavorite}
          aria-label={host.favorite ? "Remove from favourites" : "Add to favourites"}
          aria-pressed={host.favorite}
          className="absolute right-1.5 top-1.5 flex h-12 w-12 items-center justify-center rounded-full"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-black/45 text-white backdrop-blur">
            <IconStar filled={host.favorite} size={17} strokeWidth={1.8} />
          </span>
        </button>
      </div>
      {/* A narrow card puts Connect on its own line so the name keeps its room. */}
      <div className="flex flex-col gap-3 p-4 pl-5 @[21rem]:flex-row @[21rem]:items-center">
        <div className="flex min-w-0 flex-1 items-center gap-1">
        <div className="min-w-0 flex-1">
          <h3 className="flex items-center gap-2 text-lg font-semibold leading-tight">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: sw.main }} aria-hidden />
            <span className="truncate">{host.name}</span>
          </h3>
          <p className="mt-0.5 truncate pl-[1.125rem] text-sm text-ink-dim">{usedAgo(host.lastConnectedAt)}</p>
        </div>
        <button
          type="button"
          onClick={() => {
            haptic("tap");
            onMenu();
          }}
          aria-label={`More for ${host.name}`}
          className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-ink-dim active:bg-surface-2"
        >
          <IconMore />
        </button>
        </div>
        <button
          type="button"
          onClick={() => {
            haptic("tap");
            onConnect();
          }}
          className="inline-flex min-h-12 shrink-0 items-center justify-center gap-2 rounded-[10px] bg-accent px-5 text-base font-semibold text-accent-ink transition-transform active:scale-[0.98]"
        >
          <IconPlay size={16} />
          Connect
        </button>
      </div>
    </motion.article>
  );
}

/** The built in demo computer, always there to try. */
export function DemoCard({ onConnect, onHide }: { onConnect: () => void; onHide?: () => void }) {
  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative overflow-hidden rounded-[14px] border border-line bg-surface shadow-card"
    >
      <div className="flex items-center gap-3 p-4 pr-3">
        <span className="flex h-20 w-28 shrink-0 items-center justify-center rounded-[10px] bg-surface-2">
          <OsArt os="demo" backdrop={false} className="h-16 w-24" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-wider text-ink-faint">Try it out</p>
          <h3 className="text-lg font-semibold leading-tight">Demo computer</h3>
          <p className="mt-1 text-sm leading-snug text-ink-dim">A pretend desktop to practise on. Nothing to set up.</p>
        </div>
      </div>
      <div className="flex gap-2 px-4 pb-4">
        <button
          type="button"
          onClick={() => {
            haptic("tap");
            onConnect();
          }}
          className="inline-flex min-h-12 flex-1 items-center justify-center gap-2 rounded-[10px] bg-accent text-base font-semibold text-accent-ink transition-transform active:scale-[0.98]"
        >
          <IconPlay size={16} />
          Try the demo
        </button>
        {onHide && (
          <button
            type="button"
            onClick={onHide}
            className="min-h-12 rounded-[10px] border border-line bg-surface-2 px-4 text-base font-medium transition-transform active:scale-[0.98]"
          >
            Hide
          </button>
        )}
      </div>
    </motion.article>
  );
}
