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
      className="overflow-hidden rounded-[1.75rem] bg-surface shadow-card"
      onContextMenu={(e) => {
        e.preventDefault();
        onMenu();
      }}
    >
      <div className="relative aspect-[16/9] w-full overflow-hidden" style={{ background: `linear-gradient(160deg, ${sw.soft}, ${sw.main}33)` }}>
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
            <OsArt os={host.os} color={host.color} className="mx-auto h-full py-3" backdrop={false} />
          )}
        </button>
        <span className="pointer-events-none absolute left-3 top-3">
          <ProtocolBadge protocol={host.protocol} solid />
        </span>
        {online !== null && (
          <span className="pointer-events-none absolute bottom-3 left-3 inline-flex items-center gap-2 rounded-full bg-black/55 px-3 py-1.5 text-sm font-semibold text-white backdrop-blur">
            <span className={`h-2.5 w-2.5 rounded-full ${online ? "bg-[#3ddc8f] shadow-[0_0_0_3px_rgba(61,220,143,0.35)]" : "bg-white/50"}`} />
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
          <span className={`flex h-10 w-10 items-center justify-center rounded-full backdrop-blur ${host.favorite ? "bg-[#ffb520] text-white" : "bg-black/35 text-white"}`}>
            <IconStar filled={host.favorite} size={22} />
          </span>
        </button>
      </div>
      <div className="flex items-center gap-3 p-4 pl-5">
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-xl font-bold leading-tight">{host.name}</h3>
          <p className="mt-0.5 truncate text-sm text-ink-dim">{usedAgo(host.lastConnectedAt)}</p>
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
        <button
          type="button"
          onClick={() => {
            haptic("tap");
            onConnect();
          }}
          className="inline-flex min-h-14 shrink-0 items-center gap-2 rounded-[1.25rem] px-5 text-lg font-bold text-white shadow-card transition-transform active:scale-95"
          style={{ background: sw.deep }}
        >
          <IconPlay size={20} />
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
      className="relative overflow-hidden rounded-[1.75rem] text-white shadow-card"
      style={{ background: "linear-gradient(135deg, #7c5cff 0%, #b45cff 55%, #ff7aa8 100%)" }}
    >
      <div className="flex items-center gap-2 p-4 pr-3">
        <OsArt os="demo" color="violet" backdrop={false} className="h-24 w-32 shrink-0 drop-shadow-lg" />
        <div className="min-w-0 flex-1">
          <p className="text-xs font-bold uppercase tracking-wider text-white/75">Try it out</p>
          <h3 className="text-xl font-bold leading-tight">Demo computer</h3>
          <p className="mt-1 text-sm leading-snug text-white/85">A pretend desktop to practise on. Nothing to set up.</p>
        </div>
      </div>
      <div className="flex gap-2 px-4 pb-4">
        <button
          type="button"
          onClick={() => {
            haptic("tap");
            onConnect();
          }}
          className="inline-flex min-h-14 flex-1 items-center justify-center gap-2 rounded-[1.25rem] bg-white text-lg font-bold text-[#5b3fd9] shadow-card transition-transform active:scale-95"
        >
          <IconPlay size={20} />
          Try the demo
        </button>
        {onHide && (
          <button
            type="button"
            onClick={onHide}
            className="min-h-14 rounded-[1.25rem] bg-white/20 px-4 text-base font-semibold transition-transform active:scale-95"
          >
            Hide
          </button>
        )}
      </div>
    </motion.article>
  );
}
