/**
 * Your computers: big cards with a picture and one Connect button each.
 * Favourites first, a search when the list grows, pull down to refresh, and
 * the demo computer always within reach.
 */
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Host } from "../api/contract";
import { IconClose, IconEdit, IconPlay, IconPlus, IconSearch, IconStar, IconTrash } from "../art/Icons";
import { OsArt } from "../art/OsArt";
import { SceneEmptyDesk } from "../art/Scenes";
import { Button, IconButton } from "../components/Button";
import { ComputerCard, DemoCard } from "../components/ComputerCard";
import { ActionSheet, ConfirmSheet } from "../components/sheets/ActionSheet";
import { setPrefs, usePrefs } from "../lib/prefs";
import { wizardFromHost } from "../lib/wizard";
import { presenceKey, useApp } from "../state/app";
import { ScreenHeader, ScreenScroll } from "./layout";

export function Computers() {
  const app = useApp();
  const prefs = usePrefs();
  const [query, setQuery] = useState("");
  const [menuFor, setMenuFor] = useState<Host | null>(null);
  const [deleting, setDeleting] = useState<Host | null>(null);
  const scannedOnce = useRef(false);

  // One quiet look around when the list first shows, so the cards can say
  // which computers are nearby right now.
  useEffect(() => {
    if (app.loaded && app.hosts.length > 0 && !scannedOnce.current) {
      scannedOnce.current = true;
      void app.scan();
    }
  }, [app.loaded, app.hosts.length, app]);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return app.hosts
      .filter((h) => !q || h.name.toLowerCase().includes(q) || h.address.toLowerCase().includes(q))
      .sort((a, b) => Number(b.favorite) - Number(a.favorite) || (b.lastConnectedAt ?? 0) - (a.lastConnectedAt ?? 0) || a.name.localeCompare(b.name));
  }, [app.hosts, query]);

  const online = (h: Host): boolean | null => {
    if (h.protocol === "boundary") return null;
    if (app.seen.size === 0 && app.scanning) return null;
    if (app.seen.size === 0) return null;
    return app.seen.has(presenceKey(h.address, h.port));
  };

  const demo = () => app.connect({ kind: "demo" }, "Demo computer");
  const hideDemo = () => {
    setPrefs({ showDemo: false });
    app.showToast("Demo hidden. Bring it back in Settings.");
  };

  const refresh = async () => {
    await Promise.all([app.refresh(), app.scan()]);
  };

  if (app.loaded && app.hosts.length === 0) {
    return (
      <ScreenScroll onRefresh={refresh}>
        <ScreenHeader title="Your computers" />
        <div className="mx-auto flex max-w-md flex-col items-center px-6 pb-6 text-center">
          <SceneEmptyDesk className="w-72 max-w-full" />
          <h2 className="mt-2 text-2xl font-bold">No computers yet</h2>
          <p className="mt-2 text-lg text-ink-dim">Add the computers you want to reach from this phone. It only takes a minute.</p>
          <div className="mt-6 flex w-full flex-col gap-3">
            <Button size="xl" block icon={<RadarMini />} onClick={() => app.setTab("nearby")}>
              Find computers nearby
            </Button>
            <Button variant="plain" size="xl" block icon={<IconPlus />} onClick={() => app.openWizard()}>
              Add a computer
            </Button>
          </div>
        </div>
        <div className="mx-auto max-w-md px-4 pb-8">
          <DemoCard onConnect={demo} />
        </div>
      </ScreenScroll>
    );
  }

  return (
    <ScreenScroll onRefresh={refresh}>
      <ScreenHeader
        title="Your computers"
        action={
          <IconButton label="Add a computer" className="!bg-accent !text-white" onClick={() => app.openWizard()}>
            <IconPlus size={26} />
          </IconButton>
        }
      />
      {app.hosts.length > 3 && (
        <div className="px-4 pb-4 tab:px-8">
          <label className="flex min-h-14 items-center gap-3 rounded-2xl bg-surface px-4 shadow-card focus-within:ring-2 focus-within:ring-accent">
            <IconSearch className="text-ink-dim" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search your computers"
              aria-label="Search your computers"
              className="min-w-0 flex-1 bg-transparent py-3 text-lg outline-none placeholder:text-ink-dim/70"
            />
            {query && (
              <button type="button" aria-label="Clear search" className="flex h-10 w-10 items-center justify-center text-ink-dim" onClick={() => setQuery("")}>
                <IconClose size={20} />
              </button>
            )}
          </label>
        </div>
      )}
      <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,18rem),1fr))] gap-4 px-4 pb-8 tab:gap-6 tab:px-8">
        <AnimatePresence initial={false}>
          {list.map((h) => (
            <ComputerCard
              key={h.id}
              host={h}
              thumb={app.thumbs[h.id]}
              online={online(h)}
              onConnect={() => app.connect({ kind: "saved", hostId: h.id }, h.name)}
              onMenu={() => setMenuFor(h)}
              onFavorite={() => void app.toggleFavorite(h)}
            />
          ))}
        </AnimatePresence>
        {query && list.length === 0 && (
          <div className="col-span-full flex flex-col items-center py-10 text-center">
            <SearchEmpty />
            <p className="mt-3 text-lg font-semibold">Nothing called "{query}"</p>
            <Button variant="ghost" size="md" onClick={() => setQuery("")}>
              Show them all
            </Button>
          </div>
        )}
        {!query && prefs.showDemo && <DemoCard onConnect={demo} onHide={hideDemo} />}
      </div>

      <ActionSheet
        open={!!menuFor}
        onClose={() => setMenuFor(null)}
        art={menuFor ? <OsArt os={menuFor.os} color={menuFor.color} /> : undefined}
        title={menuFor?.name}
        actions={
          menuFor
            ? [
                { label: "Connect", icon: <IconPlay size={20} />, onPick: () => app.connect({ kind: "saved", hostId: menuFor.id }, menuFor.name) },
                { label: "Edit", icon: <IconEdit size={20} />, onPick: () => app.openWizard(wizardFromHost(menuFor)) },
                {
                  label: menuFor.favorite ? "Remove from favourites" : "Add to favourites",
                  icon: <IconStar size={20} filled={menuFor.favorite} />,
                  onPick: () => void app.toggleFavorite(menuFor),
                },
                { label: "Delete", icon: <IconTrash size={20} />, danger: true, onPick: () => setDeleting(menuFor) },
              ]
            : []
        }
      />
      <ConfirmSheet
        open={!!deleting}
        onClose={() => setDeleting(null)}
        art={deleting ? <OsArt os={deleting.os} color={deleting.color} /> : undefined}
        title={`Delete ${deleting?.name ?? ""}?`}
        subtitle="It leaves this phone, along with any saved password. The computer itself is not touched."
        confirm="Delete"
        onConfirm={() => {
          if (deleting) {
            void app.deleteHost(deleting.id);
            app.showToast(`${deleting.name} deleted`);
          }
        }}
      />
    </ScreenScroll>
  );
}

function RadarMini() {
  return (
    <svg viewBox="0 0 24 24" width="26" height="26" aria-hidden fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round">
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4.5" opacity={0.6} />
      <path d="M12 12l6.5-4.5" />
      <circle cx="16" cy="16" r="1.4" fill="currentColor" />
    </svg>
  );
}

function SearchEmpty() {
  return (
    <motion.div initial={{ scale: 0.8 }} animate={{ scale: 1 }} className="flex h-24 w-24 items-center justify-center rounded-full bg-surface-2 text-ink-dim">
      <IconSearch size={44} />
    </motion.div>
  );
}

