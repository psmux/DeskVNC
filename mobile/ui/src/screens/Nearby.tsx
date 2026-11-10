/**
 * Find computers nearby: a radar that sweeps while the scan runs, a blip for
 * each computer found, then a card for it with Connect and Save.
 */
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import type { FoundComputer } from "../api/contract";
import { IconCheck, IconPlay, IconPlus, IconRefresh } from "../art/Icons";
import { OsArt } from "../art/OsArt";
import { ProtocolBadge } from "../components/ProtocolBadge";
import { Radar } from "../art/Radar";
import { SceneSleepyRadar } from "../art/Scenes";
import { Button } from "../components/Button";
import { haptic } from "../lib/haptics";
import { wizardFromFound } from "../lib/wizard";
import { useApp } from "../state/app";
import { ScreenHeader, ScreenScroll } from "./layout";

const keyOf = (f: FoundComputer) => `${f.address}:${f.port}`;

export function Nearby() {
  const app = useApp();
  const [highlight, setHighlight] = useState<string | null>(null);
  const started = useRef(false);
  const count = useRef(0);

  useEffect(() => {
    if (!started.current) {
      started.current = true;
      if (!app.scanning) void app.scan();
    }
  }, [app]);

  useEffect(() => {
    if (app.found.length > count.current) haptic("select");
    count.current = app.found.length;
  }, [app.found.length]);

  const saved = (f: FoundComputer) => app.hosts.find((h) => h.address === f.address && h.port === f.port) ?? null;
  const nothing = !app.scanning && app.found.length === 0;

  return (
    <ScreenScroll onRefresh={app.scan}>
      <ScreenHeader
        title="Nearby"
        subtitle={app.scanning ? "Looking around your network…" : app.found.length ? `Found ${app.found.length} ${app.found.length === 1 ? "computer" : "computers"} on this network` : undefined}
      />
      <div className="tab:px-8 @4xl:grid @4xl:grid-cols-[minmax(0,22rem)_1fr] @4xl:gap-8">
        <div className="px-6 tab:px-0 @4xl:sticky @4xl:top-4 @4xl:self-start">
          {nothing ? (
            <div className="flex flex-col items-center text-center">
              <SceneSleepyRadar className="w-64" />
              <h2 className="text-title2">Nothing found nearby</h2>
              <p className="mt-2 text-subhead text-ink-dim">Make sure your phone is on the same Wi-Fi as the computer, and that screen sharing or Remote Desktop is turned on there.</p>
            </div>
          ) : (
            <Radar
              className="mx-auto w-full max-w-[min(22rem,42dvh)]"
              scanning={app.scanning}
              blips={app.found.map((f) => ({ key: keyOf(f), protocol: f.protocol, os: f.os }))}
              onBlip={(k) => {
                haptic("select");
                setHighlight(k);
                document.getElementById(`found-${k}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
              }}
            />
          )}
          <div className="mt-4 flex justify-center">
            <Button variant={nothing ? "primary" : "soft"} size="lg" disabled={app.scanning} icon={<IconRefresh className={app.scanning ? "dv-spin" : ""} />} onClick={() => void app.scan()}>
              {app.scanning ? "Looking…" : "Look again"}
            </Button>
          </div>
          {nothing && (
            <div className="mt-3 flex justify-center">
              <Button variant="ghost" size="md" icon={<IconPlus />} onClick={() => app.openWizard()}>
                Add one by address
              </Button>
            </div>
          )}
        </div>

        <div className="mt-6 grid grid-cols-[repeat(auto-fill,minmax(min(100%,19rem),1fr))] gap-3 px-4 pb-6 tab:px-0 @4xl:mt-0">
          <AnimatePresence>
            {app.found.map((f) => {
              const k = keyOf(f);
              const host = saved(f);
              return (
                <motion.article
                  id={`found-${k}`}
                  key={k}
                  layout
                  initial={{ opacity: 0, scale: 0.85, y: 20 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  transition={{ type: "spring", stiffness: 380, damping: 26 }}
                  className={`rounded-[14px] border bg-surface p-4 shadow-card ${highlight === k ? "border-accent ring-1 ring-accent" : "border-line"}`}
                >
                  <div className="flex items-center gap-3">
                    <span className="flex h-20 w-24 shrink-0 items-center justify-center rounded-[10px] bg-surface-2"><OsArt os={f.os} backdrop={false} className="h-16 w-20" /></span>
                    <div className="min-w-0 flex-1">
                      <h3 className="truncate text-headline">{host?.name ?? f.name ?? "A computer"}</h3>
                      <ProtocolBadge protocol={f.protocol} className="mt-1" />
                      {host && (
                        <p className="mt-1.5 flex items-center gap-1 text-footnote font-medium text-ok">
                          <IconCheck size={16} /> On your list
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="mt-3 flex gap-2">
                    <Button
                      size="lg"
                      className="flex-1"
                      icon={<IconPlay size={12} />}
                      onClick={() =>
                        host
                          ? app.connect({ kind: "saved", hostId: host.id }, host.name)
                          : app.connect({ kind: "adhoc", protocol: f.protocol, address: f.address, port: f.port }, f.name ?? f.address)
                      }
                    >
                      Connect
                    </Button>
                    {!host && (
                      <Button variant="soft" size="lg" icon={<IconPlus size={18} />} onClick={() => app.openWizard(wizardFromFound(f))}>
                        Save
                      </Button>
                    )}
                  </div>
                </motion.article>
              );
            })}
          </AnimatePresence>
        </div>
      </div>
    </ScreenScroll>
  );
}
