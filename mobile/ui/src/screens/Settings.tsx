/**
 * Settings: how the app looks, how touch works on a remote screen, picture
 * quality, haptics, and the small print.
 */
import { useState, type ReactNode } from "react";
import type { Quality } from "../api/contract";
import { IconChevron, IconExternal, IconPlay } from "../art/Icons";
import { SceneTouchMode } from "../art/Scenes";
import { Segmented, Toggle } from "../components/Field";
import { Sheet } from "../components/Sheet";
import { haptic } from "../lib/haptics";
import { setPrefs, usePrefs, type ThemeChoice, type TouchMode } from "../lib/prefs";
import { NameSheet } from "./Help";
import { ScreenHeader, ScreenScroll } from "./layout";

export const PRIVACY_URL = "https://deskvnc.ripeflow.com/privacy";
export const APP_VERSION = "1.0.0";

const LICENCES: { name: string; licence: string }[] = [
  { name: "React and React DOM", licence: "MIT" },
  { name: "Motion", licence: "MIT" },
  { name: "Tauri", licence: "MIT or Apache 2.0" },
  { name: "Tailwind CSS", licence: "MIT" },
  { name: "Vite", licence: "MIT" },
  { name: "DeskVNC protocol crates", licence: "See the DeskVNC repository" },
];

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mb-6">
      <h2 className="mb-2 px-2 text-sm font-bold uppercase tracking-wider text-ink-dim">{title}</h2>
      <div className="overflow-hidden rounded-[1.5rem] bg-surface shadow-card">{children}</div>
    </section>
  );
}

function Row({ icon, title, detail, trailing, onClick }: { icon: ReactNode; title: string; detail?: string; trailing?: ReactNode; onClick?: () => void }) {
  const inner = (
    <>
      <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl text-white">{icon}</span>
      <span className="min-w-0 flex-1">
        <span className="block text-lg font-semibold">{title}</span>
        {detail && <span className="block text-sm text-ink-dim">{detail}</span>}
      </span>
      {trailing}
    </>
  );
  const cls = "flex min-h-[4.25rem] w-full items-center gap-4 border-b border-line px-4 py-2 text-left last:border-b-0";
  return onClick ? (
    <button
      type="button"
      className={`${cls} active:bg-surface-2`}
      onClick={() => {
        haptic("tap");
        onClick();
      }}
    >
      {inner}
    </button>
  ) : (
    <div className={cls}>{inner}</div>
  );
}

function Swatch({ bg, children }: { bg: string; children: ReactNode }) {
  return (
    <span className="flex h-11 w-11 items-center justify-center rounded-2xl" style={{ background: bg }}>
      {children}
    </span>
  );
}

function ThemeArt({ mode }: { mode: ThemeChoice }) {
  const light = (
    <g>
      <rect x="2" y="2" width="36" height="26" rx="5" fill="#f5f3fc" stroke="#c9c3e6" strokeWidth={1.5} />
      <rect x="7" y="8" width="16" height="4" rx="2" fill="#6c4df6" />
      <rect x="7" y="16" width="24" height="3" rx="1.5" fill="#c9c3e6" />
    </g>
  );
  const dark = (
    <g>
      <rect x="2" y="2" width="36" height="26" rx="5" fill="#1d1b28" stroke="#35314a" strokeWidth={1.5} />
      <rect x="7" y="8" width="16" height="4" rx="2" fill="#8f78ff" />
      <rect x="7" y="16" width="24" height="3" rx="1.5" fill="#35314a" />
    </g>
  );
  return (
    <svg viewBox="0 0 40 30" width="48" height="36" aria-hidden>
      {mode === "light" && light}
      {mode === "dark" && dark}
      {mode === "system" && (
        <>
          <defs>
            <clipPath id="half">
              <path d="M0 0H40L0 30Z" />
            </clipPath>
          </defs>
          {dark}
          <g clipPath="url(#half)">{light}</g>
        </>
      )}
    </svg>
  );
}

function open(url: string) {
  window.open(url, "_blank", "noopener");
}

export function Settings({ onShowWelcome }: { onShowWelcome: () => void }) {
  const prefs = usePrefs();
  const [licences, setLicences] = useState(false);
  const [naming, setNaming] = useState(false);

  return (
    <ScreenScroll>
      <ScreenHeader title="Settings" />
      <div className="mx-auto max-w-2xl px-4 pb-8 tab:px-8">
        <Group title="Looks">
          <div className="p-3">
            <Segmented<ThemeChoice>
              label="Theme"
              value={prefs.theme}
              onChange={(theme) => setPrefs({ theme })}
              options={[
                { value: "system", label: "Automatic", art: <ThemeArt mode="system" /> },
                { value: "light", label: "Light", art: <ThemeArt mode="light" /> },
                { value: "dark", label: "Dark", art: <ThemeArt mode="dark" /> },
              ]}
            />
          </div>
        </Group>

        <Group title="Touching the remote screen">
          <div className="grid grid-cols-2 gap-3 p-3" role="radiogroup" aria-label="Touch mode">
            {(
              [
                { value: "trackpad", title: "Trackpad", text: "Slide to move a pointer, tap to click. Precise." },
                { value: "direct", title: "Direct touch", text: "Tap right where you want to click. Quick." },
              ] as { value: TouchMode; title: string; text: string }[]
            ).map((o) => {
              const on = prefs.touchMode === o.value;
              return (
                <button
                  key={o.value}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  onClick={() => {
                    haptic("select");
                    setPrefs({ touchMode: o.value });
                  }}
                  className={`flex flex-col items-center rounded-[1.25rem] border-2 p-3 text-center transition-colors ${on ? "border-accent bg-accent-soft" : "border-transparent bg-surface-2"}`}
                >
                  <SceneTouchMode mode={o.value} className="h-20" />
                  <span className="mt-1 text-lg font-bold">{o.title}</span>
                  <span className="mt-0.5 text-sm leading-snug text-ink-dim">{o.text}</span>
                </button>
              );
            })}
          </div>
          <div className="border-t border-line p-3">
            <p className="mb-2 px-1 font-semibold">Picture</p>
            <Segmented<Quality>
              label="Picture quality"
              value={prefs.quality}
              onChange={(quality) => setPrefs({ quality })}
              options={[
                { value: "auto", label: "Automatic" },
                { value: "speed", label: "Faster" },
                { value: "balanced", label: "Balanced" },
                { value: "quality", label: "Sharper" },
              ]}
            />
            <p className="mt-2 px-1 text-sm text-ink-dim">Automatic picks for you. Faster helps on a weak connection.</p>
          </div>
        </Group>

        <Group title="Feel">
          <Row
            icon={
              <Swatch bg="var(--dv-accent)">
                <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" strokeWidth={2.2} strokeLinecap="round" aria-hidden>
                  <rect x="8" y="4" width="8" height="16" rx="2" />
                  <path d="M4 9v6M20 9v6" />
                </svg>
              </Swatch>
            }
            title="Vibrate on taps"
            detail="A small buzz when you press things"
            trailing={<Toggle on={prefs.haptics} onChange={(haptics) => setPrefs({ haptics })} label="Vibrate on taps" />}
          />
          <Row
            icon={
              <Swatch bg="linear-gradient(135deg,#7c5cff,#ff7aa8)">
                <IconPlay size={20} className="text-white" />
              </Swatch>
            }
            title="Show the demo computer"
            detail="A pretend desktop to practise on"
            trailing={<Toggle on={prefs.showDemo} onChange={(showDemo) => setPrefs({ showDemo })} label="Show the demo computer" />}
          />
          <Row
            icon={
              <Swatch bg="var(--dv-boundary)">
                <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" strokeWidth={2.2} strokeLinecap="round" aria-hidden>
                  <circle cx="12" cy="8.5" r="3.5" />
                  <path d="M5 20a7 6 0 0 1 14 0" />
                </svg>
              </Swatch>
            }
            title="Your name when helping"
            detail={prefs.helperName || "Asked the first time you help someone"}
            trailing={<IconChevron className="text-ink-dim" />}
            onClick={() => setNaming(true)}
          />
          <Row
            icon={
              <Swatch bg="var(--dv-vnc)">
                <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <rect x="4" y="5" width="16" height="12" rx="2" />
                  <path d="M9 21h6" />
                  <path d="M10 9l4 2-4 2Z" fill="#fff" />
                </svg>
              </Swatch>
            }
            title="Show the welcome again"
            trailing={<IconChevron className="text-ink-dim" />}
            onClick={onShowWelcome}
          />
        </Group>

        <Group title="About">
          <Row
            icon={
              <Swatch bg="var(--dv-accent)">
                <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden>
                  <rect x="4" y="6" width="24" height="16" rx="3.5" fill="#fff" />
                  <path d="M12 27h8M16 22v5" stroke="#fff" strokeWidth={2.4} strokeLinecap="round" />
                </svg>
              </Swatch>
            }
            title="DeskVNC"
            detail={`Version ${APP_VERSION}. Open source.`}
          />
          <Row
            icon={
              <Swatch bg="var(--dv-ok)">
                <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6Z" />
                  <path d="M9 12l2 2 4-4" />
                </svg>
              </Swatch>
            }
            title="Privacy policy"
            detail="What the app keeps, and where"
            trailing={<IconExternal className="text-ink-dim" />}
            onClick={() => open(PRIVACY_URL)}
          />
          <Row
            icon={
              <Swatch bg="var(--dv-rdp)">
                <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M6 3h9l4 4v14H6Z" />
                  <path d="M9 12h7M9 16h5" />
                </svg>
              </Swatch>
            }
            title="Open source licences"
            trailing={<IconChevron className="text-ink-dim" />}
            onClick={() => setLicences(true)}
          />
        </Group>
      </div>

      <NameSheet
        open={naming}
        initial={prefs.helperName}
        onClose={() => setNaming(false)}
        onSave={(helperName) => {
          setPrefs({ helperName });
          setNaming(false);
        }}
      />
      <Sheet open={licences} onClose={() => setLicences(false)} title="Open source licences" subtitle="DeskVNC is built on the work of these projects. Thank you.">
        <ul className="divide-y divide-line rounded-2xl bg-surface-2">
          {LICENCES.map((l) => (
            <li key={l.name} className="flex min-h-14 items-center justify-between gap-3 px-4 py-2">
              <span className="font-semibold">{l.name}</span>
              <span className="text-right text-sm text-ink-dim">{l.licence}</span>
            </li>
          ))}
        </ul>
      </Sheet>
    </ScreenScroll>
  );
}
