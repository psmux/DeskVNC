/**
 * Navigation: a bottom bar with big illustrated icons on a phone, a side rail
 * on a tablet. Same four places either way.
 */
import { TabIcon, type TabKey } from "../art/Icons";

export const TABS: { key: TabKey; label: string }[] = [
  { key: "computers", label: "Computers" },
  { key: "nearby", label: "Nearby" },
  { key: "help", label: "Help someone" },
  { key: "settings", label: "Settings" },
];

export function TabBar({ tab, onTab }: { tab: TabKey; onTab: (t: TabKey) => void }) {
  return (
    <nav
      className="pb-safe pl-safe pr-safe fixed inset-x-0 bottom-0 z-30 border-t border-line bg-surface/90 backdrop-blur-xl tab:hidden"
      aria-label="Main"
    >
      <div className="mx-auto flex max-w-xl">
        {TABS.map((t) => {
          const on = t.key === tab;
          return (
            <button
              key={t.key}
              type="button"
              onClick={() => onTab(t.key)}
              aria-current={on ? "page" : undefined}
              className="flex min-h-16 flex-1 flex-col items-center justify-center gap-0.5 pb-1.5 pt-2"
            >
              <span className={`flex h-9 w-16 items-center justify-center rounded-full transition-colors ${on ? "bg-accent-soft" : ""}`}>
                <TabIcon tab={t.key} active={on} size={30} />
              </span>
              <span className={`text-xs font-medium ${on ? "text-accent" : "text-ink-dim"}`}>{t.label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}

export function SideRail({ tab, onTab }: { tab: TabKey; onTab: (t: TabKey) => void }) {
  return (
    <nav className="pt-safe pb-safe pl-safe hidden w-28 shrink-0 flex-col items-center gap-2 overflow-y-auto border-r border-line bg-surface tab:flex" aria-label="Main">
      {/* The app icon, drawn the way the desktop and phone icons are. */}
      <div className="mb-4 mt-6 flex h-14 w-14 shrink-0 [@media(max-height:560px)]:hidden items-center justify-center rounded-[14px] bg-[linear-gradient(180deg,#1d62d9,#1447ad)] shadow-card">
        <svg viewBox="0 0 32 32" width="34" height="34" aria-hidden>
          <rect x="4" y="6" width="24" height="16" rx="1.5" fill="#fff" />
          <rect x="6" y="8" width="20" height="12" rx="0.5" fill="#3c82f5" />
          <path d="M16 22v4M11.5 27h9" stroke="#fff" strokeWidth={2.2} strokeLinecap="round" />
        </svg>
      </div>
      {TABS.map((t) => {
        const on = t.key === tab;
        return (
          <button
            key={t.key}
            type="button"
            onClick={() => onTab(t.key)}
            aria-current={on ? "page" : undefined}
            className={`flex w-24 shrink-0 flex-col items-center gap-1 rounded-[14px] py-3 transition-colors first-of-type:mt-3 ${on ? "bg-accent-soft" : "active:bg-surface-2"}`}
          >
            <TabIcon tab={t.key} active={on} size={36} />
            <span className={`text-sm font-medium ${on ? "text-accent" : "text-ink-dim"}`}>{t.label}</span>
          </button>
        );
      })}
    </nav>
  );
}
