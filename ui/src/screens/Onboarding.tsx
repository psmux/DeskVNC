/** Onboarding: 3 lightweight skippable steps, no account, ends in live discovery (PRD/11 §5). */
import { useState, type ReactNode } from "react";
import { useSettings, type ThemeChoice } from "../state/SettingsContext";
import { useDiscovery } from "../state/DiscoveryContext";
import { classNames } from "../lib/util";
import { IconMonitor, IconZap, IconLock } from "../components/icons";

export function Onboarding({
  onDone,
  onAddDiscovered,
}: {
  onDone: () => void;
  onAddDiscovered: (id: string) => void;
}): ReactNode {
  const [step, setStep] = useState(0);
  const { settings, update } = useSettings();
  const { discovered, scan, startScan } = useDiscovery();
  const [ranDiscovery, setRanDiscovery] = useState(false);

  const finish = (): void => {
    update({ onboarded: true });
    onDone();
  };

  return (
    <div className="flex h-full items-center justify-center bg-canvas p-6">
      <div className="w-[520px] max-w-full rounded-lg border border-subtle bg-surface p-8 shadow-(--shadow-pop)">
        {/* progress */}
        <div className="mb-6 flex items-center gap-2" aria-label={`Step ${step + 1} of 3`}>
          {[0, 1, 2].map((i) => (
            <span
              key={i}
              className={classNames(
                "h-1 flex-1 rounded-pill",
                i <= step ? "bg-accent" : "bg-inset",
              )}
            />
          ))}
        </div>

        {step === 0 ? (
          <div className="space-y-5">
            <div className="flex justify-center text-accent">
              <IconMonitor size={56} />
            </div>
            <h1 className="text-center text-xl font-semibold text-primary">Welcome to DeskVNCViewer</h1>
            <p className="text-center text-sm text-secondary">
              See and control your other computers, fast, secure, and entirely yours. No account, ever.
            </p>
            <div>
              <p className="mb-2 text-xs font-medium text-secondary">Appearance</p>
              <div className="flex gap-2" role="radiogroup" aria-label="Theme">
                {(["system", "light", "dark"] as ThemeChoice[]).map((t) => (
                  <button
                    key={t}
                    type="button"
                    role="radio"
                    aria-checked={settings.theme === t}
                    className={classNames(
                      "flex-1 rounded-md border px-3 py-2 text-sm capitalize",
                      settings.theme === t
                        ? "border-accent bg-accent/10 font-medium text-primary"
                        : "border-subtle text-secondary hover:border-strong",
                    )}
                    onClick={() => update({ theme: t })}
                  >
                    {t === "system" ? "Follow System" : t}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="space-y-5">
            <div className="flex justify-center text-accent">
              <IconZap size={56} />
            </div>
            <h1 className="text-center text-xl font-semibold text-primary">Find your computers</h1>
            <p className="text-center text-sm text-secondary">
              DeskVNCViewer listens for computers advertising screen sharing on your local network.
              Your OS may ask permission to access the local network, that's this feature.
            </p>
            {!ranDiscovery ? (
              <div className="flex justify-center">
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => {
                    setRanDiscovery(true);
                    void startScan();
                  }}
                >
                  <IconZap size={14} /> Find computers on my network
                </button>
              </div>
            ) : (
              <div className="rounded-md border border-subtle bg-inset/50 p-3">
                {scan.running ? (
                  <div className="mb-2 overflow-hidden rounded-pill bg-inset">
                    <div className="indeterminate-bar h-0.5 w-1/3 bg-accent" />
                  </div>
                ) : null}
                {discovered.length === 0 ? (
                  <p className="text-center text-xs text-tertiary">
                    {scan.running ? "Scanning your network…" : "Nothing found yet, some VNC servers don't advertise themselves. You can add one manually later."}
                  </p>
                ) : (
                  <ul className="max-h-40 space-y-1 overflow-y-auto">
                    {discovered.map((d) => (
                      <li key={d.id} className="flex items-center gap-2.5 rounded-sm px-2 py-1.5 text-sm text-primary">
                        <IconMonitor size={15} className="text-tertiary" />
                        <span className="flex-1 truncate">{d.name}</span>
                        <span className="mono text-xs text-tertiary">{d.address}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        ) : null}

        {step === 2 ? (
          <div className="space-y-5">
            <div className="flex justify-center text-accent">
              <IconLock size={56} />
            </div>
            <h1 className="text-center text-xl font-semibold text-primary">Save your first computer</h1>
            <p className="text-center text-sm text-secondary">
              Give it a friendly name and, if you save a password, it's stored in your system
              keychain, never in a file.
            </p>
            {discovered.length > 0 ? (
              <ul className="space-y-1.5">
                {discovered.slice(0, 4).map((d) => (
                  <li key={d.id}>
                    <button
                      type="button"
                      className="flex w-full items-center gap-2.5 rounded-md border border-subtle px-3 py-2 text-left text-sm text-primary hover:border-accent"
                      onClick={() => {
                        update({ onboarded: true });
                        onAddDiscovered(d.id);
                      }}
                    >
                      <IconMonitor size={16} className="text-tertiary" />
                      <span className="flex-1 truncate">{d.name}</span>
                      <span className="mono text-xs text-tertiary">{d.address}</span>
                      <span className="text-xs font-medium text-accent">Save…</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-center text-xs text-tertiary">
                No discovered computers to pre-fill, use “+ New Host” in the library instead.
              </p>
            )}
          </div>
        ) : null}

        <div className="mt-8 flex items-center justify-between">
          <button type="button" className="text-sm text-tertiary hover:text-primary" onClick={finish}>
            Skip
          </button>
          <div className="flex gap-2.5">
            {step > 0 ? (
              <button type="button" className="btn-secondary" onClick={() => setStep((s) => s - 1)}>
                Back
              </button>
            ) : null}
            {step < 2 ? (
              <button type="button" data-autofocus className="btn-primary" onClick={() => setStep((s) => s + 1)}>
                Continue
              </button>
            ) : (
              <button type="button" className="btn-primary" onClick={finish}>
                Open my library
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
