/** Preferences: sidebar-tabbed, every setting with a one-line description (PRD/11 §3.4). */
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useSettings, type ThemeChoice } from "../state/SettingsContext";
import { useSessions } from "../state/SessionsContext";
import { ALLOW_MULTIPLE_SESSIONS_KEY, safeInvoke } from "../lib/tauri";
import {
  PREF_CLIPBOARD_AUTO,
  PREF_CLIPBOARD_ON_FOCUS,
  PREF_MATCH_LOCAL_LAYOUT,
  PREF_NATURAL_SCROLL,
  readBoolPref,
  writeBoolPref,
} from "../lib/prefs";
import { classNames } from "../lib/util";
import { IconX } from "../components/icons";

const TABS = [
  "General", "Appearance", "Connections", "Input", "Clipboard", "Files", "Security", "Network",
] as const;
type Tab = (typeof TABS)[number];

/**
 * localStorage-backed preference (until the backend settings store lands).
 *
 * Storage goes through `lib/prefs`, which is also what the code acting on
 * these preferences reads. Anything that writes a key here by hand is a
 * preference nothing can consult.
 */
function usePref(key: string, initial: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = useState<boolean>(() => readBoolPref(key, initial));
  useEffect(() => {
    writeBoolPref(key, v);
  }, [key, v]);
  return [v, setV];
}


/**
 * A preference that lives in the Rust store rather than localStorage, because
 * the backend has to consult it while building a connection (the webview is
 * not involved at that point).
 */
function useAppSetting(key: string, initial: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = useState<boolean>(initial);
  useEffect(() => {
    let cancelled = false;
    void safeInvoke<string | null>("get_app_setting", { key }, null).then((raw) => {
      if (!cancelled && raw !== null && raw !== undefined) setV(raw !== "false");
    });
    return () => {
      cancelled = true;
    };
  }, [key]);
  const set = useCallback(
    (next: boolean) => {
      setV(next);
      void safeInvoke("set_app_setting", { key, value: next ? "true" : "false" }, null);
    },
    [key],
  );
  return [v, set];
}

export function Preferences({ onClose }: { onClose: () => void }): ReactNode {
  const [tab, setTab] = useState<Tab>("General");
  const { settings, update } = useSettings();
  // The same toggle as the Library header, one source of truth, and flipping
  // it here broadcasts to session windows exactly the same way.
  const { livePreviews, setLivePreviews } = useSessions();
  const [credBackend, setCredBackend] = useState<string | null>(null);

  const [confirmDisconnect, setConfirmDisconnect] = usePref("confirmDisconnect", true);
  const [reconnectForever, setReconnectForever] = usePref("reconnectForever", true);
  const [wolDuringRetry, setWolDuringRetry] = usePref("wolDuringRetry", false);
  const [captureThumbs, setCaptureThumbs] = usePref("captureThumbs", true);
  const [naturalScroll, setNaturalScroll] = usePref(PREF_NATURAL_SCROLL, true);
  const [matchLocalLayout, setMatchLocalLayout] = usePref(PREF_MATCH_LOCAL_LAYOUT, false);
  // Store-backed (not localStorage): Rust reads these at connect time.
  const [losslessRefresh, setLosslessRefresh] = useAppSetting("lossless_refresh", true);
  const [deepNames, setDeepNames] = useAppSetting("probe_other_services", true);
  const [multipleSessions, setMultipleSessions] = useAppSetting(ALLOW_MULTIPLE_SESSIONS_KEY, false);
  const [clipboardAuto, setClipboardAuto] = usePref(PREF_CLIPBOARD_AUTO, true);
  const [clipboardOnFocus, setClipboardOnFocus] = usePref(PREF_CLIPBOARD_ON_FOCUS, true);
  const [confirmFileOverwrite, setConfirmFileOverwrite] = usePref("confirmFileOverwrite", true);
  const [strictTofu, setStrictTofu] = usePref("strictTofu", true);
  const [mdnsEnabled, setMdnsEnabled] = usePref("mdnsEnabled", true);

  useEffect(() => {
    void safeInvoke<string | null>("credential_backend", undefined, null).then(setCredBackend);
  }, []);

  // Escape closes, like every other modal in the app (the X was the only way out).
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  return (
    <div
      className="fade-in fixed inset-0 z-40 flex items-center justify-center bg-scrim"
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Preferences"
        className="flex h-[560px] w-[760px] max-w-[calc(100vw-32px)] overflow-hidden rounded-lg border border-subtle bg-surface shadow-(--shadow-pop)"
      >
        <nav className="w-44 shrink-0 space-y-0.5 border-r border-subtle bg-inset/40 p-2.5" aria-label="Preference sections">
          {TABS.map((t) => (
            <button
              key={t}
              type="button"
              aria-current={tab === t ? "true" : undefined}
              className={classNames(
                "block w-full rounded-sm px-2.5 py-1.5 text-left text-sm",
                tab === t ? "bg-accent/15 font-medium text-primary" : "text-secondary hover:bg-inset",
              )}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ))}
        </nav>
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex items-center justify-between border-b border-subtle px-5 py-3">
            <h2 className="text-base font-semibold text-primary">{tab}</h2>
            <button type="button" aria-label="Close preferences" className="rounded-sm p-1 text-tertiary hover:text-primary" onClick={onClose}>
              <IconX size={16} />
            </button>
          </div>
          <div className="flex-1 space-y-5 overflow-y-auto p-5">
            {tab === "General" ? (
              <>
                <Toggle
                  label="Confirm before disconnecting"
                  description="Ask before ending a session from the toolbar"
                  value={confirmDisconnect}
                  onChange={setConfirmDisconnect}
                />
                <Toggle
                  label="Capture thumbnails"
                  description="Save a small screenshot of each host after connecting, for the library grid"
                  value={captureThumbs}
                  onChange={setCaptureThumbs}
                />
                <Toggle
                  label="Live previews"
                  description="While a session is connected, its library tile shows a live picture (about 2 frames per second) instead of the saved thumbnail"
                  value={livePreviews}
                  onChange={setLivePreviews}
                />
                <Toggle
                  label="Compact library density"
                  description="Smaller tiles and tighter spacing for large libraries"
                  value={settings.compact}
                  onChange={(v) => update({ compact: v })}
                />
              </>
            ) : null}
            {tab === "Appearance" ? (
              <>
                <div>
                  <p className="text-sm font-medium text-primary">Theme</p>
                  <p className="mb-2 text-xs text-tertiary">Follow System switches automatically with your OS</p>
                  <div className="flex gap-2" role="radiogroup" aria-label="Theme">
                    {(["system", "light", "dark"] as ThemeChoice[]).map((t) => (
                      <button
                        key={t}
                        type="button"
                        role="radio"
                        aria-checked={settings.theme === t}
                        className={classNames(
                          "rounded-md border px-4 py-2 text-sm capitalize",
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
              </>
            ) : null}
            {tab === "Connections" ? (
              <>
                <Toggle
                  label="Show sessions as tabs in one window"
                  description="Connected computers become tabs across the top of this window, switched between like browser tabs, instead of each opening a window of its own. Sessions already running stay where they are; this decides where the next one goes."
                  value={settings.windowMode === "tabs"}
                  onChange={(v) => update({ windowMode: v ? "tabs" : "windows" })}
                />
                <Toggle
                  label={
                    settings.windowMode === "tabs"
                      ? "Allow more than one tab per computer"
                      : "Allow more than one window per computer"
                  }
                  description={
                    settings.windowMode === "tabs"
                      ? "Normally, connecting to a computer you're already connected to selects the tab it is in instead of starting a second session. Turn this on to open a separate tab every time."
                      : "Normally, connecting to a computer you're already connected to brings that window back to the front instead of starting a second session. Turn this on to open a separate window every time."
                  }
                  value={multipleSessions}
                  onChange={setMultipleSessions}
                />
                <Toggle
                  label="Sharpen the picture when motion stops"
                  description="During movement the image is compressed hard so it stays instant; a moment after things settle, the affected area is repainted at full quality. Turn this off on a metered connection to keep the saved bandwidth."
                  value={losslessRefresh}
                  onChange={setLosslessRefresh}
                />
                <Toggle
                  label="Reconnect until I close the window"
                  description="Keep retrying dropped sessions with exponential backoff"
                  value={reconnectForever}
                  onChange={setReconnectForever}
                />
                <Toggle
                  label="Send Wake-on-LAN during retries"
                  description="If a host with a saved MAC address looks down, send a magic packet while reconnecting"
                  value={wolDuringRetry}
                  onChange={setWolDuringRetry}
                />
              </>
            ) : null}
            {tab === "Input" ? (
              <>
                <Toggle
                  label="Natural scrolling"
                  description="Match your local scroll direction on the remote desktop"
                  value={naturalScroll}
                  onChange={setNaturalScroll}
                />
                <Toggle
                  label="Match my local keyboard layout"
                  description="Keys type what they type on this keyboard, instead of what the remote machine's layout assigns to the same physical key. Only matters when the two layouts differ."
                  value={matchLocalLayout}
                  onChange={setMatchLocalLayout}
                />
                <Toggle
                  label="Show the remote pointer"
                  description="Draw the remote machine's own mouse cursor. Turn this off if two pointers feel distracting, your input is sent either way."
                  value={settings.showRemoteCursor}
                  onChange={(v) => update({ showRemoteCursor: v })}
                />
              </>
            ) : null}
            {tab === "Clipboard" ? (
              <>
                <Toggle
                  label="Sync clipboard automatically"
                  description="Text copied on either side is available on the other"
                  value={clipboardAuto}
                  onChange={setClipboardAuto}
                />
                <Toggle
                  label="Push clipboard when the window gains focus"
                  description="Send your local clipboard to the remote when you switch back to the session"
                  value={clipboardOnFocus}
                  onChange={setClipboardOnFocus}
                />
              </>
            ) : null}
            {tab === "Files" ? (
              <>
                <Toggle
                  label="Confirm before overwriting files"
                  description="Ask when a transfer would replace an existing file"
                  value={confirmFileOverwrite}
                  onChange={setConfirmFileOverwrite}
                />
              </>
            ) : null}
            {tab === "Security" ? (
              <>
                <div>
                  <p className="text-sm font-medium text-primary">Credential storage</p>
                  <p className="text-xs text-tertiary">
                    {credBackend
                      ? `Passwords are stored in: ${credBackend}`
                      : "Passwords are stored in your operating system keychain, never in a file."}
                  </p>
                </div>
                <Toggle
                  label="Strict certificate pinning"
                  description="Refuse to connect when a server's certificate changes, until you explicitly re-trust it"
                  value={strictTofu}
                  onChange={setStrictTofu}
                />
              </>
            ) : null}
            {tab === "Network" ? (
              <>
                <Toggle
                  label="Look up names from other services"
                  description="Some Windows machines block every name service. Reading the name they publish on RDP or RPC names them anyway, but it means connecting briefly to ports unrelated to VNC, which strict network monitoring may flag. Turn off to use name services only."
                  value={deepNames}
                  onChange={setDeepNames}
                />
                <Toggle
                  label="Discover computers automatically (mDNS/Bonjour)"
                  description="Listen for VNC servers advertising themselves on your local network"
                  value={mdnsEnabled}
                  onChange={setMdnsEnabled}
                />
                <Toggle
                  label="Probe saved hosts for online status"
                  description="A lightweight, throttled TCP check that powers the green dot on tiles"
                  value={settings.probeOnline}
                  onChange={(v) => update({ probeOnline: v })}
                />
              </>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

function Toggle({
  label,
  description,
  value,
  onChange,
}: {
  label: string;
  description: string;
  value: boolean;
  onChange: (v: boolean) => void;
}): ReactNode {
  return (
    <label className="flex items-start justify-between gap-6">
      <span>
        <span className="block text-sm font-medium text-primary">{label}</span>
        <span className="block text-xs text-tertiary">{description}</span>
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={value}
        aria-label={label}
        className={classNames(
          // p-0 matters: a <button> carries default padding, and the knob below
          // is positioned from its *static* position, that padding was pushing
          // the dot past the right edge of the track.
          "relative mt-0.5 box-border h-5 w-9 shrink-0 rounded-pill p-0 transition-colors",
          value ? "bg-accent" : "bg-inset border border-subtle",
        )}
        onClick={() => onChange(!value)}
      >
        <span
          className={classNames(
            // Anchored with an explicit left/top so the knob can never depend
            // on inherited padding or the border the "off" state adds.
            "absolute left-0.5 top-1/2 h-4 w-4 -translate-y-1/2 rounded-full bg-white shadow transition-transform",
            value ? "translate-x-4" : "translate-x-0",
          )}
        />
      </button>
    </label>
  );
}
