/** About & Help: identity, build fingerprint, and reference material worth having offline. */
import { useEffect, useState, type ReactNode } from "react";
import { Dialog } from "../components/primitives";
import { openExternal, safeInvoke, writeClipboard } from "../lib/tauri";
import { classNames, modKeyLabel } from "../lib/util";

export const AUTHOR_NAME = "Godwin Josh";
export const AUTHOR_EMAIL = "godwin@cdtech.in";
export const PROJECT_URL = "https://github.com/psmux/DeskVNC";

type Tab = "About" | "Help";

/** Mirror of the Rust `AboutInfo` struct (src-tauri/src/commands/about.rs). */
interface AboutInfo {
  appVersion: string;
  gitDescribe: string;
  gitHash: string;
  gitHashShort: string;
  gitBranch: string;
  gitCommitDate: string;
  gitDirty: string;
  buildProfile: string;
  rustcVersion: string;
  tauriVersion: string;
  os: string;
  osVersion: string;
  arch: string;
  webviewVersion: string;
}

/**
 * The build stamp is compiled into the Rust binary (build.rs), so it can
 * never drift from what is actually running. Null in the plain-browser dev
 * server, where there is no runtime to ask.
 */
function useAboutInfo(): AboutInfo | null {
  const [info, setInfo] = useState<AboutInfo | null>(null);
  useEffect(() => {
    let cancelled = false;
    void safeInvoke<AboutInfo | null>("about_info", undefined, null).then((i) => {
      if (!cancelled) setInfo(i);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return info;
}

/**
 * The paste-into-an-issue block. Everything support needs to check out the
 * exact code a report came from, in the order a human scans it: what build,
 * which commit, on what machine.
 */
export function buildReport(i: AboutInfo): string {
  const dirty = i.gitDirty === "dirty" ? ", locally modified (dirty)" : "";
  return [
    "```",
    `DeskVNCViewer ${i.appVersion} (${i.gitDescribe})`,
    `Commit:  ${i.gitHash}`,
    `         branch ${i.gitBranch}, committed ${i.gitCommitDate}${dirty}`,
    `Build:   ${i.buildProfile} profile, tauri ${i.tauriVersion}, ${i.rustcVersion}`,
    `System:  ${i.os} ${i.osVersion} (${i.arch}), webview ${i.webviewVersion}`,
    "```",
  ].join("\n");
}

const SHORTCUTS: Array<[string, string]> = [
  [`${modKeyLabel}K`, "Command palette"],
  [`${modKeyLabel}N`, "New host"],
  [`${modKeyLabel}T`, "Jump to the QuickConnect address bar"],
  [`${modKeyLabel}F`, "Search the library"],
  [`${modKeyLabel},`, "Preferences"],
  [`${modKeyLabel}⇧D`, "Disconnect session"],
  [`${modKeyLabel}⇧M`, "Show/hide session toolbar"],
  [`${modKeyLabel}⌃F`, "Toggle fullscreen"],
  // Tabbed view only (Preferences → Connections). Harmless to list either
  // way: with no tabs open there is nothing for them to switch to.
  ["⌃⇥ / ⌃⇧⇥", "Next / previous tab"],
  [`${modKeyLabel}1…9`, "Jump to a tab (1 is the library)"],
  [`${modKeyLabel}⇧W`, "Close the current tab"],
  [`${modKeyLabel}⇧L`, "Back to the library"],
  // Splitting a tab into panes. Every one carries Alt, because the plain
  // pairs already mean something and a near miss here costs a connection.
  [`${modKeyLabel}⌥D`, "Split the pane to the right"],
  [`${modKeyLabel}⌥⇧D`, "Split the pane downwards"],
  [`${modKeyLabel}⌥←↑↓→`, "Move to the pane in that direction"],
  [`${modKeyLabel}⌥[ / ]`, "Previous / next pane"],
  [`${modKeyLabel}⌥Z`, "Maximise the current pane, or restore it"],
  [`${modKeyLabel}⌥=`, "Give every pane an equal share"],
  [`${modKeyLabel}⌥W`, "Close the current pane"],
];

const TROUBLESHOOTING: Array<[string, string]> = [
  [
    "A host is not showing up in Scan network",
    "Discovery uses mDNS and a subnet sweep, so it only sees hosts on the same network segment. Add it by IP with New Host instead.",
  ],
  [
    "The connection drops and keeps retrying",
    "Reconnect is automatic by default. Turn it off, or enable Wake-on-LAN during retry, in Preferences → Connections.",
  ],
  [
    "Keyboard input is not reaching the remote machine",
    "Check that View Only is off in the Session menu. On macOS, input capture also needs Accessibility permission.",
  ],
  [
    "Saved passwords are requested again every launch",
    "The app stores credentials in the OS keychain. Preferences → Security shows which backend is active and whether it is unlocked.",
  ],
];

export function About({ onClose }: { onClose: () => void }): ReactNode {
  const [tab, setTab] = useState<Tab>("About");
  const info = useAboutInfo();
  const [copied, setCopied] = useState(false);

  const copyReport = (): void => {
    if (!info) return;
    void writeClipboard(buildReport(info)).then((ok) => {
      setCopied(ok);
      if (ok) window.setTimeout(() => setCopied(false), 2500);
    });
  };

  return (
    <Dialog title="About DeskVNCViewer" onClose={onClose} width={560}>
      <nav className="mb-4 flex gap-1 border-b border-subtle" aria-label="About sections">
        {(["About", "Help"] as const).map((t) => (
          <button
            key={t}
            type="button"
            aria-current={tab === t ? "true" : undefined}
            className={classNames(
              "-mb-px border-b-2 px-3 py-1.5 text-sm",
              tab === t
                ? "border-accent font-medium text-primary"
                : "border-transparent text-secondary hover:text-primary",
            )}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>

      {tab === "About" ? (
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-primary">DeskVNCViewer</h3>
            <p className="text-sm text-secondary">
              A fast, native remote desktop viewer for macOS, Windows and Linux.
            </p>
            <p className="mt-1 text-sm text-tertiary">
              Version {info ? `${info.appVersion} (${info.gitDescribe})` : "-"}
            </p>
          </div>

          {info ? (
            <section aria-label="Build details">
              <div className="mb-1.5 flex items-baseline justify-between">
                <h4 className="text-sm font-semibold text-primary">Build</h4>
                <button
                  type="button"
                  className="text-xs text-accent hover:underline"
                  onClick={copyReport}
                >
                  {copied ? "Copied" : "Copy report for a bug ticket"}
                </button>
              </div>
              <dl className="space-y-1 rounded-md bg-inset/50 p-3 font-mono text-xs">
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-tertiary">Commit</dt>
                  <dd className="text-primary break-all" title={info.gitHash}>
                    {info.gitHashShort}
                    {info.gitDirty === "dirty" ? " (locally modified)" : ""}
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-tertiary">Branch</dt>
                  <dd className="text-primary">
                    {info.gitBranch}, committed {info.gitCommitDate}
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-tertiary">Toolchain</dt>
                  <dd className="text-primary">
                    {info.buildProfile} profile, tauri {info.tauriVersion},{" "}
                    {info.rustcVersion}
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-tertiary">System</dt>
                  <dd className="text-primary">
                    {info.os} {info.osVersion} ({info.arch}), webview{" "}
                    {info.webviewVersion}
                  </dd>
                </div>
              </dl>
              <p className="mt-1 text-xs text-tertiary">
                Please include the copied block when reporting an issue; it
                identifies this exact build.
              </p>
            </section>
          ) : null}

          <dl className="space-y-2 rounded-md bg-inset/50 p-3 text-sm">
            <div className="flex gap-2">
              <dt className="w-24 shrink-0 text-tertiary">Developed by</dt>
              <dd className="text-primary">{AUTHOR_NAME}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-24 shrink-0 text-tertiary">Contact</dt>
              <dd>
                <button
                  type="button"
                  className="text-accent hover:underline"
                  onClick={() => void openExternal(`mailto:${AUTHOR_EMAIL}`)}
                >
                  {AUTHOR_EMAIL}
                </button>
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-24 shrink-0 text-tertiary">License</dt>
              <dd className="text-primary">MIT OR Apache-2.0</dd>
            </div>
          </dl>

          <p className="text-xs text-tertiary">
            © {new Date().getFullYear()} {AUTHOR_NAME}. Supports RFB 3.3-3.8 with
            VNC, VeNCrypt, RA2, Apple Diffie-Hellman and MS-Logon authentication,
            and RDP with network level authentication.
          </p>

          <div className="flex gap-2 pt-1">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void openExternal(PROJECT_URL)}
            >
              Project page
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void openExternal(`mailto:${AUTHOR_EMAIL}?subject=DeskVNCViewer`)}
            >
              Contact developer
            </button>
            <button type="button" className="btn-primary ml-auto" data-autofocus onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <section>
            <h3 className="mb-1.5 text-sm font-semibold text-primary">Getting started</h3>
            <ol className="list-inside list-decimal space-y-1 text-sm text-secondary">
              <li>Use <strong className="text-primary">Scan network</strong> to find computers nearby, or <strong className="text-primary">New Host</strong> to add one by address.</li>
              <li>Double-click a tile to connect. Passwords are saved to the OS keychain on first use.</li>
              <li>Group and tag hosts from the sidebar to keep a large library navigable.</li>
            </ol>
          </section>

          <section>
            <h3 className="mb-1.5 text-sm font-semibold text-primary">Keyboard shortcuts</h3>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
              {SHORTCUTS.map(([keys, what]) => (
                <div key={keys} className="flex items-baseline gap-2">
                  <dt className="shrink-0 rounded-sm bg-inset px-1.5 py-0.5 font-mono text-xs text-primary">
                    {keys}
                  </dt>
                  <dd className="text-secondary">{what}</dd>
                </div>
              ))}
            </dl>
          </section>

          <section>
            <h3 className="mb-1.5 text-sm font-semibold text-primary">Troubleshooting</h3>
            <dl className="space-y-2 text-sm">
              {TROUBLESHOOTING.map(([symptom, fix]) => (
                <div key={symptom}>
                  <dt className="text-primary">{symptom}</dt>
                  <dd className="text-secondary">{fix}</dd>
                </div>
              ))}
            </dl>
          </section>

          <div className="flex gap-2 pt-1">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void openExternal(PROJECT_URL)}
            >
              Full documentation
            </button>
            <button type="button" className="btn-primary ml-auto" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
