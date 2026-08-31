/**
 * What sits in a pane that has nothing in it yet.
 *
 * Splitting leaves a hole, and the hole has to offer the two things anyone
 * would want to put in it: a machine that is already connected somewhere else,
 * or a new connection. Both are here rather than behind a dialog because the
 * pane is the target, and a dialog would be a modal window asking a question
 * whose answer is "the thing I am pointing at".
 *
 * Moving a connected session in does not reconnect it. The session is mounted
 * once in the window and the layout only decides where its box goes (see
 * `SplitView`), so pulling one over from another tab moves a live framebuffer
 * without a frame of interruption, and leaves an empty pane behind rather than
 * closing the tab it came from.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { usePaneVisible } from "./Pane";
import { useHosts } from "../state/HostsContext";
import { useTabs } from "../state/TabsContext";
import { useToasts } from "../state/ToastContext";
import { hostProtocol, type ProtocolKind } from "../lib/types";
import { inTauri, openSessionWindow, safeInvoke } from "../lib/tauri";
import { parseConnectTarget, presetProtocol } from "../lib/address";
import { classNames } from "../lib/util";
import { IconMonitor, IconSearch, IconTerminal, IconX } from "./icons";

/**
 * A session id for the browser-dev mock, where there is no shell to mint one.
 * Unique per pane, or two mock sessions would collide.
 */
function devSessionId(): string {
  return `dev-${Math.random().toString(36).slice(2, 10)}`;
}

function protocolIcon(protocol: ProtocolKind): ReactNode {
  return protocol === "ssh" ? <IconTerminal size={13} /> : <IconMonitor size={13} />;
}

export function PanePicker({
  tabId,
  paneId,
  onClose,
}: {
  tabId: string;
  paneId: string;
  /** Give the space back to the neighbouring panes. */
  onClose: () => void;
}): ReactNode {
  const { hosts } = useHosts();
  const owns = usePaneVisible();
  const { sessions, open, adopt } = useTabs();
  const { push } = useToasts();
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  /** One connect at a time, a double click must not dial twice. */
  const busy = useRef(false);

  // Splitting a pane is a request to put something in it, so the search box is
  // ready to type into. Only in the focused pane: a picker sitting in the pane
  // next door must not pull the caret out of the session being worked in.
  useEffect(() => {
    if (owns) inputRef.current?.focus();
    // And give it back when the pane stops being the one in use, so a picker
    // sitting in the corner is not still holding the document's focus.
    else if (document.activeElement === inputRef.current) inputRef.current?.blur();
  }, [owns]);

  /**
   * Every open session is offered, including ones already showing elsewhere:
   * choosing one of those moves it here, which is the whole point. This pane
   * is empty, so there is nothing to leave out.
   */
  const movable = useMemo(() => Object.values(sessions), [sessions]);

  const needle = query.trim().toLowerCase();
  const matchingSessions = movable.filter(
    (s) =>
      !needle ||
      s.title.toLowerCase().includes(needle) ||
      (s.params.address ?? "").toLowerCase().includes(needle),
  );
  const matchingHosts = hosts.filter(
    (h) =>
      !needle ||
      h.friendlyName.toLowerCase().includes(needle) ||
      h.address.toLowerCase().includes(needle),
  );

  /**
   * Connect a saved host straight into this pane.
   *
   * The shell still decides everything that matters and we act on what it
   * reports. A `reused` outcome means this machine is already connected, in
   * which case the right answer is to move that session here rather than to
   * refuse: the user pointed at a pane and named a machine, and there is only
   * one reading of that.
   */
  const connectHost = async (profileId: string, label: string): Promise<void> => {
    if (busy.current) return;
    busy.current = true;
    try {
      const outcome = await openSessionWindow({ profileId, asTab: true });
      if (!outcome) return;
      if (outcome.reused) {
        if (sessions[outcome.sessionId]) adopt(tabId, paneId, outcome.sessionId);
        else push("info", `${label} is already open in a window of its own`);
        return;
      }
      if (outcome.target === "tab" && outcome.params) {
        open(
          outcome.sessionId,
          {
            sessionId: outcome.sessionId,
            profileId: outcome.params.profileId,
            address: outcome.params.address,
            port: outcome.params.port,
            name: outcome.params.name,
            protocol: outcome.params.protocol,
          },
          { tabId, paneId },
        );
        void safeInvoke("touch_connected", { hostId: profileId }, null);
      }
    } finally {
      busy.current = false;
    }
  };

  const connectAddress = async (raw: string): Promise<void> => {
    const parsed = parseConnectTarget(raw);
    if (!parsed.ok) {
      push("danger", parsed.error);
      return;
    }
    if (busy.current) return;
    busy.current = true;
    try {
      const outcome = await openSessionWindow({
        address: parsed.target.address,
        port: parsed.target.port,
        // An address that named no protocol is read off its port, the same
        // way QuickConnect reads one it cannot match to a saved host.
        protocol: parsed.target.protocol ?? presetProtocol(parsed.target),
        asTab: true,
      });
      if (!outcome) return;
      if (outcome.reused) {
        if (sessions[outcome.sessionId]) adopt(tabId, paneId, outcome.sessionId);
        return;
      }
      if (outcome.target === "tab" && outcome.params) {
        open(
          outcome.sessionId,
          {
            sessionId: outcome.sessionId,
            profileId: outcome.params.profileId,
            address: outcome.params.address,
            port: outcome.params.port,
            name: outcome.params.name,
            protocol: outcome.params.protocol,
          },
          { tabId, paneId },
        );
      }
    } finally {
      busy.current = false;
    }
  };

  /** Browser dev has no shell to resolve anything, so mount the mock directly. */
  const connectDev = (
    profileId: string | null,
    address: string,
    port: number,
    name: string,
    protocol: ProtocolKind,
  ): void => {
    const id = devSessionId();
    open(id, { sessionId: id, profileId, address, port, name, protocol }, { tabId, paneId });
  };

  const chooseHost = (host: (typeof hosts)[number]): void => {
    const protocol = hostProtocol(host);
    if (inTauri()) void connectHost(host.id, host.friendlyName);
    else connectDev(host.id, host.address, host.port, host.friendlyName, protocol);
  };

  const submitAddress = (): void => {
    const raw = query.trim();
    if (!raw) return;
    if (inTauri()) {
      void connectAddress(raw);
      return;
    }
    const parsed = parseConnectTarget(raw);
    if (!parsed.ok) return;
    const { address, port } = parsed.target;
    connectDev(null, address, port, address, parsed.target.protocol ?? presetProtocol(parsed.target));
  };

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-inset">
      <div className="flex items-center gap-2 border-b border-subtle px-3 py-2">
        <IconSearch size={13} />
        <input
          ref={inputRef}
          className="min-w-0 flex-1 bg-transparent text-sm text-primary outline-none placeholder:text-tertiary"
          placeholder="Search hosts, or type an address"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              // A search that matched exactly one saved host means that host;
              // anything else is read as an address typed out in full.
              if (matchingHosts.length === 1 && matchingSessions.length === 0) {
                chooseHost(matchingHosts[0]);
              } else {
                submitAddress();
              }
            }
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              onClose();
            }
          }}
          aria-label="Choose what to show in this pane"
          // Focused as a courtesy, not because anyone asked. A secondary click
          // on the chrome lets it go, so the webview has no focused text field
          // to build an editing menu around. See `lib/contextMenu.ts`.
          data-courtesy-focus="true"
        />
        <button
          type="button"
          className="rounded-sm p-1 text-tertiary hover:bg-strong/20 hover:text-primary"
          onClick={onClose}
          aria-label="Close this pane"
          title="Close this pane"
        >
          <IconX size={13} />
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {matchingSessions.length > 0 ? (
          <Section title="Move a connected session here">
            {matchingSessions.map((s) => (
              <Row
                key={s.id}
                icon={protocolIcon(s.params.protocol)}
                label={s.title}
                detail={s.params.address ?? ""}
                onSelect={() => adopt(tabId, paneId, s.id)}
              />
            ))}
          </Section>
        ) : null}

        {matchingHosts.length > 0 ? (
          <Section title="Connect">
            {matchingHosts.slice(0, 50).map((h) => (
              <Row
                key={h.id}
                icon={protocolIcon(hostProtocol(h))}
                label={h.friendlyName}
                detail={`${h.address}:${h.port}`}
                onSelect={() => chooseHost(h)}
              />
            ))}
          </Section>
        ) : null}

        {matchingSessions.length === 0 && matchingHosts.length === 0 ? (
          <p className="px-2 py-6 text-center text-xs text-tertiary">
            {needle
              ? "Nothing matches. Press Enter to connect to it as an address."
              : "No saved hosts yet."}
          </p>
        ) : null}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }): ReactNode {
  return (
    <div className="mb-2">
      <h3 className="px-2 pb-1 text-2xs font-medium tracking-wide text-tertiary uppercase">
        {title}
      </h3>
      {children}
    </div>
  );
}

function Row({
  icon,
  label,
  detail,
  onSelect,
}: {
  icon: ReactNode;
  label: string;
  detail: string;
  onSelect: () => void;
}): ReactNode {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={classNames(
        "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left",
        "text-sm text-primary hover:bg-accent hover:text-accent-fg",
      )}
    >
      <span className="shrink-0 opacity-70">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
      <span className="mono shrink-0 text-2xs opacity-60">{detail}</span>
    </button>
  );
}
