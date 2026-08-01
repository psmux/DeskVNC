/** Floating pill session toolbar (PRD/05 §2): draggable to any edge, auto-fades
 *  to a chevron after 3s idle, recalled by hover-at-edge or Ctrl/Cmd+Shift+M. */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { QualityPreset, ScalingMode, SessionState, SessionStats } from "../lib/types";
import type { CaptureStatus } from "../lib/tauri";
import { classNames, formatBps, modKeyLabel } from "../lib/util";
import {
  IconActivity, IconCamera, IconChevronDown, IconClipboard, IconEye, IconFile,
  IconGripVertical, IconKeyboard, IconMaximize, IconMonitor, IconPin, IconPower,
  IconRefresh, IconSearch,
} from "./icons";

type Edge = "top" | "bottom" | "left" | "right";

interface ToolbarPos {
  edge: Edge;
  ratio: number; // 0..1 along the edge
}

const POS_KEY = "deskvnc.toolbar.pos";
const PIN_KEY = "deskvnc.toolbar.pin";
const IDLE_MS = 3000;

const DEFAULT_POS: ToolbarPos = { edge: "top", ratio: 0.5 };

function readPos(): ToolbarPos {
  try {
    const raw = localStorage.getItem(POS_KEY);
    if (raw) return JSON.parse(raw) as ToolbarPos;
  } catch {
    /* default below */
  }
  return DEFAULT_POS;
}

const readPinned = (): boolean => localStorage.getItem(PIN_KEY) === "1";

/**
 * Where the toolbar sits, and whether it stays put, is one preference for the
 * whole app. In tabbed view several toolbars are mounted at once and each one
 * took its own snapshot when it mounted, so dragging the toolbar in one tab
 * left every other tab's where it was until the app restarted. A `storage`
 * event does not fire in the document that wrote the value, so the writer has
 * to tell its siblings itself.
 */
const layoutListeners = new Set<() => void>();

function storeLayout(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable, the position is simply not remembered */
  }
  for (const notify of layoutListeners) notify();
}

export interface SessionToolbarProps {
  desktopName: string;
  state: SessionState;
  stats: SessionStats | null;
  scalingMode: ScalingMode;
  zoom: number;
  quality: QualityPreset;
  bwLevels: number;
  passthrough: boolean;
  /** Live native-capture state from the shell (PRD/06 §3 Tier 2). */
  captureStatus: CaptureStatus;
  viewOnly: boolean;
  recallSignal: number;
  onScalingMode: (m: ScalingMode) => void;
  onZoom: (z: number) => void;
  onQuality: (q: QualityPreset) => void;
  onBwLevels: (levels: number) => void;
  onPassthrough: (v: boolean) => void;
  /** Open the "why we need Accessibility" explainer before any OS prompt. */
  onCapturePermission: () => void;
  onSendCombo: (combo: "ctrl-alt-del" | "cmd-tab" | "win" | "alt-f4" | "escape") => void;
  onClipboardSend: () => void;
  /** Open the dual-pane file manager (PRD/08 §3.2). */
  onFiles: () => void;
  /**
   * `null` while the SSH probe is still running, `false` when SSH is
   * unreachable, the button is then disabled with an explanation rather than
   * hidden, so "why can't I send files?" has an answer (PRD/08 §5).
   */
  filesAvailable: boolean | null;
  onFullscreen: () => void;
  onViewOnly: (v: boolean) => void;
  onScreenshot: () => void;
  onRefresh: () => void;
  onDisconnect: () => void;
}

export function SessionToolbar(props: SessionToolbarProps): ReactNode {
  const [pos, setPos] = useState<ToolbarPos>(readPos);
  const [pinned, setPinned] = useState<boolean>(readPinned);
  /** Latest position, for the drag handler to persist on drop. */
  const posRef = useRef(pos);
  posRef.current = pos;

  // Follow the shared layout while other tabs' toolbars are mounted alongside.
  useEffect(() => {
    const sync = (): void => {
      setPos(readPos());
      setPinned(readPinned());
    };
    layoutListeners.add(sync);
    return () => {
      layoutListeners.delete(sync);
    };
  }, []);

  const [collapsed, setCollapsed] = useState(false);
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const idleTimer = useRef(0);
  const dragging = useRef(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const armIdle = useCallback((): void => {
    window.clearTimeout(idleTimer.current);
    idleTimer.current = window.setTimeout(() => {
      if (!pinned && !dragging.current) {
        setOpenMenu(null);
        setCollapsed(true);
      }
    }, IDLE_MS);
  }, [pinned]);

  useEffect(() => {
    armIdle();
    const wake = (): void => armIdle();
    window.addEventListener("pointermove", wake);
    return () => {
      window.removeEventListener("pointermove", wake);
      window.clearTimeout(idleTimer.current);
    };
  }, [armIdle]);

  // recall via hotkey (parent bumps recallSignal)
  useEffect(() => {
    if (props.recallSignal > 0) {
      setCollapsed(false);
      armIdle();
    }
  }, [props.recallSignal, armIdle]);

  useEffect(() => {
    if (openMenu === null) return;
    const close = (e: PointerEvent): void => {
      if (!rootRef.current?.contains(e.target as Node)) setOpenMenu(null);
    };
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [openMenu]);

  // ------------------------------------------------------------------ drag

  const onGripPointerDown = (e: React.PointerEvent): void => {
    e.preventDefault();
    dragging.current = true;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    const move = (ev: PointerEvent): void => {
      const W = window.innerWidth;
      const H = window.innerHeight;
      const dTop = ev.clientY;
      const dBottom = H - ev.clientY;
      const dLeft = ev.clientX;
      const dRight = W - ev.clientX;
      const min = Math.min(dTop, dBottom, dLeft, dRight);
      let edge: Edge = "top";
      if (min === dBottom) edge = "bottom";
      else if (min === dLeft) edge = "left";
      else if (min === dRight) edge = "right";
      const ratio =
        edge === "top" || edge === "bottom"
          ? Math.min(0.95, Math.max(0.05, ev.clientX / W))
          : Math.min(0.95, Math.max(0.05, ev.clientY / H));
      setPos({ edge, ratio });
    };
    const up = (): void => {
      dragging.current = false;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      // Through a ref, not a `setPos` updater: an updater has to be pure, and
      // this one now tells the other mounted toolbars about the move.
      storeLayout(POS_KEY, JSON.stringify(posRef.current));
      armIdle();
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const style = useMemo((): React.CSSProperties => {
    const s: React.CSSProperties = { position: "fixed", zIndex: 30 };
    switch (pos.edge) {
      case "top":
        s.top = 12;
        s.left = `${pos.ratio * 100}%`;
        s.transform = "translateX(-50%)";
        break;
      case "bottom":
        s.bottom = 12;
        s.left = `${pos.ratio * 100}%`;
        s.transform = "translateX(-50%)";
        break;
      case "left":
        s.left = 12;
        s.top = `${pos.ratio * 100}%`;
        s.transform = "translateY(-50%)";
        break;
      case "right":
        s.right = 12;
        s.top = `${pos.ratio * 100}%`;
        s.transform = "translateY(-50%)";
        break;
    }
    return s;
  }, [pos]);

  const menuBelow = pos.edge !== "bottom";

  const latency = props.stats?.rtt_ms ?? null;
  const latencyColor =
    latency === null ? "bg-tertiary/50" : latency < 40 ? "bg-success" : latency < 120 ? "bg-warning" : "bg-danger";

  const capturing = props.captureStatus.state === "active";

  if (collapsed) {
    // The capture indicator survives collapse on purpose: PRD/06 §3 requires
    // the user to always be able to see that their keyboard is grabbed.
    return (
      <div style={style} className="flex items-center gap-1.5">
        <button
          type="button"
          aria-label={`Show session toolbar (${modKeyLabel}⇧M)`}
          className="fade-in rounded-pill border border-subtle bg-raised/90 px-3 py-0.5 text-tertiary shadow-(--shadow-tile) backdrop-blur hover:text-primary"
          onPointerEnter={() => setCollapsed(false)}
          onClick={() => setCollapsed(false)}
        >
          <IconChevronDown size={14} className={pos.edge === "bottom" ? "rotate-180" : ""} />
        </button>
        {capturing ? <CaptureIndicator compact /> : null}
      </div>
    );
  }

  return (
    <div ref={rootRef} style={style}>
      <div
        role="toolbar"
        aria-label="Session controls"
        className="fade-in flex items-center gap-0.5 rounded-pill border border-subtle bg-raised/95 px-1.5 py-1 shadow-(--shadow-pop) backdrop-blur"
      >
        <button
          type="button"
          aria-label="Drag to move toolbar"
          className="cursor-grab px-0.5 text-tertiary active:cursor-grabbing"
          onPointerDown={onGripPointerDown}
        >
          <IconGripVertical size={14} />
        </button>

        {/* connection status */}
        <ToolButton
          label="Connection status"
          active={openMenu === "status"}
          onClick={() => setOpenMenu(openMenu === "status" ? null : "status")}
        >
          <span className={`h-2 w-2 rounded-full ${latencyColor}`} />
          <span className="text-xs tabular-nums text-secondary">
            {latency !== null ? `${Math.round(latency)}ms` : "-"}
          </span>
        </ToolButton>

        <Divider />

        <ToolButton label="Scaling" active={openMenu === "scale"} onClick={() => setOpenMenu(openMenu === "scale" ? null : "scale")}>
          <IconSearch size={15} />
          <span className="text-xs text-secondary">
            {props.scalingMode === "custom" ? `${Math.round(props.zoom * 100)}%` : scaleLabel(props.scalingMode)}
          </span>
        </ToolButton>

        <ToolButton label="Displays" active={openMenu === "displays"} onClick={() => setOpenMenu(openMenu === "displays" ? null : "displays")}>
          <IconMonitor size={15} />
        </ToolButton>

        <ToolButton label="Quality" active={openMenu === "quality"} onClick={() => setOpenMenu(openMenu === "quality" ? null : "quality")}>
          <IconActivity size={15} />
          <span className="text-xs uppercase text-secondary">{props.quality === "bw" ? "B&W" : props.quality}</span>
        </ToolButton>

        <ToolButton
          label={captureButtonLabel(props.captureStatus, props.passthrough)}
          active={openMenu === "keyboard"}
          toggled={capturing}
          onClick={() => setOpenMenu(openMenu === "keyboard" ? null : "keyboard")}
        >
          <IconKeyboard size={15} />
          {props.passthrough ? (
            <span
              className={classNames(
                "h-1.5 w-1.5 rounded-full",
                capturing
                  ? "bg-accent"
                  : props.captureStatus.state === "inactive"
                    ? "bg-tertiary"
                    : "bg-warning",
              )}
            />
          ) : null}
        </ToolButton>

        {capturing ? <CaptureIndicator /> : null}

        <ToolButton label="Send clipboard to remote" onClick={props.onClipboardSend}>
          <IconClipboard size={15} />
        </ToolButton>

        <ToolButton
          label={
            props.filesAvailable === true
              ? "File transfer (SFTP)"
              : props.filesAvailable === null
                ? "Checking whether SSH is available on this computer…"
                : "File transfer needs SSH on the remote computer, and it isn't reachable on this one"
          }
          disabled={props.filesAvailable !== true}
          onClick={props.onFiles}
        >
          <IconFile size={15} />
        </ToolButton>

        <Divider />

        <ToolButton label={`Fullscreen (${modKeyLabel}⌥Enter)`} onClick={props.onFullscreen}>
          <IconMaximize size={15} />
        </ToolButton>

        <ToolButton
          label={props.viewOnly ? "View only: on, click to allow input" : "View only: off, click to block input"}
          toggled={props.viewOnly}
          onClick={() => props.onViewOnly(!props.viewOnly)}
        >
          <IconEye size={15} />
        </ToolButton>

        <ToolButton label="Save screenshot" onClick={props.onScreenshot}>
          <IconCamera size={15} />
        </ToolButton>

        <ToolButton label="Request full screen refresh" onClick={props.onRefresh}>
          <IconRefresh size={15} />
        </ToolButton>

        <ToolButton
          label={pinned ? "Unpin toolbar (allow auto-hide)" : "Pin toolbar (stay visible)"}
          toggled={pinned}
          onClick={() => {
            const v = !pinned;
            setPinned(v);
            storeLayout(PIN_KEY, v ? "1" : "0");
          }}
        >
          <IconPin size={15} />
        </ToolButton>

        <Divider />

        <ToolButton label="Disconnect" danger onClick={props.onDisconnect}>
          <IconPower size={15} />
        </ToolButton>
      </div>

      {/* menus */}
      {openMenu ? (
        <div
          className={classNames(
            "absolute left-1/2 min-w-52 -translate-x-1/2 rounded-md border border-subtle bg-raised p-1.5 shadow-(--shadow-pop)",
            menuBelow ? "top-full mt-2" : "bottom-full mb-2",
          )}
          role="menu"
        >
          {openMenu === "status" ? <StatusMenu stats={props.stats} desktopName={props.desktopName} /> : null}
          {openMenu === "scale" ? (
            <div>
              {(["fit", "aspect-fit", "actual"] as ScalingMode[]).map((m) => (
                <MenuRow key={m} selected={props.scalingMode === m} onClick={() => props.onScalingMode(m)}>
                  {scaleLabel(m)}
                </MenuRow>
              ))}
              <MenuRow selected={props.scalingMode === "custom"} onClick={() => props.onScalingMode("custom")}>
                Custom zoom
              </MenuRow>
              <div className="flex items-center gap-2 px-2.5 py-1.5">
                <input
                  type="range"
                  min={25}
                  max={400}
                  step={5}
                  value={Math.round(props.zoom * 100)}
                  aria-label="Zoom percentage"
                  className="flex-1 accent-(--accent)"
                  onChange={(e) => props.onZoom(parseInt(e.target.value, 10) / 100)}
                />
                <span className="w-11 text-right text-xs tabular-nums text-secondary">
                  {Math.round(props.zoom * 100)}%
                </span>
              </div>
              <MenuRow selected={props.scalingMode === "remote-resize"} onClick={() => props.onScalingMode("remote-resize")}>
                Remote resize (match window)
              </MenuRow>
            </div>
          ) : null}
          {openMenu === "displays" ? (
            <div>
              <MenuRow selected onClick={() => undefined}>Display 1</MenuRow>
              <MenuRow disabled onClick={() => undefined}>All displays</MenuRow>
              <MenuRow disabled onClick={() => undefined}>Displays in separate windows</MenuRow>
              <p className="px-2.5 py-1 text-2xs text-tertiary">Multi-display info arrives from the server</p>
            </div>
          ) : null}
          {openMenu === "quality" ? (
            <div>
              {(["auto", "high", "medium", "low", "bw"] as QualityPreset[]).map((q) => (
                <MenuRow key={q} selected={props.quality === q} onClick={() => props.onQuality(q)}>
                  {q === "bw" ? "Black & White" : q[0].toUpperCase() + q.slice(1)}
                </MenuRow>
              ))}
              {props.quality === "bw" ? (
                <div className="mt-1 border-t border-subtle pt-1">
                  <p className="px-2.5 py-1 text-2xs text-tertiary">Gray levels</p>
                  {[256, 16, 8, 4, 2, 1].map((n) => (
                    <MenuRow key={n} selected={props.bwLevels === n} onClick={() => props.onBwLevels(n)}>
                      {n === 1 ? "1-bit (dithered)" : `${n} levels`}
                    </MenuRow>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}
          {openMenu === "keyboard" ? (
            <div>
              <MenuRow selected={props.passthrough} onClick={() => props.onPassthrough(!props.passthrough)}>
                Pass system shortcuts to remote
              </MenuRow>
              <CaptureStatusNote
                status={props.captureStatus}
                passthrough={props.passthrough}
                onPermission={props.onCapturePermission}
              />
              <div className="mt-1 border-t border-subtle pt-1">
                <p className="px-2.5 py-1 text-2xs text-tertiary">Send to remote</p>
                <MenuRow onClick={() => props.onSendCombo("ctrl-alt-del")}>Ctrl+Alt+Del</MenuRow>
                <MenuRow onClick={() => props.onSendCombo("cmd-tab")}>Cmd/Alt+Tab</MenuRow>
                <MenuRow onClick={() => props.onSendCombo("win")}>Windows/Super key</MenuRow>
                <MenuRow onClick={() => props.onSendCombo("alt-f4")}>Alt+F4</MenuRow>
                <MenuRow onClick={() => props.onSendCombo("escape")}>Escape</MenuRow>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

// ------------------------------------------------------- capture indicator

/**
 * "Your keyboard is grabbed" badge.
 *
 * PRD/06 §3 makes this non-negotiable: a stuck grab that swallows the
 * keyboard is unforgivable, so whenever native capture is live the user can
 * see it *and* is told the release chord, even when the toolbar is collapsed.
 */
function CaptureIndicator({ compact }: { compact?: boolean }): ReactNode {
  const label = "System shortcuts are going to the remote. Press Ctrl+Alt+Shift+Esc to release.";
  return (
    <span
      role="status"
      aria-live="polite"
      title={label}
      aria-label={label}
      className={classNames(
        "flex items-center gap-1.5 rounded-pill bg-accent/15 text-accent",
        compact
          ? "border border-subtle bg-raised/90 px-2 py-1 shadow-(--shadow-tile) backdrop-blur"
          : "ml-0.5 px-2 py-1",
      )}
    >
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" aria-hidden="true" />
      <IconKeyboard size={14} />
      {compact ? null : <span className="text-2xs font-medium uppercase tracking-wide">Captured</span>}
    </span>
  );
}

function captureButtonLabel(status: CaptureStatus, passthrough: boolean): string {
  switch (status.state) {
    case "active":
      return "Keyboard captured, system shortcuts go to the remote (release: Ctrl+Alt+Shift+Esc)";
    case "permission-required":
      return "Keyboard: pass-through needs permission";
    case "unsupported":
      return `Keyboard: pass-through unavailable, ${status.reason}`;
    default:
      return passthrough ? "Keyboard: pass-through waiting for focus" : "Keyboard";
  }
}

/**
 * The explanatory line under the pass-through toggle. Every non-active state
 * gets a plain-language reason and, where one exists, a way forward, never a
 * silently dead switch.
 */
function CaptureStatusNote({
  status,
  passthrough,
  onPermission,
}: {
  status: CaptureStatus;
  passthrough: boolean;
  onPermission: () => void;
}): ReactNode {
  if (status.state === "active") {
    return (
      <p className="px-2.5 pb-1 text-2xs text-accent">
        Captured. Press <span className="mono">Ctrl+Alt+Shift+Esc</span> to release.
      </p>
    );
  }
  if (status.state === "permission-required") {
    return (
      <div className="px-2.5 pb-1.5">
        <p className="text-2xs text-warning">
          Needs Accessibility permission to intercept system shortcuts.
        </p>
        <button
          type="button"
          className="mt-1 text-2xs font-medium text-accent underline underline-offset-2"
          onClick={onPermission}
        >
          How to enable it
        </button>
      </div>
    );
  }
  if (status.state === "unsupported") {
    return <p className="px-2.5 pb-1 text-2xs text-warning">{status.reason}</p>;
  }
  if (passthrough) {
    return (
      <p className="px-2.5 pb-1 text-2xs text-tertiary">
        Active only while this window is focused.
      </p>
    );
  }
  return (
    <p className="px-2.5 pb-1 text-2xs text-tertiary">
      Sends {modKeyLabel}Tab, {modKeyLabel}Space and the Windows key to the remote instead of this
      computer.
    </p>
  );
}

function scaleLabel(m: ScalingMode): string {
  switch (m) {
    case "fit":
      return "Fit";
    case "aspect-fit":
      return "Aspect fit";
    case "actual":
      return "1:1";
    case "remote-resize":
      return "Remote";
    default:
      return "Zoom";
  }
}

function ToolButton({
  label,
  onClick,
  children,
  active,
  toggled,
  danger,
  disabled,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
  active?: boolean;
  toggled?: boolean;
  danger?: boolean;
  disabled?: boolean;
}): ReactNode {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      aria-pressed={toggled}
      className={classNames(
        "flex items-center gap-1 rounded-pill px-2 py-1.5",
        disabled
          ? "cursor-default text-tertiary/50"
          : danger
            ? "text-danger hover:bg-danger-subtle"
            : active || toggled
              ? "bg-accent/15 text-accent"
              : "text-secondary hover:bg-inset hover:text-primary",
      )}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function Divider(): ReactNode {
  return <span className="mx-0.5 h-4 w-px bg-(--border-subtle)" aria-hidden="true" />;
}

function MenuRow({
  children,
  onClick,
  selected,
  disabled,
}: {
  children: ReactNode;
  onClick: () => void;
  selected?: boolean;
  disabled?: boolean;
}): ReactNode {
  return (
    <button
      type="button"
      role="menuitemradio"
      aria-checked={selected}
      disabled={disabled}
      className={classNames(
        "flex w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-left text-sm",
        disabled
          ? "cursor-default text-tertiary/60"
          : selected
            ? "font-medium text-accent"
            : "text-primary hover:bg-inset",
      )}
      onClick={onClick}
    >
      <span className="w-3 text-accent">{selected ? "✓" : ""}</span>
      {children}
    </button>
  );
}

function StatusMenu({ stats, desktopName }: { stats: SessionStats | null; desktopName: string }): ReactNode {
  return (
    <div className="w-60 px-2.5 py-1.5 text-sm">
      <p className="mb-2 truncate font-medium text-primary">{desktopName}</p>
      {stats ? (
        <dl className="grid grid-cols-2 gap-y-1 text-xs">
          <dt className="text-tertiary">Latency</dt>
          <dd className="tabular-nums text-primary">{Math.round(stats.rtt_ms)} ms</dd>
          <dt className="text-tertiary">Throughput</dt>
          <dd className="tabular-nums text-primary">{formatBps(stats.throughput_bps)}</dd>
          <dt className="text-tertiary">Frame rate</dt>
          <dd className="tabular-nums text-primary">{stats.fps.toFixed(0)} fps</dd>
          <dt className="text-tertiary">Decode</dt>
          <dd className="tabular-nums text-primary">{stats.decode_ms.toFixed(1)} ms</dd>
          <dt className="text-tertiary">Encoding</dt>
          <dd className="mono text-primary">{encodingName(stats.current_encoding)}</dd>
          <dt className="text-tertiary">Received</dt>
          <dd className="tabular-nums text-primary">{(stats.bytes_received / 1e6).toFixed(1)} MB</dd>
        </dl>
      ) : (
        <p className="text-xs text-tertiary">Statistics arrive once the session reports them.</p>
      )}
    </div>
  );
}

function encodingName(enc: number): string {
  switch (enc) {
    case 0: return "Raw";
    case 1: return "CopyRect";
    case 2: return "RRE";
    case 5: return "Hextile";
    case 7: return "Tight";
    case 16: return "ZRLE";
    case 50: return "H.264";
    default: return `#${enc}`;
  }
}
