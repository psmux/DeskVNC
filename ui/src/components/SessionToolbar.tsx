/** Floating pill session toolbar (PRD/05 §2): draggable anywhere in the window
 *  and docking flush when dropped near an edge, never able to leave the
 *  viewport, auto-fades to a chevron after 3s idle or when collapsed by hand,
 *  recalled by hover-at-edge or Ctrl/Cmd+Shift+M, which also puts it away
 *  again. Its position is remembered and shared by every mounted toolbar. */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type {
  DisplayOption,
  ProtocolKind,
  QualityPreset,
  ScalingMode,
  SessionState,
  SessionStats,
} from "../lib/types";
import { displayLabel } from "../lib/displays";
import type { LocalCursor } from "../state/SettingsContext";
import type { CaptureStatus } from "../lib/tauri";
import { classNames, formatBps, modKeyLabel } from "../lib/util";
import { usePaneVisible } from "./Pane";
import {
  IconActivity, IconCamera, IconChevronDown, IconClipboard, IconEye, IconFile,
  IconGripVertical, IconKeyboard, IconMaximize, IconMonitor, IconPin, IconPower,
  IconCursor, IconRefresh, IconSearch,
} from "./icons";

type Edge = "top" | "bottom" | "left" | "right";

interface ToolbarPos {
  /** The edge it is docked to, or null when floating free. */
  edge: Edge | null;
  /** Where along that edge its centre sits, 0..1. Unused while floating. */
  ratio: number;
  /** Top-left as a fraction of the viewport. Unused while docked. */
  x: number;
  y: number;
}

const POS_KEY = "deskvnc.toolbar.pos";
const PIN_KEY = "deskvnc.toolbar.pin";
const IDLE_MS = 3000;
/** Gap kept between the toolbar and the edges of the window. */
const MARGIN = 12;
/** Drag within this many pixels of an edge and it docks there. */
const SNAP_PX = 40;
/** Travel before a press counts as a drag rather than a click. */
const DRAG_SLOP = 4;

const DEFAULT_POS: ToolbarPos = { edge: "top", ratio: 0.5, x: 0.5, y: 0 };

const clamp = (v: number, lo: number, hi: number): number =>
  Math.min(Math.max(v, lo), hi);

/**
 * Stored positions predate free placement and carry only `{edge, ratio}`, so
 * anything missing is filled from the default rather than trusted: a `NaN`
 * left over from an older shape would put the toolbar nowhere at all.
 */
function readPos(): ToolbarPos {
  try {
    const raw = localStorage.getItem(POS_KEY);
    if (raw) {
      const p = JSON.parse(raw) as Partial<ToolbarPos>;
      const edge =
        p.edge === "top" || p.edge === "bottom" || p.edge === "left" || p.edge === "right"
          ? p.edge
          : p.edge === null
            ? null
            : DEFAULT_POS.edge;
      const num = (v: unknown, fallback: number): number =>
        typeof v === "number" && Number.isFinite(v) ? v : fallback;
      return {
        edge,
        ratio: num(p.ratio, DEFAULT_POS.ratio),
        x: num(p.x, DEFAULT_POS.x),
        y: num(p.y, DEFAULT_POS.y),
      };
    }
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
  /**
   * Which protocol this session speaks. Four rows differ, and each for its
   * own reason, written out where it is gated rather than as a list here.
   */
  protocol: ProtocolKind;
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
  zoomLocked: boolean;
  onZoomLocked: (locked: boolean) => void;
  edgePan: boolean;
  onEdgePan: (on: boolean) => void;
  /**
   * Rows for the Displays menu: real monitors, or synthetic splits, already
   * in the order to show them. Ordered by the caller so this menu and the
   * native View ▸ Displays submenu number the monitors the same way.
   */
  screens: DisplayOption[];
  /** True when `screens` is the server's own layout rather than guesses. */
  layoutKnown: boolean;
  /** Selected option id, or null for the whole desktop. */
  displayId: number | null;
  onDisplay: (id: number | null) => void;
  /** Re-run the monitor-seam detector (only offered when the layout is guessed). */
  onDetectDisplays: () => void;
  showRemoteCursor: boolean;
  onShowRemoteCursor: (show: boolean) => void;
  localCursor: LocalCursor;
  onLocalCursor: (mode: LocalCursor) => void;
  onQuality: (q: QualityPreset) => void;
  alwaysRefresh: boolean;
  onAlwaysRefresh: (enabled: boolean) => void;
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
  const onScreen = usePaneVisible();

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
  /** Read inside callbacks that must not collapse an already-collapsed bar. */
  const collapsedRef = useRef(collapsed);
  collapsedRef.current = collapsed;

  /**
   * Keeping the toolbar on screen needs three numbers the CSS cannot supply:
   * how big the window is, how big the toolbar is, and how much room the shell
   * chrome takes at the top. Clamping the anchor point alone is not enough,
   * because the anchor is the toolbar's centre; the box around it is what has
   * to stay inside, and it changes width as buttons appear and disappear.
   */
  const [viewport, setViewport] = useState(() => ({
    w: window.innerWidth,
    h: window.innerHeight,
  }));
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [insetTop, setInsetTop] = useState(0);

  useEffect(() => {
    const measure = (): void => {
      setViewport({ w: window.innerWidth, h: window.innerHeight });
      const raw = getComputedStyle(document.documentElement).getPropertyValue(
        "--session-inset-top",
      );
      setInsetTop(parseFloat(raw) || 0);
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [onScreen]);

  // The collapsed chevron is a fraction of the width of the open toolbar, and
  // the open one grows and shrinks with the capture badge, so the box is
  // measured as it renders rather than assumed.
  const rootRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const r = entry.contentRect;
      setSize((prev) =>
        Math.abs(prev.w - r.width) < 0.5 && Math.abs(prev.h - r.height) < 0.5
          ? prev
          : { w: r.width, h: r.height },
      );
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [collapsed]);

  const collapse = useCallback((): void => {
    if (collapsedRef.current) return;
    window.clearTimeout(idleTimer.current);
    setOpenMenu(null);
    setCollapsed(true);
  }, []);

  const expand = useCallback((): void => setCollapsed(false), []);

  /**
   * True while the pointer is over the toolbar.
   *
   * Auto-hide is driven by `pointermove`, so a pointer RESTING on the
   * toolbar generates no events and the thing collapsed out from under the
   * cursor, which is the one moment it is obviously wanted.
   */
  const hovering = useRef(false);

  const armIdle = useCallback((): void => {
    window.clearTimeout(idleTimer.current);
    idleTimer.current = window.setTimeout(() => {
      if (!pinned && !dragging.current && !hovering.current) collapse();
    }, IDLE_MS);
  }, [pinned, collapse]);

  // A toolbar on a background tab has nothing to auto-hide from, so it does not
  // watch the pointer: otherwise every mouse move would reset one timer per
  // open tab, for toolbars nobody can see.
  useEffect(() => {
    if (!onScreen) return;
    armIdle();
    const wake = (): void => armIdle();
    window.addEventListener("pointermove", wake);
    return () => {
      window.removeEventListener("pointermove", wake);
      window.clearTimeout(idleTimer.current);
    };
  }, [armIdle, onScreen]);

  /**
   * Show/hide via the hotkey (the parent bumps `recallSignal`). It toggles, so
   * the chord that calls the toolbar back also puts it away; the effect has to
   * act only on a genuine bump, since `armIdle` and `collapsed` change its
   * identity too and re-running on those would flip the toolbar unbidden.
   */
  const lastRecall = useRef(props.recallSignal);
  useEffect(() => {
    if (props.recallSignal === lastRecall.current) return;
    lastRecall.current = props.recallSignal;
    if (collapsed) {
      expand();
      armIdle();
    } else {
      collapse();
    }
  }, [props.recallSignal, collapsed, expand, collapse, armIdle]);

  useEffect(() => {
    if (openMenu === null) return;
    const close = (e: PointerEvent): void => {
      if (!rootRef.current?.contains(e.target as Node)) setOpenMenu(null);
    };
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [openMenu]);

  // ------------------------------------------------------------------ drag

  /**
   * The rectangle the toolbar's top-left corner is allowed to occupy.
   *
   * `--session-inset-top` is how much room the shell's own chrome takes: in
   * tabbed view the top of the viewport is the tab strip, and a toolbar placed
   * over it would swallow the clicks meant for the tabs. A session window
   * publishes nothing and the inset is simply zero.
   *
   * The `Math.max` guards a window narrower than the toolbar, where the lower
   * bound would otherwise exceed the upper one and clamp would return the
   * wrong end. Pinning it to the near edge at least keeps the drag handle
   * reachable.
   */
  const bounds = useMemo(() => {
    const minX = MARGIN;
    const minY = insetTop + MARGIN;
    return {
      minX,
      minY,
      maxX: Math.max(minX, viewport.w - size.w - MARGIN),
      maxY: Math.max(minY, viewport.h - size.h - MARGIN),
    };
  }, [viewport, size, insetTop]);

  const boundsRef = useRef(bounds);
  boundsRef.current = bounds;
  const sizeRef = useRef(size);
  sizeRef.current = size;
  const viewportRef = useRef(viewport);
  viewportRef.current = viewport;

  /**
   * Drag the whole toolbar by whatever was grabbed: the grip when open, the
   * chevron itself when collapsed.
   *
   * The chevron is also the button that reopens the toolbar, so a press has to
   * mean one thing or the other. Nothing moves until the pointer has travelled
   * `DRAG_SLOP`, and a press that never gets that far is left alone to become
   * an ordinary click. `draggedRef` then tells that click to stand down, since
   * the browser still fires one after a drag that begins and ends on the same
   * element. It is cleared on a timer rather than in the click handler so a
   * drag which ends elsewhere, firing no click at all, cannot leave the flag
   * raised and swallow the next real one.
   */
  const draggedRef = useRef(false);

  const beginDrag = (e: React.PointerEvent): void => {
    e.preventDefault();
    dragging.current = true;
    draggedRef.current = false;
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
    // Grab the toolbar where it was actually taken hold of, so it does not
    // jump to centre itself under the pointer on the first move.
    const rect = rootRef.current?.getBoundingClientRect();
    const grabX = rect ? e.clientX - rect.left : 0;
    const grabY = rect ? e.clientY - rect.top : 0;
    const fromX = e.clientX;
    const fromY = e.clientY;

    const move = (ev: PointerEvent): void => {
      if (!draggedRef.current) {
        if (Math.hypot(ev.clientX - fromX, ev.clientY - fromY) < DRAG_SLOP) return;
        draggedRef.current = true;
      }
      const { w: W, h: H } = viewportRef.current;
      const { w, h } = sizeRef.current;
      const b = boundsRef.current;
      const left = clamp(ev.clientX - grabX, b.minX, b.maxX);
      const top = clamp(ev.clientY - grabY, b.minY, b.maxY);

      // Distance from each edge of the window to the matching edge of the box.
      const dTop = top - b.minY;
      const dBottom = b.maxY - top;
      const dLeft = left - b.minX;
      const dRight = b.maxX - left;
      const nearest = Math.min(dTop, dBottom, dLeft, dRight);

      if (nearest > SNAP_PX) {
        setPos({ edge: null, ratio: 0, x: left / W, y: top / H });
        return;
      }
      let edge: Edge = "top";
      if (nearest === dBottom) edge = "bottom";
      else if (nearest === dLeft) edge = "left";
      else if (nearest === dRight) edge = "right";
      // Store the centre along the edge, so the dock survives a resize.
      const span = edge === "top" || edge === "bottom" ? W : H - insetTop;
      const centre =
        edge === "top" || edge === "bottom" ? left + w / 2 : top + h / 2 - insetTop;
      setPos({ edge, ratio: clamp(span > 0 ? centre / span : 0.5, 0, 1), x: left / W, y: top / H });
    };

    const up = (): void => {
      dragging.current = false;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      if (draggedRef.current) {
        // Through a ref, not a `setPos` updater: an updater has to be pure,
        // and this one now tells the other mounted toolbars about the move.
        storeLayout(POS_KEY, JSON.stringify(posRef.current));
        // Outlives the click the browser is about to fire, then stops being
        // able to suppress anything.
        window.setTimeout(() => {
          draggedRef.current = false;
        }, 0);
      }
      armIdle();
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  /**
   * Absolute placement, always clamped to `bounds`.
   *
   * Everything resolves to a plain left/top with no centring transform: the
   * old version anchored the toolbar's *centre* and clamped that, which let
   * half the box hang outside the window with the drag handle out of reach.
   * Clamping the corner is what actually keeps it on screen.
   */
  const style = useMemo((): React.CSSProperties => {
    const { w: W, h: H } = viewport;
    const { w, h } = size;
    const b = bounds;
    let left: number;
    let top: number;
    switch (pos.edge) {
      case "top":
      case "bottom":
        left = clamp(pos.ratio * W - w / 2, b.minX, b.maxX);
        top = pos.edge === "top" ? b.minY : b.maxY;
        break;
      case "left":
      case "right":
        left = pos.edge === "left" ? b.minX : b.maxX;
        top = clamp(insetTop + pos.ratio * (H - insetTop) - h / 2, b.minY, b.maxY);
        break;
      default:
        left = clamp(pos.x * W, b.minX, b.maxX);
        top = clamp(pos.y * H, b.minY, b.maxY);
    }
    return { position: "fixed", zIndex: 30, left, top };
  }, [pos, viewport, size, insetTop, bounds]);

  // Floating toolbars open their menus downwards unless they sit low enough
  // that the menu would run off the bottom.
  const menuBelow =
    pos.edge === "bottom"
      ? false
      : pos.edge !== null || style.top === undefined
        ? true
        : Number(style.top) < viewport.h * 0.6;

  // Zero means "never measured", not "instant": the core leaves it at 0 until
  // a probe completes, and a session showing a confident "0ms" while the real
  // round trip was ~290ms is worse than showing nothing (issue #1).
  const rtt = props.stats?.rtt_ms ?? null;
  const latency = rtt !== null && rtt > 0 ? rtt : null;
  const latencyColor =
    latency === null ? "bg-tertiary/50" : latency < 40 ? "bg-success" : latency < 120 ? "bg-warning" : "bg-danger";

  const capturing = props.captureStatus.state === "active";

  if (collapsed) {
    // The capture indicator survives collapse on purpose: PRD/06 §3 requires
    // the user to always be able to see that their keyboard is grabbed.
    return (
      <div ref={rootRef} style={style} className="flex items-center gap-1.5">
        <button
          type="button"
          aria-label={`Show session toolbar (${modKeyLabel}⇧M), drag to move`}
          title={`Show session toolbar (${modKeyLabel}⇧M), drag to move`}
          className="fade-in cursor-grab touch-none rounded-pill border border-subtle bg-raised/90 px-3 py-0.5 text-tertiary shadow-(--shadow-tile) backdrop-blur transition-shadow duration-150 hover:text-primary hover:shadow-(--shadow-glow) active:cursor-grabbing"
          onPointerDown={beginDrag}
          onClick={() => {
            // A drag that began here also ends in a click; only a real one
            // reopens the toolbar. Keyboard activation fires no pointer
            // events, so the flag is false and Enter/Space still work.
            if (!draggedRef.current) expand();
          }}
        >
          <IconChevronDown size={14} className={menuBelow ? "" : "rotate-180"} />
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
        onPointerEnter={() => {
          hovering.current = true;
          window.clearTimeout(idleTimer.current);
        }}
        onPointerLeave={() => {
          hovering.current = false;
          armIdle();
        }}
        className="fade-in flex items-center gap-0.5 rounded-pill border border-subtle bg-raised/95 px-1.5 py-1 shadow-(--shadow-pop) backdrop-blur transition-shadow duration-150 hover:shadow-(--shadow-glow)"
      >
        <button
          type="button"
          aria-label="Drag to move toolbar"
          className="cursor-grab px-0.5 text-tertiary active:cursor-grabbing"
          onPointerDown={beginDrag}
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
          {/* Fixed width, right-aligned: the figure changes every second, and
              letting it size itself made the whole toolbar twitch sideways as
              the reading moved between "-", "9ms" and "290ms". */}
          <span className="inline-block w-[5ch] text-right text-xs tabular-nums text-secondary">
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
          {props.displayId !== null ? (
            <span className="text-xs text-secondary">
              {props.screens.findIndex((s) => s.id === props.displayId) + 1}/{props.screens.length}
            </span>
          ) : null}
        </ToolButton>

        <ToolButton
          label="Pointers"
          active={openMenu === "pointer"}
          onClick={() => setOpenMenu(openMenu === "pointer" ? null : "pointer")}
        >
          <IconCursor size={15} />
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

        {/* Auto-hide only ever arrives on its own schedule, and a pinned
            toolbar never hides at all, so put it away by hand from here. */}
        <ToolButton label={`Collapse toolbar (${modKeyLabel}⇧M)`} onClick={collapse}>
          <IconChevronDown size={15} className={menuBelow ? "rotate-180" : ""} />
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
          {openMenu === "status" ? (
            <div className="w-60 px-2.5 py-1.5">
              <SessionStatusDetails stats={props.stats} desktopName={props.desktopName} />
            </div>
          ) : null}
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
              {/*
                Disabled with a reason rather than hidden, the rule the Files
                button already sets, which exists so "why can't I do this?"
                has an answer. Asking a Windows host to resize needs the
                Display Update channel, which this version does not speak
                yet.
              */}
              <MenuRow
                selected={props.scalingMode === "remote-resize"}
                disabled={props.protocol === "rdp"}
                onClick={() => props.onScalingMode("remote-resize")}
              >
                Remote resize (match window)
              </MenuRow>
              {props.protocol === "rdp" ? (
                <p className="px-2.5 pb-1 text-2xs text-tertiary">
                  Resizing the remote desktop to the window is not available for
                  Remote Desktop connections yet.
                </p>
              ) : null}
              <MenuRow
                selected={props.zoomLocked}
                onClick={() => props.onZoomLocked(!props.zoomLocked)}
              >
                Lock zoom (ignore pinch)
              </MenuRow>
              <MenuRow selected={props.edgePan} onClick={() => props.onEdgePan(!props.edgePan)}>
                Pan by moving to edges
              </MenuRow>
            </div>
          ) : null}
          {openMenu === "pointer" ? (
            <div>
              <p className="px-2.5 pt-1.5 pb-1 text-2xs uppercase tracking-wide text-tertiary">
                Remote pointer
              </p>
              <MenuRow
                selected={props.showRemoteCursor}
                onClick={() => props.onShowRemoteCursor(!props.showRemoteCursor)}
              >
                Show the remote pointer
              </MenuRow>
              <p className="px-2.5 pt-2 pb-1 text-2xs uppercase tracking-wide text-tertiary">
                My pointer
              </p>
              {(
                [
                  ["standard", "Standard arrow"],
                  ["dot", "Dot"],
                  ["off", "Hidden"],
                ] as [LocalCursor, string][]
              ).map(([mode, label]) => (
                <MenuRow
                  key={mode}
                  selected={props.localCursor === mode}
                  onClick={() => props.onLocalCursor(mode)}
                >
                  {label}
                </MenuRow>
              ))}
            </div>
          ) : null}
          {openMenu === "displays" ? (
            <div>
              <MenuRow selected={props.displayId === null} onClick={() => props.onDisplay(null)}>
                All displays
              </MenuRow>
              {!props.layoutKnown && props.screens.length > 0 ? (
                <p className="px-2.5 pt-2 pb-1 text-2xs uppercase tracking-wide text-tertiary">
                  Split this desktop
                </p>
              ) : null}
              {props.screens.map((s, i) => (
                <MenuRow
                  key={s.id}
                  selected={props.displayId === s.id}
                  onClick={() => props.onDisplay(s.id)}
                >
                  {displayLabel(s, i)}
                </MenuRow>
              ))}
              {/*
                A Remote Desktop session without multiple monitors negotiated
                is genuinely one display, not a wide framebuffer with monitors
                hidden inside it, so cutting it in half by width would be
                inventing monitors. The line that replaces the detector points
                at the setting that fills this menu instead of leaving it
                empty.
              */}
              {!props.layoutKnown && props.protocol === "rdp" ? (
                <p className="px-2.5 py-1 text-2xs text-tertiary">
                  This session is using a single display. Turn on “Use all of my
                  monitors” in this computer's settings to use more.
                </p>
              ) : !props.layoutKnown ? (
                <>
                  <MenuRow onClick={props.onDetectDisplays}>Detect displays again</MenuRow>
                  <p className="px-2.5 py-1 text-2xs text-tertiary">
                    {props.screens.length > 0
                      ? "This server does not say where its monitors meet: detection reads the picture, the other cuts are guesses by width."
                      : "This server has not described its monitors, so the whole desktop is one display."}
                  </p>
                </>
              ) : null}
            </div>
          ) : null}
          {openMenu === "quality" ? (
            <div>
              {/*
                Network mode sits above the presets because it is the choice
                people actually want to make: Auto infers the link from
                throughput, and a server that encodes slowly (a Raspberry Pi
                is the usual one) looks exactly like a slow link, so on a LAN
                it can settle far below what the network can carry. These
                override that inference; they are the presets underneath, named
                for the decision rather than for the setting.
              */}
              <p className="px-2.5 py-1 text-2xs text-tertiary">Network</p>
              <MenuRow selected={props.quality === "auto"} onClick={() => props.onQuality("auto")}>
                Auto — detect from the link
              </MenuRow>
              <MenuRow selected={props.quality === "high"} onClick={() => props.onQuality("high")}>
                LAN — full quality, no adaptation
              </MenuRow>
              <MenuRow selected={props.quality === "medium"} onClick={() => props.onQuality("medium")}>
                WAN — save bandwidth
              </MenuRow>
              <div className="mt-1 border-t border-subtle pt-1">
                <p className="px-2.5 py-1 text-2xs text-tertiary">Quality</p>
              </div>
              {(["auto", "high", "medium", "low", "bw"] as QualityPreset[]).map((q) => (
                <MenuRow key={q} selected={props.quality === q} onClick={() => props.onQuality(q)}>
                  {q === "bw" ? "Black & White" : q[0].toUpperCase() + q.slice(1)}
                </MenuRow>
              ))}
              {/*
                Hidden for RDP rather than disabled, and that asymmetry with
                "Remote resize" above is deliberate. This switch exists for a
                failure that is specific to RFB: the client asks for an
                incremental update and gets back whatever the server thinks
                changed, so a server whose damage tracking cannot be trusted
                leaves a stale picture that a poll fixes. Remote Desktop
                pushes its own updates with its own ordering, so there is no
                equivalent state to poll out of. A switch that costs the whole
                desktop in bandwidth every second and fixes nothing is worse
                than no switch, and "disabled with a reason" would still be
                claiming the problem exists.
              */}
              {props.protocol === "rdp" ? null : (
                <div className="mt-1 border-t border-subtle pt-1">
                  <MenuRow
                    selected={props.alwaysRefresh}
                    onClick={() => props.onAlwaysRefresh(!props.alwaysRefresh)}
                  >
                    Always request fresh frames
                  </MenuRow>
                  <p className="px-2.5 pb-1 text-2xs text-tertiary">
                    Re-fetches the whole screen every second instead of trusting the
                    server to report what changed. Fixes a picture that stays stale
                    or smeared; uses more bandwidth.
                  </p>
                </div>
              )}
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

/**
 * What the connection is doing. Exported because Session ▸ Connection Info
 * shows the same figures in a dialog: with the toolbar hidden there is no
 * status button to open, and the latency reading is the first thing anyone
 * looks for when a session feels slow.
 */
export function SessionStatusDetails({
  stats,
  desktopName,
}: {
  stats: SessionStats | null;
  desktopName: string;
}): ReactNode {
  return (
    <div className="text-sm">
      <p className="mb-2 truncate font-medium text-primary">{desktopName}</p>
      {stats ? (
        <dl className="grid grid-cols-2 gap-y-1 text-xs">
          <dt className="text-tertiary">Latency</dt>
          <dd className="tabular-nums text-primary">
            {stats.rtt_ms > 0 ? `${Math.round(stats.rtt_ms)} ms` : "-"}
          </dd>
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
