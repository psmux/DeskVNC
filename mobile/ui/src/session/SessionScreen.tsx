/**
 * The remote desktop screen of the phone app.
 *
 * Full screen, inside the safe areas, portrait or landscape. Until the first
 * picture arrives it shows the connecting scene; then the desktop, drawn by
 * the WebGL renderer copied from the desktop app, with touch gestures
 * (input/gestures.ts), zoom and pan (input/viewport.ts), a floating toolbar,
 * a key bar over the phone keyboard and the sign in and certificate sheets.
 */
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { Api, ConnectTarget, HostOs, Quality } from "../api/contract";
import { GestureRecognizer, type GestureAction, type Pt, type TouchInput, type TouchMode } from "./input/gestures";
import { BUTTON } from "./input/packets";
import {
  KEYSYM_BACKSPACE,
  MODIFIERS,
  SENTINEL,
  TextDiffer,
  afterKey,
  charIds,
  heldModifiers,
  namedKeyIds,
  nextModState,
  type ModState,
  type ModifierKey,
  type NamedKey,
  type TextOp,
} from "./input/keys";
import { keyEventToIds } from "./input/keysyms";
import {
  clampToFb,
  clampView,
  ensureVisible,
  fbToScreen,
  initialView,
  isFit,
  lerpView,
  momentumStep,
  panBy,
  placement,
  screenToFb,
  toggleZoomAt,
  zoomAt,
  type Size,
  type View,
} from "./input/viewport";
import { haptic } from "./haptics";
import { load, save } from "./storage";
import { qualityLevel, stepOf, LEVEL_WORDS } from "./status";
import { hasVideoDecoder, useRemoteSession } from "./useRemoteSession";
import { Coach, coachSeen } from "./ui/Coach";
import { ConnectingScreen, ErrorScreen, ReconnectCard } from "./ui/ConnectingScreen";
import { IconZoomOut } from "./ui/icons";
import { KeyBar, type KeyBarPress } from "./ui/KeyBar";
import { ClipboardSheet, ModeSheet, QualitySheet, StatsSheet } from "./ui/Panels";
import { CertSheet, CredentialSheet } from "./ui/Prompts";
import { Toolbar, type ToolbarAction } from "./ui/Toolbar";
import "./session.css";

export interface SessionScreenProps {
  api: Api;
  target: ConnectTarget;
  title: string;
  onExit(): void;
}

type SheetKind = "mode" | "quality" | "clipboard" | "stats" | null;

const NO_MODS: Record<ModifierKey, ModState> = { ctrl: "off", alt: "off", meta: "off", shift: "off" };
/** Screen pixels of finger travel per mouse wheel notch. */
const SCROLL_STEP = 22;
/** How close to an edge the pointer may get before a zoomed view follows it. */
const FOLLOW_MARGIN = 44;
/** A finger this close to an edge while dragging pans a zoomed view. */
const EDGE_ZONE = 36;

const NAMED_KEYS = new Set<string>([
  "Escape", "Tab", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown",
  "Backspace", "Delete", "Enter", "Insert",
  "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
]);

function metaLabelFor(os: HostOs | null): string {
  if (os === "mac") return "Cmd";
  if (os === "linux" || os === "raspberry") return "Super";
  return "Win";
}

export function SessionScreen({ api, target, title, onExit }: SessionScreenProps) {
  const s = useRemoteSession(api, target);
  const [mode, setModeState] = useState<TouchMode>(() => (load("mode") === "trackpad" ? "trackpad" : "direct"));
  const [sheet, setSheet] = useState<SheetKind>(null);
  const [toolbarOpen, setToolbarOpen] = useState(false);
  const [keysOn, setKeysOn] = useState(false);
  const [keyboardOn, setKeyboardOn] = useState(false);
  const [mods, setMods] = useState<Record<ModifierKey, ModState>>(NO_MODS);
  const [quality, setQualityState] = useState<Quality>("auto");
  const [coach, setCoach] = useState<TouchMode | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [ring, setRing] = useState<{ x: number; y: number; key: number } | null>(null);
  const [zoomed, setZoomed] = useState(false);
  const [stage, setStage] = useState<Size>({ w: 0, h: 0 });
  const [os, setOs] = useState<HostOs | null>(null);
  const [clipSeen, setClipSeen] = useState<string | null>(null);

  const rootRef = useRef<HTMLDivElement | null>(null);
  const stageRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const pointerRef = useRef<HTMLDivElement | null>(null);
  const haloRef = useRef<HTMLDivElement | null>(null);

  const view = useRef<View>({ zoom: 1, cx: 0, cy: 0 });
  const stageSize = useRef<Size>({ w: 0, h: 0 });
  const fb = useRef<Size>({ w: 0, h: 0 });
  const pointer = useRef({ x: 0, y: 0, movedAt: 0 });
  const mask = useRef(0);
  const scrollAcc = useRef({ x: 0, y: 0 });
  const modsRef = useRef(mods);
  modsRef.current = mods;
  const modeRef = useRef(mode);
  modeRef.current = mode;
  const differ = useRef(new TextDiffer());
  const composing = useRef(false);
  const anim = useRef<{ raf: number; kind: "none" | "momentum" | "zoom" | "edge"; vx: number; vy: number; from?: View; to?: View; t0?: number; last?: number; ex?: number; ey?: number }>({
    raf: 0,
    kind: "none",
    vx: 0,
    vy: 0,
  });
  const tickTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const recognizer = useMemo(
    () => new GestureRecognizer(mode, { canDoubleTapZoom: () => isFit(view.current) }),
    // The recognizer lives for the screen; its mode is updated below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  useEffect(() => recognizer.setMode(mode), [mode, recognizer]);

  const showToast = useCallback((text: string) => {
    setToast(text);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2600);
  }, []);

  // The host's operating system, for the Win or Cmd key label.
  useEffect(() => {
    if (target.kind !== "saved") return;
    let live = true;
    api
      .hostsList()
      .then((hosts) => {
        const h = hosts.find((x) => x.id === target.hostId);
        if (live && h) setOs(h.os);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [api, target]);

  // ------------------------------------------------------------ view

  /** Push the view to the renderer and move the overlays that follow it. */
  const applyView = useCallback(() => {
    const r = s.renderer.current;
    const st = stageSize.current;
    const f = fb.current;
    if (!r || st.w === 0 || f.w === 0) return;
    const dpr = window.devicePixelRatio || 1;
    // The renderer may have been made after the last measure; size it here too.
    r.setCanvasSize(Math.round(st.w * dpr), Math.round(st.h * dpr));
    const p = placement(view.current, st, f);
    r.setTransformOverride({ x: p.x * dpr, y: p.y * dpr, scaleX: p.scale * dpr, scaleY: p.scale * dpr });
    const z = !isFit(view.current);
    setZoomed((prev) => (prev === z ? prev : z));
    placePointerOverlay();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.renderer]);

  const placePointerOverlay = (): void => {
    const st = stageSize.current;
    const f = fb.current;
    if (f.w === 0) return;
    const p = fbToScreen(view.current, st, f, pointer.current.x, pointer.current.y);
    const t = `translate3d(${p.x}px, ${p.y}px, 0)`;
    if (pointerRef.current) pointerRef.current.style.transform = t;
    if (haloRef.current) haloRef.current.style.transform = t;
  };

  const setView = useCallback(
    (v: View) => {
      view.current = clampView(v, stageSize.current, fb.current);
      applyView();
    },
    [applyView],
  );

  // Desktop size from the session.
  useEffect(() => {
    if (s.desktop.w === 0) return;
    const changed = fb.current.w !== s.desktop.w || fb.current.h !== s.desktop.h;
    fb.current = { w: s.desktop.w, h: s.desktop.h };
    if (changed) {
      view.current = initialView(fb.current);
      pointer.current = { x: Math.round(s.desktop.w / 2), y: Math.round(s.desktop.h / 2), movedAt: 0 };
      s.renderer.current?.setCursorPosition(pointer.current.x, pointer.current.y);
    }
    applyView();
  }, [s.desktop, applyView, s.renderer]);

  // Stage size, and the canvas backing store in device pixels.
  useLayoutEffect(() => {
    const el = stageRef.current;
    if (!el) return;
    const measure = (): void => {
      const rect = el.getBoundingClientRect();
      const w = Math.round(rect.width);
      const h = Math.round(rect.height);
      stageSize.current = { w, h };
      setStage((prev) => (prev.w === w && prev.h === h ? prev : { w, h }));
      const dpr = window.devicePixelRatio || 1;
      s.renderer.current?.setCanvasSize(Math.round(w * dpr), Math.round(h * dpr));
      view.current = clampView(view.current, stageSize.current, fb.current);
      applyView();
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [applyView, s.renderer, s.phase]);

  // The phone keyboard: keep the key bar and the desktop above it.
  useEffect(() => {
    const vv = window.visualViewport;
    const root = rootRef.current;
    if (!vv || !root) return;
    const update = (): void => {
      const kb = Math.max(0, window.innerHeight - (vv.height + vv.offsetTop));
      root.style.setProperty("--s-kb", `${Math.round(kb)}px`);
      root.classList.toggle("kb-open", kb > 40);
    };
    update();
    vv.addEventListener("resize", update);
    vv.addEventListener("scroll", update);
    return () => {
      vv.removeEventListener("resize", update);
      vv.removeEventListener("scroll", update);
    };
  }, []);

  // ------------------------------------------------------------ pointer out

  const sendPointer = useCallback(() => {
    s.sender.current?.pointer(pointer.current.x, pointer.current.y, mask.current);
    s.renderer.current?.setCursorPosition(pointer.current.x, pointer.current.y);
    placePointerOverlay();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.sender, s.renderer]);

  const movePointerTo = useCallback(
    (fx: number, fy: number) => {
      const c = clampToFb(fb.current, Math.round(fx), Math.round(fy));
      pointer.current = { x: c.x, y: c.y, movedAt: performance.now() };
      sendPointer();
    },
    [sendPointer],
  );

  // Follow the computer's own pointer when it moves it (and we did not just).
  useEffect(() => {
    const c = s.serverCursor;
    if (!c) return;
    if (performance.now() - pointer.current.movedAt < 600) return;
    pointer.current = { x: c.x, y: c.y, movedAt: pointer.current.movedAt };
    placePointerOverlay();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.serverCursor]);

  const wheel = useCallback(
    (bit: number) => {
      const snd = s.sender.current;
      if (!snd) return;
      snd.pointer(pointer.current.x, pointer.current.y, mask.current | bit);
      snd.pointer(pointer.current.x, pointer.current.y, mask.current);
    },
    [s.sender],
  );

  // ------------------------------------------------------------ animation

  const stopAnim = useCallback(() => {
    cancelAnimationFrame(anim.current.raf);
    anim.current = { raf: 0, kind: "none", vx: 0, vy: 0 };
  }, []);

  const runAnim = useCallback(() => {
    const step = (now: number): void => {
      const a = anim.current;
      if (a.kind === "momentum") {
        const dt = Math.min(48, now - (a.last ?? now));
        a.last = now;
        const m = momentumStep(a.vx, a.vy, dt || 16);
        a.vx = m.vx;
        a.vy = m.vy;
        setView(panBy(view.current, stageSize.current, fb.current, m.dx, m.dy));
        if (m.vx === 0 && m.vy === 0) return stopAnim();
      } else if (a.kind === "zoom" && a.from && a.to && a.t0 !== undefined) {
        const t = (now - a.t0) / 260;
        setView(lerpView(a.from, a.to, t));
        if (t >= 1) return stopAnim();
      } else if (a.kind === "edge") {
        const dt = Math.min(48, now - (a.last ?? now)) || 16;
        a.last = now;
        setView(panBy(view.current, stageSize.current, fb.current, -(a.ex ?? 0) * dt * 0.6, -(a.ey ?? 0) * dt * 0.6));
        // Keep the held button under the finger while the picture slides.
        const finger = screenToFb(view.current, stageSize.current, fb.current, edgeFinger.current.x, edgeFinger.current.y);
        movePointerTo(finger.x, finger.y);
      } else {
        return;
      }
      a.raf = requestAnimationFrame(step);
    };
    cancelAnimationFrame(anim.current.raf);
    anim.current.raf = requestAnimationFrame(step);
  }, [setView, stopAnim, movePointerTo]);

  const edgeFinger = useRef({ x: 0, y: 0 });

  // ------------------------------------------------------------ gestures

  const openKeyboard = useCallback((open: boolean) => {
    const el = inputRef.current;
    if (!el) return;
    if (open) {
      el.value = SENTINEL;
      differ.current.reset();
      el.focus({ preventScroll: true });
      try {
        el.setSelectionRange(el.value.length, el.value.length);
      } catch {
        // Some inputs refuse a selection; the caret position does not matter much.
      }
    } else {
      el.blur();
    }
  }, []);

  const handle = useCallback(
    (acts: GestureAction[]) => {
      const st = stageSize.current;
      const f = fb.current;
      for (const a of acts) {
        switch (a.type) {
          case "move": {
            const sc = placement(view.current, st, f).scale;
            const d = Math.hypot(a.dx, a.dy);
            const gain = 1 + Math.min(1.4, Math.max(0, (d - 2) / 10));
            movePointerTo(pointer.current.x + (a.dx * gain) / sc, pointer.current.y + (a.dy * gain) / sc);
            if (!isFit(view.current)) {
              setView(ensureVisible(view.current, st, f, pointer.current.x, pointer.current.y, FOLLOW_MARGIN));
            }
            break;
          }
          case "point": {
            const p = screenToFb(view.current, st, f, a.x, a.y);
            movePointerTo(p.x, p.y);
            if (mask.current & BUTTON.left && !isFit(view.current)) {
              const ex = a.x < EDGE_ZONE ? -1 : a.x > st.w - EDGE_ZONE ? 1 : 0;
              const ey = a.y < EDGE_ZONE ? -1 : a.y > st.h - EDGE_ZONE ? 1 : 0;
              edgeFinger.current = { x: a.x, y: a.y };
              if (ex || ey) {
                anim.current.ex = ex;
                anim.current.ey = ey;
                if (anim.current.kind !== "edge") {
                  anim.current.kind = "edge";
                  anim.current.last = undefined;
                  runAnim();
                }
              } else if (anim.current.kind === "edge") stopAnim();
            }
            break;
          }
          case "click": {
            if (a.x !== undefined && a.y !== undefined) {
              const p = screenToFb(view.current, st, f, a.x, a.y);
              const c = clampToFb(f, Math.round(p.x), Math.round(p.y));
              pointer.current = { x: c.x, y: c.y, movedAt: performance.now() };
            }
            const bit = a.button === "right" ? BUTTON.right : BUTTON.left;
            mask.current |= bit;
            sendPointer();
            mask.current &= ~bit;
            sendPointer();
            haptic(a.button === "right" ? "right" : "click");
            flashClick(a.button);
            break;
          }
          case "down":
            if (a.x !== undefined && a.y !== undefined) {
              const p = screenToFb(view.current, st, f, a.x, a.y);
              movePointerTo(p.x, p.y);
            }
            mask.current |= BUTTON.left;
            sendPointer();
            haptic("soft");
            break;
          case "up":
            if (anim.current.kind === "edge") stopAnim();
            mask.current &= ~BUTTON.left;
            sendPointer();
            break;
          case "scroll": {
            const acc = scrollAcc.current;
            acc.y += -a.dy;
            acc.x += -a.dx;
            while (acc.y >= SCROLL_STEP) {
              wheel(BUTTON.wheelDown);
              acc.y -= SCROLL_STEP;
            }
            while (acc.y <= -SCROLL_STEP) {
              wheel(BUTTON.wheelUp);
              acc.y += SCROLL_STEP;
            }
            while (acc.x >= SCROLL_STEP) {
              wheel(BUTTON.wheelRight);
              acc.x -= SCROLL_STEP;
            }
            while (acc.x <= -SCROLL_STEP) {
              wheel(BUTTON.wheelLeft);
              acc.x += SCROLL_STEP;
            }
            break;
          }
          case "zoom":
            stopAnim();
            setView(zoomAt(view.current, st, f, a.factor, a.x, a.y));
            break;
          case "pan":
            setView(panBy(view.current, st, f, a.dx, a.dy));
            break;
          case "panEnd":
            if (Math.hypot(a.vx, a.vy) > 0.15) {
              anim.current = { raf: 0, kind: "momentum", vx: a.vx, vy: a.vy, last: undefined };
              runAnim();
            }
            break;
          case "doubleTapZoom": {
            const to = toggleZoomAt(view.current, st, f, a.x, a.y);
            anim.current = { raf: 0, kind: "zoom", vx: 0, vy: 0, from: { ...view.current }, to, t0: performance.now() };
            runAnim();
            haptic("soft");
            break;
          }
          case "keyboard":
            openKeyboard(document.activeElement !== inputRef.current);
            break;
          case "ring":
            if (a.state === "start") setRing({ x: a.x, y: a.y, key: performance.now() });
            else setRing(null);
            break;
        }
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [movePointerTo, sendPointer, setView, wheel, runAnim, stopAnim, openKeyboard],
  );

  const [clickFlash, setClickFlash] = useState<{ key: number; right: boolean } | null>(null);
  const flashClick = (button: "left" | "right"): void => setClickFlash({ key: performance.now(), right: button === "right" });

  const scheduleTick = useCallback(() => {
    if (tickTimer.current) return;
    const loop = (): void => {
      tickTimer.current = null;
      handle(recognizer.tick(performance.now()));
      if (recognizer.wantsTick()) tickTimer.current = setTimeout(loop, 40);
    };
    if (recognizer.wantsTick()) tickTimer.current = setTimeout(loop, 40);
  }, [handle, recognizer]);

  const feed = useCallback(
    (e: TouchInput) => {
      if (e.type === "start" && anim.current.kind === "momentum") stopAnim();
      handle(recognizer.feed(e));
      scheduleTick();
    },
    [handle, recognizer, scheduleTick, stopAnim],
  );

  // Native listeners: React's touch handlers are passive, and the page must
  // not scroll or zoom under the fingers.
  useEffect(() => {
    const el = stageRef.current;
    if (!el) return;
    const pts = (list: TouchList): Pt[] => {
      const r = el.getBoundingClientRect();
      const out: Pt[] = [];
      for (let i = 0; i < list.length; i++) {
        const t = list[i];
        out.push({ id: t.identifier, x: t.clientX - r.left, y: t.clientY - r.top });
      }
      return out;
    };
    const on = (type: TouchInput["type"]) => (ev: TouchEvent) => {
      ev.preventDefault();
      feed({ type, t: performance.now(), touches: pts(ev.touches) });
    };
    const start = on("start");
    const move = on("move");
    const end = on("end");
    const cancel = on("cancel");
    el.addEventListener("touchstart", start, { passive: false });
    el.addEventListener("touchmove", move, { passive: false });
    el.addEventListener("touchend", end, { passive: false });
    el.addEventListener("touchcancel", cancel, { passive: false });

    // A mouse (dev in a browser, a mouse on a tablet) acts as one finger, and
    // its wheel scrolls.
    let mouseDown = false;
    const mpt = (ev: PointerEvent): Pt[] => {
      const r = el.getBoundingClientRect();
      return [{ id: 999, x: ev.clientX - r.left, y: ev.clientY - r.top }];
    };
    const pd = (ev: PointerEvent): void => {
      if (ev.pointerType !== "mouse") return;
      mouseDown = true;
      feed({ type: "start", t: performance.now(), touches: mpt(ev) });
    };
    const pm = (ev: PointerEvent): void => {
      if (ev.pointerType !== "mouse" || !mouseDown) return;
      feed({ type: "move", t: performance.now(), touches: mpt(ev) });
    };
    const pu = (ev: PointerEvent): void => {
      if (ev.pointerType !== "mouse" || !mouseDown) return;
      mouseDown = false;
      feed({ type: "end", t: performance.now(), touches: [] });
    };
    const wh = (ev: WheelEvent): void => {
      ev.preventDefault();
      if (ev.ctrlKey) {
        const r = el.getBoundingClientRect();
        setView(zoomAt(view.current, stageSize.current, fb.current, Math.exp(-ev.deltaY / 200), ev.clientX - r.left, ev.clientY - r.top));
        return;
      }
      handle([{ type: "scroll", dx: -ev.deltaX, dy: -ev.deltaY }]);
    };
    el.addEventListener("pointerdown", pd);
    window.addEventListener("pointermove", pm);
    window.addEventListener("pointerup", pu);
    el.addEventListener("wheel", wh, { passive: false });
    return () => {
      el.removeEventListener("touchstart", start);
      el.removeEventListener("touchmove", move);
      el.removeEventListener("touchend", end);
      el.removeEventListener("touchcancel", cancel);
      el.removeEventListener("pointerdown", pd);
      window.removeEventListener("pointermove", pm);
      window.removeEventListener("pointerup", pu);
      el.removeEventListener("wheel", wh);
    };
  }, [feed, handle, setView]);

  useEffect(
    () => () => {
      if (tickTimer.current) clearTimeout(tickTimer.current);
      if (toastTimer.current) clearTimeout(toastTimer.current);
      cancelAnimationFrame(anim.current.raf);
    },
    [],
  );

  // ------------------------------------------------------------ keys

  const tapKey = useCallback(
    (ids: { keysym: number; keycode: number }, extraMods: ModifierKey[] = []) => {
      const snd = s.sender.current;
      if (!snd) return;
      const held = Array.from(new Set([...heldModifiers(modsRef.current), ...extraMods]));
      for (const m of held) snd.key(true, MODIFIERS[m].keysym, MODIFIERS[m].keycode);
      snd.key(true, ids.keysym, ids.keycode);
      snd.key(false, ids.keysym, ids.keycode);
      for (const m of held.slice().reverse()) snd.key(false, MODIFIERS[m].keysym, MODIFIERS[m].keycode);
      if (held.length) setMods((cur) => afterKey(cur));
    },
    [s.sender],
  );

  const applyTextOps = useCallback(
    (ops: TextOp[]) => {
      const id = s.sessionId;
      for (const op of ops) {
        if (op.type === "backspace") {
          for (let i = 0; i < op.count; i++) tapKey(KEYSYM_BACKSPACE);
        } else if (heldModifiers(modsRef.current).length > 0) {
          // Ctrl+C and friends: characters go as keys with the modifiers held.
          for (const ch of Array.from(op.text)) tapKey(charIds(ch, true));
        } else if (id) {
          // Typed text goes after anything already queued, such as a backspace.
          s.sender.current?.flush();
          void api.sessionText(id, op.text).catch(() => {});
        }
      }
    },
    [api, s.sessionId, s.sender, tapKey],
  );

  const resetFieldIfIdle = (): void => {
    const el = inputRef.current;
    if (!el || composing.current) return;
    if (el.value.length > 32 || el.value === "") {
      el.value = SENTINEL;
      differ.current.reset();
    }
  };

  const onInput = (e: React.FormEvent<HTMLInputElement>): void => {
    const native = e.nativeEvent as InputEvent;
    const ops = differ.current.onValue(e.currentTarget.value, composing.current || native.isComposing === true);
    applyTextOps(ops);
    resetFieldIfIdle();
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    const ne = e.nativeEvent;
    if (ne.isComposing || ne.keyCode === 229 || e.key === "Unidentified" || e.key === "Process") return;
    const snd = s.sender.current;
    if (!snd) return;
    if (e.key === "Control" || e.key === "Alt" || e.key === "Meta") {
      const ids = keyEventToIds(ne);
      if (ids) snd.key(true, ids.keysym, ids.keycode);
      e.preventDefault();
      return;
    }
    const hardwareMods = e.ctrlKey || e.altKey || e.metaKey;
    if (NAMED_KEYS.has(e.key) || hardwareMods) {
      // Backspace on a field the keyboard thinks is empty must still reach the computer.
      const ids = keyEventToIds(ne);
      if (!ids) return;
      e.preventDefault();
      tapKey(ids);
    }
  };

  const onKeyUp = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Control" || e.key === "Alt" || e.key === "Meta") {
      const ids = keyEventToIds(e.nativeEvent);
      if (ids) s.sender.current?.key(false, ids.keysym, ids.keycode);
    }
  };

  const onKeyBar = useCallback(
    (p: KeyBarPress) => {
      haptic("soft");
      if (p.kind === "mod") {
        setMods((cur) => ({ ...cur, [p.mod]: nextModState(cur[p.mod], p.doubleTap) }));
        return;
      }
      if (p.kind === "cad") {
        if (s.sessionId) void api.sessionKeyCombo(s.sessionId, "ctrl-alt-del").catch(() => {});
        showToast("Sent Ctrl Alt Del");
        return;
      }
      tapKey(namedKeyIds(p.key as NamedKey));
    },
    [api, s.sessionId, showToast, tapKey],
  );

  // ------------------------------------------------------------ mode and coach

  const setMode = useCallback((m: TouchMode) => {
    setModeState(m);
    save("mode", m);
    if (!coachSeen(m)) setCoach(m);
  }, []);

  useEffect(() => {
    if (s.phase === "connected" && !coachSeen(modeRef.current)) setCoach(modeRef.current);
  }, [s.phase]);

  // A picture format this phone cannot show: ask for one it can.
  useEffect(() => {
    if (s.notice === "no-h264") {
      setQualityState("quality");
      s.setQuality("quality");
      showToast("Switched to sharp still pictures for this phone");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.notice]);

  useEffect(() => {
    if (s.remoteClipboard && s.remoteClipboard !== clipSeen && s.phase === "connected") showToast("Something was copied on the computer");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.remoteClipboard]);

  // ------------------------------------------------------------ toolbar

  const leave = useCallback(async () => {
    openKeyboard(false);
    await s.disconnect();
    onExit();
  }, [onExit, openKeyboard, s]);

  const onTool = useCallback(
    (a: ToolbarAction) => {
      switch (a) {
        case "keyboard":
          openKeyboard(!keyboardOn);
          break;
        case "mode":
          setSheet("mode");
          break;
        case "keys":
          setKeysOn((v) => !v);
          break;
        case "quality":
          setSheet("quality");
          break;
        case "clipboard":
          setClipSeen(s.remoteClipboard);
          setSheet("clipboard");
          break;
        case "snapshot":
          void s.snapshot().then((ok) => showToast(ok ? "Saved as this computer's picture" : "No picture to save yet"));
          break;
        case "disconnect":
          void leave();
          break;
      }
      if (a !== "keyboard" && a !== "keys") setToolbarOpen(false);
    },
    [keyboardOn, leave, openKeyboard, s, showToast],
  );

  // ------------------------------------------------------------ render

  const name = s.desktopName && title.trim() === "" ? s.desktopName : title;
  const level = qualityLevel(s.stats);
  const showDesktop = s.phase === "connected" || s.phase === "ended";
  const reconnecting = s.state.state === "reconnecting";
  const keyBarVisible = showDesktop && (keyboardOn || keysOn);
  const ringStyle = ring ? { left: ring.x, top: ring.y } : undefined;

  return (
    <div ref={rootRef} className={`dv-session mode-${mode}${keyBarVisible ? " has-keybar" : ""}`}>
      <div ref={stageRef} className="dv-s-stage" aria-label={`Screen of ${name}`} role="application">
        <canvas ref={s.attachCanvas} className="dv-s-canvas" />
        {showDesktop ? (
          <>
            <div ref={haloRef} className={`dv-s-halo${mode === "trackpad" ? "" : " is-hidden"}`} aria-hidden="true" />
            <div ref={pointerRef} className={`dv-s-pointer${mode === "trackpad" && !s.hasCursorShape ? "" : " is-hidden"}`} aria-hidden="true">
              <svg width="22" height="30" viewBox="0 0 11 15.5">
                <path d="M0.5 0.5 L0.5 13 L3.8 9.9 L6.2 15 L8.2 14.1 L5.9 9.1 L10.3 9.1 Z" fill="#fff" stroke="#111" strokeWidth="0.9" strokeLinejoin="round" />
              </svg>
            </div>
            {clickFlash ? <ClickFlash key={clickFlash.key} pointer={pointer.current} view={view.current} stage={stage} fb={fb.current} right={clickFlash.right} /> : null}
            {ring ? (
              <svg key={ring.key} className="dv-s-ring" style={ringStyle} viewBox="0 0 80 80" aria-hidden="true">
                <circle cx="40" cy="40" r="32" className="track" />
                <circle cx="40" cy="40" r="32" className="fill" />
              </svg>
            ) : null}
          </>
        ) : null}
      </div>

      {showDesktop ? (
        <>
          <button
            type="button"
            className={`dv-s-quality level-${level}`}
            onClick={() => setSheet("stats")}
            aria-label={`${LEVEL_WORDS[level]}. Tap for details`}
          >
            <span className="bars" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
          </button>
          <Toolbar
            open={toolbarOpen}
            title={name}
            mode={mode}
            keyboardOn={keyboardOn}
            keysOn={keysOn}
            hasClipboard={!!s.remoteClipboard && s.remoteClipboard !== clipSeen}
            onToggle={() => setToolbarOpen((v) => !v)}
            onAction={onTool}
          />
          {zoomed ? (
            <button type="button" className="dv-s-zoomchip" onClick={() => {
              anim.current = { raf: 0, kind: "zoom", vx: 0, vy: 0, from: { ...view.current }, to: clampView(initialView(fb.current), stageSize.current, fb.current), t0: performance.now() };
              runAnim();
            }}>
              <IconZoomOut size={20} /> Show the whole screen
            </button>
          ) : null}
          {reconnecting ? (
            <div className="dv-s-banner" role="status">
              <span className="dv-s-spinner" aria-hidden="true" /> Reconnecting, hold on
            </div>
          ) : null}
        </>
      ) : null}

      <input
        ref={inputRef}
        className="dv-s-hidden-input"
        defaultValue={SENTINEL}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        spellCheck={false}
        aria-label="Type on the computer"
        enterKeyHint="send"
        onFocus={() => setKeyboardOn(true)}
        onBlur={() => {
          setKeyboardOn(false);
          s.sender.current?.flush();
        }}
        onInput={onInput}
        onKeyDown={onKeyDown}
        onKeyUp={onKeyUp}
        onCompositionStart={() => {
          composing.current = true;
        }}
        onCompositionEnd={(e) => {
          composing.current = false;
          applyTextOps(differ.current.onCompositionEnd(e.currentTarget.value));
          resetFieldIfIdle();
        }}
      />

      {keyBarVisible ? <KeyBar mods={mods} metaLabel={metaLabelFor(os)} onPress={onKeyBar} /> : null}

      {s.phase === "connecting" ? <ConnectingScreen title={name} step={stepOf(s.state)} reconnecting={reconnecting} onCancel={() => void leave()} /> : null}
      {s.phase === "error" ? <ErrorScreen title={name} message={s.error} onRetry={s.reconnect} onExit={() => void leave()} /> : null}
      {s.phase === "ended" && s.needsReconnect ? <ReconnectCard title={name} onReconnect={s.reconnect} onExit={() => void leave()} /> : null}

      {s.credentials ? (
        <CredentialSheet request={s.credentials} computerName={name} onSubmit={s.answerCredentials} onCancel={s.cancelCredentials} />
      ) : null}
      {s.cert ? <CertSheet data={s.cert} computerName={name} onAnswer={s.answerCert} /> : null}

      {sheet === "mode" ? (
        <ModeSheet
          mode={mode}
          onPick={(m) => {
            setMode(m);
            setSheet(null);
          }}
          onClose={() => setSheet(null)}
          onShowTips={() => {
            setSheet(null);
            setCoach(mode);
          }}
        />
      ) : null}
      {sheet === "quality" ? (
        <QualitySheet
          quality={quality}
          videoOk={hasVideoDecoder()}
          onPick={(q) => {
            setQualityState(q);
            s.setQuality(q);
            setSheet(null);
          }}
          onClose={() => setSheet(null)}
        />
      ) : null}
      {sheet === "clipboard" ? (
        <ClipboardSheet
          fromComputer={s.remoteClipboard}
          onSend={(text) => {
            if (s.sessionId) void api.sessionClipboard(s.sessionId, text).catch(() => {});
            setSheet(null);
            showToast("Sent. Paste it on the computer");
          }}
          onClose={() => setSheet(null)}
        />
      ) : null}
      {sheet === "stats" ? <StatsSheet stats={s.stats} onClose={() => setSheet(null)} onQuality={() => setSheet("quality")} /> : null}

      {coach && showDesktop && !s.credentials && !s.cert ? <Coach mode={coach} onDone={() => setCoach(null)} /> : null}

      {toast ? (
        <div className="dv-s-toast" role="status">
          {toast}
        </div>
      ) : null}
    </div>
  );
}

function ClickFlash({ pointer, view, stage, fb, right }: { pointer: { x: number; y: number }; view: View; stage: Size; fb: Size; right: boolean }) {
  if (fb.w === 0 || stage.w === 0) return null;
  const p = fbToScreen(view, stage, fb, pointer.x, pointer.y);
  return <span className={`dv-s-clickflash${right ? " right" : ""}`} style={{ left: p.x, top: p.y }} aria-hidden="true" />;
}

export default SessionScreen;
