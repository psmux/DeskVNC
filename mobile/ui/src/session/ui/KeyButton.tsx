/**
 * The round keyboard button that floats over the desktop. A tap shows or
 * hides the phone keyboard; a drag moves it, and it settles on the nearer
 * side edge. It lives outside the stage, so none of its touches reach the
 * gesture recognizer or the computer.
 */
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { IconKeyboard } from "./icons";
import {
  DragTracker,
  KEY_BUTTON_SIZE,
  clampKeyButton,
  placeKeyButton,
  sanitizeKeyButtonPos,
  snapKeyButton,
  type KeyButtonArea,
  type KeyButtonPos,
} from "../input/keyButton";

export function KeyButton({
  pos,
  bottomInset,
  open,
  onTap,
  onMoved,
}: {
  pos: KeyButtonPos;
  /** Pixels covered at the bottom: an overlaid keyboard plus the key bar. */
  bottomInset: number;
  /** The phone keyboard is up. */
  open: boolean;
  onTap(): void;
  onMoved(pos: KeyButtonPos): void;
}) {
  const layerRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const tracker = useRef(new DragTracker());
  const grab = useRef({ dx: 0, dy: 0 });
  const swallowClick = useRef(false);
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null);
  const [pressed, setPressed] = useState(false);

  // The layer is the safe area; turning or folding the phone resizes it and
  // the stored fraction puts the button back in the same relative place.
  useLayoutEffect(() => {
    const el = layerRef.current;
    if (!el) return;
    const measure = (): void => {
      const r = el.getBoundingClientRect();
      const w = Math.round(r.width);
      const h = Math.round(r.height);
      setSize((p) => (p.w === w && p.h === h ? p : { w, h }));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const area: KeyButtonArea = { w: size.w, h: size.h, bottomInset };
  const safe = sanitizeKeyButtonPos(pos);
  const at = drag ?? placeKeyButton(safe, area);

  const local = (e: { clientX: number; clientY: number }): { x: number; y: number } => {
    const r = layerRef.current?.getBoundingClientRect();
    return { x: e.clientX - (r?.left ?? 0), y: e.clientY - (r?.top ?? 0) };
  };

  useEffect(() => () => tracker.current.cancel(), []);

  return (
    <div ref={layerRef} className="dv-s-keybtn-layer">
      {size.w > 0 ? (
        <button
          type="button"
          className={`dv-s-keybtn${open ? " is-on" : ""}${drag ? " is-dragging" : ""}${pressed ? " is-pressed" : ""}`}
          style={{ width: KEY_BUTTON_SIZE, height: KEY_BUTTON_SIZE, transform: `translate3d(${at.x}px, ${at.y}px, 0)` }}
          aria-label="Keyboard"
          aria-pressed={open}
          onPointerDown={(e) => {
            // Cancelling the press keeps focus, and the phone keyboard, on
            // the hidden text field, the same way the key bar does.
            e.preventDefault();
            // A drag the browser did not follow with a click must not eat the next tap.
            swallowClick.current = false;
            if (e.pointerType === "mouse" && e.button !== 0) return;
            try {
              e.currentTarget.setPointerCapture(e.pointerId);
            } catch {
              // Capture is a nicety; without it a fast drag may end early.
            }
            const p = local(e);
            grab.current = { dx: p.x - at.x, dy: p.y - at.y };
            tracker.current.down(p.x, p.y);
            setPressed(true);
          }}
          onPointerMove={(e) => {
            if (!tracker.current.active) return;
            const p = local(e);
            if (tracker.current.move(p.x, p.y)) setDrag(clampKeyButton(p.x - grab.current.dx, p.y - grab.current.dy, area));
          }}
          onPointerUp={(e) => {
            const p = local(e);
            if (tracker.current.active) tracker.current.move(p.x, p.y);
            const how = tracker.current.up();
            setPressed(false);
            if (how === "drag") {
              const c = clampKeyButton(p.x - grab.current.dx, p.y - grab.current.dy, area);
              swallowClick.current = true;
              setDrag(null);
              onMoved(snapKeyButton(c.x, c.y, area));
            }
          }}
          onPointerCancel={() => {
            tracker.current.cancel();
            setPressed(false);
            setDrag(null);
          }}
          onMouseDown={(e) => e.preventDefault()}
          onClick={(e) => {
            e.preventDefault();
            if (swallowClick.current) {
              swallowClick.current = false;
              return;
            }
            onTap();
          }}
        >
          <IconKeyboard size={24} />
        </button>
      ) : null}
    </div>
  );
}
