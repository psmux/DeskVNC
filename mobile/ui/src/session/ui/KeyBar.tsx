/**
 * The row of computer keys a phone keyboard does not have. Sits above the
 * phone keyboard (or at the bottom when the keyboard is closed). Ctrl, Alt,
 * Win/Cmd and Shift are sticky: a tap lights one up for the next key, a double
 * tap locks it.
 */
import { useRef, useState, type ReactNode } from "react";
import type { ModState, ModifierKey, NamedKey } from "../input/keys";
import { IconArrow } from "./icons";

export type KeyBarPress = { kind: "key"; key: NamedKey } | { kind: "mod"; mod: ModifierKey; doubleTap: boolean } | { kind: "cad" };

function Key({ children, onPress, wide, state, label, repeat }: { children: ReactNode; onPress(): void; wide?: boolean; state?: ModState; label?: string; repeat?: boolean }) {
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stop = (): void => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  };
  return (
    <button
      type="button"
      className={`dv-s-key${wide ? " wide" : ""}${state && state !== "off" ? ` is-${state}` : ""}`}
      aria-label={label}
      aria-pressed={state ? state !== "off" : undefined}
      // Keep focus (and the phone keyboard) on the hidden text field.
      onPointerDown={(e) => {
        e.preventDefault();
        onPress();
        if (repeat) {
          const again = (delay: number): void => {
            timer.current = setTimeout(() => {
              onPress();
              again(60);
            }, delay);
          };
          again(420);
        }
      }}
      onPointerUp={stop}
      onPointerLeave={stop}
      onPointerCancel={stop}
      onClick={(e) => e.preventDefault()}
    >
      {children}
      {state === "locked" ? <span className="dv-s-key-lock" aria-hidden="true" /> : null}
    </button>
  );
}

export function KeyBar({
  mods,
  metaLabel,
  onPress,
}: {
  mods: Record<ModifierKey, ModState>;
  metaLabel: string;
  onPress(p: KeyBarPress): void;
}) {
  const [page, setPage] = useState<"main" | "fn" | "nav">("main");
  const lastTap = useRef<{ mod: ModifierKey; t: number } | null>(null);
  const mod = (m: ModifierKey): void => {
    const now = performance.now();
    const dbl = lastTap.current?.mod === m && now - lastTap.current.t < 350;
    lastTap.current = dbl ? null : { mod: m, t: now };
    onPress({ kind: "mod", mod: m, doubleTap: dbl });
  };
  const key = (k: NamedKey) => () => onPress({ kind: "key", key: k });

  return (
    <div className="dv-s-keybar" role="toolbar" aria-label="Computer keys">
      <div className="dv-s-keybar-tabs">
        <Key onPress={() => setPage("main")} state={page === "main" ? "once" : "off"} label="Main keys">
          Keys
        </Key>
        <Key onPress={() => setPage("fn")} state={page === "fn" ? "once" : "off"} label="Function keys">
          F1…
        </Key>
        <Key onPress={() => setPage("nav")} state={page === "nav" ? "once" : "off"} label="Page keys">
          Pg
        </Key>
      </div>
      <div className="dv-s-keybar-row">
        {page === "main" ? (
          <>
            <Key onPress={key("Escape")}>Esc</Key>
            <Key onPress={key("Tab")}>Tab</Key>
            <Key onPress={() => mod("ctrl")} state={mods.ctrl}>
              Ctrl
            </Key>
            <Key onPress={() => mod("alt")} state={mods.alt}>
              Alt
            </Key>
            <Key onPress={() => mod("meta")} state={mods.meta}>
              {metaLabel}
            </Key>
            <Key onPress={() => mod("shift")} state={mods.shift}>
              Shift
            </Key>
            <Key onPress={key("ArrowLeft")} label="Left" repeat>
              <IconArrow dir="left" size={20} />
            </Key>
            <Key onPress={key("ArrowUp")} label="Up" repeat>
              <IconArrow dir="up" size={20} />
            </Key>
            <Key onPress={key("ArrowDown")} label="Down" repeat>
              <IconArrow dir="down" size={20} />
            </Key>
            <Key onPress={key("ArrowRight")} label="Right" repeat>
              <IconArrow dir="right" size={20} />
            </Key>
            <Key onPress={key("Delete")} wide>
              Del
            </Key>
            <Key onPress={() => onPress({ kind: "cad" })} wide label="Control Alt Delete">
              Ctrl Alt Del
            </Key>
          </>
        ) : page === "fn" ? (
          ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] as const).map((n) => (
            <Key key={n} onPress={key(`F${n}`)}>
              F{n}
            </Key>
          ))
        ) : (
          <>
            <Key onPress={key("Home")} wide>
              Home
            </Key>
            <Key onPress={key("End")} wide>
              End
            </Key>
            <Key onPress={key("PageUp")} wide repeat>
              PgUp
            </Key>
            <Key onPress={key("PageDown")} wide repeat>
              PgDn
            </Key>
            <Key onPress={key("Insert")} wide>
              Ins
            </Key>
            <Key onPress={key("PrintScreen")} wide>
              PrtSc
            </Key>
          </>
        )}
      </div>
    </div>
  );
}
