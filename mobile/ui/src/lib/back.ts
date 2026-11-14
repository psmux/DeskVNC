/**
 * The Android Back button.
 *
 * Left alone, Tauri's Android activity goes back in the webview's history and,
 * with none (this app never navigates), hands Back to Android, which closes
 * the app. That ended a live session without a word. Here every screen that
 * sits above the home screen registers what Back means for it, and while any
 * is registered the app takes Back over (`onBackButtonPress`). On the home
 * screen nothing is registered, the listener is removed, and Back does what
 * Android does everywhere else.
 *
 * Layers decide who answers when several are open at once: a sheet over a
 * session over a tab. React runs a child's effect before its parent's, so
 * registration order alone would put a sheet below the screen that holds it.
 */
import { useEffect, useRef } from "react";

export const LAYER = {
  /** A tab other than the home tab. */
  tab: 1,
  /** The add computer wizard. */
  wizard: 2,
  /** A remote session, full screen. */
  session: 3,
  /** A sheet or dialog over any of them. */
  sheet: 4,
} as const;

export interface BackStack {
  /** Register a handler; returns the function that removes it. */
  push(layer: number, handler: () => void): () => void;
  /** Run the topmost handler. False when nothing is registered. */
  handle(): boolean;
  size(): number;
}

/**
 * The stack itself, apart from Tauri so it can be tested. `onActive` hears
 * when the stack becomes non empty (true) and empty again (false).
 */
export function createBackStack(onActive: (active: boolean) => void = () => {}): BackStack {
  let next = 0;
  const entries: { id: number; layer: number; handler: () => void }[] = [];
  return {
    push(layer, handler) {
      const id = next++;
      entries.push({ id, layer, handler });
      if (entries.length === 1) onActive(true);
      return () => {
        const at = entries.findIndex((e) => e.id === id);
        if (at < 0) return;
        entries.splice(at, 1);
        if (entries.length === 0) onActive(false);
      };
    },
    handle() {
      let top: (typeof entries)[number] | null = null;
      for (const e of entries) if (!top || e.layer > top.layer || (e.layer === top.layer && e.id > top.id)) top = e;
      if (!top) return false;
      top.handler();
      return true;
    },
    size: () => entries.length,
  };
}

// ------------------------------------------------------------------ Tauri

let listener: Promise<{ unregister(): Promise<void> } | null> | null = null;

function setListening(on: boolean): void {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
  if (on && !listener) {
    listener = import("@tauri-apps/api/app")
      .then(({ onBackButtonPress }) => onBackButtonPress(() => void backStack.handle()))
      .catch(() => null);
  } else if (!on && listener) {
    const old = listener;
    listener = null;
    void old.then((l) => l?.unregister()).catch(() => {});
  }
}

export const backStack = createBackStack(setListening);

/**
 * While `active`, Back runs `handler` (the latest one passed) unless a
 * higher layer is also open.
 */
export function useBack(active: boolean, layer: number, handler: () => void): void {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    if (!active) return;
    return backStack.push(layer, () => ref.current());
  }, [active, layer]);
}
