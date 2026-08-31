/**
 * One switchable surface in the library window: the library itself, or a
 * session tab.
 *
 * Panes all stay mounted and laid out, and only the one in front is painted.
 * `visibility` rather than `display: none` on purpose: a hidden pane still has
 * to have a size, or a session's canvas would collapse to zero, take the WebGL
 * viewport with it, and have to rebuild the whole framebuffer every time the
 * user came back to that tab.
 *
 * Hiding a pane stops it receiving focus and pointer events, but it does NOT
 * stop anything inside it that listens on `window`, and our dialogs and panels
 * bind Escape there in the capture phase so it beats the remote keyboard hook.
 * Without {@link usePaneVisible}, a credentials prompt parked in a background
 * tab would answer an Escape meant for the session in front, and dismiss a
 * handshake nobody was looking at. Anything that binds a window-level key
 * listener has to gate it on this.
 *
 * The default is `true` so that a session window, which has no pane around it
 * at all, behaves exactly as it did before any of this existed.
 */
import { createContext, useContext, type ReactNode } from "react";

const PaneVisibleContext = createContext(true);

/**
 * May the surface this component sits on claim the window?
 *
 * Named for what it originally answered, when one pane was on screen at a time
 * and being on screen was the same as owning the keyboard. A split makes those
 * two different questions, and this is the second one: everything that reads it
 * binds a window-level listener or takes the focus, and there is one window.
 * Several panes can be on screen at once, but only the focused one gets `true`.
 */
export function usePaneVisible(): boolean {
  return useContext(PaneVisibleContext);
}

/**
 * Declare that everything inside belongs to the focused pane, or does not.
 *
 * The split view positions its panes itself and has no use for {@link Pane}'s
 * own box, but the answer above still has to reach the dialogs and toolbars
 * inside each one.
 */
export function PaneVisible({
  value,
  children,
}: {
  value: boolean;
  children: ReactNode;
}): ReactNode {
  return <PaneVisibleContext.Provider value={value}>{children}</PaneVisibleContext.Provider>;
}

export function Pane({
  visible,
  id,
  label,
  children,
}: {
  visible: boolean;
  /** Ties the pane to the tab that controls it, for assistive technology. */
  id: string;
  label: string;
  children: ReactNode;
}): ReactNode {
  return (
    <PaneVisibleContext.Provider value={visible}>
      <div
        id={id}
        role="tabpanel"
        aria-label={label}
        className="absolute inset-0"
        style={{ visibility: visible ? "visible" : "hidden" }}
        aria-hidden={visible ? undefined : true}
        inert={visible ? undefined : true}
      >
        {children}
      </div>
    </PaneVisibleContext.Provider>
  );
}
