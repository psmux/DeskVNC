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

/** Is the surface this component sits on the one in front? */
export function usePaneVisible(): boolean {
  return useContext(PaneVisibleContext);
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
