/**
 * What Android Back does on the session screen, apart from React so it can
 * be tested. The screen registers one handler at `LAYER.session` and acts on
 * the step this returns.
 */

export interface SessionBackView {
  /** The "Leave {name}?" prompt is showing. */
  askLeave: boolean;
  /** A session sheet (touch mode, quality, clipboard, stats) is open. */
  sheet: boolean;
  toolbarOpen: boolean;
  /** The touch tips are showing. */
  coach: boolean;
  /** The desktop is live. */
  connected: boolean;
}

export type SessionBackStep = "close-leave" | "close-sheet" | "close-toolbar" | "close-coach" | "ask-leave" | "leave";

/**
 * Close whatever is open over the desktop first. On a live desktop ask
 * before leaving. Back on that prompt closes it and stays, the way Back
 * closes every other prompt; only the Leave button leaves. Anywhere else
 * (connecting, failed, ended) Back leaves at once. It never closes the app.
 */
export function sessionBackStep(v: SessionBackView): SessionBackStep {
  if (v.askLeave) return "close-leave";
  if (v.sheet) return "close-sheet";
  if (v.toolbarOpen) return "close-toolbar";
  if (v.coach) return "close-coach";
  if (v.connected) return "ask-leave";
  return "leave";
}
