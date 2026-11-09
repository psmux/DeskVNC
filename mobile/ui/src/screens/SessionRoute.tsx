/**
 * Where the session screen is mounted. Its props are
 * `{ api, target, title?, onExit }`.
 */
import { api } from "../api";
import { SessionScreen } from "../session/SessionScreen";
import { useApp } from "../state/app";

export function SessionRoute() {
  const { session, endSession } = useApp();
  if (!session) return null;
  // Its own layer over the tab bar and everything else in the shell.
  return (
    <div className="fixed inset-0 z-50">
      <SessionScreen key={session.key} api={api} target={session.target} title={session.title} onExit={endSession} />
    </div>
  );
}
