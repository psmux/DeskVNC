/**
 * Where the session screen is mounted. To switch to the real one, change the
 * import below to "../session/SessionScreen". Its props are exactly
 * `{ api, target, onExit }`.
 */
import { api } from "../api";
import { SessionScreen } from "../session/placeholder";
import { useApp } from "../state/app";

export function SessionRoute() {
  const { session, endSession } = useApp();
  if (!session) return null;
  return <SessionScreen key={session.key} api={api} target={session.target} onExit={endSession} />;
}
