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
  return <SessionScreen key={session.key} api={api} target={session.target} title={session.title} onExit={endSession} />;
}
