/**
 * The session's half of saving an ad hoc computer to the Library.
 *
 * The Library decides whether to save and does the saving: it holds the
 * preference, the host list and what discovery knows. What it cannot see from
 * another window is when the session first connected and what the server
 * calls itself, so the session tells it. The Library answers once a host was
 * saved, and the notice is shown here, where the person is looking.
 */
import { useEffect, useRef } from "react";
import { emit } from "@tauri-apps/api/event";
import { inTauri, safeListen } from "../lib/tauri";
import type { ProtocolKind, SessionState } from "../lib/types";
import {
  HOST_AUTOSAVED_EVENT,
  SESSION_CONNECTED_EVENT,
  canAutoSave,
  type HostAutoSavedPayload,
  type SessionConnectedPayload,
} from "../lib/autoSave";
import type { ToastKind } from "../state/ToastContext";

/**
 * How long after first connecting the session reports in. The server's name
 * can arrive just after the connection does, and a password the person asked
 * to remember is saved by the shell at that same moment, so a short wait
 * gives both a chance to land first.
 */
const ANNOUNCE_DELAY_MS = 1000;

export function useAutoSaveNotice(
  params: { sessionId: string | null; profileId: string | null; protocol: ProtocolKind },
  state: SessionState,
  desktopName: string,
  push: (kind: ToastKind, message: string) => void,
): void {
  const { sessionId, profileId, protocol } = params;
  const eligible = inTauri() && sessionId !== null && profileId === null && canAutoSave(protocol);

  const nameRef = useRef(desktopName);
  nameRef.current = desktopName;
  const pushRef = useRef(push);
  pushRef.current = push;
  const announced = useRef(false);
  const timer = useRef<number | undefined>(undefined);

  // Once per session. The timer is not cancelled when the state moves on: a
  // connection that drops a moment later still connected, and only closing
  // the session stops the report.
  useEffect(() => {
    if (!eligible || announced.current || state.state !== "connected" || sessionId === null) return;
    announced.current = true;
    timer.current = window.setTimeout(() => {
      const payload: SessionConnectedPayload = { sessionId, desktopName: nameRef.current };
      void emit(SESSION_CONNECTED_EVENT, payload).catch(() => {});
    }, ANNOUNCE_DELAY_MS);
  }, [eligible, state.state, sessionId]);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  useEffect(() => {
    if (!eligible || sessionId === null) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void safeListen<HostAutoSavedPayload>(HOST_AUTOSAVED_EVENT, (ev) => {
      if (cancelled || !ev || ev.sessionId !== sessionId || typeof ev.name !== "string") return;
      pushRef.current("info", `Saved ${ev.name} to your Library`);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [eligible, sessionId]);
}
