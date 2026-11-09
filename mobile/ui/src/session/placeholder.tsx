/**
 * A stand in for the session screen until src/session/SessionScreen.tsx
 * lands. It connects, draws format 0 frames, answers prompts with the shared
 * sheets, sends taps and typed text, and ends. Swap the import in
 * screens/SessionRoute.tsx to retire it.
 */
import { useEffect, useRef, useState } from "react";
import type { Api, ConnectTarget, CredentialRequest, SessionState } from "../api/contract";
import { IconClose } from "../art/Icons";
import { ConnectingSteps, stepFor, stepsFor } from "../components/ConnectingSteps";
import { CertificateSheet, type CertificatePrompt } from "../components/sheets/CertificateSheet";
import { CredentialSheet } from "../components/sheets/CredentialSheet";

export interface SessionScreenProps {
  api: Api;
  target: ConnectTarget;
  onExit: () => void;
}

export function SessionScreen({ api, target, onExit }: SessionScreenProps) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [id, setId] = useState<string | null>(null);
  const [state, setState] = useState<SessionState>({ state: "connecting" });
  const [creds, setCreds] = useState<CredentialRequest | null>(null);
  const [cert, setCert] = useState<CertificatePrompt | null>(null);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);
  const typing = useRef<HTMLInputElement>(null);
  const exit = useRef(onExit);
  exit.current = onExit;
  const protocol = target.kind === "demo" ? "demo" : target.kind === "boundary" ? "boundary" : target.kind === "adhoc" ? target.protocol : "vnc";

  useEffect(() => {
    let sessionId: string | null = null;
    let alive = true;
    const draw = (msg: ArrayBuffer) => {
      const c = canvas.current;
      const v = new DataView(msg);
      if (!c || v.getUint8(0) !== 1) return;
      const ctx = c.getContext("2d")!;
      let off = 12;
      for (let i = 0; i < v.getUint16(2, true); i++) {
        const x = v.getUint16(off, true);
        const y = v.getUint16(off + 2, true);
        const w = v.getUint16(off + 4, true);
        const h = v.getUint16(off + 6, true);
        const format = v.getUint8(off + 8);
        const len = v.getUint32(off + 10, true);
        if (format === 0) ctx.putImageData(new ImageData(new Uint8ClampedArray(msg, off + 16, len), w, h), x, y);
        off += 16 + len;
      }
    };
    api
      .sessionConnect(target, draw, (e) => {
        if (!alive) return;
        if (e.type === "state-changed") setState(e.state);
        else if (e.type === "desktop-resize" && canvas.current) {
          canvas.current.width = e.width;
          canvas.current.height = e.height;
        } else if (e.type === "credentials-required") setCreds(e.request);
        else if (e.type === "certificate-prompt") setCert(e);
        else if (e.type === "error") setError(e.message);
        else if (e.type === "ended") exit.current();
      })
      .then((r) => {
        sessionId = r.sessionId;
        if (alive) setId(r.sessionId);
        else void api.sessionDisconnect(r.sessionId);
      })
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
      if (sessionId) void api.sessionDisconnect(sessionId);
    };
  }, [api, target]);

  const tap = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const c = canvas.current;
    if (!c || !id) return;
    const r = c.getBoundingClientRect();
    const x = Math.round(((e.clientX - r.left) / r.width) * c.width);
    const y = Math.round(((e.clientY - r.top) / r.height) * c.height);
    const body = new Uint8Array(14);
    const v = new DataView(body.buffer);
    v.setUint8(0, 0);
    v.setUint16(1, x, true);
    v.setUint16(3, y, true);
    v.setUint16(5, 1, true);
    v.setUint8(7, 0);
    v.setUint16(8, x, true);
    v.setUint16(10, y, true);
    v.setUint16(12, 0, true);
    seq.current += 1;
    void api.sessionInput(id, seq.current, body);
  };

  const connected = state.state === "connected";
  return (
    <div className="fixed inset-0 z-40 flex flex-col bg-bg">
      <div className="pt-safe flex items-center justify-between px-4 py-2">
        <button type="button" onClick={onExit} className="flex min-h-12 items-center gap-2 rounded-full bg-surface px-4 font-semibold shadow-card">
          <IconClose size={20} /> End
        </button>
        {connected && (
          <button type="button" onClick={() => typing.current?.focus()} className="min-h-12 rounded-full bg-surface px-4 font-semibold shadow-card">
            Keyboard
          </button>
        )}
      </div>
      <div className="relative flex flex-1 items-center justify-center overflow-hidden">
        <canvas ref={canvas} onPointerDown={tap} className={`max-h-full max-w-full ${connected ? "" : "hidden"}`} style={{ touchAction: "none" }} />
        {!connected && (
          <ConnectingSteps steps={stepsFor(protocol, false)} current={stepFor(state, protocol)} title={error ?? "Getting connected"} />
        )}
        <input
          ref={typing}
          className="absolute -left-[999px] opacity-0"
          aria-label="Type on the computer"
          onChange={(e) => {
            if (id && e.target.value) void api.sessionText(id, e.target.value);
            e.target.value = "";
          }}
        />
      </div>
      <CredentialSheet
        open={!!creds}
        request={creds}
        onCancel={() => {
          setCreds(null);
          onExit();
        }}
        onSubmit={(u, p, save) => {
          setCreds(null);
          if (id) void api.sessionCredentials(id, u, p, save);
        }}
      />
      <CertificateSheet
        open={!!cert}
        prompt={cert}
        onAnswer={(accept) => {
          const c = cert;
          setCert(null);
          if (id && c) void api.sessionTrust(id, c.fingerprint, c.scheme, accept);
          if (!accept) onExit();
        }}
      />
    </div>
  );
}
