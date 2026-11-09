/**
 * The real Api: every call goes to Rust through `invoke`, streams arrive on
 * Tauri Channels. Command names and argument shapes are in mobile/CONTRACT.md.
 */
import { Channel, invoke } from "@tauri-apps/api/core";
import type { Api, ConnectTarget, Host, HostDraft, KeyCombo, Quality, ScanEvent, SessionEvent } from "./contract";

/** Copy the bytes so a view over a larger buffer never sends its neighbours. */
function exactBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? (bytes.buffer as ArrayBuffer)
    : (bytes.slice().buffer as ArrayBuffer);
}

export const tauriApi: Api = {
  hostsList: () => invoke<Host[]>("hosts_list"),
  hostsSave: (host: HostDraft) => invoke<Host>("hosts_save", { host }),
  hostsDelete: (id) => invoke<void>("hosts_delete", { id }),
  hostsSetSecret: (id, username, password) =>
    invoke<void>("hosts_set_secret", { id, username: username ?? undefined, password: password ?? undefined }),
  hostsThumbnail: (id) => invoke<string | null>("hosts_thumbnail", { id }),

  async scanStart(onEvent) {
    const channel = new Channel<ScanEvent>();
    channel.onmessage = onEvent;
    await invoke<void>("scan_start", { onEvent: channel });
  },
  scanStop: () => invoke<void>("scan_stop"),

  boundaryResolve: (code) => invoke<{ invitation: string }>("boundary_resolve", { code }),

  async sessionConnect(target: ConnectTarget, onFrame, onEvent) {
    const frames = new Channel<ArrayBuffer>();
    frames.onmessage = onFrame;
    const events = new Channel<SessionEvent>();
    events.onmessage = onEvent;
    return invoke<{ sessionId: string }>("session_connect", { target, onFrame: frames, onEvent: events });
  },
  sessionInput: (sessionId, seq, body) =>
    invoke<void>("session_input", exactBuffer(body), {
      headers: { "x-session-id": sessionId, "x-input-seq": String(seq) },
    }),
  sessionText: (sessionId, text) => invoke<void>("session_text", { sessionId, text }),
  sessionKeyCombo: (sessionId, combo: KeyCombo) => invoke<void>("session_key_combo", { sessionId, combo }),
  sessionCredentials: (sessionId, username, password, save) =>
    invoke<void>("session_credentials", { sessionId, username: username ?? undefined, password: password ?? undefined, save }),
  sessionTrust: (sessionId, fingerprint, scheme, accept) =>
    invoke<void>("session_trust", { sessionId, fingerprint, scheme, accept }),
  sessionQuality: (sessionId, quality: Quality) => invoke<void>("session_quality", { sessionId, quality }),
  sessionClipboard: (sessionId, text) => invoke<void>("session_clipboard", { sessionId, text }),
  // Raw RGBA body like the desktop capture_thumbnail; metadata in headers.
  sessionSnapshot: (sessionId, rgba, width, height) =>
    invoke<void>("session_snapshot", exactBuffer(rgba), {
      headers: { "x-session-id": sessionId, "x-width": String(width), "x-height": String(height) },
    }),
  sessionDisconnect: (sessionId) => invoke<void>("session_disconnect", { sessionId }),
};
