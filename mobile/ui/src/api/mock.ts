/**
 * A convincing in browser stand in for the Rust side. Six invented
 * computers, a scan that finds things over a few seconds, a help code that
 * resolves, and sessions that stream a fake desktop as real format 0 RGBA
 * frames in the byte layout of src-tauri/FRAME_FORMAT.md.
 *
 * The same session code serves the built in demo computer inside the real
 * app (see `index.ts`), so it must never touch the network.
 *
 * URL switches for screenshots and testing: `?reset=1` clears saved state,
 * `?empty=1` starts with no computers.
 */
import type {
  Api,
  ConnectTarget,
  FoundComputer,
  Host,
  HostDraft,
  HostOs,
  KeyCombo,
  ScanEvent,
  SessionEvent,
  SessionState,
} from "./contract";
import { arrowCursor, FakeDesktop, styleForOs, type DesktopStyle, type Scene } from "./mockDesktop";

/** What each sample computer's card picture shows. The wallpaper is the
 * kind of computer's own quiet one; the host's colour stays a small dot. */
const CARD_SCENES: Record<string, Scene> = {
  studio: "studio",
  mum: "family",
  officemac: "office",
  garage: "server",
  pi: "pi",
  reception: "frontdesk",
};

function cardLook(host: Host): { scene: Scene } {
  return { scene: CARD_SCENES[host.id] ?? "try" };
}

const HOSTS_KEY = "deskvnc.mock.hosts";
const THUMBS_KEY = "deskvnc.mock.thumbs";

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const DAY = 86_400_000;

function seedHosts(): Host[] {
  const now = Date.now();
  const base = { username: null, hasPassword: false, lastConnectedAt: null, hasThumbnail: false };
  return [
    { ...base, id: "studio", name: "Studio PC", protocol: "rdp", address: "10.0.0.21", port: 3389, os: "windows", color: "blue", favorite: true, username: "alex", hasPassword: true, lastConnectedAt: now - 2 * 3600_000, hasThumbnail: true },
    { ...base, id: "mum", name: "Mum's laptop", protocol: "boundary", address: "", port: 0, os: "windows", color: "rose", favorite: true, lastConnectedAt: now - 3 * DAY, hasThumbnail: true, boundaryInvitation: "boundary1:mock-mums-laptop" },
    { ...base, id: "officemac", name: "Office Mac", protocol: "vnc", address: "192.0.2.40", port: 5900, os: "mac", color: "slate", favorite: false, lastConnectedAt: now - 6 * DAY, hasThumbnail: true },
    { ...base, id: "pi", name: "Raspberry Pi", protocol: "vnc", address: "10.0.0.31", port: 5901, os: "raspberry", color: "green", favorite: false, lastConnectedAt: now - 9 * DAY, hasThumbnail: true },
    { ...base, id: "garage", name: "Garage server", protocol: "vnc", address: "10.0.0.50", port: 5900, os: "linux", color: "slate", favorite: false, lastConnectedAt: now - 20 * DAY, hasThumbnail: true, hasPassword: true },
    { ...base, id: "reception", name: "Reception desk", protocol: "rdp", address: "192.0.2.77", port: 3389, os: "windows", color: "sun", favorite: false },
  ];
}

const FOUND: FoundComputer[] = [
  { address: "10.0.0.21", port: 3389, protocol: "rdp", name: "Studio PC", os: "windows" },
  { address: "10.0.0.31", port: 5901, protocol: "vnc", name: "Raspberry Pi", os: "raspberry" },
  { address: "10.0.0.23", port: 3389, protocol: "rdp", name: "Kids' PC", os: "windows" },
  { address: "10.0.0.24", port: 5900, protocol: "vnc", name: "Spare room Mac", os: "mac" },
  { address: "10.0.0.41", port: 5900, protocol: "vnc", name: null, os: "linux" },
  { address: "10.0.0.32", port: 5900, protocol: "vnc", name: "Workshop Pi", os: "raspberry" },
];

function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
function writeJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Fine: the mock simply forgets on reload.
  }
}

// ------------------------------------------------------------------ frames

/** One full screen msg_type 1 message with a single format 0 rect. */
export function encodeRgbaFrame(rgba: Uint8ClampedArray, w: number, h: number): ArrayBuffer {
  const payload = w * h * 4;
  // 12 byte message header, then a 14 byte rect header, then the pixels.
  const buf = new ArrayBuffer(12 + 14 + payload);
  const v = new DataView(buf);
  v.setUint8(0, 1);
  v.setUint8(1, 0);
  v.setUint16(2, 1, true);
  v.setUint16(4, 0, true);
  v.setUint16(6, 0, true);
  v.setUint16(8, w, true);
  v.setUint16(10, h, true);
  v.setUint16(12, 0, true);
  v.setUint16(14, 0, true);
  v.setUint16(16, w, true);
  v.setUint16(18, h, true);
  v.setUint8(20, 0); // format 0, RGBA
  v.setUint8(21, 0);
  v.setUint32(22, payload, true);
  new Uint8Array(buf, 26).set(rgba);
  return buf;
}

function encodeCursor(): ArrayBuffer {
  const c = arrowCursor();
  const buf = new ArrayBuffer(10 + c.rgba.length);
  const v = new DataView(buf);
  v.setUint8(0, 2);
  v.setUint8(1, 0);
  v.setUint16(2, c.w, true);
  v.setUint16(4, c.h, true);
  v.setUint16(6, c.hx, true);
  v.setUint16(8, c.hy, true);
  new Uint8Array(buf, 10).set(c.rgba);
  return buf;
}

// ---------------------------------------------------------------- sessions

interface MockSession {
  id: string;
  hostId: string | null;
  desktop: FakeDesktop;
  onFrame: (m: ArrayBuffer) => void;
  onEvent: (e: SessionEvent) => void;
  timers: ReturnType<typeof setInterval>[];
  started: number;
  connected: boolean;
  /** Resolves the wait for a credentials or certificate answer. */
  answer: ((ok: boolean) => void) | null;
  ended: boolean;
  owner: Map<string, MockSession>;
}

let nextSession = 1;

const COMBO_TEXT: Record<KeyCombo, string> = {
  "ctrl-alt-del": "Ctrl + Alt + Del",
  win: "Start menu",
  "alt-tab": "Alt + Tab",
  "cmd-tab": "Cmd + Tab",
  "ctrl-c": "Copied",
  "ctrl-v": "Pasted",
  esc: "Escape",
};

function emit(s: MockSession, e: Omit<SessionEvent, "sessionId"> & { type: SessionEvent["type"] }): void {
  if (s.ended) return;
  s.onEvent({ ...(e as object), sessionId: s.id } as SessionEvent);
}
function setState(s: MockSession, state: SessionState): void {
  emit(s, { type: "state-changed", state } as Omit<SessionEvent, "sessionId"> & { type: "state-changed" });
}

/** Wait for an answer to a prompt; false when the session ended first. */
function waitAnswer(s: MockSession): Promise<boolean> {
  return new Promise((resolve) => {
    s.answer = resolve;
  });
}

async function runSession(s: MockSession, flow: { boundary: boolean; askPassword: boolean; certificate: boolean; demo: boolean }) {
  if (flow.boundary) {
    setState(s, { state: "resolving" });
    await wait(700);
    setState(s, { state: "connecting" });
    await wait(700);
    // The person on the other end sees a request and has to say yes.
    setState(s, { state: "authenticating", method: "approval" });
    await wait(2600);
  } else {
    setState(s, { state: "connecting" });
    await wait(flow.demo ? 350 : 800);
    setState(s, { state: "negotiating" });
    await wait(flow.demo ? 200 : 500);
  }
  if (s.ended) return;
  if (flow.certificate) {
    emit(s, {
      type: "certificate-prompt",
      fingerprint: "3A:7F:12:C4:9B:E0:55:21:8D:6A:F3:0C:44:B9:17:E2:5D:90:AB:CD:01:23:45:67:89:AB:CD:EF:10:32:54:76",
      subject: "CN=reception-desk.example.com",
      isChange: false,
      scheme: "rdp-tls",
    } as never);
    if (!(await waitAnswer(s))) return;
  }
  if (flow.askPassword) {
    setState(s, { state: "authenticating", method: "vnc-password" });
    let attempt = 1;
    let error: string | null = null;
    for (;;) {
      emit(s, {
        type: "credentials-required",
        request: { method: "vnc-password", kind: "password-only", attempt, error, truncatesPassword: true, usernameHint: null },
      } as never);
      if (!(await waitAnswer(s))) return;
      // Any password works except "wrong", so the retry sheet can be seen.
      if (lastPassword !== "wrong") break;
      attempt += 1;
      error = "That password did not work. Check it and try again.";
    }
  }
  if (s.ended) return;
  s.connected = true;
  setState(s, { state: "connected" });
  emit(s, { type: "desktop-resize", width: s.desktop.width, height: s.desktop.height } as never);
  emit(s, { type: "desktop-name", name: s.desktop.style === "demo" ? "Demo computer" : s.desktop.name } as never);
  s.onFrame(encodeCursor());
  pushFrame(s);
  s.timers.push(
    setInterval(() => {
      if (s.desktop.needsFrame(performance.now())) pushFrame(s);
    }, 50),
  );
  // The note caret blinks, which needs a fresh frame twice a second.
  s.timers.push(setInterval(() => (s.desktop.dirty = true), 500));
  s.timers.push(
    setInterval(() => {
      emit(s, {
        type: "stats",
        stats: { rtt_ms: 18 + Math.round(Math.random() * 14), throughput_bps: 2_400_000 + Math.round(Math.random() * 900_000), fps: 30 },
      } as never);
    }, 1000),
  );
}

let lastPassword: string | null = null;

function pushFrame(s: MockSession): void {
  if (s.ended) return;
  const rgba = s.desktop.render();
  s.onFrame(encodeRgbaFrame(rgba, s.desktop.width, s.desktop.height));
}

function endSession(s: MockSession, reason?: string): void {
  if (s.ended) return;
  if (reason) setState(s, { state: "disconnected", reason, can_retry: true });
  const durationS = Math.round((Date.now() - s.started) / 1000);
  s.onEvent({ sessionId: s.id, type: "ended", durationS });
  s.ended = true;
  s.timers.forEach(clearInterval);
  s.answer?.(false);
  s.owner.delete(s.id);
}

function decodeInput(s: MockSession, body: Uint8Array): void {
  const v = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let i = 0;
  while (i < body.length) {
    const kind = body[i];
    if (kind === 0 && i + 7 <= body.length) {
      const x = v.getUint16(i + 1, true);
      const y = v.getUint16(i + 3, true);
      const mask = v.getUint16(i + 5, true);
      s.desktop.pointer(x, y, mask);
      emit(s, { type: "cursor-position", x, y } as never);
      i += 7;
    } else if (kind === 1 && i + 10 <= body.length) {
      s.desktop.key(v.getUint32(i + 2, true), body[i + 1] === 1);
      i += 10;
    } else if (kind === 2) {
      i += 1;
    } else {
      throw new Error("Malformed input body");
    }
  }
}

/**
 * The session half of the Api, on its own so the demo computer can use it
 * inside the real app. `describe` says what to show for a saved host id.
 */
export function createMockSessions(describe: (hostId: string) => { name: string; os: HostOs; protocol: string } | null) {
  const sessions = new Map<string, MockSession>();
  const sessionFor = (id: string): MockSession => {
    const s = sessions.get(id);
    if (!s) throw new Error("That session has ended");
    return s;
  };
  return {
    async sessionConnect(target: ConnectTarget, onFrame: (m: ArrayBuffer) => void, onEvent: (e: SessionEvent) => void) {
      let style: DesktopStyle = "demo";
      let name = "Demo computer";
      let hostId: string | null = null;
      const flow = { boundary: false, askPassword: false, certificate: false, demo: false };
      if (target.kind === "demo") {
        flow.demo = true;
      } else if (target.kind === "saved") {
        const host = describe(target.hostId);
        if (!host) throw new Error("That computer is not saved any more");
        hostId = target.hostId;
        style = styleForOs(host.os);
        name = host.name;
        flow.boundary = host.protocol === "boundary";
        flow.askPassword = target.hostId === "officemac";
        flow.certificate = target.hostId === "reception";
      } else if (target.kind === "boundary") {
        style = "windows";
        name = "Their computer";
        flow.boundary = true;
      } else {
        style = target.protocol === "rdp" ? "windows" : "linux";
        name = target.address;
        flow.askPassword = target.protocol === "vnc" && !target.password;
        flow.boundary = target.protocol === "boundary";
      }
      const s: MockSession = {
        id: `mock-${nextSession++}`,
        hostId,
        desktop: new FakeDesktop(style, name),
        onFrame,
        onEvent,
        timers: [],
        started: Date.now(),
        connected: false,
        answer: null,
        ended: false,
        owner: sessions,
      };
      sessions.set(s.id, s);
      // Start after returning, so the caller has the id before events arrive.
      setTimeout(() => void runSession(s, flow), 0);
      return { sessionId: s.id };
    },
    async sessionInput(sessionId: string, _seq: number, body: Uint8Array) {
      decodeInput(sessionFor(sessionId), body);
    },
    async sessionText(sessionId: string, text: string) {
      sessionFor(sessionId).desktop.type(text);
    },
    async sessionKeyCombo(sessionId: string, combo: KeyCombo) {
      sessionFor(sessionId).desktop.say(COMBO_TEXT[combo]);
    },
    async sessionCredentials(sessionId: string, _username: string | null, password: string | null, _save: boolean) {
      lastPassword = password;
      const s = sessionFor(sessionId);
      s.answer?.(true);
    },
    async sessionTrust(sessionId: string, _fingerprint: string, _scheme: string, accept: boolean) {
      const s = sessionFor(sessionId);
      if (accept) s.answer?.(true);
      else endSession(s, "You chose not to trust this computer.");
    },
    async sessionQuality(sessionId: string) {
      sessionFor(sessionId);
    },
    async sessionClipboard(sessionId: string, text: string) {
      sessionFor(sessionId).desktop.say(`Clipboard: ${text.slice(0, 30)}`);
    },
    async sessionSnapshot(_sessionId: string, _rgba: Uint8Array, _w: number, _h: number) {
      // The full mock overrides this to store a card picture.
    },
    async sessionDisconnect(sessionId: string) {
      const s = sessions.get(sessionId);
      if (s) endSession(s);
    },
    has(sessionId: string): boolean {
      return sessions.has(sessionId);
    },
    get(sessionId: string): { hostId: string | null } | undefined {
      return sessions.get(sessionId);
    },
  };
}

export type MockSessions = ReturnType<typeof createMockSessions>;

// ---------------------------------------------------------------- full api

function withoutHelpers(m: MockSessions) {
  const { has: _has, get: _get, ...rest } = m;
  return rest;
}

function params(): URLSearchParams {
  try {
    return new URLSearchParams(window.location.search);
  } catch {
    return new URLSearchParams();
  }
}

export function createMockApi(): Api {
  const q = params();
  if (q.get("reset") === "1") {
    try {
      localStorage.removeItem(HOSTS_KEY);
      localStorage.removeItem(THUMBS_KEY);
    } catch {
      // ignore
    }
  }
  let hosts: Host[] = q.get("empty") === "1" ? [] : readJson<Host[]>(HOSTS_KEY, seedHosts());
  const thumbs: Record<string, string> = readJson(THUMBS_KEY, {});
  const save = () => writeJson(HOSTS_KEY, hosts);
  let scanning: ReturnType<typeof setTimeout>[] = [];

  const sessionsApi = createMockSessions((id) => hosts.find((h) => h.id === id) ?? null);

  async function thumbnailFor(host: Host): Promise<string | null> {
    if (!host.hasThumbnail) return null;
    if (thumbs[host.id]) return thumbs[host.id];
    const d = new FakeDesktop(styleForOs(host.os), host.name, 960, 600, cardLook(host));
    const url = await d.thumbnail(480);
    thumbs[host.id] = url;
    return url;
  }

  return {
    async hostsList() {
      await wait(150);
      return hosts.map((h) => ({ ...h }));
    },
    async hostsSave(draft: HostDraft) {
      await wait(250);
      const existing = draft.id ? hosts.find((h) => h.id === draft.id) : undefined;
      const host: Host = {
        hasPassword: existing?.hasPassword ?? false,
        lastConnectedAt: existing?.lastConnectedAt ?? null,
        hasThumbnail: existing?.hasThumbnail ?? false,
        ...draft,
        id: existing?.id ?? `h${Date.now().toString(36)}`,
      };
      hosts = existing ? hosts.map((h) => (h.id === host.id ? host : h)) : [...hosts, host];
      save();
      return { ...host };
    },
    async hostsDelete(id) {
      await wait(150);
      hosts = hosts.filter((h) => h.id !== id);
      delete thumbs[id];
      save();
    },
    async hostsSetSecret(id, username, password) {
      await wait(100);
      hosts = hosts.map((h) =>
        h.id === id ? { ...h, username: username ?? h.username, hasPassword: password ? true : password === "" ? false : h.hasPassword } : h,
      );
      save();
    },
    async hostsThumbnail(id) {
      const host = hosts.find((h) => h.id === id);
      return host ? thumbnailFor(host) : null;
    },

    async scanStart(onEvent: (e: ScanEvent) => void) {
      scanning.forEach(clearTimeout);
      scanning = [];
      const total = 254;
      const steps = 16;
      const duration = 4200;
      for (let i = 1; i <= steps; i++) {
        scanning.push(setTimeout(() => onEvent({ type: "progress", done: Math.round((total * i) / steps), total }), (duration * i) / steps));
      }
      FOUND.forEach((item, i) => {
        scanning.push(setTimeout(() => onEvent({ type: "found", item }), 450 + i * 560 + (i % 2) * 180));
      });
      scanning.push(setTimeout(() => onEvent({ type: "complete" }), duration + 100));
    },
    async scanStop() {
      scanning.forEach(clearTimeout);
      scanning = [];
    },

    async boundaryResolve(code: string) {
      await wait(1100);
      const digits = code.replace(/\D/g, "");
      if (code.trim().startsWith("boundary1:")) return { invitation: code.trim() };
      if (digits.length !== 12) throw new Error("A code has 12 numbers. Check it with them and try again.");
      if (/^0+$/.test(digits)) throw new Error("That code was not found. It may have run out; ask them for a new one.");
      return { invitation: `boundary1:mock-${digits}` };
    },

    ...withoutHelpers(sessionsApi),
    async sessionConnect(target, onFrame, onEvent) {
      const result = await sessionsApi.sessionConnect(target, onFrame, onEvent);
      if (target.kind === "saved") {
        hosts = hosts.map((h) => (h.id === target.hostId ? { ...h, lastConnectedAt: Date.now() } : h));
        save();
      }
      return result;
    },
    async sessionSnapshot(sessionId, rgba, w, h) {
      const s = sessionsApi.get(sessionId);
      if (!s?.hostId) return;
      const c = document.createElement("canvas");
      c.width = w;
      c.height = h;
      c.getContext("2d")!.putImageData(new ImageData(new Uint8ClampedArray(rgba), w, h), 0, 0);
      const small = document.createElement("canvas");
      small.width = 480;
      small.height = Math.round((h / w) * 480);
      small.getContext("2d")!.drawImage(c, 0, 0, small.width, small.height);
      thumbs[s.hostId] = small.toDataURL("image/jpeg", 0.8);
      writeJson(THUMBS_KEY, thumbs);
      hosts = hosts.map((x) => (x.id === s.hostId ? { ...x, hasThumbnail: true } : x));
      save();
    },
  };
}
