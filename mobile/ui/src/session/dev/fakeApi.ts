/**
 * A pretend computer for working on the session screen with no Rust: it
 * draws a small desktop, streams it as format 0 (raw RGBA) and format 1
 * (JPEG) rects with a moving test pattern, sends a cursor shape, and reacts
 * to clicks, scrolling and typing so input visibly does something.
 *
 * Scenarios come from the page's query string:
 *   ?cred=1        ask for a password first
 *   ?cred=user     ask for a name and password
 *   ?trunc=1       the password prompt warns about the 8 character limit
 *   ?cert=1        first time certificate question
 *   ?cert=change   changed certificate warning
 *   ?fail=1        the connection fails
 *   ?drop=5        the session ends after 5 seconds
 *   ?slow=1        stats say the link is slow
 *   ?hold=1        stay on the connecting scene
 */
import type { Api, ConnectTarget, Host, SessionEvent } from "../../api/contract";
import { arrowCursor, buildCursorMessage, buildFrameMessage } from "./frames";

const W = 1440;
const H = 900;

interface Mark {
  x: number;
  y: number;
  right: boolean;
  at: number;
}

/** A session event without its id, kept as a union so each type checks its own fields. */
type Ev = SessionEvent extends infer E ? (E extends SessionEvent ? Omit<E, "sessionId"> : never) : never;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function decodeInput(body: Uint8Array, on: { pointer(x: number, y: number, m: number): void; key(down: boolean, sym: number): void }): void {
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let i = 0;
  while (i < body.length) {
    const kind = body[i];
    if (kind === 0) {
      on.pointer(dv.getUint16(i + 1, true), dv.getUint16(i + 3, true), dv.getUint16(i + 5, true));
      i += 7;
    } else if (kind === 1) {
      on.key(body[i + 1] === 1, dv.getUint32(i + 2, true));
      i += 10;
    } else if (kind === 2) {
      i += 1;
    } else {
      throw new Error(`bad input kind ${kind}`);
    }
  }
}

class FakeDesktop {
  canvas = document.createElement("canvas");
  g: CanvasRenderingContext2D;
  text = "Hello! Try typing on your phone.\n";
  marks: Mark[] = [];
  clicks = 0;
  scroll = 0;
  menu: { x: number; y: number } | null = null;
  lastMask = 0;
  t0 = performance.now();
  mods = new Set<number>();

  constructor() {
    this.canvas.width = W;
    this.canvas.height = H;
    const g = this.canvas.getContext("2d", { willReadFrequently: true });
    if (!g) throw new Error("no 2d context");
    this.g = g;
  }

  draw(): void {
    const g = this.g;
    const grad = g.createLinearGradient(0, 0, W, H);
    grad.addColorStop(0, "#1d4e89");
    grad.addColorStop(0.55, "#2a7f9e");
    grad.addColorStop(1, "#f0a35e");
    g.fillStyle = grad;
    g.fillRect(0, 0, W, H);
    // hills
    g.fillStyle = "rgba(10,30,50,0.35)";
    g.beginPath();
    g.moveTo(0, H * 0.75);
    g.bezierCurveTo(W * 0.3, H * 0.6, W * 0.6, H * 0.9, W, H * 0.68);
    g.lineTo(W, H);
    g.lineTo(0, H);
    g.fill();

    // icons
    const icons = ["Documents", "Photos", "Music", "Recycle"];
    icons.forEach((name, i) => {
      const y = 30 + i * 110;
      g.fillStyle = ["#ffd166", "#06d6a0", "#ef476f", "#cfd8e3"][i];
      g.beginPath();
      g.roundRect(40, y, 64, 56, 10);
      g.fill();
      g.fillStyle = "#fff";
      g.font = "600 16px system-ui, sans-serif";
      g.textAlign = "center";
      g.fillText(name, 72, y + 80);
    });
    g.textAlign = "left";

    // notes window
    this.window(220, 70, 640, 430, "Notes");
    g.fillStyle = "#1b2433";
    g.font = "22px ui-monospace, Menlo, monospace";
    const lines = (this.text + (Math.floor((performance.now() - this.t0) / 500) % 2 ? "▍" : "")).split("\n");
    lines.slice(-14).forEach((ln, i) => g.fillText(ln.slice(-46), 240, 140 + i * 28));

    // welcome window with live info
    this.window(900, 120, 480, 330, "Demo computer");
    g.fillStyle = "#1b2433";
    g.font = "600 24px system-ui, sans-serif";
    g.fillText(`Clicks: ${this.clicks}`, 930, 200);
    g.font = "20px system-ui, sans-serif";
    g.fillText(`Scrolled: ${this.scroll}`, 930, 240);
    g.fillText(`Pointer buttons: ${this.lastMask}`, 930, 275);
    g.fillText("The bars below move all the time.", 930, 320);

    this.pattern();

    // taskbar
    g.fillStyle = "rgba(15,20,30,0.88)";
    g.fillRect(0, H - 56, W, 56);
    g.fillStyle = "#4d8dff";
    g.beginPath();
    g.roundRect(14, H - 46, 36, 36, 8);
    g.fill();
    g.fillStyle = "#fff";
    g.font = "600 18px system-ui, sans-serif";
    const d = new Date();
    g.fillText(`${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`, W - 110, H - 22);

    // click marks
    const now = performance.now();
    this.marks = this.marks.filter((m) => now - m.at < 1500);
    for (const m of this.marks) {
      const k = (now - m.at) / 1500;
      g.strokeStyle = m.right ? `rgba(246,167,35,${1 - k})` : `rgba(255,255,255,${1 - k})`;
      g.lineWidth = 6;
      g.beginPath();
      g.arc(m.x, m.y, 14 + k * 40, 0, Math.PI * 2);
      g.stroke();
    }
    if (this.menu) {
      const { x, y } = this.menu;
      g.fillStyle = "#fff";
      g.shadowColor = "rgba(0,0,0,0.35)";
      g.shadowBlur = 18;
      g.beginPath();
      g.roundRect(x, y, 220, 150, 10);
      g.fill();
      g.shadowBlur = 0;
      g.fillStyle = "#1b2433";
      g.font = "19px system-ui, sans-serif";
      ["Open", "Copy", "Paste", "Properties"].forEach((t, i) => g.fillText(t, x + 20, y + 36 + i * 32));
    }
  }

  /** The moving test pattern, the part sent as JPEG every tick. */
  patternRect = { x: 930, y: 340, w: 420, h: 90 };

  pattern(): void {
    const g = this.g;
    const { x, y, w, h } = this.patternRect;
    const t = (performance.now() - this.t0) / 1000;
    g.fillStyle = "#0d1220";
    g.fillRect(x, y, w, h);
    for (let i = 0; i < 14; i++) {
      const v = (Math.sin(t * 3 + i * 0.6) + 1) / 2;
      g.fillStyle = `hsl(${(i * 26 + t * 60) % 360} 80% 60%)`;
      g.fillRect(x + 10 + i * 29, y + h - 10 - v * (h - 20), 22, v * (h - 20));
    }
  }

  window(x: number, y: number, w: number, h: number, title: string): void {
    const g = this.g;
    g.shadowColor = "rgba(0,0,0,0.35)";
    g.shadowBlur = 24;
    g.fillStyle = "#f7f8fb";
    g.beginPath();
    g.roundRect(x, y, w, h, 12);
    g.fill();
    g.shadowBlur = 0;
    g.fillStyle = "#e3e7ef";
    g.beginPath();
    g.roundRect(x, y, w, 44, [12, 12, 0, 0]);
    g.fill();
    g.fillStyle = "#1b2433";
    g.font = "600 18px system-ui, sans-serif";
    g.fillText(title, x + 18, y + 29);
    ["#ff5f57", "#febc2e", "#28c840"].forEach((c, i) => {
      g.fillStyle = c;
      g.beginPath();
      g.arc(x + w - 24 - i * 22, y + 22, 7, 0, Math.PI * 2);
      g.fill();
    });
  }

  rgba(x: number, y: number, w: number, h: number): Uint8Array {
    const d = this.g.getImageData(x, y, w, h).data;
    return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  }

  async jpeg(x: number, y: number, w: number, h: number): Promise<Uint8Array> {
    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    c.getContext("2d")!.drawImage(this.canvas, x, y, w, h, 0, 0, w, h);
    const blob = await new Promise<Blob>((res) => c.toBlob((b) => res(b!), "image/jpeg", 0.85));
    return new Uint8Array(await blob.arrayBuffer());
  }

  pointer(x: number, y: number, mask: number): void {
    const pressed = mask & ~this.lastMask;
    if (pressed & 1) {
      this.clicks++;
      this.marks.push({ x, y, right: false, at: performance.now() });
      this.menu = null;
    }
    if (pressed & 4) {
      this.marks.push({ x, y, right: true, at: performance.now() });
      this.menu = { x: Math.min(x, W - 230), y: Math.min(y, H - 210) };
    }
    if (pressed & 8) this.scroll--;
    if (pressed & 16) this.scroll++;
    this.lastMask = mask;
  }

  key(down: boolean, sym: number): void {
    if (sym >= 0xffe1 && sym <= 0xffee) {
      if (down) this.mods.add(sym);
      else this.mods.delete(sym);
      return;
    }
    if (!down) return;
    if (sym === 0xff08) this.text = this.text.slice(0, -1);
    else if (sym === 0xff0d) this.text += "\n";
    else if (sym === 0xff09) this.text += "    ";
    else if (this.mods.size > 0) this.text += `[${[...this.mods].map((m) => ({ 0xffe3: "Ctrl", 0xffe9: "Alt", 0xffeb: "Win", 0xffe1: "Shift" })[m] ?? "Mod").join("+")}+${sym < 0x100 ? String.fromCharCode(sym) : sym.toString(16)}]`;
    else if (sym >= 0x20 && sym < 0x100) this.text += String.fromCharCode(sym);
    else if (sym > 0x01000000) this.text += String.fromCodePoint(sym - 0x01000000);
    else this.text += `[key ${sym.toString(16)}]`;
  }
}

export function makeFakeApi(params = new URLSearchParams(location.search)): Api {
  const sessions = new Map<string, { desk: FakeDesktop; timer: number; emit(e: Ev): void; dirty: boolean; lastSeq: number; afterTrust(): Promise<void>; start(): Promise<void> }>();
  let n = 0;
  const hosts: Host[] = [
    {
      id: "h1",
      name: "Office PC",
      protocol: "vnc",
      address: "192.0.2.10",
      port: 5900,
      username: null,
      hasPassword: true,
      os: "windows",
      color: "blue",
      favorite: true,
      lastConnectedAt: null,
      hasThumbnail: false,
    },
  ];

  const api: Api = {
    hostsList: async () => hosts,
    hostsSave: async (h) => ({ ...hosts[0], ...h, id: h.id ?? "new" }) as Host,
    hostsDelete: async () => {},
    hostsSetSecret: async () => {},
    hostsThumbnail: async () => null,
    scanStart: async () => {},
    scanStop: async () => {},
    boundaryResolve: async (code) => ({ invitation: `boundary1:${code}` }),

    async sessionConnect(_target: ConnectTarget, onFrame, onEvent) {
      const id = `s${++n}`;
      const emit = (e: Ev) => onEvent({ sessionId: id, ...e } as SessionEvent);
      const desk = new FakeDesktop();
      const s = { desk, timer: 0, emit, dirty: true, lastSeq: 0, afterTrust: () => afterTrust(id), start: () => start(id) };
      sessions.set(id, s);

      void (async () => {
        emit({ type: "state-changed", state: { state: "connecting" } });
        if (params.get("hold")) return;
        await sleep(900);
        if (params.get("fail")) {
          emit({ type: "error", message: "Connection refused by 192.0.2.10:5900" });
          emit({ type: "state-changed", state: { state: "disconnected", reason: "Connection refused", can_retry: true } });
          return;
        }
        emit({ type: "state-changed", state: { state: "negotiating" } });
        await sleep(800);
        const cert = params.get("cert");
        if (cert) {
          emit({ type: "certificate-prompt", fingerprint: "3fa94c0e5b1d22aa907c61e4d8b0f1c29a7e33d10b5c6e7f8a9b0c1d2e3f4a5b", subject: "CN=office-pc", isChange: cert === "change", scheme: "rdp-tls" });
          return; // continues in sessionTrust
        }
        await afterTrust(id);
      })();

      async function afterTrust(sid: string): Promise<void> {
        const st = sessions.get(sid);
        if (!st) return;
        const cred = params.get("cred");
        if (cred || params.get("trunc")) {
          st.emit({ type: "state-changed", state: { state: "authenticating", method: "VncAuth" } });
          st.emit({
            type: "credentials-required",
            request: {
              method: "VncAuth",
              kind: cred === "user" ? "username-and-password" : "password-only",
              attempt: 1,
              error: null,
              truncatesPassword: !!params.get("trunc") || cred !== "user",
              usernameHint: null,
            },
          });
          return; // continues in sessionCredentials
        }
        await start(sid);
      }

      async function start(sid: string): Promise<void> {
        const st = sessions.get(sid);
        if (!st) return;
        st.emit({ type: "state-changed", state: { state: "authenticating", method: "None" } });
        await sleep(600);
        st.emit({ type: "state-changed", state: { state: "connected" } });
        st.emit({ type: "desktop-resize", width: W, height: H });
        st.emit({ type: "desktop-name", name: "Demo computer" });
        if (!params.get("nocursor")) {
          const c = arrowCursor();
          onFrame(buildCursorMessage(c.w, c.h, 0, 0, c.rgba));
        }
        st.desk.draw();
        // First picture: the whole desktop as raw RGBA, in bands.
        const rects = [];
        for (let y = 0; y < H; y += 300) {
          const h = Math.min(300, H - y);
          rects.push({ x: 0, y, w: W, h, format: 0 as const, payload: st.desk.rgba(0, y, W, h) });
        }
        onFrame(buildFrameMessage(rects));
        let busy = false;
        let tick = 0;
        st.timer = window.setInterval(async () => {
          if (busy) return;
          busy = true;
          try {
            tick++;
            st.desk.draw();
            const r = st.dirty || st.desk.marks.length > 0 || tick % 10 === 0 ? { x: 0, y: 0, w: W, h: H } : st.desk.patternRect;
            st.dirty = false;
            const payload = await st.desk.jpeg(r.x, r.y, r.w, r.h);
            if (sessions.has(sid)) onFrame(buildFrameMessage([{ ...r, format: 1, payload }]));
            if (tick % 20 === 0) {
              const slow = !!params.get("slow");
              st.emit({ type: "stats", stats: { rtt_ms: slow ? 290 + Math.random() * 40 : 28 + Math.random() * 12, throughput_bps: 420000 + Math.random() * 80000, fps: slow ? 3 : 10 } });
            }
          } finally {
            busy = false;
          }
        }, 100);
        const drop = Number(params.get("drop"));
        if (drop > 0) {
          setTimeout(() => {
            if (!sessions.has(sid)) return;
            clearInterval(st.timer);
            st.emit({ type: "state-changed", state: { state: "disconnected", reason: "The app was in the background", can_retry: true } });
            st.emit({ type: "ended", durationS: drop });
          }, drop * 1000);
        }
      }
      return { sessionId: id };
    },

    async sessionInput(sessionId, seq, body) {
      const s = sessions.get(sessionId);
      if (!s) return;
      if (seq !== s.lastSeq + 1) console.warn(`[fake] input seq jumped ${s.lastSeq} to ${seq}`);
      s.lastSeq = seq;
      decodeInput(body, { pointer: (x, y, m) => s.desk.pointer(x, y, m), key: (d, k) => s.desk.key(d, k) });
      s.dirty = true;
      (window as unknown as { __lastInput?: number[] }).__lastInput = Array.from(body);
    },
    async sessionText(sessionId, text) {
      const s = sessions.get(sessionId);
      if (!s) return;
      s.desk.text += text;
      s.dirty = true;
    },
    async sessionKeyCombo(sessionId, combo) {
      const s = sessions.get(sessionId);
      if (!s) return;
      s.desk.text += `\n[${combo}]\n`;
      s.dirty = true;
    },
    async sessionCredentials(sessionId) {
      await sessions.get(sessionId)?.start();
    },
    async sessionTrust(sessionId, _fp, _scheme, accept) {
      if (accept) await sessions.get(sessionId)?.afterTrust();
    },
    async sessionQuality() {},
    async sessionClipboard(sessionId, text) {
      const s = sessions.get(sessionId);
      if (!s) return;
      s.desk.text += `\n[clipboard] ${text}\n`;
      s.dirty = true;
      setTimeout(() => s.emit({ type: "clipboard-text", text: `Copied on the demo computer at ${new Date().toLocaleTimeString()}` }), 1500);
    },
    async sessionSnapshot() {},
    async sessionDisconnect(sessionId) {
      const s = sessions.get(sessionId);
      if (s) clearInterval(s.timer);
      sessions.delete(sessionId);
    },
  };
  return api;
}
