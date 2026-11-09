/**
 * A pleasant, clearly invented desktop drawn on a canvas. The mock Api and the
 * demo computer stream it as RGBA frames, and it reacts to taps, drags and
 * typing so anyone trying the app sees their input land.
 *
 * Nothing here is a real product: the windows, icons and wallpaper are made
 * up, in four loose styles that hint at each kind of computer.
 */
import type { HostOs } from "./contract";

export type DesktopStyle = "windows" | "mac" | "linux" | "raspberry" | "demo";

type WinKind = "notes" | "hello" | "photos" | "weather" | "music" | "sheet" | "calendar" | "terminal" | "chart" | "gallery";

/**
 * Which windows are open. `try` is the interactive one every live session
 * shows; the others only dress the card pictures of the sample computers.
 */
export type Scene = "try" | "studio" | "family" | "office" | "server" | "pi" | "frontdesk";

interface Win {
  id: WinKind;
  title: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

interface Ripple {
  x: number;
  y: number;
  start: number;
}

const FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

const WALLPAPERS: Record<DesktopStyle, [string, string, string, string]> = {
  // sky top, sky bottom, near hill, far hill
  windows: ["#7fb2ff", "#d7e6ff", "#4c7ee8", "#93b4f5"],
  mac: ["#ffb199", "#ffe2c7", "#e46b7c", "#f7a08f"],
  linux: ["#2c3550", "#56607f", "#1d8c7a", "#2fb39b"],
  raspberry: ["#a8e6b8", "#effbe9", "#3fa45b", "#86cf8b"],
  demo: ["#b9a7ff", "#fbe3ff", "#7c5cff", "#c19bff"],
};

export function styleForOs(os: HostOs): DesktopStyle {
  return os === "unknown" ? "demo" : os;
}

export class FakeDesktop {
  readonly width: number;
  readonly height: number;
  readonly style: DesktopStyle;
  readonly name: string;
  private canvas: HTMLCanvasElement | OffscreenCanvas;
  private ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;
  private wins: Win[];
  private notes: string;
  private presses = 0;
  private selectedPhoto = -1;
  private ripples: Ripple[] = [];
  private drag: { win: Win; dx: number; dy: number } | null = null;
  private buttons = 0;
  private toast: { text: string; until: number } | null = null;
  dirty = true;

  private wallpaper: [string, string, string, string];
  private terminalLines: string[] = [];

  constructor(
    style: DesktopStyle,
    name: string,
    width = 1280,
    height = 800,
    opts: { scene?: Scene; wallpaper?: [string, string, string, string] } = {},
  ) {
    this.style = style;
    this.name = name;
    this.width = width;
    this.height = height;
    if (typeof OffscreenCanvas !== "undefined") {
      this.canvas = new OffscreenCanvas(width, height);
    } else {
      const c = document.createElement("canvas");
      c.width = width;
      c.height = height;
      this.canvas = c;
    }
    this.ctx = this.canvas.getContext("2d") as CanvasRenderingContext2D;
    const s = width / 1280;
    const top = style === "mac" || style === "raspberry" ? 60 : 36;
    this.wallpaper = opts.wallpaper ?? WALLPAPERS[style];
    // Card pictures sit under a badge in the top corner, so their windows
    // start a little lower and end a little shorter to stay in view.
    const card = (opts.scene ?? "try") !== "try";
    const win = (id: WinKind, title: string, x: number, y: number, w: number, h: number): Win => ({
      id,
      title,
      x: x * s,
      y: (top + y + (card ? 70 : 0)) * s,
      w: w * s,
      h: (h - (card ? 50 : 0)) * s,
    });
    const left = style === "linux" ? 100 : 60;
    switch (opts.scene ?? "try") {
      case "studio":
        this.wins = [win("weather", "Weather", 880, 10, 340, 170), win("music", "Track mixer", 60, 40, 780, 470)];
        break;
      case "family":
        this.wins = [win("notes", "Shopping list", 820, 300, 380, 260), win("gallery", "Summer by the sea", 80, 20, 700, 520)];
        break;
      case "office":
        this.wins = [win("calendar", "This week", 640, 230, 560, 360), win("sheet", "Budget", 60, 20, 640, 400)];
        break;
      case "server":
        this.wins = [
          win("chart", "Disk and network", 680, 250, 520, 300),
          win("terminal", "backups", 640, 20, 560, 210),
          win("terminal", "garage", left, 20, 520, 520),
        ];
        this.terminalLines = [
          "$ ./backup.sh photos",
          "copying 1,204 files ... done",
          "backup finished in 3 min",
          "$ uptime",
          "up 41 days, load 0.12",
          "$ df -h /data",
          "/data  1.8T  62% used",
          "$ _",
        ];
        break;
      case "pi":
        this.wins = [win("terminal", "sensors", 720, 300, 480, 260), win("chart", "Greenhouse temperature", 80, 20, 660, 400)];
        this.terminalLines = ["$ python3 read_sensors.py", "soil 41%  air 22.5\u00B0C", "soil 41%  air 22.6\u00B0C", "fan off, window open", "$ _"];
        break;
      case "frontdesk":
        this.wins = [win("notes", "Messages", 840, 330, 360, 230), win("calendar", "Bookings", 60, 20, 760, 480)];
        break;
      default:
        this.wins = [
          win("photos", "Holiday photos", 700, 210, 470, 330),
          win("weather", "Weather", 830, 10, 340, 170),
          win("hello", "Try me", 90, 380, 380, 220),
          win("notes", "Notes", 70, 10, 560, 330),
        ];
    }
    this.notes =
      opts.scene === "family"
        ? "Bread\nMilk\nStrawberries\nBirthday card for Jo\n"
        : opts.scene === "frontdesk"
          ? "10:30 courier, parcel at the desk\nCall back the plumber\nNew printer paper ordered\n"
          : style === "demo"
        ? "Welcome to the demo computer!\nTap anywhere, drag a window by its title bar, or open the keyboard and type. Your words appear here.\n"
        : `Hello from ${name}.\nThis is a pretend desktop, made up for trying the app.\nType something and it shows up here.\n`;
  }

  /** Whether the next frame differs from the last one sent. */
  needsFrame(now: number): boolean {
    return this.dirty || this.ripples.some((r) => now - r.start < 600) || (this.toast !== null && now < this.toast.until + 50);
  }

  // ---------------------------------------------------------------- input

  pointer(x: number, y: number, mask: number, now = performance.now()): void {
    const wasDown = (this.buttons & 1) !== 0;
    const down = (mask & 1) !== 0;
    const rightNow = (mask & 4) !== 0 && (this.buttons & 4) === 0;
    this.buttons = mask;
    if (rightNow) {
      this.ripples.push({ x, y, start: now });
      this.say("Right click");
    }
    if (down && !wasDown) {
      this.ripples.push({ x, y, start: now });
      this.press(x, y);
    } else if (down && this.drag) {
      const { win, dx, dy } = this.drag;
      win.x = Math.max(-win.w + 80, Math.min(this.width - 80, x - dx));
      win.y = Math.max(0, Math.min(this.height - 60, y - dy));
      this.dirty = true;
    } else if (!down && wasDown) {
      this.drag = null;
    }
    if (mask & (8 | 16)) this.say(mask & 8 ? "Scrolled up" : "Scrolled down");
  }

  private press(x: number, y: number): void {
    for (let i = this.wins.length - 1; i >= 0; i--) {
      const w = this.wins[i];
      if (x < w.x || x > w.x + w.w || y < w.y || y > w.y + w.h) continue;
      // Bring to front.
      this.wins.splice(i, 1);
      this.wins.push(w);
      const titleH = this.titleHeight();
      if (y < w.y + titleH) {
        this.drag = { win: w, dx: x - w.x, dy: y - w.y };
      } else if (w.id === "hello") {
        const b = this.helloButton(w);
        if (x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h) {
          this.presses += 1;
          this.say(this.presses === 1 ? "You pressed it!" : `Pressed ${this.presses} times`);
        }
      } else if (w.id === "photos") {
        const idx = this.photoAt(w, x, y);
        if (idx >= 0) this.selectedPhoto = idx;
      }
      this.dirty = true;
      return;
    }
    this.dirty = true;
  }

  /** An X11 keysym, as the session sends it. Only presses matter here. */
  key(keysym: number, down: boolean): void {
    if (!down) return;
    if (keysym === 0xff08) this.notes = this.notes.slice(0, -1);
    else if (keysym === 0xff0d || keysym === 0xff8d) this.notes += "\n";
    else if (keysym === 0xff09) this.notes += "    ";
    else if (keysym >= 0x20 && keysym <= 0xff) this.notes += String.fromCharCode(keysym);
    else if (keysym > 0x1000000) this.notes += String.fromCodePoint(keysym - 0x1000000);
    else return;
    this.bringNotesForward();
  }

  type(text: string): void {
    this.notes += text;
    this.bringNotesForward();
  }

  say(text: string, ms = 1400): void {
    this.toast = { text, until: performance.now() + ms };
    this.dirty = true;
  }

  private bringNotesForward(): void {
    const i = this.wins.findIndex((w) => w.id === "notes");
    if (i >= 0 && i !== this.wins.length - 1) this.wins.push(...this.wins.splice(i, 1));
    // Keep the note from growing past its window: drop the oldest lines.
    const lines = this.notes.split("\n");
    if (lines.length > 14) this.notes = lines.slice(-14).join("\n");
    this.dirty = true;
  }

  // ---------------------------------------------------------------- drawing

  private titleHeight(): number {
    return 40 * (this.width / 1280);
  }

  private helloButton(w: Win) {
    const s = this.width / 1280;
    return { x: w.x + w.w / 2 - 110 * s, y: w.y + 70 * s, w: 220 * s, h: 64 * s };
  }

  private photoAt(w: Win, x: number, y: number): number {
    const s = this.width / 1280;
    const pad = 16 * s;
    const top = w.y + this.titleHeight() + pad;
    const cw = (w.w - pad * 4) / 3;
    const ch = (w.h - this.titleHeight() - pad * 3) / 2;
    for (let i = 0; i < 6; i++) {
      const cx = w.x + pad + (i % 3) * (cw + pad);
      const cy = top + Math.floor(i / 3) * (ch + pad);
      if (x >= cx && x <= cx + cw && y >= cy && y <= cy + ch) return i;
    }
    return -1;
  }

  /** Draw the whole scene and return its pixels. */
  render(now = performance.now()): Uint8ClampedArray {
    const { ctx, width: W, height: H } = this;
    const s = W / 1280;
    const [skyTop, skyBottom, near, far] = this.wallpaper;

    // Wallpaper: sky, sun, two rolling hills.
    const sky = ctx.createLinearGradient(0, 0, 0, H);
    sky.addColorStop(0, skyTop);
    sky.addColorStop(1, skyBottom);
    ctx.fillStyle = sky;
    ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = this.style === "linux" ? "rgba(255,240,200,0.85)" : "rgba(255,255,255,0.75)";
    ctx.beginPath();
    ctx.arc(W * 0.58, H * 0.3, 70 * s, 0, Math.PI * 2);
    ctx.fill();
    if (this.style === "linux") {
      ctx.fillStyle = "rgba(255,255,255,0.7)";
      for (let i = 0; i < 40; i++) {
        const px = (i * 97.3) % W;
        const py = ((i * 53.1) % (H * 0.5)) + 10;
        ctx.fillRect(px, py, 2 * s, 2 * s);
      }
    }
    this.hill(far, H * 0.62, 0.9, 1.3);
    this.hill(near, H * 0.74, 1.4, 0.6);

    // Desktop furniture per style.
    this.chrome(now);

    for (const w of this.wins) this.window(w);

    // Touch ripples.
    this.ripples = this.ripples.filter((r) => now - r.start < 600);
    for (const r of this.ripples) {
      const t = (now - r.start) / 600;
      ctx.strokeStyle = `rgba(124,92,255,${1 - t})`;
      ctx.lineWidth = 4 * s;
      ctx.beginPath();
      ctx.arc(r.x, r.y, (12 + 40 * t) * s, 0, Math.PI * 2);
      ctx.stroke();
      ctx.fillStyle = `rgba(124,92,255,${0.35 * (1 - t)})`;
      ctx.fill();
    }

    if (this.toast && now < this.toast.until) {
      ctx.font = `600 ${22 * s}px ${FONT}`;
      const tw = ctx.measureText(this.toast.text).width + 48 * s;
      const tx = W / 2 - tw / 2;
      const ty = H - 150 * s;
      ctx.fillStyle = "rgba(28,26,46,0.88)";
      this.round(tx, ty, tw, 52 * s, 26 * s);
      ctx.fill();
      ctx.fillStyle = "#fff";
      ctx.textBaseline = "middle";
      ctx.fillText(this.toast.text, tx + 24 * s, ty + 26 * s);
      ctx.textBaseline = "alphabetic";
    } else if (this.toast) {
      this.toast = null;
    }

    this.dirty = false;
    return ctx.getImageData(0, 0, W, H).data;
  }

  private hill(color: string, base: number, freq: number, phase: number): void {
    const { ctx, width: W, height: H } = this;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.moveTo(0, H);
    for (let x = 0; x <= W; x += 16) {
      ctx.lineTo(x, base + Math.sin((x / W) * Math.PI * freq + phase) * H * 0.06);
    }
    ctx.lineTo(W, H);
    ctx.closePath();
    ctx.fill();
  }

  private round(x: number, y: number, w: number, h: number, r: number): void {
    const { ctx } = this;
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  private clock(): string {
    const d = new Date();
    return `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
  }

  private chrome(_now: number): void {
    const { ctx, width: W, height: H } = this;
    const s = W / 1280;
    const icons = ["#ff8a65", "#ffd54f", "#4fc3f7", "#81c784", "#ba68c8", "#f06292"];
    ctx.font = `600 ${16 * s}px ${FONT}`;
    if (this.style === "windows" || this.style === "demo") {
      // A floating bar along the bottom with app tiles in the middle.
      const barH = 64 * s;
      ctx.fillStyle = "rgba(255,255,255,0.72)";
      this.round(16 * s, H - barH - 12 * s, W - 32 * s, barH, 20 * s);
      ctx.fill();
      const n = icons.length;
      const size = 40 * s;
      const gap = 14 * s;
      let x = W / 2 - (n * size + (n - 1) * gap) / 2;
      for (const c of icons) {
        ctx.fillStyle = c;
        this.round(x, H - barH - 12 * s + (barH - size) / 2, size, size, 12 * s);
        ctx.fill();
        x += size + gap;
      }
      ctx.fillStyle = "#1c1a2e";
      ctx.textAlign = "right";
      ctx.fillText(this.clock(), W - 40 * s, H - 12 * s - barH / 2 + 6 * s);
      ctx.textAlign = "left";
      ctx.fillText(this.style === "demo" ? "Demo computer" : this.name, 40 * s, H - 12 * s - barH / 2 + 6 * s);
    } else if (this.style === "mac") {
      ctx.fillStyle = "rgba(255,255,255,0.6)";
      ctx.fillRect(0, 0, W, 30 * s);
      ctx.fillStyle = "#1c1a2e";
      ctx.fillText("●  Desk    File    Edit    View    Window", 18 * s, 21 * s);
      ctx.textAlign = "right";
      ctx.fillText(this.clock(), W - 18 * s, 21 * s);
      ctx.textAlign = "left";
      const size = 52 * s;
      const gap = 12 * s;
      const total = icons.length * size + (icons.length - 1) * gap + 28 * s;
      ctx.fillStyle = "rgba(255,255,255,0.5)";
      this.round(W / 2 - total / 2, H - size - 34 * s, total, size + 24 * s, 24 * s);
      ctx.fill();
      let x = W / 2 - total / 2 + 14 * s;
      for (const c of icons) {
        ctx.fillStyle = c;
        this.round(x, H - size - 22 * s, size, size, 14 * s);
        ctx.fill();
        x += size + gap;
      }
    } else if (this.style === "linux") {
      ctx.fillStyle = "rgba(15,18,30,0.85)";
      ctx.fillRect(0, 0, W, 32 * s);
      ctx.fillStyle = "#e8ecff";
      ctx.fillText("Apps", 18 * s, 22 * s);
      ctx.textAlign = "center";
      ctx.fillText(this.clock(), W / 2, 22 * s);
      ctx.textAlign = "left";
      ctx.fillStyle = "rgba(15,18,30,0.6)";
      this.round(10 * s, 120 * s, 64 * s, icons.length * 58 * s + 14 * s, 18 * s);
      ctx.fill();
      icons.forEach((c, i) => {
        ctx.fillStyle = c;
        this.round(20 * s, 132 * s + i * 58 * s, 44 * s, 44 * s, 12 * s);
        ctx.fill();
      });
    } else {
      // raspberry: a plain top panel with a berry dot.
      ctx.fillStyle = "rgba(255,255,255,0.85)";
      ctx.fillRect(0, 0, W, 36 * s);
      ctx.fillStyle = "#d6336c";
      ctx.beginPath();
      ctx.arc(22 * s, 18 * s, 10 * s, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "#3fa45b";
      ctx.beginPath();
      ctx.ellipse(22 * s, 7 * s, 7 * s, 3 * s, 0, 0, Math.PI * 2);
      ctx.fill();
      icons.slice(0, 4).forEach((c, i) => {
        ctx.fillStyle = c;
        this.round(46 * s + i * 34 * s, 7 * s, 24 * s, 22 * s, 6 * s);
        ctx.fill();
      });
      ctx.fillStyle = "#1c1a2e";
      ctx.textAlign = "right";
      ctx.fillText(this.clock(), W - 16 * s, 24 * s);
      ctx.textAlign = "left";
    }
  }

  private window(w: Win): void {
    const { ctx } = this;
    const s = this.width / 1280;
    const r = 16 * s;
    const th = this.titleHeight();
    const dark = this.style === "linux";
    ctx.save();
    ctx.shadowColor = "rgba(20,10,60,0.28)";
    ctx.shadowBlur = 30 * s;
    ctx.shadowOffsetY = 10 * s;
    ctx.fillStyle = dark ? "#262b3d" : "#ffffff";
    this.round(w.x, w.y, w.w, w.h, r);
    ctx.fill();
    ctx.restore();
    // Title bar.
    ctx.fillStyle = dark ? "#1c2030" : "#f3f1fb";
    ctx.save();
    this.round(w.x, w.y, w.w, w.h, r);
    ctx.clip();
    ctx.fillRect(w.x, w.y, w.w, th);
    ctx.restore();
    const dots = ["#ff6b6b", "#ffc145", "#3ccf7a"];
    if (this.style === "mac" || this.style === "demo") {
      dots.forEach((c, i) => {
        ctx.fillStyle = c;
        ctx.beginPath();
        ctx.arc(w.x + 22 * s + i * 22 * s, w.y + th / 2, 7 * s, 0, Math.PI * 2);
        ctx.fill();
      });
    } else {
      ctx.strokeStyle = dark ? "#9aa3c0" : "#6b6880";
      ctx.lineWidth = 2 * s;
      const cx = w.x + w.w - 24 * s;
      const cy = w.y + th / 2;
      ctx.beginPath();
      ctx.moveTo(cx - 6 * s, cy - 6 * s);
      ctx.lineTo(cx + 6 * s, cy + 6 * s);
      ctx.moveTo(cx + 6 * s, cy - 6 * s);
      ctx.lineTo(cx - 6 * s, cy + 6 * s);
      ctx.moveTo(cx - 48 * s, cy);
      ctx.lineTo(cx - 36 * s, cy);
      ctx.stroke();
    }
    ctx.fillStyle = dark ? "#e8ecff" : "#1c1a2e";
    ctx.font = `600 ${16 * s}px ${FONT}`;
    ctx.textAlign = this.style === "mac" || this.style === "demo" ? "center" : "left";
    ctx.fillText(w.title, this.style === "mac" || this.style === "demo" ? w.x + w.w / 2 : w.x + 18 * s, w.y + th / 2 + 6 * s);
    ctx.textAlign = "left";

    const ink = dark ? "#e8ecff" : "#1c1a2e";
    const dim = dark ? "#9aa3c0" : "#6b6880";
    if (w.id === "notes") {
      ctx.save();
      ctx.beginPath();
      ctx.rect(w.x, w.y + th, w.w, w.h - th);
      ctx.clip();
      ctx.font = `${19 * s}px ${FONT}`;
      ctx.fillStyle = ink;
      const lines = this.wrap(this.notes, w.w - 48 * s);
      const lineH = 28 * s;
      const maxLines = Math.floor((w.h - th - 30 * s) / lineH);
      const shown = lines.slice(-maxLines);
      shown.forEach((line, i) => ctx.fillText(line, w.x + 24 * s, w.y + th + 34 * s + i * lineH));
      // Caret after the last character.
      const last = shown[shown.length - 1] ?? "";
      const cx = w.x + 24 * s + ctx.measureText(last).width + 2 * s;
      const cy = w.y + th + 34 * s + (shown.length - 1) * lineH;
      if (Math.floor(performance.now() / 500) % 2 === 0) {
        ctx.fillStyle = "#7c5cff";
        ctx.fillRect(cx, cy - 20 * s, 3 * s, 26 * s);
      }
      ctx.restore();
    } else if (w.id === "hello") {
      const b = this.helloButton(w);
      const hue = (this.presses * 47) % 360;
      ctx.fillStyle = this.presses === 0 ? "#7c5cff" : `hsl(${hue} 80% 58%)`;
      this.round(b.x, b.y, b.w, b.h, b.h / 2);
      ctx.fill();
      ctx.fillStyle = "#fff";
      ctx.font = `700 ${24 * s}px ${FONT}`;
      ctx.textAlign = "center";
      ctx.fillText("Press me", b.x + b.w / 2, b.y + b.h / 2 + 8 * s);
      ctx.fillStyle = dim;
      ctx.font = `${17 * s}px ${FONT}`;
      ctx.fillText(
        this.presses === 0 ? "Tap the button to see it react" : `Pressed ${this.presses} ${this.presses === 1 ? "time" : "times"}`,
        w.x + w.w / 2,
        b.y + b.h + 44 * s,
      );
      ctx.textAlign = "left";
    } else if (w.id === "photos") {
      const pad = 16 * s;
      const top = w.y + th + pad;
      const cw = (w.w - pad * 4) / 3;
      const ch = (w.h - th - pad * 3) / 2;
      const scenes = [
        ["#ffcf70", "#ff8a65"],
        ["#8fd3ff", "#3b82f6"],
        ["#b5f2c2", "#3fbf5f"],
        ["#ffc2dc", "#f0508c"],
        ["#d9ccff", "#7c5cff"],
        ["#fff0a8", "#f5b52e"],
      ];
      scenes.forEach(([a, b], i) => {
        const x = w.x + pad + (i % 3) * (cw + pad);
        const y = top + Math.floor(i / 3) * (ch + pad);
        const g = ctx.createLinearGradient(x, y, x, y + ch);
        g.addColorStop(0, a);
        g.addColorStop(1, b);
        ctx.fillStyle = g;
        this.round(x, y, cw, ch, 12 * s);
        ctx.fill();
        // A little mountain and sun in every picture.
        ctx.fillStyle = "rgba(255,255,255,0.8)";
        ctx.beginPath();
        ctx.arc(x + cw * 0.72, y + ch * 0.3, ch * 0.12, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "rgba(0,0,0,0.18)";
        ctx.beginPath();
        ctx.moveTo(x + cw * 0.08, y + ch * 0.92);
        ctx.lineTo(x + cw * 0.38, y + ch * 0.45);
        ctx.lineTo(x + cw * 0.62, y + ch * 0.92);
        ctx.fill();
        if (i === this.selectedPhoto) {
          ctx.strokeStyle = "#7c5cff";
          ctx.lineWidth = 5 * s;
          this.round(x, y, cw, ch, 12 * s);
          ctx.stroke();
        }
      });
    } else if (w.id === "weather") {
      ctx.fillStyle = "#ffc145";
      ctx.beginPath();
      ctx.arc(w.x + 70 * s, w.y + th + 62 * s, 34 * s, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = dark ? "#e8ecff" : "#ffffff";
      ctx.beginPath();
      ctx.arc(w.x + 92 * s, w.y + th + 86 * s, 22 * s, 0, Math.PI * 2);
      ctx.arc(w.x + 118 * s, w.y + th + 80 * s, 26 * s, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = ink;
      ctx.font = `700 ${44 * s}px ${FONT}`;
      ctx.fillText("21°", w.x + 170 * s, w.y + th + 70 * s);
      ctx.fillStyle = dim;
      ctx.font = `${17 * s}px ${FONT}`;
      ctx.fillText("Mostly sunny", w.x + 172 * s, w.y + th + 102 * s);
    } else {
      this.extraWindow(w, { s, th, ink, dim, dark });
    }
  }

  /** A seeded wobble, so the made up data looks the same every time. */
  private wobble(i: number, seed = 1): number {
    const x = Math.sin(i * 12.9898 + seed * 78.233) * 43758.5453;
    return x - Math.floor(x);
  }

  private photo(x: number, y: number, w: number, h: number, i: number): void {
    const { ctx } = this;
    const s = this.width / 1280;
    const scenes = [
      ["#8fd3ff", "#3b82f6", "#ffe08a"],
      ["#ffcf70", "#ff8a65", "#fff3c4"],
      ["#b5f2c2", "#3fbf5f", "#ffffff"],
      ["#ffc2dc", "#f0508c", "#fff0f6"],
      ["#d9ccff", "#7c5cff", "#fff7d1"],
      ["#a7f3e4", "#14b8a6", "#fffbe6"],
      ["#fff0a8", "#f5b52e", "#ffffff"],
      ["#c9d6ff", "#5b7cfa", "#ffe8f0"],
    ][i % 8];
    const g = ctx.createLinearGradient(x, y, x, y + h);
    g.addColorStop(0, scenes[0]);
    g.addColorStop(1, scenes[1]);
    ctx.fillStyle = g;
    this.round(x, y, w, h, 10 * s);
    ctx.fill();
    ctx.save();
    this.round(x, y, w, h, 10 * s);
    ctx.clip();
    ctx.fillStyle = scenes[2];
    ctx.beginPath();
    ctx.arc(x + w * (0.25 + 0.5 * this.wobble(i, 3)), y + h * 0.3, h * 0.13, 0, Math.PI * 2);
    ctx.fill();
    // Sea or hills along the bottom.
    ctx.fillStyle = "rgba(255,255,255,0.45)";
    ctx.beginPath();
    ctx.moveTo(x, y + h);
    for (let k = 0; k <= 8; k++) ctx.lineTo(x + (w * k) / 8, y + h * (0.68 + 0.08 * Math.sin(k + i)));
    ctx.lineTo(x + w, y + h);
    ctx.fill();
    ctx.fillStyle = "rgba(0,0,0,0.16)";
    ctx.beginPath();
    ctx.moveTo(x + w * 0.05, y + h);
    ctx.lineTo(x + w * (0.3 + 0.2 * this.wobble(i, 5)), y + h * 0.5);
    ctx.lineTo(x + w * 0.75, y + h);
    ctx.fill();
    ctx.restore();
  }

  private extraWindow(w: Win, t: { s: number; th: number; ink: string; dim: string; dark: boolean }): void {
    const { ctx } = this;
    const { s, th, ink, dim, dark } = t;
    const bodyX = w.x + 18 * s;
    const bodyY = w.y + th + 16 * s;
    const bodyW = w.w - 36 * s;
    const bodyH = w.h - th - 32 * s;
    const line = dark ? "#3a4058" : "#ece9f6";

    if (w.id === "music") {
      const colors = ["#7c5cff", "#f0508c", "#14b8a6", "#f5b52e"];
      const names = ["Vocals", "Guitar", "Drums", "Keys"];
      const rowH = (bodyH - 70 * s) / 4;
      names.forEach((name, r) => {
        const y = bodyY + r * rowH;
        ctx.fillStyle = colors[r];
        this.round(bodyX, y + 6 * s, 110 * s, rowH - 12 * s, 10 * s);
        ctx.fill();
        ctx.fillStyle = "#fff";
        ctx.font = `600 ${16 * s}px ${FONT}`;
        ctx.fillText(name, bodyX + 14 * s, y + rowH / 2 + 6 * s);
        ctx.fillStyle = line;
        this.round(bodyX + 124 * s, y + 6 * s, bodyW - 124 * s, rowH - 12 * s, 10 * s);
        ctx.fill();
        // A waveform of thin bars.
        ctx.fillStyle = colors[r];
        const bars = 70;
        const bw = (bodyW - 140 * s) / bars;
        for (let b = 0; b < bars; b++) {
          const amp = (0.25 + 0.75 * this.wobble(b + r * 100, r + 1)) * Math.abs(Math.sin(b / (5 + r)));
          const bh = Math.max(3 * s, amp * (rowH - 26 * s));
          ctx.fillRect(bodyX + 132 * s + b * bw, y + rowH / 2 - bh / 2, Math.max(1, bw * 0.6), bh);
        }
      });
      // Playhead and transport.
      ctx.fillStyle = "#ff4d4d";
      ctx.fillRect(bodyX + 124 * s + (bodyW - 124 * s) * 0.42, bodyY, 3 * s, rowH * 4);
      const cy = bodyY + rowH * 4 + 34 * s;
      ctx.fillStyle = "#7c5cff";
      ctx.beginPath();
      ctx.arc(w.x + w.w / 2, cy, 24 * s, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "#fff";
      ctx.beginPath();
      ctx.moveTo(w.x + w.w / 2 - 7 * s, cy - 11 * s);
      ctx.lineTo(w.x + w.w / 2 + 11 * s, cy);
      ctx.lineTo(w.x + w.w / 2 - 7 * s, cy + 11 * s);
      ctx.fill();
      ctx.fillStyle = dim;
      ctx.font = `600 ${18 * s}px ${FONT}`;
      ctx.fillText("1:42 / 3:58", bodyX, cy + 6 * s);
      ctx.textAlign = "right";
      ctx.fillText("Sunday song, take 3", bodyX + bodyW, cy + 6 * s);
      ctx.textAlign = "left";
    } else if (w.id === "gallery") {
      const cols = 4;
      const rows = 3;
      const gap = 10 * s;
      const cw = (bodyW - gap * (cols - 1)) / cols;
      const ch = (bodyH - gap * (rows - 1)) / rows;
      for (let i = 0; i < cols * rows; i++) {
        const c = i % cols;
        const r = Math.floor(i / cols);
        // The first picture is a big one, spanning two by two.
        if (i === 0) this.photo(bodyX, bodyY, cw * 2 + gap, ch * 2 + gap, 0);
        else if (!(r < 2 && c < 2)) this.photo(bodyX + c * (cw + gap), bodyY + r * (ch + gap), cw, ch, i);
      }
      ctx.fillStyle = "#f0508c";
      ctx.beginPath();
      const hx = bodyX + 24 * s;
      const hy = bodyY + 24 * s;
      ctx.arc(hx - 6 * s, hy, 8 * s, 0, Math.PI * 2);
      ctx.arc(hx + 6 * s, hy, 8 * s, 0, Math.PI * 2);
      ctx.moveTo(hx - 14 * s, hy + 3 * s);
      ctx.lineTo(hx, hy + 18 * s);
      ctx.lineTo(hx + 14 * s, hy + 3 * s);
      ctx.fill();
    } else if (w.id === "sheet") {
      const cols = 5;
      const rows = 9;
      const cw = bodyW / cols;
      const rh = (bodyH * 0.62) / rows;
      const heads = ["Month", "Rent", "Food", "Travel", "Saved"];
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const x = bodyX + c * cw;
          const y = bodyY + r * rh;
          ctx.fillStyle = r === 0 ? "#7c5cff" : r % 2 ? (dark ? "#2c3247" : "#f7f5fd") : dark ? "#262b3d" : "#ffffff";
          ctx.fillRect(x, y, cw - 1, rh - 1);
          ctx.fillStyle = r === 0 ? "#fff" : c === 0 ? ink : dim;
          ctx.font = `${r === 0 ? 600 : 400} ${14 * s}px ${FONT}`;
          const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug"];
          const text = r === 0 ? heads[c] : c === 0 ? months[r - 1] : String(Math.round(120 + 880 * this.wobble(r * 7 + c, 2)));
          ctx.fillText(text, x + 8 * s, y + rh / 2 + 5 * s);
        }
      }
      // A little bar chart under the table.
      const chartY = bodyY + bodyH * 0.68;
      const chartH = bodyH * 0.3;
      for (let b = 0; b < 8; b++) {
        const v = 0.3 + 0.7 * this.wobble(b, 9);
        ctx.fillStyle = b === 7 ? "#14b8a6" : "#c4b5fd";
        this.round(bodyX + b * (bodyW / 8) + 8 * s, chartY + chartH * (1 - v), bodyW / 8 - 16 * s, chartH * v, 6 * s);
        ctx.fill();
      }
    } else if (w.id === "calendar") {
      const days = ["Mon", "Tue", "Wed", "Thu", "Fri"];
      const cw = bodyW / days.length;
      ctx.font = `600 ${15 * s}px ${FONT}`;
      days.forEach((d, i) => {
        ctx.fillStyle = i === 2 ? "#7c5cff" : dim;
        ctx.fillText(d, bodyX + i * cw + 8 * s, bodyY + 14 * s);
        ctx.fillStyle = line;
        ctx.fillRect(bodyX + i * cw, bodyY + 26 * s, 1, bodyH - 26 * s);
      });
      const events: [number, number, number, string, string][] = [
        [0, 0.05, 0.18, "#3b82f6", "Team call"],
        [0, 0.5, 0.2, "#14b8a6", "Lunch"],
        [1, 0.2, 0.3, "#f0508c", "Dentist"],
        [2, 0.08, 0.16, "#f5b52e", "Delivery"],
        [2, 0.42, 0.34, "#7c5cff", "Workshop"],
        [3, 0.3, 0.2, "#3b82f6", "Review"],
        [4, 0.12, 0.22, "#14b8a6", "Gym"],
        [4, 0.6, 0.24, "#f97a3c", "Pizza night"],
      ];
      const top = bodyY + 30 * s;
      const span = bodyH - 30 * s;
      for (const [d, y0, hh, c, label] of events) {
        ctx.fillStyle = c;
        this.round(bodyX + d * cw + 5 * s, top + span * y0, cw - 10 * s, span * hh, 8 * s);
        ctx.fill();
        ctx.fillStyle = "#fff";
        ctx.font = `600 ${14 * s}px ${FONT}`;
        ctx.fillText(label, bodyX + d * cw + 13 * s, top + span * y0 + 20 * s, cw - 24 * s);
      }
    } else if (w.id === "terminal") {
      ctx.fillStyle = "#151a28";
      this.round(w.x + 4 * s, w.y + th, w.w - 8 * s, w.h - th - 4 * s, 12 * s);
      ctx.fill();
      ctx.font = `${17 * s}px ui-monospace, Menlo, Consolas, monospace`;
      const lines = w.title === "backups" ? this.terminalLines.slice(0, 3) : this.terminalLines;
      lines.forEach((l, i) => {
        ctx.fillStyle = l.startsWith("$") ? "#3ddc8f" : "#d6dcf5";
        ctx.fillText(l, bodyX, bodyY + 14 * s + i * 28 * s);
      });
    } else if (w.id === "chart") {
      const n = 24;
      const pts: [number, number][] = [];
      for (let i = 0; i < n; i++) {
        const v = 0.45 + 0.25 * Math.sin(i / 3.2) + 0.15 * this.wobble(i, 4);
        pts.push([bodyX + (bodyW * i) / (n - 1), bodyY + bodyH * (1 - v)]);
      }
      ctx.strokeStyle = line;
      ctx.lineWidth = 1;
      for (let g = 0; g <= 4; g++) {
        ctx.beginPath();
        ctx.moveTo(bodyX, bodyY + (bodyH * g) / 4);
        ctx.lineTo(bodyX + bodyW, bodyY + (bodyH * g) / 4);
        ctx.stroke();
      }
      const grad = ctx.createLinearGradient(0, bodyY, 0, bodyY + bodyH);
      grad.addColorStop(0, "rgba(20,184,166,0.45)");
      grad.addColorStop(1, "rgba(20,184,166,0)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(pts[0][0], bodyY + bodyH);
      pts.forEach(([x, y]) => ctx.lineTo(x, y));
      ctx.lineTo(pts[n - 1][0], bodyY + bodyH);
      ctx.fill();
      ctx.strokeStyle = "#14b8a6";
      ctx.lineWidth = 4 * s;
      ctx.lineJoin = "round";
      ctx.beginPath();
      pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      ctx.stroke();
      const [lx, ly] = pts[n - 1];
      ctx.fillStyle = "#14b8a6";
      ctx.beginPath();
      ctx.arc(lx, ly, 7 * s, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = ink;
      ctx.font = `700 ${30 * s}px ${FONT}`;
      ctx.fillText(w.title.startsWith("Green") ? "22.6\u00B0" : "62%", bodyX + 6 * s, bodyY + 34 * s);
    }
  }

  private wrap(text: string, max: number): string[] {
    const out: string[] = [];
    for (const para of text.split("\n")) {
      let line = "";
      for (const word of para.split(" ")) {
        const next = line ? `${line} ${word}` : word;
        if (this.ctx.measureText(next).width > max && line) {
          out.push(line);
          line = word;
        } else {
          line = next;
        }
      }
      out.push(line);
    }
    return out;
  }

  /** A small JPEG of the current screen for a computer card. */
  async thumbnail(width = 480): Promise<string> {
    this.render();
    const h = Math.round((this.height / this.width) * width);
    const c = document.createElement("canvas");
    c.width = width;
    c.height = h;
    const cx = c.getContext("2d")!;
    cx.drawImage(this.canvas as CanvasImageSource, 0, 0, width, h);
    return c.toDataURL("image/jpeg", 0.82);
  }
}

/** An arrow cursor as RGBA, for the msg_type 2 cursor message. */
export function arrowCursor(): { w: number; h: number; hx: number; hy: number; rgba: Uint8ClampedArray } {
  const w = 20;
  const h = 28;
  const shape = [
    "X",
    "XX",
    "X.X",
    "X..X",
    "X...X",
    "X....X",
    "X.....X",
    "X......X",
    "X.......X",
    "X........X",
    "X.........X",
    "X......XXXXX",
    "X...X..X",
    "X..XX..X",
    "X.X  X..X",
    "XX   X..X",
    "X     X..X",
    "      X..X",
    "       XX",
  ];
  const rgba = new Uint8ClampedArray(w * h * 4);
  shape.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      const ch = row[x];
      if (ch === " ") continue;
      const i = (y * w + x) * 4;
      const v = ch === "X" ? 20 : 255;
      rgba[i] = v;
      rgba[i + 1] = v;
      rgba[i + 2] = ch === "X" ? 40 : 255;
      rgba[i + 3] = 255;
    }
  });
  return { w, h, hx: 0, hy: 0, rgba };
}
