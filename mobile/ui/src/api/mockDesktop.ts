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

interface Win {
  id: "notes" | "hello" | "photos" | "weather";
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

  constructor(style: DesktopStyle, name: string, width = 1280, height = 800) {
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
    this.wins = [
      { id: "photos", title: "Holiday photos", x: 700 * s, y: (top + 210) * s, w: 470 * s, h: 330 * s },
      { id: "weather", title: "Weather", x: 830 * s, y: (top + 10) * s, w: 340 * s, h: 170 * s },
      { id: "hello", title: "Try me", x: 90 * s, y: (top + 380) * s, w: 380 * s, h: 220 * s },
      { id: "notes", title: "Notes", x: 70 * s, y: (top + 10) * s, w: 560 * s, h: 330 * s },
    ];
    this.notes =
      style === "demo"
        ? "Welcome to the demo computer!\nTap anywhere, drag a window by its title bar, or open the keyboard and type. Your words appear here.\n\n"
        : `Hello from ${name}.\nThis is a pretend desktop, made up for trying the app.\n\n`;
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
    const [skyTop, skyBottom, near, far] = WALLPAPERS[this.style];

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
