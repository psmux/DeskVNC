#!/usr/bin/env node
// Store screenshots for both stores, rendered from the phone UI in mock mode.
//
//   cd mobile/scripts && npm install          once (Playwright only)
//   node store-screenshots.mjs --serve        start the UI dev server on 5174,
//                                             shoot every device, stop it
//   node store-screenshots.mjs                use a dev server already running
//   node store-screenshots.mjs --only iphone-6.9,android-phone
//   node store-screenshots.mjs --stub         shoot a stand in page instead of
//                                             the UI, to test this script
//
// Each shot is saved twice under mobile/store/screenshots/out/<device>/:
// raw/NN-name.png at the exact store size with nothing added, and
// NN-name.png framed on the brand background with a caption above.
//
// Headless Playwright Chromium, muted. Never the system Chrome.

import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Routes in the phone UI. Change these when the UI's routes change. `?mock=1`
// is added by url() below, before any hash.
const ROUTES = {
  computers: "/",
  nearby: "/nearby",
  help: "/help",
  settings: "/settings",
  // The built in demo computer's session, which needs no network.
  demoSession: "/session/demo",
};

// What marks a screen as drawn. The UI sets data-screen-ready on its root
// once mock data has loaded; until it does, the script waits for any content
// in #root and a short settle.
const READY_SELECTOR = "[data-screen-ready], #root > *";
const SETTLE_MS = 600;

// The shots, in store order. The first two or three are what most people see
// in search results, so they carry the point of the app.
const SHOTS = [
  { name: "demo-session", route: ROUTES.demoSession, caption: "Your computer's screen, on your phone" },
  { name: "computers", route: ROUTES.computers, caption: "Every computer you use, at a glance" },
  { name: "help", route: ROUTES.help, caption: "Help someone with a twelve digit code" },
  { name: "nearby", route: ROUTES.nearby, caption: "Find computers on your network" },
  { name: "settings", route: ROUTES.settings, caption: "No account, nothing collected" },
];

// out: the store's pixel size. view and scale: the CSS viewport and device
// pixel ratio the app is drawn at for the raw shot, which equals out for the
// sizes the stores accept as raw screenshots.
const DEVICES = {
  // App Store, 6.9 inch iPhone (16 Pro Max class). Required set.
  "iphone-6.9": { out: [1320, 2868], view: [440, 956], scale: 3, mobile: true },
  // App Store, 13 inch iPad. Required because the app runs on iPad.
  "ipad-13": { out: [2064, 2752], view: [1032, 1376], scale: 2, mobile: true },
  // Google Play phone. 9:16, inside Play's 2:1 limit, 1080 wide for promotion.
  "android-phone": { out: [1080, 1920], view: [360, 640], scale: 3, mobile: true },
  // Google Play 7 inch and 10 inch tablets.
  "android-tablet-7": { out: [1200, 1920], view: [600, 960], scale: 2, mobile: true },
  "android-tablet-10": { out: [1600, 2560], view: [800, 1280], scale: 2, mobile: true },
};

const here = dirname(fileURLToPath(import.meta.url));
const mobile = join(here, "..");

function parseArgs() {
  const a = process.argv.slice(2);
  const o = { base: "http://localhost:5174", out: join(mobile, "store", "screenshots", "out"), only: null, serve: false, stub: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--base") o.base = a[++i];
    else if (a[i] === "--out") o.out = a[++i];
    else if (a[i] === "--only") o.only = a[++i].split(",");
    else if (a[i] === "--serve") o.serve = true;
    else if (a[i] === "--stub") o.stub = true;
    else throw new Error(`Unknown option ${a[i]}`);
  }
  return o;
}

function url(base, route) {
  const [path, hash] = route.split("#");
  const sep = path.includes("?") ? "&" : "?";
  return `${base}${path}${sep}mock=1${hash !== undefined ? `#${hash}` : ""}`;
}

async function waitForServer(base, ms = 60000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(base);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Nothing answered at ${base}`);
}

// A stand in for the UI: one page per route, drawn like a phone screen, so the
// framing and sizes can be checked before the real UI exists.
function startStub(port) {
  const server = createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const name = Object.entries(ROUTES).find(([, r]) => r === u.pathname)?.[0] || "unknown";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><meta name=viewport content="width=device-width">
<style>body{margin:0;font:600 20px system-ui;background:#0f172a;color:#e2e8f0}
header{padding:48px 20px 16px;font-size:28px}.card{margin:12px 16px;height:140px;border-radius:18px;background:#1e293b;display:flex;align-items:end;padding:14px}
.card:nth-child(odd){background:#1d4ed8}</style>
<div id=root data-screen-ready><header>${name}</header>${'<div class=card>Sample</div>'.repeat(6)}</div>`);
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

function frameHtml(png, device, caption) {
  const [W, H] = device.out;
  const tablet = W / H > 0.6;
  const pad = Math.round(W * 0.07);
  const captionSize = Math.round(W * (tablet ? 0.048 : 0.068));
  const captionBlock = Math.round(H * 0.17);
  // The screen keeps the raw shot's aspect ratio and fits under the caption.
  const [vw, vh] = [device.view[0] * device.scale, device.view[1] * device.scale];
  const maxW = W - pad * 2;
  const maxH = H - captionBlock - pad;
  const s = Math.min(maxW / vw, maxH / vh);
  const sw = Math.round(vw * s);
  const sh = Math.round(vh * s);
  const bezel = Math.round(W * 0.018);
  const radius = Math.round(W * (tablet ? 0.03 : 0.07));
  return `<!doctype html><html><head><style>
  html,body{margin:0;width:${W}px;height:${H}px;overflow:hidden}
  body{background:linear-gradient(180deg,#1D62D9 0%,#1447AD 100%);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",Roboto,sans-serif;color:#fff}
  .cap{position:absolute;left:${pad}px;right:${pad}px;top:0;height:${captionBlock}px;display:flex;align-items:center;justify-content:center;text-align:center;font-weight:700;font-size:${captionSize}px;line-height:1.15;letter-spacing:-0.01em}
  .dev{position:absolute;left:${Math.round((W - sw) / 2) - bezel}px;top:${captionBlock}px;padding:${bezel}px;border-radius:${radius + bezel}px;background:#0b1220;box-shadow:0 ${Math.round(W * 0.02)}px ${Math.round(W * 0.06)}px rgba(0,0,0,.35)}
  .dev img{display:block;width:${sw}px;height:${sh}px;border-radius:${radius}px}
  </style></head><body><div class="cap">${caption}</div><div class="dev"><img src="data:image/png;base64,${png.toString("base64")}"></div></body></html>`;
}

async function main() {
  const o = parseArgs();
  const devices = Object.entries(DEVICES).filter(([k]) => !o.only || o.only.includes(k));
  if (!devices.length) throw new Error(`No device matches ${o.only}. Known: ${Object.keys(DEVICES).join(", ")}`);

  let child = null;
  let stub = null;
  try {
    if (o.stub) {
      stub = await startStub(Number(new URL(o.base).port || 5174));
    } else if (o.serve) {
      const port = new URL(o.base).port || "5174";
      child = spawn("npm", ["run", "dev", "--", "--port", port, "--strictPort"], {
        cwd: join(mobile, "ui"),
        stdio: ["ignore", "inherit", "inherit"],
        detached: true,
      });
    }
    await waitForServer(o.base);

    const browser = await chromium.launch({ headless: true, args: ["--mute-audio"] });
    try {
      for (const [key, device] of devices) {
        const dir = join(o.out, key);
        mkdirSync(join(dir, "raw"), { recursive: true });
        const ctx = await browser.newContext({
          viewport: { width: device.view[0], height: device.view[1] },
          deviceScaleFactor: device.scale,
          isMobile: device.mobile,
          hasTouch: true,
          colorScheme: "dark",
          reducedMotion: "reduce",
        });
        const page = await ctx.newPage();
        const frame = await browser.newPage({ viewport: { width: device.out[0], height: device.out[1] }, deviceScaleFactor: 1 });
        for (const [i, shot] of SHOTS.entries()) {
          const n = String(i + 1).padStart(2, "0");
          await page.goto(url(o.base, shot.route), { waitUntil: "networkidle" });
          await page.waitForSelector(READY_SELECTOR, { timeout: 15000 });
          // No blinking caret or half finished transition in a store image.
          await page.addStyleTag({ content: "*{caret-color:transparent!important;transition:none!important;animation:none!important}" });
          await page.waitForTimeout(SETTLE_MS);
          const raw = await page.screenshot({ type: "png" });
          writeFileSync(join(dir, "raw", `${n}-${shot.name}.png`), raw);
          await frame.setContent(frameHtml(raw, device, shot.caption), { waitUntil: "load" });
          await frame.screenshot({ path: join(dir, `${n}-${shot.name}.png`), type: "png" });
          console.log(`${key} ${n}-${shot.name}`);
        }
        await frame.close();
        await ctx.close();
      }
    } finally {
      await browser.close();
    }
  } finally {
    if (child) {
      try { process.kill(-child.pid, "SIGTERM"); } catch {}
    }
    if (stub) stub.close();
  }
  console.log(`Screenshots in ${o.out}`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
