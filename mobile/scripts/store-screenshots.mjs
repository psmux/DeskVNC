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
// Each shot is saved twice, both at the exact store size:
// mobile/store/screenshots/<device>/NN-name.png, framed on the brand
// background with a caption above (these are committed and uploaded), and
// mobile/store/screenshots/raw/<device>/NN-name.png, the bare screen (ignored
// by git, for a store slot that wants it plain).
//
// Headless Playwright Chromium, muted. Never the system Chrome.

import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// How each screen is reached in the phone UI's mock mode (see mobile/ui/src
// main.tsx and App.tsx). The query string starts the app fresh, in mock mode,
// past the welcome, in the light theme. A tab is chosen with ?tab=, the add
// wizard and the demo session are opened by pressing their buttons.
const BASE_QUERY = "mock=1&reset=1&onboarded=1&theme=light";
const TABS = { computers: "computers", nearby: "nearby", help: "help", settings: "settings" };
const LABELS = {
  tryDemo: "Try the demo", // the demo computer card's button
  addComputer: "Add a computer", // aria-label of the + button on Computers
  showToolbar: "Show the toolbar", // aria-label of the session toolbar handle
  lookAgain: "Look again", // Nearby's button once a scan has finished
};
// The session's touch coach would cover the desktop in a store image.
const SEEN_STORAGE = { "deskvnc.session.coach.trackpad": "1", "deskvnc.session.coach.direct": "1" };

const READY_SELECTOR = "#root > *";
// On iOS the app's root size is the Dynamic Type body size, 17 px at the
// default setting (index.css). Chromium does not know -apple-system-body, so
// the Apple shots set it, or every rem would come out a sixteenth too small.
const IOS_TEXT_SIZE = () => {
  document.addEventListener("DOMContentLoaded", () => {
    const st = document.createElement("style");
    st.textContent = "html{font-size:17px}";
    document.head.append(st);
  });
};
const SETTLE_MS = 900;

// The shots, in store order. The first two or three are what most people see
// in search results, so they carry the point of the app. A landscape shot is
// taken with the device turned sideways and framed sideways on the upright
// store canvas; its raw file is the landscape store size.
const SHOTS = [
  {
    name: "demo-session",
    caption: "Your computer's screen, on your phone",
    tabletCaption: "Your computer's screen, on your tablet",
    tab: TABS.computers,
    landscape: true,
    async setup(page) {
      await page.getByRole("button", { name: LABELS.tryDemo }).first().click();
      await page.getByRole("button", { name: LABELS.showToolbar }).waitFor({ timeout: 15000 });
      await page.waitForTimeout(2500); // let the demo desktop draw a few frames
      await page.getByRole("button", { name: LABELS.showToolbar }).click();
    },
  },
  {
    name: "computers",
    caption: "Every computer you use, at a glance",
    tab: TABS.computers,
    async setup(page) {
      await page.waitForTimeout(1500); // thumbnails are drawn on first load
    },
  },
  {
    name: "help",
    caption: "Help someone with a twelve digit code",
    tab: TABS.help,
    async setup(page) {
      await page.keyboard.type("48271935");
    },
  },
  {
    name: "nearby",
    caption: "Find the computers on your network",
    tab: TABS.nearby,
    async setup(page) {
      await page.getByRole("button", { name: LABELS.lookAgain }).waitFor({ timeout: 20000 });
    },
  },
  {
    name: "add-computer",
    caption: "Pick how you reach it, and it asks the rest",
    tab: TABS.computers,
    async setup(page) {
      await page.getByRole("button", { name: LABELS.addComputer }).first().click();
    },
  },
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
  // 432 points wide, the width of a current large phone; 360 cut card titles.
  "android-phone": { out: [1080, 1920], view: [432, 768], scale: 2.5, mobile: true },
  // Google Play 7 inch and 10 inch tablets.
  "android-tablet-7": { out: [1200, 1920], view: [600, 960], scale: 2, mobile: true },
  "android-tablet-10": { out: [1600, 2560], view: [800, 1280], scale: 2, mobile: true },
};

const here = dirname(fileURLToPath(import.meta.url));
const mobile = join(here, "..");

function parseArgs() {
  const a = process.argv.slice(2);
  const o = { base: "http://localhost:5174", out: join(mobile, "store", "screenshots"), only: null, serve: false, stub: false };
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
    const name = u.searchParams.get("tab") || "unknown";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><meta name=viewport content="width=device-width">
<style>body{margin:0;font:600 20px system-ui;background:#0f172a;color:#e2e8f0}
header{padding:48px 20px 16px;font-size:28px}.card{margin:12px 16px;height:140px;border-radius:18px;background:#1e293b;display:flex;align-items:end;padding:14px}
.card:nth-child(odd){background:#1d4ed8}</style>
<div id=root><header>${name}</header>${'<div class=card>Sample</div>'.repeat(6)}</div>`);
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

// The framed image. An upright shot gets the caption above the device. A
// landscape shot gets a landscape canvas (the store size turned sideways,
// which both stores accept) with the caption on the left.
function frameHtml(png, device, caption, landscape = false) {
  const [W, H] = landscape ? [device.out[1], device.out[0]] : device.out;
  const short = Math.min(W, H);
  const tablet = device.out[0] / device.out[1] > 0.6;
  const pad = Math.round(short * 0.07);
  const bezel = Math.round(short * 0.018);
  const radius = Math.round(short * (tablet ? 0.03 : 0.07));
  const [vw, vh] = landscape
    ? [device.view[1] * device.scale, device.view[0] * device.scale]
    : [device.view[0] * device.scale, device.view[1] * device.scale];
  let cap, box;
  if (landscape) {
    const capW = Math.round(W * (tablet ? 0.3 : 0.28));
    cap = { left: pad, top: 0, width: capW - pad, height: H, size: Math.round(short * (tablet ? 0.05 : 0.068)), align: "left" };
    box = { left: capW + pad, top: pad, width: W - capW - pad * 2, height: H - pad * 2 };
  } else {
    const capH = Math.round(H * 0.17);
    cap = { left: pad, top: 0, width: W - pad * 2, height: capH, size: Math.round(W * (tablet ? 0.048 : 0.068)), align: "center" };
    box = { left: pad, top: capH, width: W - pad * 2, height: H - capH - pad };
  }
  // The screen keeps the raw shot's aspect ratio; the bezel fits in the box too.
  const s = Math.min((box.width - bezel * 2) / vw, (box.height - bezel * 2) / vh);
  const sw = Math.round(vw * s);
  const sh = Math.round(vh * s);
  const devLeft = box.left + Math.round((box.width - sw) / 2) - bezel;
  const devTop = box.top + (landscape ? Math.round((box.height - sh) / 2) - bezel : 0);
  return `<!doctype html><html><head><style>
  html,body{margin:0;width:${W}px;height:${H}px;overflow:hidden}
  body{background:linear-gradient(180deg,#1D62D9 0%,#1447AD 100%);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",Roboto,sans-serif;color:#fff}
  .cap{position:absolute;left:${cap.left}px;top:${cap.top}px;width:${cap.width}px;height:${cap.height}px;display:flex;align-items:center;justify-content:${cap.align === "left" ? "flex-start" : "center"};text-align:${cap.align};font-weight:700;font-size:${cap.size}px;line-height:1.15;letter-spacing:-0.01em;text-wrap:balance}
  .dev{position:absolute;left:${devLeft}px;top:${devTop}px;padding:${bezel}px;border-radius:${radius + bezel}px;background:#0b1220;box-shadow:0 ${Math.round(short * 0.02)}px ${Math.round(short * 0.06)}px rgba(0,0,0,.35)}
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
        const rawDir = join(o.out, "raw", key);
        mkdirSync(dir, { recursive: true });
        mkdirSync(rawDir, { recursive: true });
        const frame = await browser.newPage({ viewport: { width: device.out[0], height: device.out[1] }, deviceScaleFactor: 1 });
        for (const [i, shot] of SHOTS.entries()) {
          const n = String(i + 1).padStart(2, "0");
          const [vw, vh] = shot.landscape ? [device.view[1], device.view[0]] : device.view;
          const ctx = await browser.newContext({
            viewport: { width: vw, height: vh },
            deviceScaleFactor: device.scale,
            isMobile: device.mobile,
            hasTouch: true,
            colorScheme: "light",
            reducedMotion: "reduce",
          });
          await ctx.addInitScript((seen) => {
            for (const [k, v] of Object.entries(seen)) localStorage.setItem(k, v);
          }, SEEN_STORAGE);
          if (/^(iphone|ipad)/.test(key)) await ctx.addInitScript(IOS_TEXT_SIZE);
          const page = await ctx.newPage();
          await page.goto(`${o.base}/?${BASE_QUERY}&tab=${shot.tab}`, { waitUntil: "networkidle" });
          await page.waitForSelector(READY_SELECTOR, { timeout: 15000 });
          if (!o.stub && shot.setup) await shot.setup(page);
          // No blinking caret in a store image.
          await page.addStyleTag({ content: "*{caret-color:transparent!important}" });
          await page.waitForTimeout(SETTLE_MS);
          const raw = await page.screenshot({ type: "png" });
          writeFileSync(join(rawDir, `${n}-${shot.name}.png`), raw);
          const [fw, fh] = shot.landscape ? [device.out[1], device.out[0]] : device.out;
          await frame.setViewportSize({ width: fw, height: fh });
          await frame.setContent(frameHtml(raw, device, (device.out[0] / device.out[1] > 0.6 && shot.tabletCaption) || shot.caption, shot.landscape), { waitUntil: "load" });
          await frame.screenshot({ path: join(dir, `${n}-${shot.name}.png`), type: "png" });
          await ctx.close();
          console.log(`${key} ${n}-${shot.name}`);
        }
        await frame.close();
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
