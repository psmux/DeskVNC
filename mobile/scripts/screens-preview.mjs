#!/usr/bin/env node
// Preview screenshots of the phone UI, every screen in light and dark, for
// design review. Not uploaded anywhere; they land in mobile/ui/screens-preview.
//
//   cd mobile/scripts && npm install          once (Playwright only)
//   node screens-preview.mjs --serve          start the UI dev server on 5174,
//                                             shoot everything, stop it
//   node screens-preview.mjs                  use a dev server already running
//   node screens-preview.mjs --only iphone    one device set
//   node screens-preview.mjs --theme dark     one theme
//
// Playwright's own Chromium (Chrome for Testing), muted. Never the system Chrome.

import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = join(here, "..");
const OUT = join(mobile, "ui", "screens-preview");

// The phone gets every screen; the tablets and the landscape sizes get the
// main ones.
const DEVICES = {
  iphone: { view: [430, 932], scale: 3, all: true },
  android: { view: [360, 800], scale: 2 },
  ipad: { view: [1032, 1376], scale: 2 },
  tab800: { view: [800, 1280], scale: 2 },
  land1024: { view: [1024, 768], scale: 2 },
};
const MAIN = new Set(["01-welcome", "03-computers", "06-nearby-done", "07-help", "10-add-how", "15-settings", "17-session-demo"]);
const COACH_SEEN = { "deskvnc.session.coach.trackpad": "1", "deskvnc.session.coach.direct": "1" };
const button = (page, name) => page.getByRole("button", { name, exact: false }).first();

// name, query, setup. The query is added to mock=1&reset=1&theme=...
const SHOTS = [
  { name: "01-welcome", q: "", async setup(p) { await p.waitForTimeout(600); } },
  { name: "02-welcome-ways", q: "", async setup(p) { await button(p, "Next").click(); await p.waitForTimeout(700); } },
  { name: "03-computers", q: "onboarded=1&tab=computers", async setup(p) { await p.waitForTimeout(1800); } },
  { name: "04-computers-empty", q: "onboarded=1&tab=computers&empty=1", async setup(p) { await p.waitForTimeout(900); } },
  { name: "05-nearby", q: "onboarded=1&tab=nearby", async setup(p) { await p.waitForTimeout(1300); } },
  { name: "06-nearby-done", q: "onboarded=1&tab=nearby", async setup(p) { await button(p, "Look again").waitFor({ timeout: 20000 }); await p.waitForTimeout(600); } },
  { name: "07-help", q: "onboarded=1&tab=help", async setup(p) { await p.keyboard.type("48271935"); await p.waitForTimeout(600); } },
  {
    name: "08-help-lookup",
    q: "onboarded=1&tab=help",
    async setup(p) {
      await p.keyboard.type("482719350617");
      await p.waitForTimeout(300);
      await p.getByRole("button", { name: /^Connect$/ }).first().click();
      const named = p.getByRole("button", { name: "Save" });
      if (await named.isVisible().catch(() => false)) {
        await p.getByLabel("Your name").fill("Sam");
        await named.click();
      }
      await p.waitForTimeout(350);
    },
  },
  {
    name: "09-help-approve",
    q: "onboarded=1&tab=help",
    async setup(p) {
      await p.keyboard.type("482719350617");
      await p.waitForTimeout(300);
      await p.getByRole("button", { name: /^Connect$/ }).first().click();
      const named = p.getByRole("button", { name: "Save" });
      if (await named.isVisible().catch(() => false)) {
        await p.getByLabel("Your name").fill("Sam");
        await named.click();
      }
      await p.waitForTimeout(2100);
    },
  },
  { name: "10-add-how", q: "onboarded=1&tab=computers", async setup(p) { await button(p, "Add a computer").click(); await p.waitForTimeout(900); } },
  {
    name: "11-add-where",
    q: "onboarded=1&tab=computers",
    async setup(p) {
      await button(p, "Add a computer").click();
      await button(p, "Windows Remote Desktop").click();
      await p.waitForTimeout(900);
    },
  },
  {
    name: "12-add-look",
    q: "onboarded=1&tab=computers",
    async setup(p) {
      await button(p, "Add a computer").click();
      await button(p, "Windows Remote Desktop").click();
      await p.waitForTimeout(500);
      await p.getByRole("textbox").first().fill("192.0.2.40");
      await button(p, "Continue").click();
      await p.waitForTimeout(900);
    },
  },
  {
    name: "13-add-signin",
    q: "onboarded=1&tab=computers",
    async setup(p) {
      await button(p, "Add a computer").click();
      await button(p, "Windows Remote Desktop").click();
      await p.waitForTimeout(500);
      await p.getByRole("textbox").first().fill("192.0.2.40");
      await button(p, "Continue").click();
      await p.waitForTimeout(500);
      await p.getByRole("textbox").first().fill("Front office");
      await button(p, "Continue").click();
      await p.waitForTimeout(900);
    },
  },
  {
    name: "14-add-done",
    q: "onboarded=1&tab=computers",
    async setup(p) {
      await button(p, "Add a computer").click();
      await button(p, "Windows Remote Desktop").click();
      await p.waitForTimeout(500);
      await p.getByRole("textbox").first().fill("192.0.2.40");
      await button(p, "Continue").click();
      await p.waitForTimeout(500);
      await p.getByRole("textbox").first().fill("Front office");
      await button(p, "Continue").click();
      await p.waitForTimeout(500);
      await p.getByRole("button", { name: /^(Save|Continue|Skip)/ }).last().click();
      await p.waitForTimeout(1200);
    },
  },
  { name: "15-settings", q: "onboarded=1&tab=settings", async setup(p) { await p.waitForTimeout(700); } },
  { name: "16-menu", q: "onboarded=1&tab=computers", async setup(p) { await button(p, "More for Studio PC").click(); await p.waitForTimeout(800); } },
  {
    name: "17-session-demo",
    q: "onboarded=1&tab=computers",
    seen: true,
    async setup(p) {
      await button(p, "Try the demo").click();
      await button(p, "Show the toolbar").waitFor({ timeout: 15000 });
      await p.waitForTimeout(2200);
      await button(p, "Show the toolbar").click();
      await p.waitForTimeout(700);
    },
  },
  { name: "18-credentials", q: "onboarded=1&tab=computers", async setup(p) { await button(p, "Connect to Office Mac").click(); await p.waitForTimeout(2600); } },
  { name: "19-certificate", q: "onboarded=1&tab=computers", async setup(p) { await button(p, "Connect to Reception desk").click(); await p.waitForTimeout(2600); } },
  {
    name: "20-session-tips",
    q: "onboarded=1&tab=computers",
    async setup(p) {
      await button(p, "Try the demo").click();
      await p.waitForTimeout(3200);
    },
  },
];

function parseArgs() {
  const a = process.argv.slice(2);
  const o = { base: "http://localhost:5174", only: null, themes: ["light", "dark"], serve: false, shots: null };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--base") o.base = a[++i];
    else if (a[i] === "--only") o.only = a[++i].split(",");
    else if (a[i] === "--theme") o.themes = a[++i].split(",");
    else if (a[i] === "--shots") o.shots = a[++i].split(",");
    else if (a[i] === "--serve") o.serve = true;
    else throw new Error(`Unknown option ${a[i]}`);
  }
  return o;
}

async function waitForServer(base, ms = 60000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      if ((await fetch(base)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Nothing answered at ${base}`);
}

async function main() {
  const o = parseArgs();
  let server = null;
  if (o.serve) {
    server = spawn("npx", ["vite", "--port", "5174", "--strictPort"], { cwd: join(mobile, "ui"), stdio: "ignore", detached: true });
  }
  try {
    await waitForServer(o.base);
    mkdirSync(OUT, { recursive: true });
    const browser = await chromium.launch({ args: ["--mute-audio"] });
    try {
      for (const [dev, d] of Object.entries(DEVICES)) {
        if (o.only && !o.only.includes(dev)) continue;
        for (const theme of o.themes) {
          for (const shot of SHOTS) {
            if (!d.all && !MAIN.has(shot.name)) continue;
            if (o.shots && !o.shots.some((s) => shot.name.startsWith(s))) continue;
            const ctx = await browser.newContext({
              viewport: { width: d.view[0], height: d.view[1] },
              deviceScaleFactor: d.scale,
              isMobile: true,
              hasTouch: true,
              colorScheme: theme,
              reducedMotion: "no-preference",
            });
            const page = await ctx.newPage();
            const seen = shot.name === "20-session-tips" ? {} : COACH_SEEN;
            await page.addInitScript((kv) => {
              for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v);
            }, seen);
            const url = `${o.base}/?mock=1&reset=1&theme=${theme}${shot.q ? `&${shot.q}` : ""}`;
            const file = join(OUT, `${dev}-${theme}-${shot.name}.png`);
            try {
              await page.goto(url);
              await page.waitForSelector("#root > *", { timeout: 15000 });
              await page.waitForTimeout(400);
              await shot.setup(page);
              await page.screenshot({ path: file });
              console.log(`ok   ${dev}-${theme}-${shot.name}`);
            } catch (e) {
              console.log(`FAIL ${dev}-${theme}-${shot.name}: ${String(e.message).split("\n")[0]}`);
            }
            await ctx.close();
          }
        }
      }
    } finally {
      await browser.close();
    }
  } finally {
    if (server) {
      try {
        process.kill(-server.pid);
      } catch {}
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
