#!/usr/bin/env node
// Turn mobile/store/privacy-policy.md into mobile/store/privacy.html, the
// page the site serves at /privacy. The Markdown is the source; run this after
// every edit so the two never drift.
//
//   node mobile/scripts/privacy-html.mjs
//
// Handles what the policy uses: headings, paragraphs, bullet lists and bare
// links. Nothing else.

import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const store = join(dirname(fileURLToPath(import.meta.url)), "..", "store");
const md = readFileSync(join(store, "privacy-policy.md"), "utf8");

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const inline = (s) =>
  esc(s).replace(/https:\/\/[^\s)]+[^\s).,]/g, (u) => `<a href="${u}">${u}</a>`);

const out = [];
let para = [];
let list = null;
const flush = () => {
  if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
  para = [];
  if (list) out.push(`<ul>\n${list.map((li) => `  <li>${inline(li)}</li>`).join("\n")}\n</ul>`);
  list = null;
};
let title = "Privacy policy";
for (const line of md.split("\n")) {
  if (/^# /.test(line)) { flush(); title = line.slice(2); out.push(`<h1>${esc(title)}</h1>`); }
  else if (/^## /.test(line)) { flush(); out.push(`<h2>${esc(line.slice(3))}</h2>`); }
  else if (/^\* /.test(line)) { if (para.length) { out.push(`<p>${inline(para.join(" "))}</p>`); para = []; } (list ||= []).push(line.slice(2)); }
  else if (/^\s{2}\S/.test(line) && list) { list[list.length - 1] += " " + line.trim(); }
  else if (!line.trim()) { flush(); }
  else { if (list) flush(); para.push(line.trim()); }
}
flush();

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<!-- Generated from mobile/store/privacy-policy.md by mobile/scripts/privacy-html.mjs. Edit the Markdown. -->
<style>
  :root { color-scheme: light dark; --fg: #1b1f24; --muted: #57606a; --bg: #ffffff; --link: #1d62d9; }
  @media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --muted: #9da7b3; --bg: #0d1117; --link: #6ea8ff; } }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 17px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 680px; margin: 0 auto; padding: 40px 16px 64px; }
  h1 { font-size: 30px; line-height: 1.2; margin: 0 0 24px; }
  h2 { font-size: 20px; margin: 32px 0 8px; }
  a { color: var(--link); overflow-wrap: anywhere; }
  li { margin: 6px 0; }
</style>
</head>
<body>
<main>
${out.join("\n")}
</main>
</body>
</html>
`;
writeFileSync(join(store, "privacy.html"), html);
console.log("Wrote mobile/store/privacy.html");
