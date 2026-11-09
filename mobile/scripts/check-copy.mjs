#!/usr/bin/env node
// Check the store copy against each store's length limits and the house
// style: no dash punctuation and none of the words the copy must avoid.
//
//   node mobile/scripts/check-copy.mjs
//
// Fields are the blocks between <!-- field: NAME --> and <!-- end --> in the
// listing files. Every Markdown file under mobile/store is also scanned for
// em dashes, en dashes, horizontal bars and double hyphens in prose.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const store = join(dirname(fileURLToPath(import.meta.url)), "..", "store");
const limits = {
  "listing-app-store.md": { promo: 170, keywords: 100, description: 4000, whatsnew: 4000 },
  "listing-google-play.md": { short: 80, full: 4000 },
  "review-notes.md": { "apple-review": 4000, "play-access": 4000 },
};
const fixed = { "App Store subtitle": ["VNC and RDP for your computers", 30], "Name": ["DeskVNC", 30] };
const banned = /\b(leverage|seamless(ly)?|robust|cutting edge|delve|elevate|unlock|harness|landscape|journey|transformative|testament)\b/i;
// A double hyphen counts when it stands between words, not in a CSS custom
// property such as --fg.
const dashes = /[\u2013\u2014\u2015]|\s--(\s|$)|[A-Za-z]--[A-Za-z]/;

let bad = 0;
const fail = (msg) => { bad++; console.log(`FAIL ${msg}`); };

for (const [file, fields] of Object.entries(limits)) {
  const text = readFileSync(join(store, file), "utf8");
  for (const [name, max] of Object.entries(fields)) {
    const m = text.match(new RegExp(`<!-- field: ${name} -->\\n([\\s\\S]*?)\\n<!-- end -->`));
    if (!m) { fail(`${file}: no field ${name}`); continue; }
    const value = m[1].trim();
    const len = [...value].length;
    console.log(`${len <= max ? "ok  " : "FAIL"} ${file} ${name}: ${len} of ${max}`);
    if (len > max) bad++;
    if (name === "keywords" && /,\s/.test(value)) fail(`${file}: keywords have a space after a comma, which wastes characters`);
  }
}
for (const [label, [value, max]] of Object.entries(fixed)) {
  console.log(`${value.length <= max ? "ok  " : "FAIL"} ${label}: ${value.length} of ${max}`);
}

const walk = (dir) => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (f === "out" || f === "node_modules") return [];
  return statSync(p).isDirectory() ? walk(p) : [p];
});
for (const file of walk(store).filter((f) => /\.(md|txt|html|svg)$/.test(f))) {
  readFileSync(file, "utf8").split("\n").forEach((line, i) => {
    // Table rules and HTML comments are formatting, not punctuation.
    const prose = line.replace(/^\s*\|?[-|: ]+\|?\s*$/, "").replace(/<!--|-->/g, "");
    if (dashes.test(prose)) fail(`${file}:${i + 1}: dash punctuation: ${line.trim()}`);
    if (banned.test(prose)) fail(`${file}:${i + 1}: word to avoid: ${line.trim()}`);
  });
}

console.log(bad ? `${bad} problem(s)` : "Copy is within limits and style.");
process.exit(bad ? 1 : 0);
