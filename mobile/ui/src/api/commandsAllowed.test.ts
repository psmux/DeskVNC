/**
 * Every command the UI calls must be declared in build.rs and granted in the
 * capability file. A command missing from either still compiles, and only
 * fails on the phone with "not allowed by ACL".
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "../../../src-tauri");
const buildRs = readFileSync(join(root, "build.rs"), "utf8");
const declared = [...buildRs.slice(buildRs.indexOf("COMMANDS"), buildRs.indexOf("];")).matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
const granted = (JSON.parse(readFileSync(join(root, "capabilities/default.json"), "utf8")).permissions as string[]).filter((p) => p.startsWith("allow-"));
const called = [...readFileSync(join(__dirname, "tauri.ts"), "utf8").matchAll(/invoke(?:<[^>]*>)?\("([a-z_]+)"/g)].map((m) => m[1]);

describe("command permissions", () => {
  it("finds the commands the UI calls", () => {
    expect(called.length).toBeGreaterThan(10);
  });

  it.each([...new Set(called)])("%s is declared and granted", (cmd) => {
    expect(declared).toContain(cmd);
    expect(granted).toContain(`allow-${cmd.replace(/_/g, "-")}`);
  });
});
