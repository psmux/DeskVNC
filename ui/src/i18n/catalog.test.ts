/**
 * The translated screens stay translated.
 *
 * For every file in `TRANSLATED`, every string handed to `t` or `tn` has to
 * be in each catalog, and no English text may reach the screen without going
 * through one of them. A new English string on one of these screens fails
 * here until it is translated, or until it is added to `ALLOWED` because it
 * is the same in every language (a protocol name, an address scheme, the
 * product's name).
 *
 * The screens not listed are still English only. Adding one here is how its
 * translation is finished and kept finished.
 */
import { describe, expect, it } from "vitest";
import { LANGUAGES, catalogFor, type Catalog } from ".";
import { hasWords, placeholders, scanSource } from "./scan";

// Every source file's text, read by Vite at test time.
const SOURCES = import.meta.glob<string>(["../**/*.tsx", "../**/*.ts", "!../**/*.test.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});

function source(file: string): string {
  const text = SOURCES[`../${file}`];
  if (text === undefined) throw new Error(`${file} is listed in TRANSLATED but does not exist`);
  return text;
}

/** Files whose text is translated, relative to `ui/src`. */
export const TRANSLATED = [
  "App.tsx",
  "screens/Library.tsx",
  "screens/Preferences.tsx",
  "components/HostDialog.tsx",
  "components/QuickConnect.tsx",
  "components/TabStrip.tsx",
  "components/Sidebar.tsx",
  "components/HostTile.tsx",
  "components/ScanButton.tsx",
  "components/primitives.tsx",
  "components/CredentialPrompt.tsx",
  "components/CredentialUnlock.tsx",
  "components/CertPrompt.tsx",
  "components/SshHostKeyPrompt.tsx",
  "components/SaveTabHostDialog.tsx",
  "components/MacSessionPrompt.tsx",
  "lib/macSession.ts",
  "components/SavedCredentials.tsx",
  "lib/savedCredentials.ts",
];

/**
 * Text that is the same in every language. Protocol names and address
 * schemes stay as they are by design, and so does the product's name.
 */
const ALLOWED = new Set<string>([
  "DeskVNCViewer",
  "DeskVNC",
  "SSH",
  "VNC",
  "RDP",
  "SFTP",
  "Boundary",
  "Wake-on-LAN",
  "ssh://",
  "vnc://",
  "rdp://",
]);

/** A literal made only of allowed names, punctuation, numbers and spaces. */
function allowed(text: string): boolean {
  if (ALLOWED.has(text)) return true;
  const rest = text
    .split(/[^A-Za-z0-9:/.@_-]+/)
    .filter((word) => word && !ALLOWED.has(word))
    .join(" ");
  return !hasWords(rest);
}

const translations = LANGUAGES.filter((l) => l.code !== "en");

describe.each(TRANSLATED)("%s", (file) => {
  const scan = scanSource(source(file), file);

  it.each(translations)("has every string in the $code catalog", ({ code }) => {
    const catalog: Catalog = catalogFor(code);
    const missing = [...new Set(scan.keys.filter((k) => !(k.text in catalog)).map((k) => `${file}:${k.line}  ${JSON.stringify(k.text)}`))];
    expect(missing, `strings with no ${code} translation`).toEqual([]);
  });

  it("shows no English that skips the catalog", () => {
    const loose = scan.literals
      .filter((l) => !allowed(l.text))
      .map((l) => `${file}:${l.line}  ${JSON.stringify(l.text)}`);
    expect(loose, "wrap these in t(), or add them to ALLOWED if they never change").toEqual([]);
  });
});

describe.each(translations)("the $code catalog", ({ code }) => {
  const catalog = catalogFor(code);

  it("keeps every placeholder of the English", () => {
    const wrong: string[] = [];
    for (const [english, value] of Object.entries(catalog)) {
      const forms = typeof value === "string" ? [value] : Object.values(value);
      for (const form of forms) {
        if (placeholders(form ?? "").join() !== placeholders(english).join()) {
          wrong.push(`${JSON.stringify(english)} -> ${JSON.stringify(form)}`);
        }
      }
    }
    expect(wrong).toEqual([]);
  });

  it("has no empty translations", () => {
    const empty = Object.entries(catalog)
      .filter(([, v]) => (typeof v === "string" ? v : (v.other ?? "")).trim() === "")
      .map(([k]) => k);
    expect(empty).toEqual([]);
  });
});
