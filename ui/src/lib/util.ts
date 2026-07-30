/** Small shared utilities: color hashing, formatting, fuzzy matching, mnemonics. */

/** Deterministic pleasant hue from a host id, used for icon-placeholder tiles. */
export function colorFromId(id: string): string {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const hue = (h >>> 0) % 360;
  return `oklch(0.55 0.11 ${hue})`;
}

export function timeAgo(ts: number | null): string {
  if (!ts) return "never";
  const s = Math.max(1, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

export function formatBps(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(1)} Gb/s`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mb/s`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(0)} kb/s`;
  return `${bps.toFixed(0)} b/s`;
}

export interface FuzzyResult {
  score: number;
  /** indices of matched characters in the haystack (for highlighting) */
  positions: number[];
}

/** Simple subsequence fuzzy matcher; higher score = better. Null if no match. */
export function fuzzyMatch(query: string, haystack: string): FuzzyResult | null {
  const q = query.toLowerCase();
  const h = haystack.toLowerCase();
  if (q.length === 0) return { score: 0, positions: [] };
  let qi = 0;
  let score = 0;
  let streak = 0;
  const positions: number[] = [];
  for (let hi = 0; hi < h.length && qi < q.length; hi++) {
    if (h[hi] === q[qi]) {
      positions.push(hi);
      streak += 1;
      score += 1 + streak * 2;
      // bonus for word-boundary matches
      if (hi === 0 || h[hi - 1] === " " || h[hi - 1] === "-" || h[hi - 1] === ".") {
        score += 6;
      }
      qi++;
    } else {
      streak = 0;
    }
  }
  if (qi < q.length) return null;
  // prefer shorter haystacks
  score -= Math.floor(h.length / 8);
  return { score, positions };
}

const MNEMONIC_WORDS = [
  "amber", "anchor", "apple", "arrow", "aspen", "atlas", "badge", "bamboo",
  "basil", "beacon", "berry", "birch", "bison", "blaze", "breeze", "brook",
  "cabin", "camel", "candle", "canyon", "cedar", "cello", "cherry", "cliff",
  "clover", "cobalt", "comet", "coral", "cosmos", "crane", "creek", "crystal",
  "dawn", "delta", "denim", "drift", "eagle", "ember", "falcon", "fern",
  "flint", "forest", "fox", "garnet", "geyser", "glacier", "grove", "harbor",
  "hazel", "heron", "hollow", "ivory", "jade", "jasper", "juniper", "kelp",
  "lagoon", "lantern", "lark", "lava", "lilac", "linen", "lotus", "lunar",
  "maple", "marble", "meadow", "mesa", "mint", "mirror", "moss", "mountain",
  "nectar", "north", "oak", "ocean", "olive", "onyx", "opal", "orchid",
  "otter", "owl", "pearl", "pebble", "pine", "plume", "prairie", "prism",
  "quartz", "quill", "raven", "reef", "ridge", "river", "robin", "rose",
  "saffron", "sage", "salmon", "sand", "sequoia", "shadow", "shore", "sierra",
  "silver", "sky", "slate", "smoke", "sparrow", "spruce", "star", "stone",
  "storm", "summit", "sunset", "swan", "thistle", "thunder", "tiger", "topaz",
  "trail", "tulip", "tundra", "valley", "velvet", "violet", "walnut", "willow",
] as const;

/**
 * Derive a 4-word mnemonic from a hex SHA-256 fingerprint so humans can compare
 * certificates over the phone. Uses the first 28 bits (7 bits per word).
 */
export function fingerprintMnemonic(fingerprintHex: string): string {
  const hex = fingerprintHex.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length < 8) return "";
  const bits = parseInt(hex.slice(0, 8), 16);
  const words: string[] = [];
  for (let i = 0; i < 4; i++) {
    words.push(MNEMONIC_WORDS[(bits >>> (i * 7)) & 0x7f]);
  }
  return words.join("-");
}

/** Group fingerprint hex into byte pairs: "AB:CD:EF:…" */
export function formatFingerprint(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  if (hex.length === 0) return fp;
  return hex.match(/.{1,2}/g)?.join(":") ?? fp;
}

export function classNames(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const isMac: boolean =
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

/** Platform modifier label: ⌘ on macOS, Ctrl elsewhere. */
export const modKeyLabel: string = isMac ? "⌘" : "Ctrl";
