/**
 * The Preferences defaults that a NEW SSH host starts with.
 *
 * Mirrors `rdpDefaults.ts`: a switch in Preferences with no reader is worse
 * than no switch at all, because it looks like it works. This module is the
 * read half, so a value Preferences writes actually reaches the next host
 * that gets created.
 *
 * Cached rather than awaited, for the same reason as `rdpDefaults`: a draft
 * is built synchronously wherever a blank SSH host is needed, and threading a
 * promise through every call site to reach a value that is already known
 * would be a lot of churn for no gain. The load happens when the library
 * mounts, long before any dialog opens; a dialog that somehow opens first
 * gets the plain blank, which is the old behaviour and not a wrong one.
 */
import { safeInvoke } from "./tauri";
import type { MultiplexerKind, SshSettings } from "./ssh";

/** The subset of a host's SSH settings that Preferences has a default for. */
type Defaults = Pick<SshSettings, "term" | "multiplexer" | "fallbackToShell" | "fontSize" | "scrollback">;

/** The app-setting key for each, and what it means when unset. */
export const SSH_DEFAULT_KEYS = {
  term: "ssh_default_term",
  multiplexer: "ssh_default_multiplexer",
  fallbackToShell: "ssh_default_fallback_to_shell",
  fontSize: "ssh_default_font_size",
  scrollback: "ssh_default_scrollback",
} as const;

let cache: Partial<Defaults> = {};

const MULTIPLEXER_KINDS: readonly MultiplexerKind[] = [
  "auto", "none", "psmux", "tmux", "screen", "zellij", "custom",
];

/** Read every default into the cache. Safe to call more than once. */
export async function loadSshDefaults(): Promise<void> {
  const read = async (key: string): Promise<string | null> =>
    await safeInvoke<string | null>("get_app_setting", { key }, null);

  const [term, multiplexer, fallbackToShell, fontSize, scrollback] = await Promise.all([
    read(SSH_DEFAULT_KEYS.term),
    read(SSH_DEFAULT_KEYS.multiplexer),
    read(SSH_DEFAULT_KEYS.fallbackToShell),
    read(SSH_DEFAULT_KEYS.fontSize),
    read(SSH_DEFAULT_KEYS.scrollback),
  ]);

  const next: Partial<Defaults> = {};
  // Each is applied only when the key is actually present. An absent key means
  // the user never expressed a preference, and `blankSshSettings` already says
  // what a host with no preference looks like.
  if (term !== null && term !== "") next.term = term;
  if (multiplexer !== null && (MULTIPLEXER_KINDS as readonly string[]).includes(multiplexer)) {
    next.multiplexer = multiplexer as MultiplexerKind;
  }
  if (fallbackToShell !== null) next.fallbackToShell = fallbackToShell !== "false";
  if (fontSize !== null) {
    const n = parseInt(fontSize, 10);
    if (Number.isFinite(n) && n > 0) next.fontSize = n;
  }
  if (scrollback !== null) {
    const n = parseInt(scrollback, 10);
    if (Number.isFinite(n) && n >= 0) next.scrollback = n;
  }
  cache = next;
}

/** What a new host should start with, on top of the blank. */
export function sshDefaults(): Partial<Defaults> {
  return cache;
}

/** Record a default that Preferences has just changed. */
export function setSshDefault<K extends keyof Defaults>(key: K, value: Defaults[K]): void {
  cache = { ...cache, [key]: value };
}
