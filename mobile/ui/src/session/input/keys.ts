/**
 * Keys the phone sends: the key bar, characters typed while a key bar
 * modifier is held, and the hidden text field that catches the phone
 * keyboard (with autocorrect and IME composition) and turns its changes into
 * text and backspaces.
 */
import { CODE_TO_XT_SCANCODE, codePointToKeysym, keyEventToIds, type KeyIds } from "./keysyms";

export type ModifierKey = "ctrl" | "alt" | "meta" | "shift";

export const MODIFIERS: Record<ModifierKey, KeyIds> = {
  ctrl: { keysym: 0xffe3, keycode: CODE_TO_XT_SCANCODE.ControlLeft },
  alt: { keysym: 0xffe9, keycode: CODE_TO_XT_SCANCODE.AltLeft },
  meta: { keysym: 0xffeb, keycode: CODE_TO_XT_SCANCODE.MetaLeft },
  shift: { keysym: 0xffe1, keycode: CODE_TO_XT_SCANCODE.ShiftLeft },
};

/** Named keys of the key bar, by DOM `key` name. */
export type NamedKey =
  | "Escape"
  | "Tab"
  | "ArrowUp"
  | "ArrowDown"
  | "ArrowLeft"
  | "ArrowRight"
  | "Home"
  | "End"
  | "PageUp"
  | "PageDown"
  | "Backspace"
  | "Delete"
  | "Enter"
  | "Insert"
  | "PrintScreen"
  | `F${1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12}`;

/** keysym and scancode for a named key. */
export function namedKeyIds(key: NamedKey): KeyIds {
  const ids = keyEventToIds({ key, code: key });
  if (!ids) throw new Error(`no keysym for ${key}`);
  return ids;
}

/** The DOM `code` of the key that types `ch` on a US layout, when there is one. */
function codeForChar(ch: string): string | null {
  const lower = ch.toLowerCase();
  if (lower >= "a" && lower <= "z" && lower.length === 1) return `Key${lower.toUpperCase()}`;
  if (ch >= "0" && ch <= "9" && ch.length === 1) return `Digit${ch}`;
  const table: Record<string, string> = {
    " ": "Space",
    "-": "Minus",
    "=": "Equal",
    "[": "BracketLeft",
    "]": "BracketRight",
    "\\": "Backslash",
    ";": "Semicolon",
    "'": "Quote",
    "`": "Backquote",
    ",": "Comma",
    ".": "Period",
    "/": "Slash",
  };
  return table[ch] ?? null;
}

/**
 * keysym and scancode for one typed character. With Ctrl or Alt held the
 * letter goes lower case, the way a real keyboard sends Ctrl+C.
 */
export function charIds(ch: string, withModifier: boolean): KeyIds {
  const c = withModifier && ch.length === 1 && ch >= "A" && ch <= "Z" ? ch.toLowerCase() : ch;
  const cp = c.codePointAt(0) ?? 0;
  const code = codeForChar(c);
  return { keysym: codePointToKeysym(cp), keycode: code ? CODE_TO_XT_SCANCODE[code] ?? 0 : 0 };
}

export const KEYSYM_BACKSPACE = namedKeyIds("Backspace");
export const KEYSYM_ENTER = namedKeyIds("Enter");

/**
 * Sticky modifiers on the key bar. A tap lights one up for the next key, a
 * double tap locks it until it is tapped again.
 */
export type ModState = "off" | "once" | "locked";

export function nextModState(cur: ModState, doubleTap: boolean): ModState {
  if (doubleTap) return cur === "locked" ? "off" : "locked";
  return cur === "off" ? "once" : "off";
}

/** After a key went out with modifiers held, the one shot ones turn off. */
export function afterKey(mods: Record<ModifierKey, ModState>): Record<ModifierKey, ModState> {
  const out = { ...mods };
  for (const k of Object.keys(out) as ModifierKey[]) if (out[k] === "once") out[k] = "off";
  return out;
}

export function heldModifiers(mods: Record<ModifierKey, ModState>): ModifierKey[] {
  return (Object.keys(mods) as ModifierKey[]).filter((k) => mods[k] !== "off");
}

// ------------------------------------------------------------ text field

/**
 * The hidden text field always holds this, so a backspace on an "empty"
 * field still has something to delete and fires an input event.
 */
export const SENTINEL = "​";

export type TextOp = { type: "text"; text: string } | { type: "backspace"; count: number };

/**
 * Turns what the phone keyboard did to the hidden field into text and
 * backspaces. The keyboard may replace a whole word (autocorrect, a
 * suggestion, an IME commit), so this compares against what was last sent:
 * the common start stays, what disappeared becomes backspaces, what is new
 * becomes text.
 *
 * While an IME is composing (Japanese, Chinese, Korean...) nothing is sent
 * until the composition ends, so the computer never sees half built syllables.
 * Latin keyboards on Android also "compose" every word; for those the text
 * is plain enough to send letter by letter, which feels much more alive.
 */
export class TextDiffer {
  private sent = SENTINEL;

  /** Call after every input event. `composing` is `InputEvent.isComposing` or a composition in progress. */
  onValue(value: string, composing: boolean): TextOp[] {
    if (composing && !isPlainLatin(value)) return [];
    return this.diff(value);
  }

  /** Call on compositionend with the field's value. */
  onCompositionEnd(value: string): TextOp[] {
    return this.diff(value);
  }

  /** The field was put back to the sentinel. */
  reset(): void {
    this.sent = SENTINEL;
  }

  /** What the field holds as far as the computer knows. */
  current(): string {
    return this.sent;
  }

  private diff(value: string): TextOp[] {
    const a = Array.from(this.sent);
    const b = Array.from(value);
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    const ops: TextOp[] = [];
    const removed = a.length - i;
    // The sentinel itself can be deleted (backspace on an empty field), and
    // that counts as a backspace too, it is how the field reports one.
    if (removed > 0) ops.push({ type: "backspace", count: removed });
    const added = b.slice(i).join("").split(SENTINEL).join("");
    if (added) ops.push({ type: "text", text: added });
    this.sent = value;
    return ops;
  }
}

function isPlainLatin(s: string): boolean {
  for (const ch of s) {
    if (ch === SENTINEL) continue;
    const cp = ch.codePointAt(0) ?? 0;
    if (cp > 0x024f) return false;
  }
  return true;
}
