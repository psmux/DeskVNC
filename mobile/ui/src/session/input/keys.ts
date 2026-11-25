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

  /** Take `value` as what the field holds, sending nothing. */
  rebase(value: string): void {
    this.sent = value;
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

// ------------------------------------------------------------ keyboard field

export type FieldOp = TextOp | { type: "enter" };

/** The parts of a KeyboardEvent the field looks at. */
export interface FieldKey {
  key: string;
  keyCode?: number;
  isComposing?: boolean;
  ctrlKey?: boolean;
  altKey?: boolean;
  metaKey?: boolean;
}

function commonPrefix(a: string[], b: string[]): number {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

/**
 * The hidden field as a whole: composition state, the text differ, and the
 * Enter key. Android keyboards such as Gboard keep the current word in a
 * composition, so an Enter right after typed letters can arrive as a keydown
 * flagged as composing (keyCode 229), or only as a `beforeinput` line break.
 * Either way the composed text goes out first and then one Return.
 *
 * The field keeps its text after Enter: writing to it from script while the
 * keyboard is up puts Gboard's idea of the caret out of step with the field,
 * and its next suggestion or double space edit then lands at an old offset.
 * Instead the field remembers where the line after the Enter starts. The
 * keyboard still sees the words before it and may offer to replace one of
 * them; such a rewrite cannot be undone on the computer, where those words
 * are on the line above, so it is dropped. Gboard replaces a word in two
 * steps (delete the word, then insert the new one), so after a dropped
 * deletion the insertion that follows is dropped too. A deletion that comes
 * from a Backspace key is the person's and goes through.
 */
export class KeyboardField {
  private readonly differ = new TextDiffer();
  private composingNow = false;
  /** An Enter keydown was handled and its keyup has not come yet. */
  private enterDown = false;
  /** Where the line after the last Enter starts in the field, in code points, or -1. */
  private lineStart = -1;
  /** A Backspace keydown is being left to the field and its input event has not come yet. */
  private backspaceDown = false;
  /** The keyboard deleted text from before the line start; its insertion is next. */
  private replacing = false;

  composing(): boolean {
    return this.composingNow;
  }

  reset(): void {
    this.differ.reset();
    this.enterDown = false;
    this.lineStart = -1;
    this.backspaceDown = false;
    this.replacing = false;
  }

  /** True after an Enter, until the field starts over. */
  afterEnter(): boolean {
    return this.lineStart >= 0;
  }

  compositionStart(): void {
    this.composingNow = true;
  }

  compositionEnd(value: string): FieldOp[] {
    this.composingNow = false;
    return this.guard(value) ?? this.differ.onCompositionEnd(value);
  }

  /** An `input` event. `nativeComposing` is `InputEvent.isComposing`. */
  input(value: string, nativeComposing: boolean): FieldOp[] {
    const composing = this.composingNow || nativeComposing;
    const guarded = this.guard(value);
    this.backspaceDown = false;
    return guarded ?? this.differ.onValue(value, composing);
  }

  /**
   * A plain Backspace the field will apply itself (the caller lets the
   * browser delete); the deletion that follows is the person's.
   */
  backspaceKey(): void {
    this.backspaceDown = true;
    this.replacing = false;
  }

  /**
   * [] for a change the computer must not see because it rewrites text from
   * before the last Enter, ops for a Backspace across it, null otherwise.
   */
  private guard(value: string): FieldOp[] | null {
    if (this.lineStart < 0) return null;
    const a = Array.from(this.differ.current());
    const b = Array.from(value);
    const i = commonPrefix(a, b);
    const deletion = i === b.length && b.length < a.length;
    const insertion = i === a.length && b.length > a.length;
    if (this.replacing && insertion) {
      // The new word of a replacement whose deletion was dropped.
      this.replacing = false;
      this.differ.rebase(value);
      this.lineStart = b.length;
      return [];
    }
    this.replacing = false;
    if (i >= this.lineStart) return null;
    if (deletion && this.backspaceDown) {
      // Backspace at the start of the line: the computer joins the lines.
      const ops = this.differ.onCompositionEnd(value);
      this.lineStart = b.length;
      return ops;
    }
    // The keyboard rewrote text from the line above. Whatever this line
    // already holds stays; the rewrite is not sent.
    this.differ.rebase(value);
    this.lineStart = b.length;
    this.replacing = deletion;
    return [];
  }

  /**
   * A keydown. Returns the ops for an Enter the field owns, or null when the
   * caller should handle the key itself (or ignore it, for IME keys).
   */
  keyDown(e: FieldKey, value: string): FieldOp[] | null {
    if (e.key !== "Enter") return null;
    const ops = this.enter(value, e.isComposing === true);
    if (ops) this.enterDown = true;
    return ops;
  }

  keyUp(e: FieldKey): void {
    if (e.key === "Enter") this.enterDown = false;
    if (e.key === "Backspace") this.backspaceDown = false;
  }

  /**
   * A `beforeinput` event. Returns null when it is not a line break the
   * field sends; a line break from a keydown already handled gives [].
   */
  beforeInput(inputType: string, value: string): FieldOp[] | null {
    if (inputType !== "insertLineBreak" && inputType !== "insertParagraph") return null;
    if (this.enterDown) return [];
    return this.enter(value, false);
  }

  /** Commit whatever the field holds, then Return. */
  private enter(value: string, nativeComposing: boolean): FieldOp[] | null {
    // A CJK IME uses Enter to accept its candidate; that is not a Return.
    if ((this.composingNow || nativeComposing) && !isPlainLatin(value)) return null;
    const ops: FieldOp[] = [...(this.guard(value) ?? this.differ.onCompositionEnd(value)), { type: "enter" }];
    this.lineStart = Array.from(value).length;
    this.replacing = false;
    return ops;
  }
}

// ------------------------------------------------------------ hidden field

/** The parts of the hidden `<input>` the field reads and writes. */
export interface FieldElement {
  value: string;
  setSelectionRange?(start: number, end: number): void;
}

/** Timers, injectable for tests. */
export interface FieldTimer {
  set(cb: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

const realTimer: FieldTimer = {
  set: (cb, ms) => setTimeout(cb, ms),
  clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/** What the caller does with a keydown: cancel it, leave it to the field, or handle it itself (null). */
export type KeyVerdict = "cancel" | "field" | null;

/**
 * The hidden `<input>` and its event handlers, apart from React so the same
 * code runs in the app, in unit tests and in a plain test page. Each handler
 * reads the element's value at the moment its event fires and hands the
 * result to `send`.
 *
 * Script writes to the field only when the keyboard opens and after the
 * person has stopped typing for a while (`IDLE_MS`). A write while the
 * keyboard is busy tells it the caret jumped; Gboard learns that only after
 * the calls it has already made, and with the app's main thread busy
 * drawing frames that is several keys later. Its next double space or
 * suggestion then deletes and inserts at an old offset, which is how fast
 * typing came out with words swapped round.
 */
export class HiddenField {
  /** Quiet time after which a long field, or one past an Enter, starts over. */
  static readonly IDLE_MS = 2000;
  /** Past this many characters an idle field starts over. */
  static readonly LONG = 256;

  readonly field = new KeyboardField();
  private idle: unknown = null;

  constructor(
    private readonly el: () => FieldElement | null,
    private readonly send: (ops: FieldOp[]) => void,
    private readonly timer: FieldTimer = realTimer,
  ) {}

  /** The keyboard is about to show: start from an empty field. */
  open(): void {
    const el = this.el();
    if (!el) return;
    this.startOver(el);
  }

  composing(): boolean {
    return this.field.composing();
  }

  input(nativeComposing: boolean): void {
    const el = this.el();
    if (!el) return;
    this.send(this.field.input(el.value, nativeComposing));
    this.afterChange(el);
  }

  compositionStart(): void {
    this.field.compositionStart();
  }

  compositionEnd(): void {
    const el = this.el();
    if (!el) return;
    this.send(this.field.compositionEnd(el.value));
    this.afterChange(el);
  }

  /**
   * "cancel" for a key the field sent (Enter, or Backspace on an empty
   * field), "field" for a Backspace the browser should apply to the field so
   * it stays in step with the keyboard, null for a key the caller handles.
   */
  keyDown(e: FieldKey): KeyVerdict {
    const el = this.el();
    if (!el) return null;
    if (e.key === "Backspace" && !e.ctrlKey && !e.altKey && !e.metaKey && e.keyCode !== 229) {
      if (Array.from(el.value).length > 1) {
        // The keyboard thinks a character goes; take it out of the field too,
        // and the input event sends the backspace.
        this.field.backspaceKey();
        return "field";
      }
      this.send([{ type: "backspace", count: 1 }]);
      return "cancel";
    }
    const ops = this.field.keyDown(e, el.value);
    if (!ops) return null;
    this.send(ops);
    this.armIdle();
    return "cancel";
  }

  keyUp(e: FieldKey): void {
    this.field.keyUp(e);
  }

  /** True when the line break was sent and the event should be cancelled. */
  beforeInput(inputType: string): boolean {
    const el = this.el();
    if (!el) return false;
    const ops = this.field.beforeInput(inputType, el.value);
    if (!ops) return false;
    this.send(ops);
    this.armIdle();
    return true;
  }

  private afterChange(el: FieldElement): void {
    // The sentinel went too: put it back so the next Backspace has
    // something to delete. The keyboard sees an empty field either way.
    if (el.value === "" && !this.field.composing()) this.startOver(el);
    this.armIdle();
  }

  private armIdle(): void {
    if (this.idle !== null) this.timer.clear(this.idle);
    this.idle = this.timer.set(() => {
      this.idle = null;
      const el = this.el();
      if (!el || this.field.composing()) return;
      if (this.field.afterEnter() || Array.from(el.value).length > HiddenField.LONG) this.startOver(el);
    }, HiddenField.IDLE_MS);
  }

  private startOver(el: FieldElement): void {
    el.value = SENTINEL;
    this.field.reset();
    this.caretToEnd(el);
  }

  private caretToEnd(el: FieldElement): void {
    try {
      el.setSelectionRange?.(el.value.length, el.value.length);
    } catch {
      // Some inputs refuse a selection; the caret position does not matter much.
    }
  }
}
