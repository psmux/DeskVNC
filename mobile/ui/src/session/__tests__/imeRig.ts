/**
 * A pretend Chrome input box for replaying what an Android keyboard does to
 * the hidden field, and a pretend computer that applies what the field sends.
 *
 * The keyboard talks to Chrome through Android's InputConnection: it sets
 * and commits composing text, deletes around the caret, marks existing text
 * as composing, and sends key events. Chrome applies each call to the DOM and
 * fires the same events a WebView fires, in the same order:
 *
 *   setComposingText   compositionstart (first time), beforeinput, compositionupdate, input (isComposing)
 *   commitText         with a composition: beforeinput, compositionupdate, input (isComposing), compositionend
 *                      without one: beforeinput insertText, input
 *   finishComposing    compositionend
 *   setComposingRegion compositionstart, compositionupdate (no input event)
 *   deleteSurrounding  beforeinput deleteContentBackward, input
 *   key event          keydown (229 while composing), beforeinput line break if not cancelled, keyup
 *
 * A script assigning `value` from JavaScript ends any composition, the way
 * Blink drops its composition range when the text node is replaced. The
 * keyboard only hears about that later, so it can keep sending calls built
 * on what the field held before; scenarios model that by sending them.
 */
import { HiddenField, SENTINEL, type FieldOp } from "../input/keys";

type Cps = string[];
const cps = (s: string): Cps => Array.from(s);

export class FakeInput {
  private text: Cps = cps(SENTINEL);
  /** Caret, in code points. */
  caret = 1;
  /** Composition range in code points, or null. */
  comp: [number, number] | null = null;
  /** Every JavaScript write to `value`, for the assertions. */
  jsWrites = 0;
  private readonly hidden: HiddenField;
  /** Events, for a readable failure message. */
  readonly trace: string[] = [];

  constructor(
    private readonly send: (ops: FieldOp[]) => void,
    make?: (el: () => FakeInput, send: (ops: FieldOp[]) => void) => HiddenField,
  ) {
    this.hidden = make ? make(() => this, send) : new HiddenField(() => this, send);
  }

  /** Text before the caret. */
  beforeCaret(): string {
    return this.text.slice(0, this.caret).join("");
  }

  get value(): string {
    return this.text.join("");
  }

  set value(v: string) {
    this.jsWrites++;
    this.text = cps(v);
    this.caret = this.text.length;
    this.comp = null;
    this.trace.push(`js value=${JSON.stringify(v)}`);
  }

  setSelectionRange(start: number, end: number): void {
    this.caret = Math.min(Math.max(start, end), this.text.length);
  }

  /** The keyboard opens on the field. */
  open(): void {
    this.hidden.open();
  }

  // ------------------------------------------------------- InputConnection

  setComposingText(t: string): void {
    if (!this.comp) {
      this.comp = [this.caret, this.caret];
      this.fire("compositionstart");
    }
    this.fire("beforeinput", "insertCompositionText", true);
    const [s, e] = this.comp;
    const add = cps(t);
    this.text.splice(s, e - s, ...add);
    this.caret = s + add.length;
    this.comp = [s, s + add.length];
    this.fire("compositionupdate");
    this.fire("input", "insertCompositionText", true);
    if (add.length === 0) {
      // An empty composition is no composition.
      this.comp = null;
      this.fire("compositionend");
    }
  }

  commitText(t: string): void {
    const add = cps(t);
    if (this.comp) {
      const [s, e] = this.comp;
      this.fire("beforeinput", "insertCompositionText", true);
      this.text.splice(s, e - s, ...add);
      this.caret = s + add.length;
      this.fire("compositionupdate");
      this.fire("input", "insertCompositionText", true);
      this.comp = null;
      this.fire("compositionend");
      return;
    }
    if (this.fire("beforeinput", "insertText", false)) return;
    this.text.splice(this.caret, 0, ...add);
    this.caret += add.length;
    this.fire("input", "insertText", false);
  }

  finishComposingText(): void {
    if (!this.comp) return;
    this.comp = null;
    this.fire("compositionend");
  }

  /** Offsets as the keyboard computed them, clamped the way Blink clamps them. */
  setComposingRegion(start: number, end: number): void {
    const n = this.text.length;
    const s = Math.min(Math.max(0, start), n);
    const e = Math.min(Math.max(0, end), n);
    if (s === e) {
      this.finishComposingText();
      return;
    }
    const had = this.comp !== null;
    this.comp = [Math.min(s, e), Math.max(s, e)];
    if (!had) this.fire("compositionstart");
    this.fire("compositionupdate");
  }

  deleteSurroundingText(before: number, after = 0): void {
    if (this.fire("beforeinput", "deleteContentBackward", false)) return;
    const s = Math.max(0, this.caret - before);
    const e = Math.min(this.text.length, this.caret + after);
    this.text.splice(s, e - s);
    if (this.comp) {
      // Blink keeps a composition that the deletion did not touch.
      const [cs, ce] = this.comp;
      if (ce <= s) this.comp = [cs, ce];
      else this.comp = null;
    }
    this.caret = s;
    this.fire("input", "deleteContentBackward", false);
  }

  /**
   * A key event from the keyboard: Enter, or Backspace, which Gboard sends
   * as a key event (keyCode 8) rather than as a deletion. What the session
   * screen does with a key the field leaves alone is played here too: it
   * cancels a Backspace and sends it to the computer itself.
   */
  key(key: string, keyCode: number): void {
    const composing = this.comp !== null;
    const code = composing ? 229 : keyCode;
    const v: unknown = this.hidden.keyDown({ key, keyCode: code, isComposing: composing });
    // Before the fix keyDown said true for cancel and false for "not mine".
    const verdict = v === true ? "cancel" : v === false ? null : (v as "cancel" | "field" | null);
    let cancelled = verdict === "cancel";
    if (verdict === null && key === "Backspace" && code !== 229) {
      this.send([{ type: "backspace", count: 1 }]);
      cancelled = true;
    }
    this.trace.push(`keydown ${key} ${code}${cancelled ? " (cancelled)" : ""}`);
    if (!cancelled && key === "Enter") {
      // A single line input inserts nothing for Enter, but Chrome still
      // reports the line break as beforeinput.
      this.fire("beforeinput", "insertLineBreak", false);
    }
    if (!cancelled && key === "Backspace" && this.caret > 0) {
      // The browser's own Backspace: one character before the caret.
      if (!this.fire("beforeinput", "deleteContentBackward", false)) {
        this.text.splice(this.caret - 1, 1);
        this.caret -= 1;
        this.fire("input", "deleteContentBackward", false);
      }
    }
    this.hidden.keyUp({ key, keyCode: code, isComposing: composing });
  }

  /** Paste: Chrome inserts the clipboard text at the caret, outside any composition. */
  paste(t: string): void {
    this.finishComposingText();
    if (this.fire("beforeinput", "insertFromPaste", false)) return;
    const add = cps(t);
    this.text.splice(this.caret, 0, ...add);
    this.caret += add.length;
    this.fire("input", "insertFromPaste", false);
  }

  /** Returns true when a handler cancelled the event. */
  private fire(type: string, inputType?: string, composing?: boolean): boolean {
    this.trace.push(`${type}${inputType ? ` ${inputType}` : ""} value=${JSON.stringify(this.value.replace(SENTINEL, "·"))}`);
    switch (type) {
      case "compositionstart":
        this.hidden.compositionStart();
        return false;
      case "compositionend":
        this.hidden.compositionEnd();
        return false;
      case "input":
        this.hidden.input(composing === true);
        return false;
      case "beforeinput":
        return this.hidden.beforeInput(inputType ?? "");
      default:
        return false;
    }
  }
}

/** What the computer shows after the ops, with Backspace able to join lines. */
export class FakeRemote {
  private chars: Cps = [];
  readonly ops: FieldOp[] = [];

  apply = (ops: FieldOp[]): void => {
    for (const op of ops) {
      this.ops.push(op);
      if (op.type === "text") this.chars.push(...cps(op.text));
      else if (op.type === "enter") this.chars.push("\n");
      else this.chars.splice(Math.max(0, this.chars.length - op.count), op.count);
    }
  };

  get text(): string {
    return this.chars.join("");
  }
}

/** A field and a computer, wired together. */
export function rig(make?: (el: () => FakeInput, send: (ops: FieldOp[]) => void) => HiddenField) {
  const remote = new FakeRemote();
  const field = new FakeInput(remote.apply, make);
  field.open();
  return { field, remote };
}

/**
 * Gboard as it behaves in Chrome's WebView on this field (the emulator
 * traces in the pull request): no composition, every letter a commitText,
 * Backspace a key event, a double space turned into ". " by deleting the
 * space and committing, a suggestion applied by deleting the word and
 * committing the new one.
 *
 * Gboard keeps its own idea of the caret and checks it against the caret
 * Chrome reports after each call. Those reports reach it `lag` calls late
 * when the app's main thread is busy. A report that does not match what it
 * expected for that call (the field was written from script) makes it take
 * the reported caret as the truth, though that caret is `lag` calls old,
 * and its next double space then puts the caret there before deleting.
 */
export class Gboard {
  /** Where Gboard thinks the caret is. */
  private caret: number;
  private readonly history: { actual: number; expected: number }[] = [];

  constructor(
    private readonly f: FakeInput,
    private readonly lag = 0,
  ) {
    this.caret = f.caret;
  }

  private after(expected: number): void {
    this.caret = expected;
    this.history.push({ actual: this.f.caret, expected });
    const n = this.history.length - 1 - this.lag;
    if (n < 0) return;
    const r = this.history[n];
    // Reports at or after a resync are compared with the resynced count.
    if (r.actual !== r.expected) {
      const typedSince = this.history.length - 1 - n;
      this.caret = r.actual + (this.lag > 0 ? 0 : typedSince);
      for (let k = n; k < this.history.length; k++) this.history[k].expected = this.history[k].actual;
    }
  }

  type(text: string): void {
    let prev = "";
    for (const ch of Array.from(text)) {
      if (ch === "<") {
        this.f.key("Backspace", 8);
        this.after(Math.max(0, this.caret - 1));
      } else if (ch === " " && prev === " " && this.f.beforeCaret().endsWith(" ")) {
        // Double space: the space before the caret becomes ". ".
        this.f.setSelectionRange(this.caret, this.caret);
        this.f.deleteSurroundingText(1);
        this.f.commitText(". ");
        this.after(this.caret + 1);
        prev = "";
        continue;
      } else {
        this.f.commitText(ch);
        this.after(this.caret + 1);
      }
      prev = ch;
    }
  }

  /** Tap the suggestion `word` for the `replaces` characters before the caret. */
  suggest(replaces: number, word: string): void {
    this.f.deleteSurroundingText(replaces);
    this.f.commitText(word);
    this.after(this.caret - replaces + Array.from(word).length);
  }

  enter(): void {
    this.f.key("Enter", 13);
    this.after(this.caret);
  }
}

/**
 * Gboard typing a word letter by letter: each key press sets the whole word
 * so far as the composing text.
 */
export function typeWord(f: FakeInput, word: string, from = ""): void {
  let w = from;
  for (const ch of cps(word)) {
    w += ch;
    f.setComposingText(w);
  }
}
