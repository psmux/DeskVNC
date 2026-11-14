/**
 * Enter on an Android soft keyboard while the word is still composing.
 * The event sequences are the ones Gboard produces in Chrome's WebView.
 */
import { describe, expect, it } from "vitest";
import { KeyboardField, SENTINEL, type FieldOp } from "../input/keys";

/** Plays events against a field and collects what would be sent. */
function rig() {
  const field = new KeyboardField();
  const out: FieldOp[] = [];
  let value = SENTINEL;
  const push = (ops: FieldOp[] | null): void => {
    if (ops) out.push(...ops);
  };
  return {
    sent(): string {
      return out.map((op) => (op.type === "text" ? op.text : op.type === "enter" ? "<Return>" : `<BS${op.count}>`)).join("");
    },
    start(): void {
      field.compositionStart();
    },
    update(word: string): void {
      value = SENTINEL + word;
      push(field.input(value, true));
    },
    end(): void {
      push(field.compositionEnd(value));
    },
    keyDown(key: string, keyCode: number, isComposing: boolean): void {
      push(field.keyDown({ key, keyCode, isComposing }, value));
    },
    keyUp(key: string): void {
      field.keyUp({ key });
    },
    beforeInput(inputType: string): void {
      push(field.beforeInput(inputType, value));
    },
  };
}

/** Gboard: compositionstart, then per letter a keydown 229 and an input with the whole word. */
function typeComposing(r: ReturnType<typeof rig>, word: string): void {
  r.start();
  for (let i = 1; i <= word.length; i++) {
    r.keyDown("Unidentified", 229, true);
    r.update(word.slice(0, i));
  }
}

describe("Enter while Gboard composes", () => {
  it("sends the letters and then Return for a keydown Enter flagged as composing", () => {
    const r = rig();
    typeComposing(r, "abc");
    r.keyDown("Enter", 229, true);
    r.keyUp("Enter");
    r.end();
    expect(r.sent()).toBe("abc<Return>");
  });

  it("sends Return for a keydown Enter with isComposing and keyCode 13", () => {
    const r = rig();
    typeComposing(r, "abc");
    r.keyDown("Enter", 13, true);
    r.keyUp("Enter");
    expect(r.sent()).toBe("abc<Return>");
  });

  it("sends Return when the line break only shows up as beforeinput", () => {
    const r = rig();
    typeComposing(r, "abc");
    r.keyDown("Unidentified", 229, true);
    r.beforeInput("insertLineBreak");
    r.end();
    expect(r.sent()).toBe("abc<Return>");
  });

  it("treats insertParagraph like insertLineBreak", () => {
    const r = rig();
    typeComposing(r, "ab");
    r.beforeInput("insertParagraph");
    expect(r.sent()).toBe("ab<Return>");
  });

  it("commits text the field holds but has not sent before the Return", () => {
    const field = new KeyboardField();
    field.compositionStart();
    expect(field.input(SENTINEL + "na", true)).toEqual([{ type: "text", text: "na" }]);
    // The last letter landed in the field without an input event of its own.
    const ops = field.keyDown({ key: "Enter", keyCode: 229, isComposing: true }, SENTINEL + "nai");
    expect(ops).toEqual([{ type: "text", text: "i" }, { type: "enter" }]);
    expect(field.compositionEnd(SENTINEL + "nai")).toEqual([]);
  });

  it("sends one Return when keydown and beforeinput both report it", () => {
    const r = rig();
    typeComposing(r, "abc");
    r.keyDown("Enter", 13, true);
    r.beforeInput("insertLineBreak");
    r.keyUp("Enter");
    r.end();
    expect(r.sent()).toBe("abc<Return>");
  });

  it("still sends Return after a committed word", () => {
    const r = rig();
    typeComposing(r, "abc ");
    r.end();
    r.keyDown("Enter", 13, false);
    r.keyUp("Enter");
    expect(r.sent()).toBe("abc <Return>");
  });

  it("leaves Enter to a CJK IME, which uses it to pick the candidate", () => {
    const field = new KeyboardField();
    field.compositionStart();
    expect(field.input(SENTINEL + "日本", true)).toEqual([]);
    expect(field.keyDown({ key: "Enter", keyCode: 229, isComposing: true }, SENTINEL + "日本")).toBeNull();
    expect(field.beforeInput("insertLineBreak", SENTINEL + "日本")).toBeNull();
    expect(field.compositionEnd(SENTINEL + "日本")).toEqual([{ type: "text", text: "日本" }]);
  });

  it("leaves other keys to the caller", () => {
    const field = new KeyboardField();
    expect(field.keyDown({ key: "Tab", keyCode: 9 }, SENTINEL)).toBeNull();
    expect(field.beforeInput("insertText", SENTINEL + "a")).toBeNull();
  });
});
