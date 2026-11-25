/**
 * Phone keyboard sequences replayed against the hidden field, checking what
 * the computer ends up with. See imeRig.ts for how each keyboard call
 * becomes DOM events, and for the Gboard model built from emulator traces.
 */
import { describe, expect, it } from "vitest";
import { HiddenField, SENTINEL, type FieldOp, type FieldTimer } from "../input/keys";
import { InputSender, SendLane } from "../input/packets";
import { FakeRemote, Gboard, rig, typeWord, type FakeInput } from "./imeRig";

describe("Gboard in Chrome's WebView", () => {
  it("types letters, Backspace, double space and an emoji", () => {
    const { field, remote } = rig();
    new Gboard(field).type("helo<<llo world  ok 👍<");
    expect(remote.text).toBe("hello world. ok ");
  });

  it("keeps the field in step with the keyboard when Backspace comes as a key", () => {
    const { field, remote } = rig();
    new Gboard(field).type("abc<<");
    expect(remote.text).toBe("a");
    expect(field.value).toBe(SENTINEL + "a");
  });

  it("sends Backspace on an empty field", () => {
    const { field, remote } = rig();
    new Gboard(field).type("<<");
    expect(remote.ops).toEqual([
      { type: "backspace", count: 1 },
      { type: "backspace", count: 1 },
    ]);
  });

  it("does not let a suggestion tapped after Enter edit the line already sent", () => {
    // Emulator trace: after "hello" and Enter, Gboard still offers "hero".
    // Tapping it deletes "llo" and commits "ro ", which backspaced over the
    // Return and gave "helro " on the computer.
    const { field, remote } = rig();
    const g = new Gboard(field);
    g.type("hello");
    g.enter();
    g.suggest(3, "ro ");
    expect(remote.text).toBe("hello\n");
    g.type("world ");
    expect(remote.text).toBe("hello\nworld ");
  });

  it("still lets Backspace at the start of a line join it to the one above", () => {
    const { field, remote } = rig();
    const g = new Gboard(field);
    g.type("ls");
    g.enter();
    g.type("<");
    expect(remote.text).toBe("ls");
  });

  it("keeps suggestions working on the line after Enter", () => {
    const { field, remote } = rig();
    const g = new Gboard(field);
    g.type("ok");
    g.enter();
    g.type("helo");
    g.suggest(4, "hello ");
    expect(remote.text).toBe("ok\nhello ");
  });

  it("keeps fast typing right past 32 characters while Gboard hears about the caret late", () => {
    // Emulator trace at 22 keys a second with a busy page: "words here  ok"
    // came out as "words. ok here". The field had emptied itself from
    // script at 32 characters; Gboard took a stale caret from the late
    // report and its double space deleted and inserted at that old offset.
    const { field, remote } = rig();
    new Gboard(field, 6).type("the quick brown fox jumps over it is fine  ok ");
    expect(remote.text).toBe("the quick brown fox jumps over it is fine. ok ");
  });

  it("keeps fast corrections right while Gboard hears about the caret late", () => {
    const { field, remote } = rig();
    new Gboard(field, 4).type("thsi is a tset<<<<test of fats<<st typing  and more wrods<<<<ords here  ok ");
    expect(remote.text).toBe("thsi is a test of fast typing. and more words here. ok ");
  });

  it("does not write to the field while the person types", () => {
    const { field } = rig();
    const writes = field.jsWrites;
    new Gboard(field).type("a long line of words that runs well past thirty two characters<<<< and on ");
    expect(field.jsWrites).toBe(writes);
  });
});

describe("the field starting over", () => {
  function timed() {
    let pending: (() => void) | null = null;
    const timer: FieldTimer = {
      set: (cb) => {
        pending = cb;
        return 1;
      },
      clear: () => {
        pending = null;
      },
    };
    const r = rig((el, send) => new HiddenField(el, send, timer));
    return {
      ...r,
      idle(): void {
        const cb = pending;
        pending = null;
        cb?.();
      },
    };
  }

  it("starts over once the person stops after an Enter", () => {
    const { field, remote, idle } = timed();
    const g = new Gboard(field);
    g.type("ls");
    g.enter();
    idle();
    expect(field.value).toBe(SENTINEL);
    // A keyboard that deletes rather than sending a Backspace key reaches
    // the computer again, and joins the lines.
    field.deleteSurroundingText(1);
    expect(remote.text).toBe("ls");
  });

  it("starts over once a long line goes quiet, and not before", () => {
    const { field, idle } = timed();
    const g = new Gboard(field);
    g.type("word ".repeat(60));
    expect(field.value.length).toBeGreaterThan(HiddenField.LONG);
    idle();
    expect(field.value).toBe(SENTINEL);
  });

  it("leaves a short line alone when it goes quiet", () => {
    const { field, idle } = timed();
    new Gboard(field).type("short ");
    idle();
    expect(field.value).toBe(SENTINEL + "short ");
  });
});

describe("other keyboards (composing every word)", () => {
  it("sends fast typed words with autocorrect on space", () => {
    const { field, remote } = rig();
    typeWord(field, "teh");
    field.commitText("the ");
    typeWord(field, "quick");
    field.commitText("quick ");
    typeWord(field, "brwn");
    field.commitText("brown ");
    expect(remote.text).toBe("the quick brown ");
  });

  it("sends pasted text", () => {
    const { field, remote } = rig();
    typeWord(field, "say");
    field.paste("hello there");
    expect(remote.text).toBe("sayhello there");
  });

  it("sends the word and Return when Enter comes while the word composes", () => {
    const { field, remote } = rig();
    typeWord(field, "hello");
    field.key("Enter", 13);
    expect(remote.text).toBe("hello\n");
  });

  it("does not let a suggestion for the composing word after Enter edit the line already sent", () => {
    // Enter arrived as a keydown while the word composed; the field
    // cancelled it, so the keyboard still composes "hello".
    const { field, remote } = rig();
    typeWord(field, "hello");
    field.key("Enter", 13);
    field.commitText("Hello ");
    expect(remote.text).toBe("hello\n");
  });

  it("does not let a suggestion for the word before the caret edit the line already sent", () => {
    const { field, remote } = rig();
    typeWord(field, "hello");
    field.finishComposingText();
    field.key("Enter", 13);
    field.setComposingRegion(1, 6);
    field.commitText("Hello ");
    expect(remote.text).toBe("hello\n");
  });

  it("types the next line normally after Enter", () => {
    const { field, remote } = rig();
    typeWord(field, "ls");
    field.key("Enter", 13);
    field.finishComposingText();
    typeWord(field, "pwd");
    field.key("Enter", 13);
    expect(remote.text).toBe("ls\npwd\n");
  });
});

describe("a slow link", () => {
  it("keeps edits in order while earlier ones are still on their way", async () => {
    // The same wiring as useRemoteSession: text through session_text,
    // backspaces and Return as key bodies, one call at a time.
    const got: FieldOp[] = [];
    const remote = new FakeRemote();
    const delays = [9, 0, 4, 1, 7, 2, 0, 5];
    let d = 0;
    const later = (apply: () => void): Promise<void> =>
      new Promise((resolve) =>
        setTimeout(() => {
          apply();
          resolve();
        }, delays[d++ % delays.length]),
      );
    const lane = new SendLane();
    const pending: Promise<void>[] = [];
    const flushes: (() => void)[] = [];
    const BS = 0xff08;
    const RET = 0xff0d;
    const sender = new InputSender({
      send: (_seq, body) => {
        const p = lane.run(() =>
          later(() => {
            const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
            for (let at = 0; at + 10 <= body.length; at += 10) {
              if (dv.getUint8(at) !== 1 || dv.getUint8(at + 1) !== 1) continue;
              const sym = dv.getUint32(at + 2, true);
              if (sym === BS) got.push({ type: "backspace", count: 1 });
              if (sym === RET) got.push({ type: "enter" });
            }
          }),
        );
        pending.push(p);
        return p;
      },
      schedule: (cb) => flushes.push(cb),
    });
    const apply = (ops: FieldOp[]): void => {
      for (const op of ops) {
        if (op.type === "text") {
          sender.flush(true);
          pending.push(lane.run(() => later(() => got.push(op))));
        } else {
          const sym = op.type === "enter" ? RET : BS;
          const n = op.type === "backspace" ? op.count : 1;
          for (let k = 0; k < n; k++) {
            sender.key(true, sym, 0);
            sender.key(false, sym, 0);
          }
        }
      }
    };
    const r = rig((el, send) => new HiddenField(el, (ops) => (send(ops), apply(ops))));
    const field: FakeInput = r.field;
    const g = new Gboard(field);
    g.type("helo<<llo");
    for (const f of flushes.splice(0)) f();
    g.enter();
    g.type("wrold<<<<orld  ok");
    for (const f of flushes.splice(0)) f();
    while (pending.length) await Promise.all(pending.splice(0));
    remote.apply(got);
    expect(remote.text).toBe("hello\nworld. ok");
  });
});
