import { describe, expect, it } from "vitest";
import { codeBoxes, codeDigits, formatCode, isCompleteCode, isInvitation, readPastedHelp } from "./code";

describe("help codes", () => {
  it("groups digits in fours", () => {
    expect(formatCode("123456789012")).toBe("1234 5678 9012");
    expect(formatCode("12345")).toBe("1234 5");
    expect(formatCode("1234-5678-9012")).toBe("1234 5678 9012");
    expect(formatCode("")).toBe("");
  });

  it("never keeps more than twelve digits", () => {
    expect(codeDigits("1234 5678 9012 3456")).toBe("123456789012");
  });

  it("lays the code out as three rows of four boxes", () => {
    expect(codeBoxes("123456")).toEqual([
      ["1", "2", "3", "4"],
      ["5", "6", "", ""],
      ["", "", "", ""],
    ]);
  });

  it("knows a complete code", () => {
    expect(isCompleteCode("1234 5678 9012")).toBe(true);
    expect(isCompleteCode("1234 5678 901")).toBe(false);
  });

  it("knows an invitation", () => {
    expect(isInvitation("boundary1:abcDEF")).toBe(true);
    expect(isInvitation("boundary1:")).toBe(false);
    expect(isInvitation("hello")).toBe(false);
  });
});

describe("readPastedHelp", () => {
  it("finds a code inside a whole message", () => {
    expect(readPastedHelp("hi! my code is 1234-5678-9012, thanks")).toEqual({ kind: "code", digits: "123456789012" });
    expect(readPastedHelp("1234 5678 9012")).toEqual({ kind: "code", digits: "123456789012" });
  });

  it("finds an invitation", () => {
    expect(readPastedHelp("Here you go: boundary1:QUJD123 ok")).toEqual({
      kind: "invitation",
      invitation: "boundary1:QUJD123",
    });
  });

  it("says when there is nothing useful", () => {
    expect(readPastedHelp("call me at 5")).toEqual({ kind: "nothing" });
    expect(readPastedHelp("1234 5678")).toEqual({ kind: "nothing" });
  });
});
