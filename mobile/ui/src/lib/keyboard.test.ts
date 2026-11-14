// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { wantsKeyboardRoom } from "./keyboard";

function make(html: string): HTMLElement {
  document.body.innerHTML = html;
  return document.body.querySelector("#it") as HTMLElement;
}

describe("which fields get scrolled above the keyboard", () => {
  it("includes text, password and text areas", () => {
    expect(wantsKeyboardRoom(make('<input id="it" type="password">'))).toBe(true);
    expect(wantsKeyboardRoom(make('<input id="it">'))).toBe(true);
    expect(wantsKeyboardRoom(make('<textarea id="it"></textarea>'))).toBe(true);
  });

  it("leaves out buttons, read only fields and the session's hidden typing field", () => {
    expect(wantsKeyboardRoom(make('<input id="it" type="checkbox">'))).toBe(false);
    expect(wantsKeyboardRoom(make('<input id="it" readonly>'))).toBe(false);
    expect(wantsKeyboardRoom(make('<div class="dv-session"><input id="it" class="dv-s-hidden-input"></div>'))).toBe(false);
    expect(wantsKeyboardRoom(make('<button id="it">Go</button>'))).toBe(false);
    expect(wantsKeyboardRoom(null)).toBe(false);
  });
});
