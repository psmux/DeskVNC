import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement, createRef } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QuickConnect } from "./QuickConnect";
import type { ProtocolKind } from "../lib/types";

// The two buttons beside the field read app state this test does not need.
vi.mock("./BoundaryConnect", () => ({ BoundaryConnect: () => null }));
vi.mock("./GetHelp", () => ({ GetHelp: () => null }));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
// jsdom has no layout, and the list scrolls its highlighted row into view.
Element.prototype.scrollIntoView ??= function () {};

type Call = [ProtocolKind, string, number];

let root: Root;
let host: HTMLDivElement;

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

/** The bar as Library draws it, with these past quick connects. */
function render(recents: string[], calls: Call[]): HTMLInputElement {
  act(() => {
    root.render(
      createElement(QuickConnect, {
        hosts: [],
        discovered: [],
        recents,
        inputRef: createRef<HTMLInputElement>(),
        onConnectHost: () => {},
        onConnectAddress: (protocol, address, port) => calls.push([protocol, address, port]),
        onRemember: () => {},
      }),
    );
  });
  return host.querySelector("input")!;
}

/** Type the way a person does: React only hears a native input event. */
function type(input: HTMLInputElement, text: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  act(() => {
    input.focus();
    setter.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function key(input: HTMLInputElement, name: string): void {
  act(() => {
    input.dispatchEvent(new KeyboardEvent("keydown", { key: name, bubbles: true, cancelable: true }));
  });
}

function connectButton(): HTMLButtonElement {
  const b = [...host.querySelectorAll("button")].find((x) => x.textContent?.trim() === "Connect");
  if (!b) throw new Error("no Connect button");
  return b as HTMLButtonElement;
}

/** The protocol chip, the control just left of Connect. */
function chip(): HTMLButtonElement {
  return connectButton().previousElementSibling as HTMLButtonElement;
}

function option(text: string): HTMLElement {
  const o = [...host.querySelectorAll<HTMLElement>("[role=option]")].find((x) => x.textContent?.includes(text));
  if (!o) throw new Error(`no suggestion ${text}`);
  return o;
}

/** The mouse passing over a row on its way somewhere else. */
function hover(el: HTMLElement): void {
  act(() => {
    el.dispatchEvent(new MouseEvent("pointermove", { bubbles: true }));
    el.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
  });
}

function placeOfConnect(): number {
  const b = connectButton();
  return [...b.parentElement!.children].indexOf(b);
}

describe("a bare address in the quick connect bar", () => {
  it("does not move the Connect button when typing brings up the protocol chip", () => {
    const input = render([], []);
    const before = placeOfConnect();
    type(input, "192.0.2.5");
    // A chip put in ahead of Connect pushed it right by the chip's width, so
    // a click aimed at Connect landed on the chip and switched to RDP.
    expect(placeOfConnect()).toBe(before);
  });

  it("keeps the protocol chip out of reach while the field is empty", () => {
    render([], []);
    expect(chip().className).toContain("invisible");
    expect(chip().disabled).toBe(true);
  });

  it("connects with VNC on Connect, whatever an RDP recent for that address says", () => {
    const calls: Call[] = [];
    const input = render(["rdp://192.0.2.5"], calls);
    type(input, "192.0.2.5");
    hover(option("rdp://192.0.2.5"));
    act(() => connectButton().click());
    expect(calls).toEqual([["vnc", "192.0.2.5", 5900]]);
  });

  it("connects with VNC on Enter when the mouse only passed over an RDP suggestion", () => {
    const calls: Call[] = [];
    const input = render(["rdp://192.0.2.5"], calls);
    type(input, "192.0.2.5");
    hover(option("rdp://192.0.2.5"));
    key(input, "Enter");
    expect(calls).toEqual([["vnc", "192.0.2.5", 5900]]);
  });

  it("uses a suggestion picked with the arrow keys", () => {
    const calls: Call[] = [];
    const input = render(["rdp://192.0.2.5"], calls);
    type(input, "192.0.2.5");
    key(input, "ArrowDown");
    key(input, "ArrowDown");
    key(input, "Enter");
    expect(calls).toEqual([["rdp", "192.0.2.5", 3389]]);
  });

  it("uses a suggestion that was clicked", () => {
    const calls: Call[] = [];
    const input = render(["rdp://192.0.2.5"], calls);
    type(input, "192.0.2.5");
    act(() => option("rdp://192.0.2.5").click());
    expect(calls).toEqual([["rdp", "192.0.2.5", 3389]]);
  });

  it("uses the protocol the person picked on the chip", () => {
    const calls: Call[] = [];
    const input = render([], calls);
    type(input, "192.0.2.5");
    act(() => chip().click());
    act(() => connectButton().click());
    expect(calls).toEqual([["rdp", "192.0.2.5", 5900]]);
  });
});
