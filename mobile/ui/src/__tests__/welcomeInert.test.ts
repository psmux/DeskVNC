// @vitest-environment jsdom
/**
 * The welcome pages cover the whole screen, but the home screen under them
 * stayed in the accessibility tree: TalkBack, a hardware keyboard and UI
 * automation could reach "Add a computer" and the tab bar through the
 * welcome. The home screen is inert while they show, as it already is under
 * the add computer wizard and a session.
 */
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { App } from "../App";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function button(text: string): HTMLButtonElement | undefined {
  return [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === text);
}

describe("welcome pages", () => {
  let host: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    localStorage.clear();
    window.matchMedia ??= ((q: string) => ({
      matches: false,
      media: q,
      onchange: null,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia;
    host = document.createElement("div");
    document.body.appendChild(host);
  });

  afterEach(() => {
    act(() => root.unmount());
    host.remove();
  });

  it("keep the home screen out of reach until they are skipped", async () => {
    await act(async () => {
      root = createRoot(host);
      root.render(createElement(App));
    });
    const skip = button("Skip");
    expect(skip).toBeTruthy();
    const settings = button("Settings");
    expect(settings).toBeTruthy();
    expect(settings!.closest("[inert]")).not.toBeNull();

    await act(async () => skip!.click());
    expect(button("Settings")!.closest("[inert]")).toBeNull();
  });
});
