import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import type { TabSummary } from "../state/TabsContext";
import { TabStrip } from "./TabStrip";

// jsdom lays nothing out, so there is nothing for this to report. The strip
// only needs it to exist.
class NoResizeObserver {
  observe(): void {}
  disconnect(): void {}
}

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const tab = (id: string): TabSummary =>
  ({ id, title: id, state: { state: "connected" } }) as unknown as TabSummary;

let host: HTMLDivElement;
let root: Root;
let onCloseMany: Mock<(ids: readonly string[]) => void>;

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", NoResizeObserver);
  Element.prototype.scrollIntoView = () => {};
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  onCloseMany = vi.fn<(ids: readonly string[]) => void>();
  act(() => {
    root.render(
      createElement(TabStrip, {
        tabs: ["a", "b", "c", "d"].map(tab),
        activeId: "b",
        onSelect: () => {},
        onClose: () => {},
        onCloseMany,
        onSelectRelative: () => {},
      }),
    );
  });
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  vi.unstubAllGlobals();
});

function rightClick(name: string): void {
  const el = [...host.querySelectorAll<HTMLElement>('[role="tab"]')].find(
    (t) => t.title === name,
  );
  if (!el) throw new Error(`no tab ${name}`);
  act(() => {
    el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
  });
}

function menuItem(label: string): HTMLButtonElement {
  const item = [...document.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')].find(
    (b) => b.textContent === label,
  );
  if (!item) throw new Error(`no menu item ${label}`);
  return item;
}

describe("the tab strip's right-click menu", () => {
  it("offers the browser's close commands on a tab", () => {
    rightClick("b");
    const labels = [...document.querySelectorAll('[role="menuitem"]')].map((b) => b.textContent);
    expect(labels).toEqual([
      "Close tab",
      "Close other tabs",
      "Close tabs to the left",
      "Close tabs to the right",
      "Close all tabs",
    ]);
  });

  it("closes the tabs to the right of the one clicked", () => {
    rightClick("b");
    act(() => menuItem("Close tabs to the right").click());
    expect(onCloseMany).toHaveBeenCalledWith(["c", "d"]);
    expect(document.querySelector('[role="menu"]')).toBeNull();
  });

  it("closes every tab but the one clicked", () => {
    rightClick("c");
    act(() => menuItem("Close other tabs").click());
    expect(onCloseMany).toHaveBeenCalledWith(["a", "b", "d"]);
  });

  it("dims a command with nothing to close", () => {
    rightClick("d");
    expect(menuItem("Close tabs to the right").disabled).toBe(true);
    expect(menuItem("Close tabs to the left").disabled).toBe(false);
  });

  it("offers the item its tab asks for: Add for an unsaved machine, Edit for a saved one", () => {
    const onSaveHost = vi.fn<(id: string) => void>();
    act(() => {
      root.render(
        createElement(TabStrip, {
          tabs: ["a", "b", "c", "d"].map(tab),
          activeId: "b",
          onSelect: () => {},
          onClose: () => {},
          onCloseMany,
          onSelectRelative: () => {},
          // "c" stands for a quick connect, "b" for a saved host, "a" for a
          // tab that offers neither (a Boundary session).
          saveHostLabel: (t: TabSummary) =>
            t.id === "c" ? "Add to saved hosts" : t.id === "a" ? null : "Edit saved host",
          onSaveHost,
        }),
      );
    });

    rightClick("c");
    const labels = [...document.querySelectorAll('[role="menuitem"]')].map((b) => b.textContent);
    expect(labels[0]).toBe("Add to saved hosts");
    expect(labels.slice(1)).toEqual([
      "Close tab",
      "Close other tabs",
      "Close tabs to the left",
      "Close tabs to the right",
      "Close all tabs",
    ]);
    act(() => menuItem("Add to saved hosts").click());
    expect(onSaveHost).toHaveBeenCalledWith("c");
    expect(onCloseMany).not.toHaveBeenCalled();

    rightClick("b");
    const saved = [...document.querySelectorAll('[role="menuitem"]')].map((b) => b.textContent);
    expect(saved[0]).toBe("Edit saved host");
    expect(saved).not.toContain("Add to saved hosts");
    act(() => menuItem("Edit saved host").click());
    expect(onSaveHost).toHaveBeenLastCalledWith("b");

    rightClick("a");
    const neither = [...document.querySelectorAll('[role="menuitem"]')].map((b) => b.textContent);
    expect(neither[0]).toBe("Close tab");

    rightClick("Library");
    const library = [...document.querySelectorAll('[role="menuitem"]')].map((b) => b.textContent);
    expect(library).toEqual(["Close all tabs"]);
  });

  it("offers only Close all tabs on the library, which never closes", () => {
    rightClick("Library");
    const labels = [...document.querySelectorAll('[role="menuitem"]')].map((b) => b.textContent);
    expect(labels).toEqual(["Close all tabs"]);
    act(() => menuItem("Close all tabs").click());
    expect(onCloseMany).toHaveBeenCalledWith(["a", "b", "c", "d"]);
  });
});
