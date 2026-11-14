import { describe, expect, it } from "vitest";
import { LAYER, createBackStack } from "./back";

describe("the Back stack", () => {
  it("does nothing, and leaves Back to Android, on the home screen", () => {
    const active: boolean[] = [];
    const stack = createBackStack((on) => active.push(on));
    expect(stack.handle()).toBe(false);
    expect(active).toEqual([]);
  });

  it("takes Back over while anything is open and gives it back after", () => {
    const active: boolean[] = [];
    const stack = createBackStack((on) => active.push(on));
    const offTab = stack.push(LAYER.tab, () => {});
    const offWizard = stack.push(LAYER.wizard, () => {});
    offWizard();
    offTab();
    offTab();
    expect(active).toEqual([true, false]);
  });

  it("answers with the highest layer, whatever order they registered in", () => {
    const calls: string[] = [];
    const stack = createBackStack();
    // React runs the sheet's effect before the session that holds it.
    stack.push(LAYER.sheet, () => calls.push("sign in sheet"));
    const offSession = stack.push(LAYER.session, () => calls.push("session"));
    stack.push(LAYER.tab, () => calls.push("tab"));
    expect(stack.handle()).toBe(true);
    expect(calls).toEqual(["sign in sheet"]);
    offSession();
    expect(stack.size()).toBe(2);
  });

  it("prefers the latest of two on the same layer", () => {
    const calls: string[] = [];
    const stack = createBackStack();
    stack.push(LAYER.sheet, () => calls.push("first"));
    stack.push(LAYER.sheet, () => calls.push("second"));
    stack.handle();
    expect(calls).toEqual(["second"]);
  });
});
