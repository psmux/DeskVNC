import { afterEach, describe, expect, it, vi } from "vitest";
import { devSessionId } from "./devSession";

describe("devSessionId", () => {
  afterEach(() => vi.restoreAllMocks());

  it("is a dev prefixed UUID", () => {
    expect(devSessionId()).toMatch(
      /^dev-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("never draws on Math.random", () => {
    const spy = vi.spyOn(Math, "random");
    devSessionId();
    expect(spy).not.toHaveBeenCalled();
  });

  it("does not repeat", () => {
    const ids = new Set(Array.from({ length: 1000 }, devSessionId));
    expect(ids.size).toBe(1000);
  });
});
