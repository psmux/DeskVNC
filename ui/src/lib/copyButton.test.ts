import { describe, expect, it } from "vitest";
import { copyButtonLabel, copyFailedHint, copyOutcomeMs } from "./copyButton";

describe("copy button", () => {
  it("rests on its own label", () => {
    expect(copyButtonLabel(null, "Copy invitation")).toBe("Copy invitation");
  });

  it("says Copied only when the clipboard took it", () => {
    expect(copyButtonLabel({ ok: true }, "Copy code")).toBe("Copied");
  });

  it("says so when the copy failed instead of looking the same", () => {
    expect(copyButtonLabel({ ok: false }, "Copy code")).toBe("Could not copy");
  });

  it("keeps a failure up longer than a success", () => {
    expect(copyOutcomeMs(false)).toBeGreaterThan(copyOutcomeMs(true));
  });

  it("names the right keys for the platform", () => {
    expect(copyFailedHint(true)).toContain("Command C");
    expect(copyFailedHint(false)).toContain("Ctrl C");
  });
});
