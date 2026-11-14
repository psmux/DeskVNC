import { describe, expect, it } from "vitest";
import { sessionBackStep, type SessionBackView } from "../back";

const LIVE: SessionBackView = { askLeave: false, sheet: false, toolbarOpen: false, coach: false, connected: true };

describe("Android Back in a session", () => {
  it("closes what is open over the desktop first", () => {
    expect(sessionBackStep({ ...LIVE, sheet: true })).toBe("close-sheet");
    expect(sessionBackStep({ ...LIVE, toolbarOpen: true })).toBe("close-toolbar");
    expect(sessionBackStep({ ...LIVE, coach: true })).toBe("close-coach");
  });

  it("asks before leaving a live desktop", () => {
    expect(sessionBackStep(LIVE)).toBe("ask-leave");
  });

  it("closes the Leave prompt and stays when Back is pressed on it", () => {
    expect(sessionBackStep({ ...LIVE, askLeave: true })).toBe("close-leave");
    expect(sessionBackStep({ ...LIVE, askLeave: true, sheet: true })).toBe("close-leave");
  });

  it("leaves at once when there is no desktop to lose", () => {
    expect(sessionBackStep({ ...LIVE, connected: false })).toBe("leave");
  });
});
