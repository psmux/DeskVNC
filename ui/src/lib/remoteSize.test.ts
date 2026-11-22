import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { blankRdpSettings, parseRdpSettings, serializeRdpSettings } from "./rdp";
import { RESIZE_GRACE_MS, ResizeWatch, remoteResizeTarget } from "./remoteSize";

// Issue #60: a Retina Mac (two physical pixels to the point) connected to a
// Windows 11 guest got a desktop at the window's physical size and 100
// percent scaling, so everything was half size, and resizing the window did
// nothing to the remote desktop.

describe("remoteResizeTarget", () => {
  it("keeps physical pixels for Remote Desktop, which sends the scale beside them", () => {
    expect(remoteResizeTarget("rdp", 3840, 1890, 2)).toEqual({ w: 3840, h: 1890 });
  });

  it("asks a VNC server for points on a Retina screen, since RFB has no scale to send", () => {
    expect(remoteResizeTarget("vnc", 3840, 1890, 2)).toEqual({ w: 1920, h: 945 });
    expect(remoteResizeTarget("vnc", 2880, 1800, 1.5)).toEqual({ w: 1920, h: 1200 });
  });

  it("changes nothing on an ordinary screen or for a nonsense ratio", () => {
    expect(remoteResizeTarget("vnc", 1920, 1080, 1)).toEqual({ w: 1920, h: 1080 });
    expect(remoteResizeTarget("vnc", 1920, 1080, 0)).toEqual({ w: 1920, h: 1080 });
    expect(remoteResizeTarget("vnc", 1920, 1080, Number.NaN)).toEqual({ w: 1920, h: 1080 });
  });
});

describe("ResizeWatch", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("says so when the server never answers a resize", () => {
    const refused = vi.fn();
    const watch = new ResizeWatch(refused);
    watch.requested({ w: 2560, h: 1400 }, { w: 3840, h: 1890 });
    vi.advanceTimersByTime(RESIZE_GRACE_MS - 1);
    expect(refused).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(refused).toHaveBeenCalledWith({ w: 2560, h: 1400 }, { w: 3840, h: 1890 });
  });

  it("stays quiet when the server rebuilds its desktop in time", () => {
    const refused = vi.fn();
    const watch = new ResizeWatch(refused);
    watch.requested({ w: 2560, h: 1400 }, { w: 3840, h: 1890 });
    vi.advanceTimersByTime(1500);
    watch.resized();
    vi.advanceTimersByTime(RESIZE_GRACE_MS * 2);
    expect(refused).not.toHaveBeenCalled();
  });

  it("does not wait for a change that was not needed", () => {
    const refused = vi.fn();
    const watch = new ResizeWatch(refused);
    // RDP aligns widths down to a multiple of eight, so 1917 comes back 1912.
    watch.requested({ w: 1917, h: 1080 }, { w: 1912, h: 1080 });
    watch.requested({ w: 1920, h: 1080 }, null);
    vi.advanceTimersByTime(RESIZE_GRACE_MS * 2);
    expect(refused).not.toHaveBeenCalled();
  });

  it("reports a run of refusals once, and again after a resize has worked", () => {
    const refused = vi.fn();
    const watch = new ResizeWatch(refused);
    for (let i = 0; i < 3; i++) {
      watch.requested({ w: 2000 + i * 100, h: 1200 }, { w: 3840, h: 1890 });
      vi.advanceTimersByTime(RESIZE_GRACE_MS);
    }
    expect(refused).toHaveBeenCalledTimes(1);
    watch.resized();
    watch.requested({ w: 1600, h: 900 }, { w: 2000, h: 1200 });
    vi.advanceTimersByTime(RESIZE_GRACE_MS);
    expect(refused).toHaveBeenCalledTimes(2);
  });

  it("restarts the wait on every new request, so a drag is judged by where it ends", () => {
    const refused = vi.fn();
    const watch = new ResizeWatch(refused);
    watch.requested({ w: 2000, h: 1200 }, { w: 3840, h: 1890 });
    vi.advanceTimersByTime(RESIZE_GRACE_MS - 100);
    watch.requested({ w: 2100, h: 1200 }, { w: 3840, h: 1890 });
    vi.advanceTimersByTime(RESIZE_GRACE_MS - 100);
    expect(refused).not.toHaveBeenCalled();
    vi.advanceTimersByTime(100);
    expect(refused).toHaveBeenCalledTimes(1);
  });
});

describe("RDP settings for a HiDPI screen", () => {
  it("follows the window and the screen's scale on a new host", () => {
    const blank = blankRdpSettings();
    expect(blank.resolution).toEqual({ mode: "follow-window" });
    expect(blank.matchLocalScale).toBe(true);
    // Still nothing to store for an untouched host.
    expect(serializeRdpSettings(blank)).toBeNull();
  });

  it("matches the screen's scale on a host saved before the switch existed", () => {
    const old = parseRdpSettings(
      '{"v":1,"domain":"CORP","resolution":{"mode":"window-at-connect"},"desktopScaleFactor":100}',
    );
    expect(old?.matchLocalScale).toBe(true);
    // A resolution somebody stored is theirs, and is kept.
    expect(old?.resolution).toEqual({ mode: "window-at-connect" });
  });

  it("keeps a host that was set not to match", () => {
    const off = parseRdpSettings('{"v":1,"matchLocalScale":false,"desktopScaleFactor":125}');
    expect(off?.matchLocalScale).toBe(false);
    expect(off?.desktopScaleFactor).toBe(125);
    expect(JSON.parse(serializeRdpSettings(off) ?? "{}").matchLocalScale).toBe(false);
  });

  it("reads a host with no resolution stored as following the window", () => {
    expect(parseRdpSettings('{"v":1,"domain":"CORP"}')?.resolution).toEqual({
      mode: "follow-window",
    });
    // The setting it replaced said "not dynamic", and that is still honoured.
    expect(parseRdpSettings('{"v":1,"dynamicResolution":false}')?.resolution).toEqual({
      mode: "window-at-connect",
    });
  });
});
