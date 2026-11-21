import { describe, expect, it } from "vitest";
import { friendlyError, isSignInRefusal, qualityLevel, routeWords, stepOf } from "../status";
import { wireQuality } from "../useRemoteSession";

describe("status words", () => {
  it("names a Boundary route in plain words", () => {
    expect(routeWords("direct")).toBe("Direct");
    expect(routeWords("relay")).toBe("Through a relay");
  });

  it("maps session states to the four friendly steps", () => {
    expect(stepOf({ state: "connecting" })).toBe(0);
    expect(stepOf({ state: "negotiating" })).toBe(1);
    expect(stepOf({ state: "authenticating", method: "VncAuth" })).toBe(2);
    expect(stepOf({ state: "connected" })).toBe(3);
  });

  it("colours the badge from round trip time and frame rate", () => {
    expect(qualityLevel({ rtt_ms: 30, fps: 30, throughput_bps: 1 })).toBe("good");
    expect(qualityLevel({ rtt_ms: 150, fps: 30, throughput_bps: 1 })).toBe("fair");
    expect(qualityLevel({ rtt_ms: 400, fps: 30, throughput_bps: 1 })).toBe("poor");
    expect(qualityLevel({ rtt_ms: 90, fps: 2, throughput_bps: 1 })).toBe("fair");
    expect(qualityLevel({ rtt_ms: 30, fps: 0, throughput_bps: 1 })).toBe("good");
  });

  it("explains errors in plain words", () => {
    expect(friendlyError("Connection refused (os error 61)").title).toBe("We could not reach the computer");
    expect(friendlyError("Authentication failed").title).toBe("That sign in did not work");
    expect(friendlyError("weird thing").detail).toBe("weird thing");
    // A server that hangs up during RSA-AES never saw a password.
    expect(
      friendlyError(
        "The server closed the connection during the RSA-AES key exchange, before any name or password was sent.",
      ).title,
    ).toBe("The computer could not set up encryption");
    expect(
      friendlyError("The server refused the RSA-AES key exchange before any name or password was sent: no key").title,
    ).toBe("The computer could not set up encryption");
    expect(
      friendlyError("This computer's identity was not trusted, so no name or password was sent to it.").title,
    ).toBe("You did not trust this computer");
    expect(friendlyError("This computer's identity has changed.").title).toBe("The computer's identity did not check out");
  });

  it("says when the VNC server needs a setting changed, not that the password or identity failed", () => {
    // TigerVNC left with only TLSVnc (issue #56). The sentence names VncAuth
    // and encryption, which the sign in and identity rules would claim.
    const tls =
      "This computer's VNC server only offers TLSVnc or TLSNone, a kind of encryption DeskVNC cannot use. Add VncAuth, X509Vnc or RA2 to its SecurityTypes setting.";
    expect(friendlyError(tls).title).toBe("The computer's VNC server needs a setting changed");
    expect(friendlyError(tls).detail).toBe(tls);
    expect(isSignInRefusal(tls)).toBe(false);
    const method = "This server uses an authentication method DeskVNCViewer does not support.";
    expect(friendlyError(method).title).toBe("The computer's VNC server needs a setting changed");
    expect(isSignInRefusal(method)).toBe(false);
  });

  it("names the local network permission when an Android phone cannot reach a computer", () => {
    // Android 17 drops the connect until DeskVNC may use the local network,
    // so it times out (issue #56).
    const timeout = "The computer did not respond. It may be asleep or unreachable.";
    expect(friendlyError(timeout, true).title).toBe("We could not reach the computer");
    expect(friendlyError(timeout, true).detail).toContain("Nearby devices");
    expect(friendlyError(timeout, false).detail).not.toContain("Nearby devices");
  });

  it("asks for still pictures when the phone has no video decoder", () => {
    expect(wireQuality("auto", false)).toBe("quality");
    expect(wireQuality("auto", true)).toBe("auto");
    expect(wireQuality("speed", false)).toBe("speed");
  });
});

describe("step words", () => {
  it("says a Boundary session is waiting for the other person", async () => {
    const { stepWords } = await import("../status");
    expect(stepWords({ state: "authenticating", method: "approval" })).toBe("Waiting for them to say yes");
    expect(stepWords({ state: "authenticating", method: "VncAuth" })).toBe("Signing in");
  });
});
