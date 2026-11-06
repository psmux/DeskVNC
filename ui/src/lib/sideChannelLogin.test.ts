import { describe, expect, it } from "vitest";
import { blankSshTunnel, parseSshTunnel, sideChannelLogin } from "./types";

describe("sideChannelLogin", () => {
  it("signs in as the tunnel's user on the tunnel's port when the tunnel ends at this computer", () => {
    // The blob the host editor writes for a VNC host with "Tunnel over SSH"
    // ticked, a user typed in and the gateway left blank.
    const tunnel = parseSshTunnel(
      '{"enabled":true,"host":"","port":2222,"user":"dvtest","auth":"stored","keyPath":null}',
    );
    expect(sideChannelLogin("10.0.0.4", tunnel)).toEqual({
      host: "10.0.0.4",
      port: 2222,
      username: "dvtest",
      auth: "stored",
      keyPath: null,
    });
  });

  it("treats a gateway spelled as the session's own address as this computer", () => {
    const tunnel = { ...blankSshTunnel(), enabled: true, host: "Box.Example ", user: "ops" };
    expect(sideChannelLogin("box.example", tunnel).username).toBe("ops");
  });

  it("passes a key file through only for key-file auth", () => {
    const keyed = { ...blankSshTunnel(), user: "ops", auth: "key-file" as const, keyPath: "C:/k" };
    expect(sideChannelLogin("10.0.0.4", keyed)).toMatchObject({ auth: "key-file", keyPath: "C:/k" });
    const agent = { ...keyed, auth: "agent" as const };
    expect(sideChannelLogin("10.0.0.4", agent)).toMatchObject({ auth: "agent", keyPath: null });
  });

  it("does not borrow a login meant for a different gateway", () => {
    const tunnel = { ...blankSshTunnel(), enabled: true, host: "jump.example", user: "ops" };
    expect(sideChannelLogin("10.0.0.4", tunnel)).toEqual({
      host: "10.0.0.4",
      port: 22,
      username: "",
      auth: "stored",
      keyPath: null,
    });
  });

  it("keeps the old default when the profile has no SSH settings at all", () => {
    expect(sideChannelLogin("10.0.0.4", null)).toEqual({
      host: "10.0.0.4",
      port: 22,
      username: "",
      auth: "stored",
      keyPath: null,
    });
  });
});
