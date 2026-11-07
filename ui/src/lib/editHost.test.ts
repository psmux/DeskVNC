import { describe, expect, it } from "vitest";
import { agentOpenOptions } from "./editHost";

describe("agentOpenOptions", () => {
  it("opens a saved machine by its id even when this window has not loaded it yet", () => {
    // The library's host list is read when the window loads. A machine saved
    // after that used to be opened by address, which the shell never matched
    // to the profile id it was waiting for, so it dialled the machine twice.
    expect(
      agentOpenOptions({
        hostId: "11111111-0000-4000-8000-000000000001",
        address: "192.0.2.10",
        port: 5900,
        protocol: "vnc",
        background: true,
      }),
    ).toEqual({ profileId: "11111111-0000-4000-8000-000000000001", background: true });
  });

  it("opens an unsaved machine by its endpoint", () => {
    expect(
      agentOpenOptions({ address: "192.0.2.11", port: 22, protocol: "ssh" }),
    ).toEqual({ address: "192.0.2.11", port: 22, protocol: "ssh", background: false });
  });
});
