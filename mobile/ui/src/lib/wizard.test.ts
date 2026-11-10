import { describe, expect, it } from "vitest";
import type { Host } from "../api/contract";
import {
  boundaryKind,
  canContinue,
  newWizard,
  reduceWizard,
  suggestName,
  toDraft,
  wizardFromFound,
  wizardFromHost,
  type WizardAction,
  type WizardState,
} from "./wizard";

function run(state: WizardState, ...actions: WizardAction[]): WizardState {
  return actions.reduce(reduceWizard, state);
}

describe("the add computer wizard", () => {
  it("cannot leave the first step without a choice", () => {
    const s = run(newWizard(), { type: "next" });
    expect(s.step).toBe("how");
    expect(s.error).toMatch(/Pick/);
  });

  it("moves on as soon as a way is picked, with sensible defaults", () => {
    const s = run(newWizard(), { type: "pick-protocol", protocol: "rdp" });
    expect(s).toMatchObject({ step: "where", protocol: "rdp", port: 3389, os: "windows", color: "blue" });
  });

  it("walks the whole way for a Remote Desktop computer", () => {
    const s = run(
      newWizard(),
      { type: "pick-protocol", protocol: "rdp" },
      { type: "address", text: "studio-pc.example.com" },
      { type: "next" },
      { type: "next" },
      { type: "username", text: "alice" },
      { type: "password", text: "secret" },
    );
    expect(s.step).toBe("signin");
    expect(s.name).toBe("Studio pc");
    const draft = toDraft(s);
    expect(draft).toMatchObject({
      name: "Studio pc",
      protocol: "rdp",
      address: "studio-pc.example.com",
      port: 3389,
      username: "alice",
      os: "windows",
    });
    expect(draft).not.toHaveProperty("password");
  });

  it("refuses an empty address with a plain reason", () => {
    const s = run(newWizard("vnc"), { type: "next" });
    expect(s.step).toBe("where");
    expect(s.error).toMatch(/address/);
  });

  it("fills everything from a pasted rdp link and switches protocol", () => {
    const s = run(newWizard("vnc"), { type: "address", text: "rdp://bob@192.0.2.30:3390" });
    expect(s).toMatchObject({ protocol: "rdp", address: "192.0.2.30", port: 3390, username: "bob", color: "blue" });
  });

  it("keeps a typed host:port as typed and splits it when the step is left", () => {
    let s = run(newWizard("vnc"), { type: "address", text: "10.0.0.5:5901" });
    expect(s.address).toBe("10.0.0.5:5901");
    s = run(s, { type: "next" });
    expect(s).toMatchObject({ step: "look", address: "10.0.0.5", port: 5901 });
  });

  it("starts from a computer found nearby", () => {
    const s = wizardFromFound({ address: "10.0.0.12", port: 5900, protocol: "vnc", name: "Kitchen Pi", os: "raspberry" });
    expect(s).toMatchObject({ step: "where", protocol: "vnc", name: "Kitchen Pi", os: "raspberry" });
    expect(canContinue(s).ok).toBe(true);
  });

  it("does not overwrite a name the person typed", () => {
    const s = run(newWizard("vnc"), { type: "name", text: "Den" }, { type: "address", text: "office.local" });
    expect(s.name).toBe("Den");
  });

  it("needs a name on the look step", () => {
    const s = run(newWizard("vnc"), { type: "address", text: "10.0.0.5" }, { type: "next" }, { type: "name", text: " " }, { type: "next" });
    expect(s.step).toBe("look");
    expect(s.error).toMatch(/name/);
  });

  it("goes back a step and stops at the first", () => {
    const s = run(newWizard("vnc"), { type: "back" }, { type: "back" });
    expect(s.step).toBe("how");
  });

  it("accepts a Boundary code, invitation or computer ID", () => {
    const base = newWizard("boundary");
    expect(canContinue(run(base, { type: "boundary", text: "1234 5678 9012" })).ok).toBe(true);
    expect(canContinue(run(base, { type: "boundary", text: "boundary1:abc" })).ok).toBe(true);
    expect(canContinue(run(base, { type: "boundary", text: "a".repeat(64) })).ok).toBe(true);
    expect(canContinue(run(base, { type: "boundary", text: "1234" })).ok).toBe(false);
    expect(boundaryKind("1234-5678-9012")).toBe("code");
  });

  it("saves a Boundary invitation and no address", () => {
    const s = run(newWizard("boundary"), { type: "boundary", text: "boundary1:abc" }, { type: "next" });
    expect(toDraft(s)).toMatchObject({ protocol: "boundary", address: "", port: 0, boundaryInvitation: "boundary1:abc" });
    const code = run(newWizard("boundary"), { type: "boundary", text: "1234 5678 9012" });
    expect(toDraft(code, "boundary1:resolved").boundaryInvitation).toBe("boundary1:resolved");
  });

  it("edits a saved computer from the address step and cannot go back past it", () => {
    const host: Host = {
      id: "h1",
      name: "Office Mac",
      protocol: "vnc",
      address: "10.0.0.20",
      port: 5900,
      username: null,
      hasPassword: true,
      os: "mac",
      color: "rose",
      favorite: true,
      lastConnectedAt: null,
      hasThumbnail: false,
    };
    const s = run(wizardFromHost(host), { type: "back" });
    expect(s).toMatchObject({ mode: "edit", step: "where", color: "rose", favorite: true });
    expect(toDraft(s)).toMatchObject({ id: "h1", name: "Office Mac", color: "rose" });
  });
});

describe("suggestName", () => {
  it("makes a readable name from a host name and none from an IP", () => {
    expect(suggestName("mums-laptop.local")).toBe("Mums laptop");
    expect(suggestName("192.0.2.4")).toBe("");
  });
});
