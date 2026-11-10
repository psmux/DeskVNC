/**
 * The add or edit computer wizard as a plain reducer, so every rule about
 * what may happen next is testable without a screen.
 *
 * Steps: how (pick a way to connect), where (address, or code for Boundary),
 * look (name, artwork, colour), signin (optional), done.
 */
import type { FoundComputer, Host, HostDraft, HostOs, Protocol } from "../api/contract";
import { defaultPort, looksLikeLink, parsePhoneTarget } from "./address";
import { isCompleteCode, isInvitation, codeDigits } from "./code";

export type WizardStep = "how" | "where" | "look" | "signin" | "done";
export const STEPS: WizardStep[] = ["how", "where", "look", "signin"];

export interface WizardState {
  mode: "add" | "edit";
  step: WizardStep;
  id?: string;
  protocol: Protocol | null;
  address: string;
  port: number;
  portTouched: boolean;
  domain: string;
  /** Boundary: a 12 digit code, a `boundary1:` invitation or a 64 character computer ID. */
  boundaryText: string;
  name: string;
  nameTouched: boolean;
  os: HostOs;
  osTouched: boolean;
  color: string;
  colorTouched: boolean;
  username: string;
  password: string;
  remember: boolean;
  favorite: boolean;
  error: string | null;
}

export type WizardAction =
  | { type: "pick-protocol"; protocol: Protocol }
  | { type: "address"; text: string }
  | { type: "port"; port: number }
  | { type: "domain"; text: string }
  | { type: "boundary"; text: string }
  | { type: "found"; item: FoundComputer }
  | { type: "name"; text: string }
  | { type: "os"; os: HostOs }
  | { type: "color"; color: string }
  | { type: "username"; text: string }
  | { type: "password"; text: string }
  | { type: "remember"; on: boolean }
  | { type: "next" }
  | { type: "back" }
  | { type: "saved"; id: string };

const PROTOCOL_COLOR: Record<Protocol, string> = { rdp: "blue", vnc: "teal", boundary: "orange" };
const PROTOCOL_OS: Record<Protocol, HostOs> = { rdp: "windows", vnc: "unknown", boundary: "unknown" };

export function newWizard(protocol: Protocol | null = null): WizardState {
  const base: WizardState = {
    mode: "add",
    step: "how",
    protocol: null,
    address: "",
    port: 5900,
    portTouched: false,
    domain: "",
    boundaryText: "",
    name: "",
    nameTouched: false,
    os: "unknown",
    osTouched: false,
    color: "blue",
    colorTouched: false,
    username: "",
    password: "",
    remember: true,
    favorite: false,
    error: null,
  };
  return protocol ? withProtocol(base, protocol, true) : base;
}

/** Start from a computer the scan found: protocol, address and artwork already known. */
export function wizardFromFound(item: FoundComputer): WizardState {
  const s = withProtocol(newWizard(), item.protocol, true);
  return reduceWizard(s, { type: "found", item });
}

/** Edit an existing computer, starting on the address step. */
export function wizardFromHost(host: Host): WizardState {
  return {
    ...newWizard(),
    mode: "edit",
    step: "where",
    id: host.id,
    protocol: host.protocol,
    address: host.address,
    port: host.port,
    portTouched: true,
    domain: host.domain ?? "",
    boundaryText: host.boundaryInvitation ?? host.address,
    name: host.name,
    nameTouched: true,
    os: host.os,
    osTouched: true,
    color: host.color,
    colorTouched: true,
    username: host.username ?? "",
    remember: host.hasPassword,
    favorite: host.favorite,
  };
}

function withProtocol(s: WizardState, protocol: Protocol, advance: boolean): WizardState {
  return {
    ...s,
    protocol,
    port: s.portTouched && s.protocol === protocol ? s.port : defaultPort(protocol),
    portTouched: s.protocol === protocol ? s.portTouched : false,
    os: s.osTouched ? s.os : PROTOCOL_OS[protocol],
    color: s.colorTouched ? s.color : PROTOCOL_COLOR[protocol],
    step: advance && s.step === "how" ? "where" : s.step,
    error: null,
  };
}

/** A friendly name from an address: `studio-pc.local` becomes `Studio pc`. */
export function suggestName(address: string): string {
  const bare = address.replace(/^[0-9a-f]{64}@/i, "");
  if (/^[\d.]+$/.test(bare) || bare.includes(":")) return "";
  const first = bare.split(".")[0].replace(/[-_]+/g, " ").trim();
  if (!first) return "";
  return first.charAt(0).toUpperCase() + first.slice(1);
}

export function reduceWizard(s: WizardState, a: WizardAction): WizardState {
  switch (a.type) {
    case "pick-protocol":
      return withProtocol(s, a.protocol, true);
    case "address": {
      let next: WizardState = { ...s, address: a.text, error: null };
      // A pasted link fills everything it carries: protocol, port, user name.
      // Only a link with a scheme is rewritten in place; `box:3389` stays as
      // typed so the field never jumps under someone's fingers, and its port
      // is read when the step is left.
      if (looksLikeLink(a.text) && a.text.includes("://")) {
        const parsed = parsePhoneTarget(a.text, s.protocol ?? undefined);
        if (parsed.ok) {
          const t = parsed.target;
          if (t.protocol === "boundary") {
            next = { ...withProtocol(next, "boundary", true), boundaryText: t.address, address: "" };
            return next;
          }
          if (t.protocol && t.protocol !== s.protocol) next = withProtocol(next, t.protocol, true);
          next = {
            ...next,
            address: t.address,
            port: t.explicitPort ? t.port : next.port,
            portTouched: t.explicitPort || next.portTouched,
            username: t.username ?? next.username,
          };
        }
      }
      if (!next.nameTouched) next.name = suggestName(next.address);
      return next;
    }
    case "port":
      return { ...s, port: a.port, portTouched: true, error: null };
    case "domain":
      return { ...s, domain: a.text };
    case "boundary": {
      const text = a.text.trim();
      // A twelve digit code is kept as its digits; anything else verbatim.
      const digits = codeDigits(text);
      const stored = /^[\d\s-]+$/.test(text) && digits.length > 0 ? digits : a.text;
      return { ...s, boundaryText: stored, error: null };
    }
    case "found": {
      const p = a.item.protocol;
      let next = s.protocol === p ? s : withProtocol(s, p, false);
      next = {
        ...next,
        address: a.item.address,
        port: a.item.port,
        portTouched: a.item.port !== defaultPort(p),
        error: null,
      };
      if (!next.nameTouched) next.name = a.item.name ?? suggestName(a.item.address);
      if (!next.osTouched && a.item.os !== "unknown") next.os = a.item.os;
      if (next.step === "how") next.step = "where";
      return next;
    }
    case "name":
      return { ...s, name: a.text, nameTouched: true, error: null };
    case "os":
      return { ...s, os: a.os, osTouched: true };
    case "color":
      return { ...s, color: a.color, colorTouched: true };
    case "username":
      return { ...s, username: a.text };
    case "password":
      return { ...s, password: a.text };
    case "remember":
      return { ...s, remember: a.on };
    case "next": {
      const check = canContinue(s);
      if (!check.ok) return { ...s, error: check.error };
      const i = STEPS.indexOf(s.step);
      if (s.step === "where" && s.protocol !== "boundary") s = settleAddress(s);
      if (s.step === "where" && !s.name.trim()) {
        const fallback = s.protocol === "boundary" ? "Their computer" : suggestName(s.address) || s.address;
        return { ...s, step: "look", name: s.nameTouched ? s.name : fallback, error: null };
      }
      return { ...s, step: i >= 0 && i < STEPS.length - 1 ? STEPS[i + 1] : s.step, error: null };
    }
    case "back": {
      const i = STEPS.indexOf(s.step);
      if (s.mode === "edit" && s.step === "where") return s;
      return { ...s, step: i > 0 ? STEPS[i - 1] : s.step, error: null };
    }
    case "saved":
      return { ...s, id: a.id, step: "done", error: null };
  }
}

/** Split a typed `host:port` into its parts, presetting Remote Desktop for 3389. */
function settleAddress(s: WizardState): WizardState {
  const parsed = parsePhoneTarget(s.address, s.protocol ?? undefined);
  if (!parsed.ok) return s;
  const t = parsed.target;
  let next: WizardState = { ...s, address: t.address, username: s.username || t.username || "" };
  if (t.explicitPort) next = { ...next, port: t.port, portTouched: true };
  if (!next.nameTouched && !next.name) next.name = suggestName(t.address);
  return next;
}

/** Whether the current step is complete, with a plain reason when it is not. */
export function canContinue(s: WizardState): { ok: true } | { ok: false; error: string } {
  switch (s.step) {
    case "how":
      return s.protocol ? { ok: true } : { ok: false, error: "Pick one of the three ways first" };
    case "where": {
      if (s.protocol === "boundary") {
        const t = s.boundaryText.trim();
        if (isCompleteCode(t) || isInvitation(t) || /^[0-9a-fA-F]{64}$/.test(t)) return { ok: true };
        if (t === "") return { ok: false, error: "Type their code, or paste the invitation they sent" };
        return { ok: false, error: "That does not look like a code. A code has 12 numbers." };
      }
      if (s.address.trim() === "") return { ok: false, error: "Type the computer's address, or tap one found nearby" };
      const parsed = parsePhoneTarget(s.address, s.protocol ?? undefined);
      if (!parsed.ok) return parsed;
      if (!Number.isInteger(s.port) || s.port < 1 || s.port > 65535) {
        return { ok: false, error: "The port number must be between 1 and 65535" };
      }
      return { ok: true };
    }
    case "look":
      return s.name.trim() ? { ok: true } : { ok: false, error: "Give it a name you will recognise" };
    case "signin":
    case "done":
      return { ok: true };
  }
}

/** What the Boundary field holds, so the screen knows whether to look a code up first. */
export function boundaryKind(text: string): "code" | "invitation" | "machine" | "none" {
  const t = text.trim();
  if (isInvitation(t)) return "invitation";
  if (/^[0-9a-fA-F]{64}$/.test(t)) return "machine";
  if (isCompleteCode(t)) return "code";
  return "none";
}

/**
 * The draft to save. For Boundary, a computer ID goes in `address` (the way
 * the desktop app stores it) and an invitation in `boundaryInvitation`. A
 * code must be looked up into an invitation before this is called; pass the
 * result as `resolvedInvitation`.
 */
export function toDraft(s: WizardState, resolvedInvitation?: string): HostDraft {
  const protocol = s.protocol ?? "vnc";
  let address = s.address.trim();
  let port = s.port;
  let boundaryInvitation: string | null = null;
  if (protocol === "boundary") {
    const kind = boundaryKind(s.boundaryText);
    address = kind === "machine" ? s.boundaryText.trim().toLowerCase() : "";
    boundaryInvitation = kind === "invitation" ? s.boundaryText.trim() : resolvedInvitation ?? null;
    port = 0;
  } else {
    const parsed = parsePhoneTarget(address, protocol);
    if (parsed.ok) {
      address = parsed.target.address;
      if (parsed.target.explicitPort && !s.portTouched) port = parsed.target.port;
    }
  }
  return {
    ...(s.id ? { id: s.id } : {}),
    name: s.name.trim(),
    protocol,
    address,
    port,
    username: s.username.trim() || null,
    os: s.os,
    color: s.color,
    favorite: s.favorite,
    domain: protocol === "rdp" ? s.domain.trim() || null : null,
    boundaryInvitation,
  };
}
