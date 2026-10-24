/**
 * Get help: this computer shared over Boundary, from inside DeskVNC.
 *
 * Rust owns everything (`src-tauri/src/commands/support.rs`). It sends the
 * whole picture as one `SupportView` on `support://state` whenever anything
 * changes, and every action is a command. The window keeps nothing of its own
 * apart from the code service URL, which is remembered here and handed to
 * Rust when the main window starts.
 */
import { useEffect, useState } from "react";
import { mustInvoke, safeInvoke, safeListen } from "./tauri";

export type NetworkProfile =
  | { mode: "Automatic" }
  | { mode: "Private"; address: string }
  | { mode: "Relay"; url: string };

export interface PairedHelper {
  id: string;
  name: string;
  control: boolean;
  tools: boolean;
  added: number;
}

export interface SupportView {
  displays: { id: number; name: string }[];
  display: number | null;
  screenPermission: boolean;
  inputPermission: boolean;
  status: string;
  error: boolean;
  sharing: boolean;
  connected: boolean;
  invitation: string | null;
  code: string | null;
  codeBusy: boolean;
  codesAvailable: boolean;
  codeMessage: string;
  codeService: string;
  pending: { name: string; peer: string; tools: boolean } | null;
  helper: { name: string; peer: string; paired: boolean } | null;
  control: boolean;
  toolsOffered: boolean;
  tools: boolean;
  activity: string[];
  route: string | null;
  warning: string | null;
  network: NetworkProfile;
  networkLabel: string;
  networkError: string | null;
  unattended: {
    enabled: boolean;
    reachable: boolean;
    machineId: string;
    /** What a helper on a network that routes here can type instead of the ID. */
    addresses: string[];
    autostart: boolean;
    helpers: PairedHelper[];
    hasPassword: boolean;
    minPassword: number;
    message: string;
    error: boolean;
    /** Every helper connected unattended right now. */
    active: { id: number; name: string; control: boolean; tools: boolean; activity: string[] }[];
    /** A helper that is not paired asking to come in by this computer's ID. */
    ask: { name: string; peer: string; tools: boolean } | null;
  };
}

export const SUPPORT_EVENT = "support://state";
const CODE_SERVICE_KEY = "deskvnc.support.codeService";

/** The latest view, or null until Rust has answered. */
export function useSupport(): SupportView | null {
  const [view, setView] = useState<SupportView | null>(null);
  useEffect(() => {
    let alive = true;
    let unlisten: (() => void) | undefined;
    void safeListen<SupportView>(SUPPORT_EVENT, (next) => {
      if (alive) setView(next);
    }).then((fn) => {
      if (alive) unlisten = fn;
      else fn();
    });
    void safeInvoke<SupportView | null>("support_state", undefined, null).then((first) => {
      if (alive && first) setView((current) => current ?? first);
    });
    return () => {
      alive = false;
      unlisten?.();
    };
  }, []);
  return view;
}

export function rememberedCodeService(): string {
  try {
    return localStorage.getItem(CODE_SERVICE_KEY) ?? "";
  } catch {
    return "";
  }
}

export async function setCodeService(url: string): Promise<void> {
  await mustInvoke("support_set_code_service", { url });
  try {
    localStorage.setItem(CODE_SERVICE_KEY, url.trim());
  } catch {
    // Blocked storage: the setting lasts until DeskVNC quits.
  }
}

/** An ID shortened for display; Copy gives the whole one. */
export function shortId(id: string): string {
  return id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-8)}` : id;
}

export const support = {
  share: () => mustInvoke("support_share"),
  stop: () => mustInvoke("support_stop"),
  fullInvitation: () => mustInvoke("support_full_invitation"),
  refreshDisplays: () => mustInvoke("support_refresh_displays"),
  setDisplay: (id: number) => mustInvoke("support_set_display", { id }),
  answer: (decision: "control" | "view" | "deny", allowTools: boolean) =>
    mustInvoke("support_answer", { decision, allowTools }),
  answerAsk: (decision: "control" | "view" | "deny", allowTools: boolean, pair: boolean) =>
    mustInvoke("support_answer_ask", { decision, allowTools, pair }),
  setControl: (allowed: boolean) => mustInvoke("support_set_control", { allowed }),
  setTools: (allowed: boolean) => mustInvoke("support_set_tools", { allowed }),
  pair: () => mustInvoke("support_pair"),
  setUnattended: (enabled: boolean) => mustInvoke("support_set_unattended", { enabled }),
  /** Windows only: whether the firewall lets helpers in by address. Null elsewhere. */
  directAllowed: () => mustInvoke<boolean | null>("support_direct_allowed"),
  /** Windows only: one administrator prompt to let helpers in by address. */
  allowDirect: () => mustInvoke("support_allow_direct"),
  setHelper: (id: string, control: boolean, tools: boolean) =>
    mustInvoke("support_set_helper", { id, control, tools }),
  removeHelper: (id: string) => mustInvoke("support_remove_helper", { id }),
  setPassword: (password: string | null) => mustInvoke("support_set_password", { password }),
  setAutostart: (enabled: boolean) => mustInvoke("support_set_autostart", { enabled }),
  endUnattended: (id: number) => mustInvoke("support_end_unattended", { id }),
  stopUnattendedTools: (id: number) => mustInvoke("support_stop_unattended_tools", { id }),
  requestScreenPermission: () => mustInvoke("support_request_screen_permission"),
  openInputSettings: () => mustInvoke("support_open_input_settings"),
  saveNetwork: (profile: NetworkProfile) => mustInvoke("support_save_network", { profile }),
};
