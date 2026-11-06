/**
 * Turning an imported `.rdp` file into a host the person can review and save.
 *
 * The shell reads the file (`import_rdp_file`) and hands back a whole draft
 * profile. This puts it in the editor's shape: the file's own settings rather
 * than the Preferences defaults a new host starts with, the account name in
 * the credential fields, and what could not come across as notes above the
 * form. Nothing is saved until the person presses Save, and there is never a
 * password to fill in: the shell does not read that line of the file.
 */
import { draftFromHost, type HostDraft } from "../components/HostDialog";
import { parseRdpSettings } from "./rdp";
import type { RdpImport } from "./tauri";

/**
 * Split `DOMAIN\user` when the domain part is the file's own domain, or the
 * file has none. Anything else (a UPN, or a name with spaces and switches in
 * it, as some brokers write) is kept whole: guessing at it would sign in as
 * someone else.
 */
export function splitRdpUser(
  username: string | null,
  domain: string | null,
): { user: string; domain: string } {
  const name = (username ?? "").trim();
  const fileDomain = (domain ?? "").trim();
  const slash = name.indexOf("\\");
  if (slash > 0 && !/\s/.test(name)) {
    const prefix = name.slice(0, slash);
    const rest = name.slice(slash + 1);
    if (rest && (!fileDomain || prefix.toLowerCase() === fileDomain.toLowerCase())) {
      return { user: rest, domain: fileDomain || prefix };
    }
  }
  return { user: name, domain: fileDomain };
}

/** The editor's draft for an imported file. A new host: it has no id yet. */
export function draftFromRdpImport(imported: RdpImport): HostDraft {
  const p = imported.profile;
  const base = draftFromHost(null, {
    protocol: "rdp",
    friendlyName: p.friendlyName,
    address: p.address,
    port: p.port,
    importNotes: imported.warnings.length > 0 ? imported.warnings : undefined,
  });
  const rdp = parseRdpSettings(p.rdpSettings) ?? base.rdp;
  const { user, domain } = splitRdpUser(imported.username, rdp?.domain ?? null);
  return {
    ...base,
    qualityPref: p.qualityPref,
    scalingMode: p.scalingMode,
    rdp,
    rdpUser: user,
    rdpDomain: domain,
    // The port came from the file, so switching protocol must not move it.
    portTouched: p.port !== 3389,
  };
}
