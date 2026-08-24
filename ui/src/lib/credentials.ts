/**
 * Splitting a typed Windows logon name.
 *
 * Its own module, and a plain `.ts` one, so the rule can be tested without
 * rendering a dialog: the vitest `include` pattern is `.test.ts`, so a rule
 * that lives inside a `.tsx` component is a rule nothing can check.
 */

export interface DomainUser {
  domain: string | null;
  user: string;
}

/**
 * Split a typed logon name.
 *
 *   `CORP\alice`     -> { domain: "CORP", user: "alice" }
 *   `alice`          -> { domain: null,   user: "alice" }
 *   `alice@corp.com` -> { domain: null,   user: "alice@corp.com" }
 *
 * The UPN case is the one that matters. An RDP server accepts a UPN as the
 * user name with an empty domain; splitting it at the `@` and sending
 * `corp.com\alice` fails against Entra ID and against any forest whose
 * NetBIOS name is not the DNS label. So `@` is never a separator here.
 *
 * A backslash is, and the LAST one wins: a name may legitimately contain
 * one and the domain prefix is always leftmost. A leading backslash with
 * nothing before it is not a domain, it is a typo, so it yields no domain
 * rather than an empty one.
 */
export function splitDomainUser(raw: string): DomainUser {
  const at = raw.lastIndexOf("\\");
  if (at < 0) return { domain: null, user: raw };
  const domain = raw.slice(0, at);
  const user = raw.slice(at + 1);
  return { domain: domain === "" ? null : domain, user };
}

/**
 * Put the two back together the way the wire wants them.
 *
 * Left alone when the name already carries a domain, and when it is a UPN,
 * for the reason above.
 */
export function joinDomainUser(domain: string | null, user: string): string {
  const d = domain?.trim() ?? "";
  if (!d || !user || user.includes("\\") || user.includes("@")) return user;
  return `${d}\\${user}`;
}
