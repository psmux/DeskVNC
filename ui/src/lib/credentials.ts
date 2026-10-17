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

/**
 * What the person put into the last credential prompt in this window, minus
 * the password. Held by `useSession` so the next prompt can start from it.
 */
export interface PromptAnswer {
  username: string | null;
  domain: string | null;
  save: boolean;
}

export interface PromptStart {
  username: string;
  domain: string;
  save: boolean;
}

/**
 * What a credential prompt opens with.
 *
 * The prompt is unmounted the moment it is answered, so every later prompt
 * (a rejected password asked again, or the first prompt of a Reconnect after
 * the connection failed) used to open from nothing: the domain blank and
 * "Remember" unticked. Somebody who ticked it, mistyped once and then typed
 * the right password got nothing saved, because the second answer went out
 * as "do not remember" and revoked the first (issue #9).
 *
 * The user name the person typed last wins over the hint, which is only the
 * stored or local account name. "Remember" stays an opt in: it starts ticked
 * when this person ticked it in this window, or when they already saved a
 * password for this host. The saved one was refused or is missing, and the
 * right one typed here should replace it rather than be forgotten after this
 * connection, which is what "I have to fill in passwords again" was
 * (issue #9). The password is never carried, and there is nowhere here to
 * carry it.
 */
export function promptStart(
  usernameHint: string | null | undefined,
  previous: PromptAnswer | null | undefined,
  savedBefore = false,
): PromptStart {
  const typed = previous?.username?.trim() ? previous.username : null;
  return {
    username: typed ?? usernameHint ?? "",
    domain: previous?.domain ?? "",
    save: previous?.save ?? savedBefore,
  };
}
