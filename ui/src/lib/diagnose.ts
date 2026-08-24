/**
 * Turning a terminal disconnect reason into a sentence a person can act on.
 *
 * These two functions were module-private in `screens/Session.tsx`. They are
 * pure string-to-string with no React in them; they were in a component file
 * by history rather than by design, and the vitest `include` pattern does not
 * collect `.tsx`, so nothing could test the branch ordering that all of this
 * depends on.
 *
 * The shape is a chain of substring tests over a lowercased reason, ordered
 * so a more specific reading wins over a more general one. The input is
 * coerced before `toLowerCase` for a real reason: a payload arriving without
 * a reason once threw during render and unmounted the tree.
 *
 * Where a reason carries a stable lowercase symbol the workspace owns
 * (`nla-refused`, `legacy-tls-required`), the test matches that symbol rather
 * than prose somebody may reword. Where the driver currently sends only its
 * English sentence, a distinctive fragment of that sentence is matched too,
 * so the copy works today and keeps working once the symbol is carried.
 */

/**
 * Would offering "reconnect" here re-prompt for a credential?
 *
 * It decides whether the reconnect affordance offers to ask again. Getting
 * this wrong is expensive in one specific direction: re-prompting after a
 * refusal nothing the user types can fix walks them through typing a
 * password three times into an Active Directory lockout counter.
 */
export function isAuthFailure(reason: string): boolean {
  const r = reason.toLowerCase();
  // Neither of these can be fixed by typing a different password, and both
  // contain words the generic tests below would otherwise catch: the policy
  // refusal mentions authentication, and both legacy TLS symbols contain
  // "tls". Checked first, and explicitly, because the alternative is that a
  // future symbol containing the word "auth" silently changes what the
  // button does and no test fails.
  if (
    r.includes("ntlm-refused-by-policy") ||
    r.includes("legacy-tls-required") ||
    r.includes("legacy-tls-unavailable") ||
    r.includes("nla-refused") ||
    r.includes("would not accept network level authentication")
  ) {
    return false;
  }
  if (r.includes("cancel")) return true;
  return r.includes("auth") || r.includes("password") || r.includes("credential");
}

export function diagnose(reason: unknown): string {
  const text = typeof reason === "string" ? reason : "";
  const r = text.toLowerCase();
  // Ordered: "cancelled" must win over the generic auth match below, or
  // dismissing the password prompt would be reported as a failed login.
  if (r.includes("cancel")) return "Authentication was cancelled. Reconnect to try again.";

  // Ordered above the generic password match for the same reason "cancel"
  // is: a message that mentions authentication and a domain policy must not
  // be reported as a wrong password. The two deserve opposite advice, and
  // the wrong one wastes an afternoon.
  if (r.includes("ntlm-refused-by-policy")) {
    return (
      "This computer's domain does not accept the sign-in method this version " +
      "uses. An administrator has set “Restrict NTLM: Incoming NTLM " +
      "traffic” or raised “LAN Manager authentication level” on " +
      "the remote computer, so it will only accept Kerberos. Kerberos sign-in " +
      "is coming in a later release. Until then this computer can be reached " +
      "from a client that speaks Kerberos, or an administrator can allow NTLM " +
      "for it."
    );
  }
  if (
    r.includes("nla-refused") ||
    r.includes("would not accept network level authentication")
  ) {
    return (
      "The computer refused network level authentication. If it is an older " +
      "or non-Windows server, turn on “Allow connecting without network " +
      "level authentication” in this computer's settings."
    );
  }

  // Ordered ABOVE the certificate/TLS arm below, which would otherwise
  // swallow both of these: the symbols contain the substring "tls".
  if (r.includes("legacy-tls-required")) {
    return (
      "This computer only offers TLS 1.0 or 1.1 to encrypt the connection, " +
      "and this app does not use those versions unless you say so. That is " +
      "normal for a Windows 7 or Server 2008 R2 machine that was never " +
      "updated. To connect anyway, edit this computer, open Advanced, then " +
      "Security, and tick “Allow legacy TLS (1.0 and 1.1)”. Read " +
      "what it says there first: those versions are weak, and that is the " +
      "reason it is off by default."
    );
  }
  if (r.includes("legacy-tls-unavailable")) {
    return (
      "This computer only offers TLS 1.0 or 1.1, and this copy of the app was " +
      "built without support for them, so the setting you turned on cannot be " +
      "used. A build that includes legacy TLS support will connect. Nothing " +
      "you change here will help, and nothing is wrong with the computer you " +
      "are connecting to."
    );
  }

  // The diagnosis is about the port, not about which server ought to be on
  // it, so it does not name a protocol.
  if (r.includes("refused")) return "Connection refused, nothing is listening on that port.";
  if (r.includes("timed out") || r.includes("timeout")) return "The computer didn't respond, it may be asleep, off, or unreachable from this network.";
  // Deliberately NOT a bare "auth" match. That caught every message merely
  // mentioning authentication, so a server offering none at all was reported
  // to the user as "incorrect password" for a server that has no password
  // (issue #1). Match only what really means "the credentials were rejected".
  if (
    r.includes("password") ||
    r.includes("authentication failed") ||
    r.includes("auth failed")
  ) {
    return "Incorrect password, the server did not accept it.";
  }
  if (r.includes("certificate") || r.includes("tls")) return "The secure connection could not be verified.";
  if (r.includes("reset")) return "The connection was closed by the other side.";
  return text || "The connection ended.";
}

/**
 * Does this failure have a fix in the host editor's Security section?
 *
 * The disconnect panel offers a button that opens the editor with Advanced
 * and Security already expanded, which is the same "open it expanded" rule
 * the editor applies to a setting that is already on.
 */
export function opensSecuritySettings(reason: string): boolean {
  const r = reason.toLowerCase();
  return (
    r.includes("legacy-tls-required") ||
    r.includes("nla-refused") ||
    r.includes("would not accept network level authentication")
  );
}
