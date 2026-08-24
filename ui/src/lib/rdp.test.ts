import { describe, expect, it } from "vitest";
import { blankRdpSettings, parseRdpSettings, serializeRdpSettings } from "./rdp";
import { diagnose, isAuthFailure, opensSecuritySettings } from "./diagnose";

describe("parseRdpSettings", () => {
  it("reads nothing as nothing", () => {
    expect(parseRdpSettings(null)).toBeNull();
    expect(parseRdpSettings("")).toBeNull();
    expect(parseRdpSettings("null")).toBeNull();
    expect(parseRdpSettings("not json")).toBeNull();
    expect(parseRdpSettings("[]")).toBeNull();
  });

  it("reads an empty object as the defaults", () => {
    expect(parseRdpSettings("{}")).toEqual(blankRdpSettings());
  });

  it("refuses to relax network level authentication on a value it does not know", () => {
    // Security relevant: an unrecognised NLA value must never read as the
    // fallback policy.
    expect(parseRdpSettings('{"nla":"nonsense"}')?.nla).toBe("required");
    expect(parseRdpSettings('{"nla":"allow-fallback"}')?.nla).toBe("allow-fallback");
  });

  it("reads legacy TLS off unless it is literally true", () => {
    expect(parseRdpSettings("{}")?.legacyTls).toBe(false);
    // "yes" is a string, JavaScript calls it truthy, and a blob written by
    // another tool must not turn a relaxation on by being sloppy.
    expect(parseRdpSettings('{"legacyTls":"yes"}')?.legacyTls).toBe(false);
    expect(parseRdpSettings('{"legacyTls":1}')?.legacyTls).toBe(false);
    expect(parseRdpSettings('{"legacyTls":true}')?.legacyTls).toBe(true);
  });

  it("never lets the uncompressed fallback be turned off", () => {
    expect(parseRdpSettings('{"codecs":{"uncompressed":false}}')?.codecs.uncompressed).toBe(true);
  });
});

describe("serializeRdpSettings", () => {
  it("writes null for an untouched object, so the column stays empty", () => {
    expect(serializeRdpSettings(null)).toBeNull();
    expect(serializeRdpSettings(blankRdpSettings())).toBeNull();
  });

  it("round trips a change", () => {
    const s = { ...blankRdpSettings(), domain: "CORP" };
    const text = serializeRdpSettings(s);
    expect(text).not.toBeNull();
    expect(parseRdpSettings(text)).toEqual(s);
  });

  it("re-emits a field this build has never heard of", () => {
    // The editor parses into a typed object and writes a fresh one, so
    // without this a UI predating a field drops it on every save. The field
    // that makes that bite is a security relaxation.
    const parsed = parseRdpSettings('{"v":1,"domain":"CORP","somethingNewer":{"a":1}}');
    const text = serializeRdpSettings(parsed);
    expect(text).toContain("somethingNewer");
    expect(JSON.parse(text as string).somethingNewer).toEqual({ a: 1 });
  });
});

describe("the disconnect copy", () => {
  it("names both Group Policy settings and says Kerberos comes later", () => {
    const text = diagnose("ntlm-refused-by-policy");
    expect(text).toContain("Restrict NTLM");
    expect(text).toContain("LAN Manager authentication level");
    expect(text).toContain("later release");
  });

  it("names the setting and where to find it for a legacy TLS failure", () => {
    const text = diagnose("legacy-tls-required");
    expect(text).toContain("Advanced");
    expect(text).toContain("Allow legacy TLS");
  });

  it("says there is no local fix when the build cannot do it", () => {
    const text = diagnose("legacy-tls-unavailable");
    expect(text).toContain("built without");
    expect(text).toContain("Nothing you change here will help");
    expect(text).not.toContain("Advanced");
  });

  it("points an NLA refusal at the per-host switch", () => {
    expect(diagnose("nla-refused")).toContain("without network level authentication");
    // The driver currently sends its English sentence rather than the token,
    // so the same branch has to catch that too.
    expect(diagnose("the server would not accept network level authentication")).toContain(
      "without network level authentication",
    );
  });

  it("does not report a policy refusal as a wrong password", () => {
    expect(diagnose("ntlm-refused-by-policy")).not.toContain("Incorrect password");
  });

  it("is still protocol neutral about a refused port", () => {
    expect(diagnose("connection refused")).toBe(
      "Connection refused, nothing is listening on that port.",
    );
  });

  it("keeps its old branches", () => {
    expect(diagnose("cancelled")).toMatch(/cancelled/);
    expect(diagnose("authentication failed")).toBe("Incorrect password, the server did not accept it.");
    expect(diagnose("tls handshake")).toBe("The secure connection could not be verified.");
    expect(diagnose(undefined)).toBe("The connection ended.");
  });
});

describe("isAuthFailure", () => {
  // Re-prompting after a refusal nothing the user types can fix walks them
  // through typing a password three times into a lockout counter.
  it("is false for every failure a password cannot fix", () => {
    expect(isAuthFailure("ntlm-refused-by-policy")).toBe(false);
    expect(isAuthFailure("legacy-tls-required")).toBe(false);
    expect(isAuthFailure("legacy-tls-unavailable")).toBe(false);
    expect(isAuthFailure("nla-refused")).toBe(false);
  });

  it("is still true for the failures it was always true for", () => {
    expect(isAuthFailure("cancelled")).toBe(true);
    expect(isAuthFailure("authentication failed")).toBe(true);
    expect(isAuthFailure("bad password")).toBe(true);
  });
});

describe("opensSecuritySettings", () => {
  it("offers the editor only where the editor holds the fix", () => {
    expect(opensSecuritySettings("legacy-tls-required")).toBe(true);
    expect(opensSecuritySettings("nla-refused")).toBe(true);
    // The build is the fix here, not a setting, and the copy says so.
    expect(opensSecuritySettings("legacy-tls-unavailable")).toBe(false);
    expect(opensSecuritySettings("authentication failed")).toBe(false);
  });
});
