import { describe, expect, it } from "vitest";
import { shownFingerprint, subjectLabel } from "./CertificateSheet";

describe("the label over the computer's identity", () => {
  it("does not call a bare RSA key a certificate", () => {
    expect(subjectLabel("ra2")).toBe("Kind of key");
    expect(subjectLabel("apple-rsa")).toBe("Kind of key");
  });

  it("keeps the certificate wording where there is one", () => {
    expect(subjectLabel("tls")).toBe("Name on its certificate");
    expect(subjectLabel("rdp-tls")).toBe("Name on its certificate");
    expect(subjectLabel("rdg-tls")).toBe("Name on its certificate");
  });
});

describe("an SSH computer's key", () => {
  it("is named for what it is and shown in SSH's own form", () => {
    expect(subjectLabel("ssh")).toBe("SSH computer");
    const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    expect(shownFingerprint("ssh", fp)).toBe(fp);
    expect(shownFingerprint("tls", "abcd1234")).toBe("AB CD 12 34");
  });
});
