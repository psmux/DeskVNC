import { describe, expect, it } from "vitest";
import { subjectLabel } from "./CertificateSheet";

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
