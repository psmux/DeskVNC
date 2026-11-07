import { afterEach, describe, expect, it } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  CERTIFICATE_SHA256_LABEL,
  FINGERPRINT_LABEL,
  FingerprintBlock,
  THUMBPRINT_LABEL,
} from "./CertPrompt";

// The pin is the SHA-256 of the public key. Labelled as a certificate
// fingerprint, it never matched the certificate's own SHA-256 or the
// thumbprint Windows shows, so a correct server looked like an impostor.
describe("FingerprintBlock", () => {
  let root: Root | null = null;
  let host: HTMLDivElement | null = null;
  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
  });

  it("says the hex is the SHA-256 of the public key, on screen and to a screen reader", () => {
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    act(() =>
      root!.render(
        createElement(FingerprintBlock, {
          fingerprint: "ad5b3a6edd01ec7f1df5158a0ad9fa64c1c744889e2df2c94dbd288427ab04a8",
          mnemonic: "",
          subject: "box",
        }),
      ),
    );
    expect(host.textContent).toMatch(/public key/i);
    const labelled = host.querySelector("[aria-label]");
    expect(labelled?.getAttribute("aria-label")).toMatch(/public key/i);
    expect(labelled?.getAttribute("aria-label")).not.toMatch(/certificate fingerprint/i);
  });
});

// The pin hashes only the public key, which no Windows dialog shows. A
// gateway admin reads the certificate's Thumbprint (SHA-1) or its SHA-256,
// so the prompt has to show those too or the person has nothing to match.
describe("FingerprintBlock with the certificate's own digests", () => {
  let root: Root | null = null;
  let host: HTMLDivElement | null = null;
  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
  });

  function render(certificate: { thumbprint: string; sha256: string } | null): HTMLDivElement {
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    act(() =>
      root!.render(
        createElement(FingerprintBlock, {
          fingerprint: "c42563ef393c1cabdf5438ffc8c5a8f0ecd2796cc33b556d4ee4d9f386e2118a",
          mnemonic: "",
          subject: "vnc.example.test",
          certificate,
        }),
      ),
    );
    return host;
  }

  it("shows the thumbprint the way Windows prints it, and the certificate SHA-256, beside the key hash", () => {
    const el = render({
      thumbprint: "44:E7:9D:B3:6D:E8:A9:97:D8:A8:57:B9:B6:0C:40:BA:91:EA:62:BF",
      sha256:
        "17:4D:A4:1D:A3:4E:09:D6:E5:86:D9:A8:B7:1E:13:60:4B:15:C5:04:FC:20:8B:36:1C:45:8D:61:83:61:A3:78",
    });
    const byLabel = (label: string): string | null | undefined =>
      el.querySelector(`[aria-label="${label}"]`)?.textContent;
    expect(byLabel(THUMBPRINT_LABEL)).toBe("44E79DB36DE8A997D8A857B9B60C40BA91EA62BF");
    expect(byLabel(CERTIFICATE_SHA256_LABEL)).toBe(
      "17:4D:A4:1D:A3:4E:09:D6:E5:86:D9:A8:B7:1E:13:60:4B:15:C5:04:FC:20:8B:36:1C:45:8D:61:83:61:A3:78",
    );
    // The pinned value is still there, under its own label.
    expect(byLabel(FINGERPRINT_LABEL)).toBe(
      "C4:25:63:EF:39:3C:1C:AB:DF:54:38:FF:C8:C5:A8:F0:EC:D2:79:6C:C3:3B:55:6D:4E:E4:D9:F3:86:E2:11:8A",
    );
    expect(el.textContent).toMatch(/Thumbprint/);
  });

  it("shows only the key hash for a key that came without a certificate", () => {
    const el = render(null);
    expect(el.querySelector(`[aria-label="${THUMBPRINT_LABEL}"]`)).toBeNull();
    expect(el.querySelector(`[aria-label="${CERTIFICATE_SHA256_LABEL}"]`)).toBeNull();
    expect(el.querySelector(`[aria-label="${FINGERPRINT_LABEL}"]`)).not.toBeNull();
  });
});
