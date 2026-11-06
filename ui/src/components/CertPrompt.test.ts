import { afterEach, describe, expect, it } from "vitest";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { FingerprintBlock } from "./CertPrompt";

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
