import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import type { ScanNetwork, ScanProgress, ScanTarget } from "../lib/types";
import { ScanButton } from "./ScanButton";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/** What `scan_networks` returns on a Linux box with Ethernet, WARP and Docker. */
const NETWORKS: ScanNetwork[] = [
  {
    id: "eth0|10.0.0.0/24",
    name: "Ethernet (eth0)",
    kind: "lan",
    interface: "eth0",
    range: "10.0.0.0/24",
    cidrs: ["10.0.0.0/24"],
    addresses: 254,
    verdict: "scan",
  },
  {
    id: "CloudflareWARP|10.0.0.0/8",
    name: "Cloudflare WARP",
    kind: "warp",
    interface: "CloudflareWARP",
    range: "10.0.0.0/8",
    cidrs: ["10.0.0.0/8"],
    addresses: 16777214,
    verdict: "too-large",
  },
  {
    id: "CloudflareWARP|192.168.50.0/25",
    name: "Cloudflare WARP",
    kind: "warp",
    interface: "CloudflareWARP",
    range: "192.168.50.0/24, part",
    cidrs: ["192.168.50.0/25", "192.168.50.128/27"],
    addresses: 156,
    verdict: "scan",
  },
  {
    id: "docker0|172.17.0.0/16",
    name: "Docker (docker0)",
    kind: "virtual",
    interface: "docker0",
    range: "172.17.0.0/16",
    cidrs: ["172.17.0.0/16"],
    addresses: 65534,
    verdict: "confirm",
  },
];

let host: HTMLDivElement;
let root: Root;
let onScan: Mock<(target?: ScanTarget) => Promise<void>>;
let onStop: Mock<() => void>;

const idle: ScanProgress = { running: false, done: 0, total: 0 };

function render(scan: ScanProgress = idle, networks: ScanNetwork[] = NETWORKS): void {
  act(() => {
    root.render(
      createElement(ScanButton, {
        scan,
        onScan,
        onStop,
        listNetworks: () => Promise.resolve(networks),
      }),
    );
  });
}

const main = (): HTMLButtonElement => host.querySelector("button")!;
const arrow = (): HTMLButtonElement =>
  host.querySelector<HTMLButtonElement>('[aria-label="Choose a network to scan"]')!;
const menu = (): HTMLElement | null => host.querySelector('[role="menu"]');
const items = (): HTMLButtonElement[] => [...host.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')];
const item = (text: string): HTMLButtonElement => items().find((b) => b.textContent?.includes(text))!;

async function openWithClick(): Promise<void> {
  await act(async () => {
    arrow().click();
  });
}

function key(target: Element, k: string): void {
  act(() => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true }));
  });
}

beforeEach(() => {
  localStorage.clear();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  onScan = vi.fn<(target?: ScanTarget) => Promise<void>>(() => Promise.resolve());
  onStop = vi.fn<() => void>();
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  document.body.innerHTML = "";
});

describe("ScanButton", () => {
  it("the main part still runs the default scan", () => {
    render();
    act(() => main().click());
    expect(onScan).toHaveBeenCalledTimes(1);
    expect(onScan.mock.calls[0][0]).toBeUndefined();
    expect(menu()).toBeNull();
  });

  it("the arrow lists every network with its kind and size, virtual last", async () => {
    render();
    expect(arrow().getAttribute("aria-haspopup")).toBe("menu");
    expect(arrow().getAttribute("aria-expanded")).toBe("false");
    await openWithClick();
    expect(arrow().getAttribute("aria-expanded")).toBe("true");
    // Its tooltip would cover the menu it opened.
    expect(arrow().title).toBe("");
    const rows = items().map((b) => b.textContent);
    expect(rows).toEqual([
      "Ethernet (eth0)LAN10.0.0.0/24254 addresses",
      "Cloudflare WARPWARP10.0.0.0/8too large to scan whole",
      "Cloudflare WARPWARP192.168.50.0/24, part156 addresses",
      "Docker (docker0)Virtual172.17.0.0/1665,534 addresses",
      "Scan an address range…",
    ]);
    expect(item("10.0.0.0/8").disabled).toBe(true);
    // The first enabled row has the focus, ready for the keyboard.
    expect(document.activeElement).toBe(item("Ethernet"));
  });

  it("picking a network scans just its ranges and is remembered", async () => {
    render();
    await openWithClick();
    act(() => item("192.168.50.0/24").click());
    expect(onScan).toHaveBeenCalledWith({
      cidrs: ["192.168.50.0/25", "192.168.50.128/27"],
      allowLarge: false,
    });
    expect(menu()).toBeNull();
    // Reopened, the pick is marked and has the focus, so Enter repeats it.
    await openWithClick();
    expect(item("192.168.50.0/24").dataset.last).toBe("true");
    expect(item("192.168.50.0/24").querySelector('[aria-label="Last scanned"]')).not.toBeNull();
    expect(document.activeElement).toBe(item("192.168.50.0/24"));
  });

  it("a range larger than a /22 asks first, with the count", async () => {
    render();
    await openWithClick();
    act(() => item("Docker").click());
    expect(onScan).not.toHaveBeenCalled();
    const dialog = document.querySelector('[role="dialog"]')!;
    expect(dialog.textContent).toContain("172.17.0.0/16 on Docker (docker0) has 65,534 addresses.");
    const cancel = [...dialog.querySelectorAll("button")].find((b) => b.textContent === "Cancel")!;
    act(() => cancel.click());
    expect(onScan).not.toHaveBeenCalled();

    await openWithClick();
    act(() => item("Docker").click());
    const go = document.querySelector<HTMLButtonElement>("[data-confirm]")!;
    expect(go.textContent).toBe("Scan 65,534 addresses");
    act(() => go.click());
    expect(onScan).toHaveBeenCalledWith({ cidrs: ["172.17.0.0/16"], allowLarge: true });
  });

  it("works from the keyboard: arrows move, Escape closes and returns focus", async () => {
    render();
    arrow().focus();
    await act(async () => {
      arrow().dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    });
    expect(menu()).not.toBeNull();
    expect(document.activeElement).toBe(item("Ethernet"));
    // The too large row is skipped.
    key(document.activeElement!, "ArrowDown");
    expect(document.activeElement).toBe(item("192.168.50.0/24"));
    key(document.activeElement!, "End");
    expect(document.activeElement).toBe(item("Scan an address range"));
    key(document.activeElement!, "ArrowDown");
    expect(document.activeElement).toBe(item("Ethernet"));
    key(document.activeElement!, "ArrowUp");
    expect(document.activeElement).toBe(item("Scan an address range"));
    key(document.activeElement!, "Escape");
    expect(menu()).toBeNull();
    expect(document.activeElement).toBe(arrow());
  });

  it("a press outside closes the menu", async () => {
    render();
    await openWithClick();
    act(() => {
      document.body.dispatchEvent(new Event("pointerdown", { bubbles: true }));
    });
    expect(menu()).toBeNull();
  });

  it("scans a typed range, and refuses a public or oversized one", async () => {
    render();
    await openWithClick();
    act(() => item("Scan an address range").click());
    const input = document.querySelector<HTMLInputElement>('[role="dialog"] input')!;
    const form = input.closest("form")!;
    const type = (text: string): void => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
      act(() => {
        setter.call(input, text);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
    };
    const submit = (): void => {
      act(() => {
        form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      });
    };

    type("8.8.8.0/24");
    submit();
    expect(onScan).not.toHaveBeenCalled();
    expect(document.getElementById("scan-range-note")!.textContent).toMatch(/not a private range/);

    type("10.0.0.0/12");
    submit();
    expect(onScan).not.toHaveBeenCalled();
    expect(document.getElementById("scan-range-note")!.textContent).toMatch(/more than a \/16/);

    type("10.20.0.0/20");
    expect(form.querySelector<HTMLButtonElement>('button[type="submit"]')!.textContent).toBe(
      "Scan 4,094 addresses",
    );
    submit();
    expect(onScan).toHaveBeenCalledWith({ cidrs: ["10.20.0.0/20"], allowLarge: true });

    // A typed range is offered again next time, ahead of the dialog.
    await openWithClick();
    expect(item("Scan 10.20.0.0/20 again").dataset.last).toBe("true");
  });

  it("the arrow is off while a scan runs", () => {
    render({ running: true, done: 3, total: 254 });
    expect(arrow().disabled).toBe(true);
  });

  it("a running scan turns the main part into Stop, with how far it has got", () => {
    render({ running: true, done: 12345, total: 65534 });
    expect(main().textContent).toBe("Stop scan 12,345 of 65,534");
    act(() => main().click());
    expect(onStop).toHaveBeenCalledTimes(1);
    expect(onScan).not.toHaveBeenCalled();
  });

  it("says Stop scan before the first progress arrives", () => {
    render({ running: true, done: 0, total: 0 });
    expect(main().textContent).toBe("Stop scan");
    act(() => main().click());
    expect(onStop).toHaveBeenCalledTimes(1);
  });

  it("Escape on the button stops a running scan and does nothing when idle", () => {
    render();
    main().focus();
    key(main(), "Escape");
    expect(onStop).not.toHaveBeenCalled();

    render({ running: true, done: 40, total: 254 });
    expect(document.activeElement).toBe(main());
    key(main(), "Escape");
    expect(onStop).toHaveBeenCalledTimes(1);
  });

  it("once stopping it says so and does not stop twice", () => {
    render({ running: true, done: 40, total: 254, stopping: true });
    expect(main().textContent).toBe("Stopping…");
    expect(main().disabled).toBe(true);
    key(main(), "Escape");
    expect(onStop).not.toHaveBeenCalled();
  });

  it("goes back to Scan network when the scan ends", () => {
    render({ running: true, done: 40, total: 254 });
    render({ running: false, done: 40, total: 254 });
    expect(main().textContent).toBe("Scan network");
    expect(arrow().disabled).toBe(false);
    act(() => main().click());
    expect(onScan).toHaveBeenCalledTimes(1);
    expect(onStop).not.toHaveBeenCalled();
  });
});
