import { afterEach, describe, expect, it } from "vitest";
import {
  formatAddresses,
  formatCidr,
  hostCount,
  judgeCidrs,
  judgeRange,
  parseCidr,
  rangeProblem,
  roughDuration,
  readLastPick,
  writeLastPick,
} from "./scanRange";

const c = (t: string) => parseCidr(t)!;

describe("parseCidr", () => {
  it("reads ranges and bare addresses and clears host bits", () => {
    expect(formatCidr(c("192.168.1.77/24"))).toBe("192.168.1.0/24");
    expect(formatCidr(c(" 10.1.2.3 "))).toBe("10.1.2.3/32");
    expect(formatCidr(c("10.200.3.4/16"))).toBe("10.200.0.0/16");
    expect(formatCidr(c("0.0.0.0/0"))).toBe("0.0.0.0/0");
  });

  it("refuses what is not a range", () => {
    for (const bad of ["", "10.1.2", "10.1.2.3/", "10.1.2.3/33", "10.1.2.3/+8", "256.1.1.1/24", "a.b.c.d", "10.1.2.3/24/1"]) {
      expect(parseCidr(bad), bad).toBeNull();
    }
  });
});

describe("limits", () => {
  it("scans up to a /22, asks up to a /16, refuses beyond", () => {
    expect(judgeRange(c("192.168.1.0/24"))).toBe("scan");
    expect(judgeRange(c("10.0.0.0/22"))).toBe("scan");
    expect(judgeRange(c("10.0.0.0/21"))).toBe("confirm");
    expect(judgeRange(c("172.17.0.0/16"))).toBe("confirm");
    expect(judgeRange(c("10.0.0.0/15"))).toBe("too-large");
    expect(hostCount(c("172.17.0.0/16"))).toBe(65534);
  });

  it("refuses public and straddling ranges", () => {
    for (const t of ["8.8.8.0/24", "198.51.100.0/24", "172.32.0.0/24", "172.0.0.0/11", "127.0.0.0/24", "169.254.1.0/24"]) {
      expect(judgeRange(c(t)), t).toBe("public");
    }
    expect(judgeRange(c("100.100.1.0/24"))).toBe("scan");
  });

  it("asks when small ranges add up past a /22", () => {
    const four = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"];
    expect(judgeCidrs(four)).toEqual({ verdict: "scan", addresses: 1016 });
    expect(judgeCidrs([...four, "10.0.4.0/24"])).toEqual({ verdict: "confirm", addresses: 1270 });
    expect(judgeCidrs(["10.0.0.0/24", "8.8.8.0/24"]).verdict).toBe("public");
  });

  it("says what is wrong with a typed range", () => {
    expect(rangeProblem("10.0.0.0/24")).toBeNull();
    expect(rangeProblem("10.0.0.0/18")).toBeNull();
    expect(rangeProblem("nope")).toMatch(/for example/);
    expect(rangeProblem("8.8.8.0/24")).toMatch(/not a private range/);
    expect(rangeProblem("10.0.0.0/8")).toMatch(/16,777,214 addresses, more than a \/16/);
  });

  it("estimates the time from the timeout bound rate, not the rate cap", () => {
    expect(roughDuration(254)).toBe("about a minute");
    // 65,534 addresses, 3 probes each, 400 a second: a little over 8 minutes.
    expect(roughDuration(65534)).toBe("about 8 minutes");
  });

  it("formats counts", () => {
    expect(formatAddresses(1)).toBe("1 address");
    expect(formatAddresses(65534)).toBe("65,534 addresses");
  });
});

describe("last pick", () => {
  afterEach(() => localStorage.clear());

  it("round trips and ignores junk", () => {
    expect(readLastPick()).toBeNull();
    writeLastPick({ name: "Cloudflare WARP", range: "10.62.0.0/16", cidrs: ["10.62.0.0/16"] });
    expect(readLastPick()).toEqual({ name: "Cloudflare WARP", range: "10.62.0.0/16", cidrs: ["10.62.0.0/16"] });
    localStorage.setItem("deskvnc.scan.lastPick", '{"name":1}');
    expect(readLastPick()).toBeNull();
    localStorage.setItem("deskvnc.scan.lastPick", '{"name":"x","range":"y","cidrs":["nope"]}');
    expect(readLastPick()).toBeNull();
  });
});
