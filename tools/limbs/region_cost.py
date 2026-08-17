#!/usr/bin/env python3
"""limb: region. What does one update cost this server, by region size?

Answers: "how much of the freeze is the server's encoder, and does asking for
less of the screen actually buy anything?"

(Was rfb_probe2.py in the scratchpad.)

Everything here uses NON-incremental requests, which a server must answer
immediately with real content, so the measurement never depends on whether the
remote desktop happens to be changing. That is the whole trick: an incremental
request against a still desktop tells you nothing, because the server is
entitled to sit on it indefinitely.

Two results come out:

  * a size sweep, 1x1 up to full screen. If answer time is flat across sizes
    the server has a fixed per-request cost (a capture or polling cycle) and
    requesting smaller regions will not help. If it scales with area, the
    encoder is the cost and clipping the damage rect is worth doing.
  * a sustained full-screen repaint ceiling. 1000/median is the highest full
    frame rate this server can produce for anybody, which is the number that
    decides whether a "60 fps" target was ever reachable.

Read only. No input is ever sent, so the remote desktop is not touched.

  ./limbs.py region --host 192.168.77.173
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402
from rfb_probe import RFB, APP_ENCODINGS  # noqa: E402


def timed_request(c, x, y, w, h):
    """Non-incremental request for a region; return (ms, wire_bytes, nrects)."""
    t0 = time.perf_counter()
    c.fb_update_request(False, x, y, w, h)
    total = 0
    nrects = 0
    while True:
        t, info = c.read_message()
        if t != "fb":
            continue
        for (rx, ry, rw, rh, enc, n) in info["rects"]:
            total += n
            nrects += 1
        break
    return (time.perf_counter() - t0) * 1000, total, nrects


def stats(xs):
    xs = sorted(xs)
    return (xs[0], xs[len(xs) // 2], xs[min(len(xs) - 1, int(len(xs) * 0.95))], xs[-1])


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py region",
        description="Server answer latency by requested region size, plus the "
                    "sustained full-screen repaint ceiling. Read only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Healthy: full-screen median under about 60 ms, so over 15 full "
               "frames/s are available.\n"
               "Unhealthy: full-screen median of 120 to 180 ms, which is a "
               "5 to 8 frames/s ceiling shared with every other client on the "
               "server. That was the reading on the 2880x1800 machine.",
    )
    p.add_argument("--host", default="127.0.0.1", help="server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5900, help="server port (default 5900)")
    p.add_argument("--samples", type=int, default=10,
                   help="samples per region size (default 10)")
    p.add_argument("--repaints", type=int, default=15,
                   help="back-to-back full-screen requests for the ceiling (default 15)")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(creds.describe_source(args.profile))
    c = RFB(args.host, args.port, creds.password_from_args(args))
    print(f"server {c.name!r}  {c.width}x{c.height}\n")

    c.set_encodings(list(APP_ENCODINGS))
    c.fb_update_request(False, 0, 0, c.width, c.height)
    c.read_message()  # drain the first full paint

    # How does the server's answer latency scale with the region it must encode?
    print(f"region size -> time to answer a non-incremental request "
          f"({args.samples} samples each)")
    print(f"{'region':>16} {'min':>8} {'median':>8} {'p95':>8} {'max':>8} {'KiB':>8} {'rects':>7}")
    for (w, h, label) in [
        (1, 1, "1x1"),
        (64, 64, "64x64"),
        (256, 256, "256x256"),
        (640, 480, "640x480"),
        (1280, 720, "1280x720"),
        (c.width, c.height, f"{c.width}x{c.height} FULL"),
    ]:
        w = min(w, c.width)
        h = min(h, c.height)
        times, byts, rcts = [], [], []
        for _ in range(args.samples):
            ms, n, nr = timed_request(c, 0, 0, w, h)
            times.append(ms)
            byts.append(n)
            rcts.append(nr)
            time.sleep(0.03)
        mn, md, p95, mx = stats(times)
        print(f"{label:>16} {mn:7.1f}ms {md:7.1f}ms {p95:7.1f}ms {mx:7.1f}ms "
              f"{sum(byts)/len(byts)/1024:7.0f} {sum(rcts)/len(rcts):7.1f}")

    # Back-to-back full-screen requests: the server's sustained repaint rate.
    print(f"\nsustained full-screen repaint, {args.repaints} back-to-back requests")
    times = []
    for _ in range(args.repaints):
        ms, n, nr = timed_request(c, 0, 0, c.width, c.height)
        times.append(ms)
    mn, md, p95, mx = stats(times)
    print(f"  min {mn:.1f} ms  median {md:.1f} ms  p95 {p95:.1f} ms  max {mx:.1f} ms"
          f"   -> {1000/md:.1f} full frames/s ceiling")


if __name__ == "__main__":
    main()
