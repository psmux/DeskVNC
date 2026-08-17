#!/usr/bin/env python3
"""limb: quality. What does each quality rung actually cost on a real server?

Answers: "is the Auto tuner's ladder made of rungs that differ in the way it
believes they do?"

(Was rfb_probe4.py in the scratchpad.)

The Auto tuner picks a (JPEG quality, Tight compression) pair and assumes lower
quality means fewer bytes and less server work. That assumption is only true if
the server honours the pseudo-encodings the way the tuner expects, and on the
2880x1800 machine it did not: compression level 0 does not mean "compress a
little", it means DO NOT COMPRESS, and the byte count goes up by roughly 4x
rather than down. This limb measures every rung on a real server so the ladder
can be checked against reality instead of against the tuner's model of it.

The auto-lossless-refresh path is measured too. That path disables JPEG,
re-sends SetEncodings, and issues a NON-incremental request over the accumulated
lossy damage bounding box. On a 2880x1800 screen that bbox is often most of the
desktop, so the "refresh" is close to a full repaint at lossless quality.

Read only. No input is sent to the remote desktop.

  ./limbs.py quality --host 192.168.77.173
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402
from rfb_probe import RFB  # noqa: E402


def enc_list(jpeg_quality=None, compression=None):
    """Build a SetEncodings list for one rung of the quality ladder.

    JPEG quality levels occupy pseudo-encodings -32 to -23 (level 0 to 9) and
    Tight compression levels occupy -256 to -247 (level 0 to 9). Sending
    neither leaves the server on its own defaults, which is a different
    measurement again, so both are always explicit here unless the scenario
    is specifically testing their absence.
    """
    v = [7, 1, -224]
    if jpeg_quality is not None:
        v.append(-32 + jpeg_quality)      # JPEG quality levels are -32 to -23
    if compression is not None:
        v.append(-256 + compression)      # compression levels are -256 to -247
    return v


def pull_full(c):
    t0 = time.perf_counter()
    c.fb_update_request(False, 0, 0, c.width, c.height)
    got = 0
    nr = 0
    while True:
        t, info = c.read_message()
        if t != "fb":
            continue
        for (x, y, w, h, e, n) in info["rects"]:
            got += n
            nr += 1
        break
    return (time.perf_counter() - t0) * 1000, got, nr


# The ladder, in the order it is worth reading. The compression-0 rung is here
# because it is the one that cost 9.9 MB/s in production, and a diagnostic that
# cannot reproduce the bug it was written for is not worth keeping.
SCENARIOS = [
    ("JPEG q9 / compress 0  (THE BUG: server stops compressing)", enc_list(9, 0)),
    ("JPEG q9 / compress 1  (High preset, least server work)", enc_list(9, 1)),
    ("JPEG q9 / compress 3", enc_list(9, 3)),
    ("JPEG q6 / compress 3  (Auto starting point)", enc_list(6, 3)),
    ("JPEG q3 / compress 3  (what Auto degraded to)", enc_list(3, 3)),
    ("JPEG q0 / compress 6  (Low preset)", enc_list(0, 6)),
    ("JPEG disabled         (auto-lossless-refresh)", enc_list(None, 3)),
]


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py quality",
        description="Measure the bytes and latency of every rung of the Auto "
                    "quality ladder against a real server. Read only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Healthy: bytes per full screen fall monotonically as quality "
               "falls, and compression 1 to 9 all land in the same order of "
               "magnitude.\n"
               "Unhealthy: the compression-0 rung ships several times MORE "
               "bytes than every other rung. That is the server refusing to "
               "compress, not a mild quality setting.",
    )
    p.add_argument("--host", default="127.0.0.1", help="server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5900, help="server port (default 5900)")
    p.add_argument("--samples", type=int, default=5,
                   help="full-screen pulls per rung, after a warm-up pull (default 5)")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(creds.describe_source(args.profile))
    c = RFB(args.host, args.port, creds.password_from_args(args))
    print(f"server {c.name!r}  {c.width}x{c.height}\n")

    for label, encs in SCENARIOS:
        c.set_encodings(encs)
        pull_full(c)  # warm: let the server settle into the new encoder config
        times, byts = [], []
        for _ in range(args.samples):
            ms, n, nr = pull_full(c)
            times.append(ms)
            byts.append(n)
        times.sort()
        print(f"{label}")
        print(f"    median {times[len(times)//2]:7.1f} ms   "
              f"max {times[-1]:7.1f} ms   "
              f"{sum(byts)/len(byts)/1024:6.0f} KiB per full screen")


if __name__ == "__main__":
    main()
