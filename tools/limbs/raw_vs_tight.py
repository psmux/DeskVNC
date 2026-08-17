#!/usr/bin/env python3
"""limb: wire. Separate network throughput from server encode cost.

Answers: "is the link slow, or is the server's encoder slow?" Those two look
identical from the app, and the fix for one is useless for the other.

(Was rfb_probe3.py in the scratchpad.)

Method: force Raw encoding and pull one full screen. Raw is a known,
incompressible byte count (width * height * bytes-per-pixel) and the server
does essentially no work to produce it, so the elapsed time is dominated by the
wire. That gives a clean throughput figure with no encoder in it.

Then pull the same screen with Tight on the SAME connection at the SAME moment,
so the two numbers are comparable and no drift in the network between two
separate runs can be blamed. If Tight ships a tenth of the bytes but takes
nearly as long, the encoder is the bottleneck. If Tight is proportionally
faster, the wire is.

Read only. Sends no input, touches nothing on the remote desktop.

  ./limbs.py wire --host 192.168.77.173
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402
from rfb_probe import RFB  # noqa: E402


def pull_full(c):
    """One non-incremental full-screen request; return (seconds, wire_bytes, nrects)."""
    t0 = time.perf_counter()
    c.fb_update_request(False, 0, 0, c.width, c.height)
    got = 0
    nr = 0
    while True:
        t, info = c.read_message()
        if t != "fb":
            continue
        for (x, y, w, h, enc, n) in info["rects"]:
            got += n
            nr += 1
        break
    return time.perf_counter() - t0, got, nr


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py wire",
        description="Force Raw to measure the link, then Tight on the same "
                    "connection to measure the encoder. Read only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Healthy: the Raw figure lands near the link's real capacity "
               "(about 80 Mbit/s on the Wi-Fi under test) and Tight's much "
               "smaller payload arrives proportionally faster.\n"
               "Unhealthy: Raw reports about 24 Mbit/s effective while iperf "
               "says the link is fine, which means the server cannot even "
               "shovel uncompressed pixels at line rate.",
    )
    p.add_argument("--host", default="127.0.0.1", help="server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5900, help="server port (default 5900)")
    p.add_argument("--assumed-link-mbit", type=float, default=20.0, metavar="MBIT",
                   help="link rate used for the 'if the wire were the only "
                        "limit' line (default 20)")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(creds.describe_source(args.profile))
    c = RFB(args.host, args.port, creds.password_from_args(args))
    print(f"server {c.name!r}  {c.width}x{c.height}  {c.bpp}bpp")

    # --- 1. Raw, full screen: pure wire test.
    c.set_encodings([0])  # Raw only
    expect = c.width * c.height * (c.bpp // 8)
    print(f"\nRaw full screen, expecting ~{expect/1024/1024:.1f} MiB of pixels")

    dt, got, _ = pull_full(c)
    print(f"  {got/1024/1024:.1f} MiB in {dt*1000:.0f} ms "
          f"-> {got*8/dt/1e6:.1f} Mbit/s effective wire rate")

    # --- 2. Same again, so the first sample's warmup does not mislead.
    dt, got, _ = pull_full(c)
    print(f"  repeat: {got/1024/1024:.1f} MiB in {dt*1000:.0f} ms "
          f"-> {got*8/dt/1e6:.1f} Mbit/s")

    # --- 3. Tight full screen for comparison, same connection, same moment.
    c.set_encodings([7, -224])
    dt, got, nr = pull_full(c)
    link = args.assumed_link_mbit * 1e6
    print(f"\nTight full screen: {got/1024:.0f} KiB in {dt*1000:.0f} ms, {nr} rects "
          f"-> {got*8/dt/1e6:.1f} Mbit/s of compressed bytes")
    print(f"  if the wire were the only limit this would take "
          f"{got*8/link*1000:.0f} ms at {args.assumed_link_mbit:.0f} Mbit/s")


if __name__ == "__main__":
    main()
