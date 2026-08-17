#!/usr/bin/env python3
"""limb: phase. Is a slow echo a polling cycle or a fixed deferral?

Answers: "the typing limb says 250 ms, so what KIND of 250 ms is it?" The two
causes look the same in a latency histogram and have completely different
fixes, so guessing here wastes days.

Distinguishing test: vary the delay between the last screen activity and the
keystroke, then look at how echo latency responds.

  * POLLING on period P: the keystroke lands at a random phase in the cycle, so
    echo latency spreads roughly uniformly over 0 to P and correlates with the
    injected delay modulo P.
  * FIXED DEFERRAL of D: the server starts a D timer when damage appears, so
    echo latency stays flat at about D no matter when the key is pressed.

The fix differs: a deferral is usually a server config knob, a polling cycle is
about capture method and screen size.

It also measures whether requesting a SMALL region instead of the full screen
changes the answer. If it does not, the server rescans everything it is asked
for regardless, and clipping our requests is wasted effort.

This limb DOES send input, the same type-and-backspace cycle as the typing
limb, so the remote desktop ends where it started. A focused text field is
required.

  ./limbs.py phase --host 192.168.77.173
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402
from rfb_probe import RFB  # noqa: E402
from type_latency import (  # noqa: E402
    send_key, drain_until_quiet, await_damage, KEY_A, KEY_BACKSPACE,
)


def one_sample(c, pre_delay, region):
    """Wait pre_delay after quiet, then type, and time the echo."""
    if not drain_until_quiet(c, quiet_s=0.45, cap_s=6.0):
        return None
    time.sleep(pre_delay)
    x, y, w, h = region
    c.fb_update_request(True, x, y, w, h)
    t0 = time.perf_counter()
    send_key(c, KEY_A, True)
    send_key(c, KEY_A, False)
    px = await_damage(c, 2.5)
    if px is None:
        return None
    dt = (time.perf_counter() - t0) * 1000
    # undo
    time.sleep(0.1)
    c.fb_update_request(True, 0, 0, c.width, c.height)
    send_key(c, KEY_BACKSPACE, True)
    send_key(c, KEY_BACKSPACE, False)
    await_damage(c, 1.0)
    time.sleep(0.1)
    return dt


def summarize(label, xs):
    if not xs:
        print(f"  {label:<28} no samples")
        return
    s = sorted(xs)
    spread = s[-1] - s[0]
    print(f"  {label:<28} median {s[len(s)//2]:6.1f} ms   "
          f"range {s[0]:6.1f} to {s[-1]:6.1f}   spread {spread:5.1f} ms")


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py phase",
        description="Vary the delay before a keystroke to tell a server "
                    "polling cycle apart from a fixed deferral.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="REQUIRES a focused text field on the remote desktop.\n\n"
               "Reading it: a wide spread that tracks the injected delay means "
               "POLLING, and the period is roughly the spread. A flat median "
               "regardless of delay means FIXED DEFERRAL of about that median.",
    )
    p.add_argument("--host", default="127.0.0.1", help="server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5900, help="server port (default 5900)")
    p.add_argument("--samples", type=int, default=4,
                   help="samples per injected delay (default 4)")
    p.add_argument("--delays", default="0,0.06,0.12,0.18,0.24,0.30", metavar="LIST",
                   help="comma separated pre-keystroke delays in seconds "
                        "(default 0,0.06,0.12,0.18,0.24,0.30)")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(creds.describe_source(args.profile))
    c = RFB(args.host, args.port, creds.password_from_args(args))
    print(f"server {c.name!r}  {c.width}x{c.height}")
    print("a focused text field is required on the remote\n")

    c.set_encodings([7, 16, 1, 5, 6, 0, -224])
    c.fb_update_request(False, 0, 0, c.width, c.height)
    c.read_message()

    full = (0, 0, c.width, c.height)
    delays = [float(d) for d in args.delays.split(",") if d.strip()]

    # --- 1. phase sweep: vary the delay before the keystroke
    print(f"phase sweep, full-screen request ({args.samples} samples per delay)")
    print(f"  {'injected delay':<28} result")
    by_delay = {}
    for delay in delays:
        xs = []
        for _ in range(args.samples):
            r = one_sample(c, delay, full)
            if r is not None:
                xs.append(r)
        by_delay[delay] = xs
        summarize(f"+{int(delay*1000)} ms before key", xs)

    allx = [v for xs in by_delay.values() for v in xs]
    if allx:
        s = sorted(allx)
        print(f"\n  overall spread across all phases: {s[-1]-s[0]:.1f} ms "
              f"(median {s[len(s)//2]:.1f} ms)")
        print("  wide spread that tracks the delay => POLLING")
        print("  flat regardless of delay          => FIXED DEFERRAL")

    # --- 2. does the requested region size matter?
    print("\nrequest region size, 5 samples each")
    for label, region in [
        ("full screen", full),
        ("centre 640x480", (c.width // 2 - 320, c.height // 2 - 240, 640, 480)),
    ]:
        xs = []
        for _ in range(5):
            r = one_sample(c, 0.0, region)
            if r is not None:
                xs.append(r)
        summarize(label, xs)


if __name__ == "__main__":
    main()
