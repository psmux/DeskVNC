#!/usr/bin/env python3
"""limb: typing. Keystroke to pixel latency, measured with a minimal RFB client.

Answers: "does this feel laggy, and by how much?" This is the number a user
actually perceives, and it is the first thing to measure because it is the only
one that maps directly onto the complaint.

Because it uses the independent client from rfb_probe rather than vnc-core, it
is the BASELINE: what this server can do for a viewer that does nothing clever
and nothing stupid. Take the same measurement while the app is running and the
difference is our client's fault. That comparison is how the compression-0 bug
was pinned on the client rather than the server: this limb read 3.2 ms alone
and 259 to 414 ms with one misbehaving app session on the same server.

Method per sample:
  * keep one incremental request outstanding (mandatory, since this server has
    no ContinuousUpdates), so the server can answer the instant damage appears
  * stamp t0, send KeyDown + KeyUp
  * stop the clock when the next FramebufferUpdate carrying real damage lands
  * send BackSpace to undo the character, so the remote ends where it started

Updates smaller than MIN_DAMAGE_PX pixels are ignored. A server answering a
probe-style request sends a 1x1 rect that carries no glyph, and counting that
as "the character appeared" would report a latency far lower than anything a
user could see.

REQUIRES a focused text field on the remote desktop (a text editor, an address
bar, anything with a caret). Without focus there is no damage and every sample
times out.

This limb DOES send input. It types 'a' and deletes it again, so the remote
desktop ends where it started, but it is the one limb here that is not read
only.

  ./limbs.py typing --host 192.168.77.173 --samples 10
"""
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402
from rfb_probe import RFB  # noqa: E402

KEY_A = 0x0061
KEY_BACKSPACE = 0xFF08

TIMEOUT_S = 2.0
MIN_DAMAGE_PX = 4          # ignore 1x1 probe-answer style updates

# Encoding list for the latency limbs: the app's preferences minus the
# ContinuousUpdates and Fence pseudo-encodings, because a server that switched
# itself into continuous mode mid-run would change what "the next update" means
# and quietly invalidate the timing.
LATENCY_ENCODINGS = (7, 16, 1, 5, 6, 0, -239, -240, -314, -223, -308, -307, -224)


def send_key(c, keysym, down):
    c.s.sendall(struct.pack(">BBHI", 4, 1 if down else 0, 0, keysym))


def drain_until_quiet(c, quiet_s=0.5, cap_s=6.0):
    """Absorb in-flight updates until the screen has been still for quiet_s.

    Without this, a sample started while the previous character's repaint is
    still arriving stops the clock on the wrong update and reports a latency
    near zero.
    """
    end = time.time() + cap_s
    c.s.settimeout(quiet_s)
    while time.time() < end:
        try:
            c.read_message()
        except (socket.timeout, TimeoutError):
            c.s.settimeout(None)
            return True
        except Exception:
            break
    c.s.settimeout(None)
    return False


def await_damage(c, deadline_s):
    """Wait for an update carrying more than MIN_DAMAGE_PX pixels of change."""
    c.s.settimeout(deadline_s)
    try:
        while True:
            t, info = c.read_message()
            if t != "fb":
                continue
            px = sum(w * h for (x, y, w, h, e, n) in info["rects"] if e >= 0)
            if px >= MIN_DAMAGE_PX:
                return px
    except (socket.timeout, TimeoutError):
        return None
    finally:
        c.s.settimeout(None)


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py typing",
        description="Keystroke to pixel latency against a real server. Types "
                    "'a' and backspaces it, so the remote ends unchanged.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="REQUIRES a focused text field on the remote desktop.\n\n"
               "Healthy: median under about 30 ms on a LAN. The measured "
               "baseline on the server under test was 3.2 ms.\n"
               "Unhealthy: 250 ms or more, or a median that only goes bad "
               "when another client is connected, which points at that other "
               "client rather than at the server.",
    )
    p.add_argument("--host", default="127.0.0.1", help="server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5900, help="server port (default 5900)")
    p.add_argument("--samples", type=int, default=20, help="samples to take (default 20)")
    p.add_argument("--quiet", action="store_true",
                   help="print only the summary, not each sample")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    n = args.samples
    print(creds.describe_source(args.profile))

    c = RFB(args.host, args.port, creds.password_from_args(args))
    print(f"server {c.name!r}  {c.width}x{c.height}")
    print("NOTE: a text field on the remote must have keyboard focus.\n")

    c.set_encodings(list(LATENCY_ENCODINGS))
    c.fb_update_request(False, 0, 0, c.width, c.height)
    c.read_message()

    samples = []
    misses = 0

    for i in range(n):
        if not drain_until_quiet(c):
            print(f"  sample {i+1}: screen never went quiet, skipping")
            continue

        # Arm the request BEFORE the keystroke, the way a good client does.
        c.fb_update_request(True, 0, 0, c.width, c.height)

        t0 = time.perf_counter()
        send_key(c, KEY_A, True)
        send_key(c, KEY_A, False)

        px = await_damage(c, TIMEOUT_S)
        if px is None:
            misses += 1
            print(f"  sample {i+1}: no damage within {TIMEOUT_S}s "
                  f"(is a text field focused?)")
            continue
        dt = (time.perf_counter() - t0) * 1000
        samples.append(dt)
        if not args.quiet:
            print(f"  sample {i+1:2d}: {dt:7.1f} ms   ({px} px changed)")

        # Undo the character so the remote ends where it started.
        time.sleep(0.12)
        c.fb_update_request(True, 0, 0, c.width, c.height)
        send_key(c, KEY_BACKSPACE, True)
        send_key(c, KEY_BACKSPACE, False)
        await_damage(c, 1.0)
        time.sleep(0.12)

    print()
    if not samples:
        print("no usable samples")
        return 1
    samples.sort()
    k = len(samples)
    print(f"keystroke -> pixel, {k} samples ({misses} timed out)")
    print(f"  min    {samples[0]:7.1f} ms")
    print(f"  median {samples[k//2]:7.1f} ms")
    print(f"  p95    {samples[min(k-1, int(k*0.95))]:7.1f} ms")
    print(f"  max    {samples[-1]:7.1f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
