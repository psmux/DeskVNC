#!/usr/bin/env python3
"""limb: probe. Independent minimal RFB client, and the library the rest use.

Answers: "is this server slow, or is our client slow?"

Everything here is written from the RFB spec and speaks to the socket directly.
It deliberately does not use vnc-core, so it cross-checks our own client rather
than inheriting its assumptions. When this limb and the app disagree about a
server, the app is wrong.

Run as a limb it reports:
  * server name, screen size, negotiated pixel format
  * whether the server supports ContinuousUpdates (-313) and Fence (-312).
    Without ContinuousUpdates every single frame costs a full client-server
    round trip, which sets a hard floor on interactivity that no amount of
    client tuning can get under.
  * request -> update round trip for a 1x1 non-incremental request. A server
    must answer a non-incremental request immediately with real content, and a
    1x1 rect has no side effects on the remote desktop, so this isolates
    round-trip cost from encode cost.
  * update cadence, sizes and encodings observed over a watch window

Imported as a library it provides `RFB`, `ENC_NAMES` and `vnc_des`, which the
proxy, region, wire, quality, typing and phase limbs all build on.

Read only. Sends no input, so the remote desktop is never touched.

  ./limbs.py probe --host 192.168.77.173 --watch 10
"""
import argparse
import os
import socket
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402

# The encoding preference list the shipping app negotiates. Every limb sends
# this exact list so the server picks the same code paths it picks for us; a
# different list measures a different server.
APP_ENCODINGS = (7, 16, 1, 5, 6, 0, -239, -240, -314, -223, -308, -307, -224, -312, -313)

# ---------------------------------------------------------------- DES for VNC auth

_PC1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,
        62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3]
_PC2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,
        40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31]
_IP = [57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7,
       56,48,40,32,24,16,8,0,58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6]
_FP = [39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,
       35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25,32,0,40,8,48,16,56,24]
_E = [31,0,1,2,3,4,3,4,5,6,7,8,7,8,9,10,11,12,11,12,13,14,15,16,15,16,17,18,19,20,19,20,
      21,22,23,24,23,24,25,26,27,28,27,28,29,30,31,0]
_P = [15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24]
_SBOX = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


def _bits(data):
    out = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _frombits(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def _des_encrypt_block(key8, block8):
    k = _bits(key8)
    c = [k[x] for x in _PC1[:28]]
    d = [k[x] for x in _PC1[28:]]
    subkeys = []
    for r in range(16):
        c = c[_SHIFTS[r]:] + c[:_SHIFTS[r]]
        d = d[_SHIFTS[r]:] + d[:_SHIFTS[r]]
        cd = c + d
        subkeys.append([cd[x] for x in _PC2])
    b = _bits(block8)
    b = [b[x] for x in _IP]
    left, right = b[:32], b[32:]
    for r in range(16):
        expanded = [right[x] for x in _E]
        x = [expanded[i] ^ subkeys[r][i] for i in range(48)]
        out = []
        for s in range(8):
            chunk = x[s * 6:(s + 1) * 6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            val = _SBOX[s][row * 16 + col]
            out += [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]
        out = [out[x] for x in _P]
        new_right = [left[i] ^ out[i] for i in range(32)]
        left, right = right, new_right
    final = right + left
    return _frombits([final[x] for x in _FP])


def vnc_des(password, challenge):
    """VNC auth: DES-ECB with each key byte's bits reversed."""
    key = password.encode()[:8].ljust(8, b"\0")
    key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
    return b"".join(_des_encrypt_block(key, challenge[i:i + 8]) for i in (0, 8))


# ---------------------------------------------------------------- RFB

ENC_NAMES = {
    0: "Raw", 1: "CopyRect", 2: "RRE", 4: "CoRRE", 5: "Hextile", 6: "zlib",
    7: "Tight", 16: "ZRLE", 50: "OpenH264",
    -239: "pseudo:Cursor", -240: "pseudo:XCursor", -223: "pseudo:DesktopSize",
    -224: "pseudo:LastRect", -307: "pseudo:DesktopName", -308: "pseudo:ExtDesktopSize",
    -312: "pseudo:Fence", -313: "pseudo:ContinuousUpdates", -314: "pseudo:CursorWithAlpha",
}


class RFB:
    def __init__(self, host, port, password):
        self.s = socket.create_connection((host, port), 5)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        self._handshake(password)

    def recv(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError("server closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _handshake(self, password):
        self.version = self.recv(12)
        self.s.sendall(b"RFB 003.008\n")
        n = self.recv(1)[0]
        if n == 0:
            raise RuntimeError("server refused: " + self.recv(struct.unpack(">I", self.recv(4))[0]).decode())
        types = list(self.recv(n))
        # Prefer plain VNC auth, which is what real servers under test offer.
        # Fall back to None so that the probe can be pointed at the `proxy`
        # limb, which deliberately offers only None downstream. Chaining the
        # two (probe -> proxy -> server) is how the proxy's own decoding gets
        # checked against a client whose behaviour is known exactly.
        if 2 in types:
            self.s.sendall(bytes([2]))
            challenge = self.recv(16)
            self.s.sendall(vnc_des(password, challenge))
            result = struct.unpack(">I", self.recv(4))[0]
            if result != 0:
                raise RuntimeError("authentication failed")
        elif 1 in types:
            self.s.sendall(bytes([1]))
            # RFB 3.8 sends a SecurityResult even for None, unlike 3.3.
            result = struct.unpack(">I", self.recv(4))[0]
            if result != 0:
                raise RuntimeError("server rejected security type None")
        else:
            raise RuntimeError(
                f"server offers security types {types}; this client speaks "
                f"only 2 (VNC auth) and 1 (None). Test through the app instead."
            )
        self.s.sendall(bytes([1]))  # shared
        w, h = struct.unpack(">HH", self.recv(4))
        pf = self.recv(16)
        namelen = struct.unpack(">I", self.recv(4))[0]
        self.name = self.recv(namelen).decode("latin-1")
        self.width, self.height = w, h
        (self.bpp, self.depth, self.big_endian, self.true_colour,
         self.rmax, self.gmax, self.bmax, self.rsh, self.gsh, self.bsh) = struct.unpack(">BBBBHHHBBB", pf[:13])

    def set_encodings(self, encs):
        msg = struct.pack(">BBH", 2, 0, len(encs)) + b"".join(struct.pack(">i", e) for e in encs)
        self.s.sendall(msg)

    def fb_update_request(self, incremental, x, y, w, h):
        self.s.sendall(struct.pack(">BBHHHH", 3, 1 if incremental else 0, x, y, w, h))

    def read_message(self):
        """Return (type, info dict). Consumes one server message."""
        t = self.recv(1)[0]
        if t == 0:
            self.recv(1)
            nrects = struct.unpack(">H", self.recv(2))[0]
            rects = []
            for _ in range(nrects):
                x, y, w, h, enc = struct.unpack(">HHHHi", self.recv(12))
                if enc == -224:  # LastRect
                    rects.append((x, y, w, h, enc, 0))
                    break
                n = self._skip_rect(w, h, enc)
                rects.append((x, y, w, h, enc, n))
            return "fb", {"rects": rects}
        if t == 1:
            self.recv(3)
            n = struct.unpack(">H", self.recv(2))[0]
            self.recv(n * 6)
            return "colourmap", {}
        if t == 2:
            return "bell", {}
        if t == 3:
            self.recv(3)
            n = struct.unpack(">I", self.recv(4))[0]
            self.recv(n)
            return "cuttext", {}
        if t == 150:
            return "end_continuous_updates", {}
        if t == 248:
            self.recv(3)
            flags = struct.unpack(">I", self.recv(4))[0]
            ln = self.recv(1)[0]
            self.recv(ln)
            return "fence", {"flags": flags}
        raise RuntimeError(f"unhandled server message type {t}")

    def _skip_rect(self, w, h, enc):
        """Consume a rect body, returning its wire byte count."""
        start = len(self.buf)
        bpp = self.bpp // 8
        if enc == 0:
            n = w * h * bpp
            self.recv(n)
            return n
        if enc == 1:
            self.recv(4)
            return 4
        if enc in (-239,):
            n = w * h * bpp + ((w + 7) // 8) * h
            self.recv(n)
            return n
        if enc == -240:
            if w * h:
                self.recv(6 + 2 * ((w + 7) // 8) * h)
            return 0
        if enc in (-223, -308, -307, -312, -313, -314):
            # pseudo rects we do not need the body of, or that carry none
            if enc == -307:
                n = struct.unpack(">I", self.recv(4))[0]
                self.recv(n)
            elif enc == -308:
                cnt = self.recv(1)[0]
                self.recv(3 + cnt * 16)
            elif enc == -314:
                n = w * h * 4
                self.recv(n)
                return n
            return 0
        if enc == 7:  # Tight
            return self._skip_tight(w, h)
        if enc == 16:  # ZRLE
            n = struct.unpack(">I", self.recv(4))[0]
            self.recv(n)
            return n + 4
        if enc == 6:  # zlib
            n = struct.unpack(">I", self.recv(4))[0]
            self.recv(n)
            return n + 4
        if enc == 5:  # Hextile
            return self._skip_hextile(w, h)
        raise RuntimeError(f"cannot skip encoding {enc} ({ENC_NAMES.get(enc, '?')})")

    def _read_compact_len(self):
        b = self.recv(1)[0]
        n = b & 0x7F
        used = 1
        if b & 0x80:
            b = self.recv(1)[0]
            n |= (b & 0x7F) << 7
            used += 1
            if b & 0x80:
                b = self.recv(1)[0]
                n |= b << 14
                used += 1
        return n, used

    def _skip_tight(self, w, h):
        total = 0
        ctl = self.recv(1)[0]
        total += 1
        comp = ctl >> 4
        if comp == 0x08:  # fill
            self.recv(3)
            return total + 3
        if comp == 0x09:  # jpeg
            n, used = self._read_compact_len()
            self.recv(n)
            return total + used + n
        filt = 0
        if ctl & 0x40:
            filt = self.recv(1)[0]
            total += 1
        bpp = 3
        if filt == 1:  # palette
            ncol = self.recv(1)[0] + 1
            self.recv(ncol * bpp)
            total += 1 + ncol * bpp
            bits = 1 if ncol <= 2 else 8
            raw = ((w * bits + 7) // 8) * h if bits == 1 else w * h
        else:
            raw = w * h * bpp
        if raw < 12:
            self.recv(raw)
            return total + raw
        n, used = self._read_compact_len()
        self.recv(n)
        return total + used + n

    def _skip_hextile(self, w, h):
        total = 0
        bpp = self.bpp // 8
        for ty in range(0, h, 16):
            th = min(16, h - ty)
            for tx in range(0, w, 16):
                tw = min(16, w - tx)
                mask = self.recv(1)[0]
                total += 1
                if mask & 0x01:
                    n = tw * th * bpp
                    self.recv(n)
                    total += n
                    continue
                if mask & 0x02:
                    self.recv(bpp)
                    total += bpp
                if mask & 0x04:
                    self.recv(bpp)
                    total += bpp
                if mask & 0x08:
                    cnt = self.recv(1)[0]
                    total += 1
                    per = (bpp + 2) if (mask & 0x10) else 2
                    self.recv(cnt * per)
                    total += cnt * per
        return total

def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py probe",
        description="Minimal independent RFB client: capabilities, round trip "
                    "floor, and live update cadence. Read only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Healthy: round trip median under about 15 ms on a LAN.\n"
               "Unhealthy: ContinuousUpdates NO plus a round trip over 40 ms, "
               "which caps the frame rate at under 25/s before a single pixel "
               "is encoded.",
    )
    p.add_argument("--host", default="127.0.0.1", help="server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=5900, help="server port (default 5900)")
    p.add_argument("--watch", type=float, default=10.0, metavar="SECONDS",
                   help="how long to watch live updates (default 10)")
    p.add_argument("--samples", type=int, default=30,
                   help="round trip samples to take (default 30)")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    host, port, watch = args.host, args.port, args.watch
    password = creds.password_from_args(args)
    print(creds.describe_source(args.profile))

    c = RFB(host, port, password)
    print(f"server name      : {c.name!r}")
    print(f"rfb version      : {c.version.decode().strip()}")
    print(f"screen           : {c.width}x{c.height}")
    print(f"pixel format     : {c.bpp}bpp depth{c.depth} "
          f"{'BE' if c.big_endian else 'LE'} truecolour={bool(c.true_colour)} "
          f"max=({c.rmax},{c.gmax},{c.bmax}) shift=({c.rsh},{c.gsh},{c.bsh})")

    # Same preference list the app sends, so the server behaves as it does for us.
    c.set_encodings(list(APP_ENCODINGS))

    # --- capability discovery, PASSIVE first.
    # Sending EnableContinuousUpdates or ClientFence to a server that does not
    # implement them desyncs the stream, so only advertise-then-use.
    supports_cu = False
    supports_fence = False

    c.fb_update_request(False, 0, 0, c.width, c.height)
    deadline = time.time() + 4.0
    c.s.settimeout(0.5)
    while time.time() < deadline:
        try:
            t, info = c.read_message()
        except (socket.timeout, TimeoutError):
            break
        except Exception as e:
            print(f"  (capability scan stopped: {e})")
            break
        if t == "fb":
            for (x, y, w, h, enc, n) in info["rects"]:
                if enc == -313:
                    supports_cu = True
                if enc == -312:
                    supports_fence = True
            break
    c.s.settimeout(None)

    # Only now, if advertised, confirm the handshake actually completes.
    if supports_cu:
        c.s.sendall(struct.pack(">BBHHHH", 150, 1, 0, 0, c.width, c.height))
        c.s.settimeout(1.5)
        try:
            while True:
                t, info = c.read_message()
                if t == "end_continuous_updates":
                    break
        except Exception:
            supports_cu = False
        c.s.settimeout(None)

    print(f"ContinuousUpdates: {'YES' if supports_cu else 'NO  <-- every frame costs a full round trip'}")
    print(f"Fence            : {'YES' if supports_fence else 'NO'}")

    # --- round trip floor: 1x1 non-incremental request, no side effects
    n_rtt = max(1, args.samples)
    print(f"\n-- request -> update round trip, 1x1 rect, {n_rtt} samples --")
    rtts = []
    for _ in range(n_rtt):
        t0 = time.perf_counter()
        c.fb_update_request(False, 0, 0, 1, 1)
        while True:
            t, info = c.read_message()
            if t == "fb":
                break
        rtts.append((time.perf_counter() - t0) * 1000)
        time.sleep(0.02)
    rtts.sort()
    print(f"  min {rtts[0]:.1f} ms   median {rtts[len(rtts)//2]:.1f} ms   "
          f"p95 {rtts[min(len(rtts)-1, int(len(rtts)*0.95))]:.1f} ms   max {rtts[-1]:.1f} ms")

    # --- watch real traffic
    print(f"\n-- watching {watch:.0f}s of live updates (move a window on the remote now) --")
    encs_seen = Counter()
    bytes_seen = 0
    updates = 0
    rect_count = 0
    gaps = []
    last = None
    c.fb_update_request(True, 0, 0, c.width, c.height)
    end = time.time() + watch
    c.s.settimeout(1.0)
    while time.time() < end:
        try:
            t, info = c.read_message()
        except (socket.timeout, TimeoutError):
            continue
        if t != "fb":
            continue
        now = time.perf_counter()
        if last is not None:
            gaps.append((now - last) * 1000)
        last = now
        updates += 1
        for (x, y, w, h, enc, n) in info["rects"]:
            encs_seen[ENC_NAMES.get(enc, str(enc))] += 1
            bytes_seen += n
            rect_count += 1
        if not supports_cu:
            c.fb_update_request(True, 0, 0, c.width, c.height)

    print(f"  updates        : {updates} ({updates/watch:.1f}/s)")
    print(f"  rects          : {rect_count} ({rect_count/max(updates,1):.1f} per update)")
    print(f"  wire bytes     : {bytes_seen/1024:.0f} KiB ({bytes_seen/watch/1024:.0f} KiB/s)")
    print(f"  encodings      : {dict(encs_seen)}")
    if gaps:
        gaps.sort()
        print(f"  update gap     : min {gaps[0]:.1f} ms  median {gaps[len(gaps)//2]:.1f} ms  "
              f"p95 {gaps[min(len(gaps)-1, int(len(gaps)*0.95))]:.1f} ms  max {gaps[-1]:.1f} ms")


if __name__ == "__main__":
    main()
