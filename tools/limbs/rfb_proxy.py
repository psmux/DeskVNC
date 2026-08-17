#!/usr/bin/env python3
"""limb: proxy. RFB man-in-the-middle. Ground truth for what a client does.

Answers: "is the client misbehaving, and if so, how?"

This is the limb that found the compression-0 bug. Every other measurement in
this directory tells you a number is bad; this one tells you which message made
it bad, because it decodes the client's side of the conversation instead of
inferring it.

It sits between a VNC client and the real server, decodes every client->server
message, counts every server->client byte, and prints a per-2s breakdown. No
guessing about what the client is asking for.

  Proxy <-> server : real handshake, VNC auth with the resolved password.
  Proxy <-> client : advertises security type 1 (None), so the client under
                     test connects with no password prompt. That matters: it
                     means any client, including a release build of the app,
                     can be pointed at the proxy without reconfiguring stored
                     credentials.

The two knobs it watches hardest are the ones the Auto quality tuner drives:
the JPEG quality pseudo-encoding (-32 to -23) and the Tight compression
pseudo-encoding (-256 to -247). Compression level 0 means the server sends
UNCOMPRESSED Tight data, which on a 2880x1800 desktop measured 9.9 MB/s and
saturated an 82 Mbit/s link on its own. The proxy shouts about that case
specifically, because a wrong compression level looks identical to a slow
network from every other vantage point.

Point the client under test at 127.0.0.1:5901.

  ./limbs.py proxy --port 5901 --target 192.168.77.173
"""
import argparse
import os
import socket
import struct
import sys
import threading
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creds  # noqa: E402
from rfb_probe import vnc_des, ENC_NAMES  # noqa: E402


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()
        self.bytes_from_server = 0
        self.bytes_to_server = 0
        self.encodings_negotiated = None
        self.pixel_format_sets = 0

    def reset(self):
        self.fbur_incr = 0
        self.fbur_full = 0
        self.fbur_full_regions = Counter()
        self.fbur_incr_regions = Counter()
        self.keys = 0
        self.pointers = 0
        self.setenc = 0
        self.other = Counter()
        self.win_bytes_from_server = 0


S = Stats()


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise EOFError
        buf += c
    return buf


def server_handshake(host, port, password):
    """Do a full RFB handshake with the real server. Returns (sock, serverinit)."""
    s = socket.create_connection((host, port), 6)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    version = recv_exactly(s, 12)
    s.sendall(b"RFB 003.008\n")
    n = recv_exactly(s, 1)[0]
    types = list(recv_exactly(s, n))
    if 2 not in types:
        raise RuntimeError(f"server offers {types}, no plain VNC auth")
    s.sendall(bytes([2]))
    challenge = recv_exactly(s, 16)
    s.sendall(vnc_des(password, challenge))
    if struct.unpack(">I", recv_exactly(s, 4))[0] != 0:
        raise RuntimeError("auth failed against real server")
    s.sendall(bytes([1]))  # shared
    head = recv_exactly(s, 24)
    namelen = struct.unpack(">I", head[20:24])[0]
    name = recv_exactly(s, namelen)
    return s, head + name


def client_handshake(c, serverinit):
    """Present ourselves to the client under test. Security type 1 (None)."""
    c.sendall(b"RFB 003.008\n")
    cv = recv_exactly(c, 12)
    c.sendall(bytes([1, 1]))            # one security type: None
    chosen = recv_exactly(c, 1)[0]
    if chosen != 1:
        raise RuntimeError(f"client picked security {chosen}, expected 1")
    c.sendall(struct.pack(">I", 0))     # SecurityResult: OK
    shared = recv_exactly(c, 1)         # ClientInit
    c.sendall(serverinit)
    return cv, shared


def pump_server_to_client(srv, cli):
    """Relay verbatim, counting bytes. Message parsing here is not needed:
    the question is what the CLIENT asks for and how much comes back."""
    try:
        while True:
            data = srv.recv(262144)
            if not data:
                break
            with S.lock:
                S.bytes_from_server += len(data)
                S.win_bytes_from_server += len(data)
            cli.sendall(data)
    except Exception:
        pass
    finally:
        try:
            cli.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


def region_label(x, y, w, h, fw, fh):
    if (x, y, w, h) == (0, 0, fw, fh):
        return "FULL-SCREEN"
    frac = (w * h) / max(1, fw * fh)
    return f"{w}x{h}+{x}+{y} ({frac*100:.0f}% of screen)"


def pump_client_to_server(cli, srv, fw, fh):
    """Decode every client->server message, then forward it untouched."""
    buf = b""

    def need(n):
        nonlocal buf
        while len(buf) < n:
            d = cli.recv(65536)
            if not d:
                raise EOFError
            buf += d

    def take(n):
        """Consume n bytes, forward them upstream verbatim, and return them."""
        nonlocal buf
        need(n)
        msg, buf = buf[:n], buf[n:]
        srv.sendall(msg)
        with S.lock:
            S.bytes_to_server += n
        return msg

    try:
        while True:
            need(1)
            t = buf[0]
            if t == 0:                       # SetPixelFormat
                msg = take(20)
                with S.lock:
                    S.pixel_format_sets += 1
                bpp, depth, be, tc = msg[4], msg[5], msg[6], msg[7]
                print(f"  [client] SetPixelFormat bpp={bpp} depth={depth} "
                      f"bigendian={be} truecolour={tc}")
            elif t == 2:                     # SetEncodings
                need(4)
                cnt = struct.unpack(">H", buf[2:4])[0]
                msg = take(4 + 4 * cnt)
                encs = [struct.unpack(">i", msg[4 + 4 * i:8 + 4 * i])[0] for i in range(cnt)]
                named = [ENC_NAMES.get(e, str(e)) for e in encs]
                # The two knobs the auto tuner actually drives.
                jpegq = next((e + 32 for e in encs if -32 <= e <= -23), None)
                comp = next((e + 256 for e in encs if -256 <= e <= -247), None)
                base = [ENC_NAMES.get(e, str(e)) for e in encs if e >= 0]
                with S.lock:
                    S.setenc += 1
                    S.encodings_negotiated = named
                print(f"  [client] SetEncodings  JPEG quality={jpegq}  compression={comp}"
                      f"   base={','.join(base)}")
                if comp == 0:
                    print("           ^^^ compression 0: the server will send "
                          "UNCOMPRESSED tight data")
                if jpegq is None:
                    print("           ^^^ NO JPEG quality advertised: lossless mode")
            elif t == 3:                     # FramebufferUpdateRequest
                msg = take(10)
                inc, x, y, w, h = struct.unpack(">BHHHH", msg[1:10])
                with S.lock:
                    if inc:
                        S.fbur_incr += 1
                        S.fbur_incr_regions[region_label(x, y, w, h, fw, fh)] += 1
                    else:
                        S.fbur_full += 1
                        S.fbur_full_regions[region_label(x, y, w, h, fw, fh)] += 1
            elif t == 4:                     # KeyEvent
                take(8)
                with S.lock:
                    S.keys += 1
            elif t == 5:                     # PointerEvent
                take(6)
                with S.lock:
                    S.pointers += 1
            elif t == 6:                     # ClientCutText
                need(8)
                ln = struct.unpack(">I", buf[4:8])[0]
                take(8 + ln)
                with S.lock:
                    S.other["ClientCutText"] += 1
            elif t == 150:                   # EnableContinuousUpdates
                take(10)
                with S.lock:
                    S.other["EnableContinuousUpdates"] += 1
            elif t == 248:                   # ClientFence
                need(9)
                ln = buf[8]
                take(9 + ln)
                with S.lock:
                    S.other["ClientFence"] += 1
            elif t == 255:                   # QEMU extended key event
                need(2)
                sub = buf[1]
                size = {0: 12}.get(sub)
                if size is None:
                    with S.lock:
                        S.other[f"vendor255/{sub} UNPARSED"] += 1
                    raise RuntimeError(f"cannot frame vendor message 255/{sub}")
                take(size)
                with S.lock:
                    S.other[f"qemu{sub}"] += 1
            else:
                with S.lock:
                    S.other[f"UNKNOWN type {t}"] += 1
                raise RuntimeError(f"unknown client message type {t}; framing lost")
    except Exception as e:
        print(f"  [client->server pump ended: {e}]")
    finally:
        try:
            srv.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


def reporter(fw, fh, every):
    last = time.time()
    while True:
        time.sleep(every)
        now = time.time()
        dt = now - last
        last = now
        with S.lock:
            kb = S.win_bytes_from_server / 1024 / dt
            line = (f"[{time.strftime('%H:%M:%S')}] "
                    f"down {kb:8.0f} KB/s | "
                    f"req incr {S.fbur_incr/dt:5.1f}/s  "
                    f"req FULL {S.fbur_full/dt:5.1f}/s | "
                    f"keys {S.keys:3d} ptr {S.pointers:4d} setenc {S.setenc}")
            print(line, flush=True)
            if S.fbur_full:
                for r, c in S.fbur_full_regions.most_common(3):
                    print(f"           NON-INCREMENTAL -> {r}  x{c}", flush=True)
            if S.other:
                print(f"           other: {dict(S.other)}", flush=True)
            S.reset()


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py proxy",
        description="RFB man-in-the-middle. Decodes every client->server "
                    "message and counts every server->client byte.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Healthy: compression 1 to 9 on every SetEncodings, sustained "
               "'down' under about 1000 KB/s for a mostly-idle desktop.\n"
               "Unhealthy: 'compression=0', or 'down' above 2000 KB/s while "
               "nothing on the remote is moving.",
    )
    p.add_argument("--port", type=int, default=5901, metavar="N",
                   help="local port to listen on (default 5901)")
    p.add_argument("--listen", default="127.0.0.1", metavar="ADDR",
                   help="local address to bind (default 127.0.0.1, loopback "
                        "only, because the proxy offers security type None)")
    p.add_argument("--target", default=os.environ.get("DVV_HOST", "127.0.0.1"),
                   metavar="HOST",
                   help="real VNC server to relay to (default $DVV_HOST, else 127.0.0.1)")
    p.add_argument("--target-port", type=int, default=5900, metavar="N",
                   help="real VNC server port (default 5900)")
    p.add_argument("--interval", type=float, default=2.0, metavar="SECONDS",
                   help="seconds between summary lines (default 2)")
    creds.add_credential_args(p)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    password = creds.password_from_args(args)
    print(creds.describe_source(args.profile))

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.listen, args.port))
    ls.listen(1)
    print(f"RFB proxy listening on {args.listen}:{args.port} -> {args.target}:{args.target_port}")
    print(f"Point the client under test at {args.listen}:{args.port} (no password needed)\n")

    cli, addr = ls.accept()
    cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"client connected from {addr}")

    srv, serverinit = server_handshake(args.target, args.target_port, password)
    fw, fh = struct.unpack(">HH", serverinit[0:4])
    name = serverinit[24:].decode("latin-1", "replace")
    print(f"upstream server {name!r} {fw}x{fh}")

    client_handshake(cli, serverinit)
    print("handshake complete, relaying\n")

    threading.Thread(target=pump_server_to_client, args=(srv, cli), daemon=True).start()
    threading.Thread(target=reporter, args=(fw, fh, args.interval), daemon=True).start()
    pump_client_to_server(cli, srv, fw, fh)


if __name__ == "__main__":
    main()
