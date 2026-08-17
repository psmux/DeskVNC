#!/usr/bin/env python3
"""limb: scan. Find and fingerprint every RFB server on a host.

Answers: "are we even talking to the same server as the client we are being
compared against?"

If RealVNC Viewer is smooth against "the same machine" while we are slow, the
first thing to rule out is that it is talking to a different server process on
a different port with a different encoder. A macOS box can easily be running
the built-in Screen Sharing server and a third party one at the same time, and
they perform nothing like each other.

Also worth running before any other limb: the security types a server offers
decide whether the python limbs can authenticate at all. They speak plain VNC
auth (type 2) and nothing else, so a server offering only Apple DH (30) or
VeNCrypt (19) has to be tested through the app instead.

No authentication is attempted and no password is needed. The scan stops at
the security-types list, so it cannot log in and cannot disturb a session.

  ./limbs.py scan --host 192.168.77.173
"""
import argparse
import socket
import struct

SEC_NAMES = {
    0: "Invalid", 1: "None", 2: "VNC auth", 5: "RA2", 6: "RA2ne",
    13: "RA2_256", 14: "RA2ne_256", 16: "Tight", 18: "TLS", 19: "VeNCrypt",
    20: "SASL", 21: "MD5 hash", 22: "xvp", 30: "Apple DH", 35: "Apple ARD",
}

# The display range VNC servers conventionally use (5900 + display number),
# plus the Java applet port, the listening-viewer port and a couple of ports
# third party servers are known to pick.
DEFAULT_PORTS = [5800, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908,
                 5909, 5910, 5999, 6000, 5500, 4900, 63000]


def probe(host, port, connect_timeout, read_timeout):
    try:
        s = socket.create_connection((host, port), connect_timeout)
    except Exception:
        return None
    s.settimeout(read_timeout)
    try:
        banner = s.recv(12)
        if not banner.startswith(b"RFB "):
            return ("open, not RFB", banner[:24])
        s.sendall(b"RFB 003.008\n")
        n = s.recv(1)[0]
        if n == 0:
            ln = struct.unpack(">I", s.recv(4))[0]
            return (banner.decode().strip(), f"refused: {s.recv(ln).decode()}")
        types = list(s.recv(n))
        named = ", ".join(f"{t} ({SEC_NAMES.get(t, '?')})" for t in types)
        return (banner.decode().strip(), named)
    except Exception as e:
        return ("open", f"error: {e}")
    finally:
        s.close()


def build_parser():
    p = argparse.ArgumentParser(
        prog="limbs.py scan",
        description="Find every RFB server on a host and report its version "
                    "and security types. No authentication is attempted.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Healthy: exactly one server, offering security type 2 (VNC "
               "auth) so the python limbs can reach it.\n"
               "Unhealthy: two servers on different ports, which means any "
               "client-to-client comparison may be comparing two different "
               "pieces of server software.",
    )
    p.add_argument("--host", default="127.0.0.1", help="host to scan (default 127.0.0.1)")
    p.add_argument("--ports", default=None, metavar="LIST",
                   help="comma separated ports to try (default is the usual "
                        "5800, 5900 to 5910, 5999, 6000, 5500, 4900, 63000)")
    p.add_argument("--connect-timeout", type=float, default=1.5, metavar="SECONDS",
                   help="TCP connect timeout per port (default 1.5)")
    p.add_argument("--read-timeout", type=float, default=2.0, metavar="SECONDS",
                   help="banner read timeout per port (default 2.0)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ports = DEFAULT_PORTS
    if args.ports:
        ports = [int(x) for x in args.ports.split(",") if x.strip()]

    print(f"scanning {args.host}\n")
    found = 0
    for p in ports:
        r = probe(args.host, p, args.connect_timeout, args.read_timeout)
        if r is None:
            continue
        found += 1
        print(f"  port {p:>5} : {r[0]}")
        print(f"              security: {r[1]}")
    if not found:
        print("  nothing listening on the scanned ports")
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
