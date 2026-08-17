#!/usr/bin/env python3
"""limbs: the diagnostic limbs for DeskVNCViewer. Nothing runs unless invoked.

A "limb" is one self-contained probe that answers exactly one question about a
live VNC session. They exist because the interesting failures in this project
are all attribution problems: the picture is slow, and the candidates are the
network, the server's encoder, our protocol behaviour, our decoder and the
webview, and every one of them looks like the others from inside the app.

This is the on/off switch. There is no daemon, no background sampling, no
always-on instrumentation. A limb runs when you name it and stops when it is
done.

  ./limbs.py                      list the limbs
  ./limbs.py list                 the same, with more detail
  ./limbs.py proxy --help         help for one limb
  ./limbs.py proxy --port 5901 --target 192.168.77.173
  ./limbs.py typing --host 192.168.77.173 --samples 10
  ./limbs.py scan --host 192.168.77.173

Full documentation, including how to read every output and what a healthy
reading looks like, is in docs/DIAGNOSTICS.md.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


class Limb:
    def __init__(self, name, script, question, note=""):
        self.name = name
        self.script = script
        self.question = question
        self.note = note

    @property
    def path(self):
        return os.path.join(HERE, self.script)

    @property
    def is_shell(self):
        return self.script.endswith(".sh")


# Ordered by the sequence you would actually run them in during an
# investigation, not alphabetically. See the decision guide in
# docs/DIAGNOSTICS.md.
LIMBS = [
    Limb("typing", "type_latency.py",
         "How laggy does this server feel, in milliseconds?",
         "sends input: types 'a' and backspaces it. Needs a focused text field."),
    Limb("proxy", "rfb_proxy.py",
         "What is the client actually asking the server for?",
         "the limb that found the compression-0 bug. Point a client at it."),
    Limb("probe", "rfb_probe.py",
         "Is this server slow, or is our client slow?",
         "read only. Also the library the other python limbs import."),
    Limb("scan", "scan.py",
         "Which RFB servers are on this host, and what auth do they offer?",
         "read only, no password needed."),
    Limb("region", "region_cost.py",
         "What does one update cost this server, by region size?",
         "read only."),
    Limb("wire", "raw_vs_tight.py",
         "Is the link slow, or is the server's encoder slow?",
         "read only. Pulls a full uncompressed screen, so it is not cheap."),
    Limb("quality", "quality_rungs.py",
         "What does each rung of the Auto quality ladder really cost?",
         "read only."),
    Limb("phase", "phase_test.py",
         "Is a slow echo a polling cycle or a fixed deferral?",
         "sends input. Needs a focused text field."),
    Limb("interference", "interference.sh",
         "Does one client's behaviour wreck another client's session?",
         "runs a load session. Needs a release build of stall_probe."),
    Limb("bandwidth", "bandwidth_ab.sh",
         "Does a session's bandwidth climb over time, and which setting causes it?",
         "A/B two configurations. Needs a release build of stall_probe."),
    Limb("paired", "paired_tier.sh",
         "What does a quality setting really cost this server?",
         "paired arms, immune to screen-activity drift. Needs stall_probe."),
]

BY_NAME = {limb.name: limb for limb in LIMBS}


def print_list(verbose=False):
    print(__doc__.strip().splitlines()[0])
    print()
    width = max(len(limb.name) for limb in LIMBS)
    for limb in LIMBS:
        print(f"  {limb.name:<{width}}  {limb.question}")
        if verbose:
            print(f"  {'':<{width}}  {limb.script}")
            if limb.note:
                print(f"  {'':<{width}}  {limb.note}")
            print()
    if not verbose:
        print()
        print("  ./limbs.py list           more detail")
        print("  ./limbs.py <name> --help  help for one limb")
        print("  docs/DIAGNOSTICS.md       how to read every output")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        print_list(verbose=False)
        return 0
    if argv[0] == "list":
        print_list(verbose=True)
        return 0

    name = argv[0]
    rest = argv[1:]
    limb = BY_NAME.get(name)
    if limb is None:
        print(f"no limb named {name!r}\n", file=sys.stderr)
        print_list(verbose=False)
        return 2

    if limb.is_shell:
        cmd = ["/bin/zsh", limb.path] + rest
    else:
        # Run as a subprocess rather than importing, so a limb that blocks on a
        # socket or leaves a thread running cannot wedge the dispatcher, and so
        # Ctrl-C reaches the limb and nothing else.
        cmd = [sys.executable, limb.path] + rest

    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
