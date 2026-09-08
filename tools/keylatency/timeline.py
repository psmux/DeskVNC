"""Print one timeline from trace.log (+ optional key.py output): everything
between the first and last event of interest, relative ms, so a keystroke can
be followed key_down -> TX KeyEvent -> RX header -> emitted -> webview ->
applied -> drawn."""
import re, sys, datetime
log = sys.argv[1]; posts = sys.argv[2] if len(sys.argv) > 2 else None
t0 = sys.argv[3] if len(sys.argv) > 3 else None   # HH:MM:SS start filter
t1 = sys.argv[4] if len(sys.argv) > 4 else None
ansi = re.compile(r'\x1b\[[0-9;]*m')
ev = []
def hms(s):
    h, m, sec = s.split(':'); return int(h) * 3600 + int(m) * 60 + float(sec)
for line in open(log):
    line = ansi.sub('', line).rstrip()
    m = re.match(r'(\d{4}-\d\d-\d\dT)(\d\d:\d\d:\d\d\.\d+)Z\s+\w+\s+(\S+):\s+(.*)', line)
    if not m: continue
    ts, src, msg = m.group(2), m.group(3), m.group(4)
    if msg.startswith('UI mark'):
        mm = re.search(r'label=(\w+) at=(\S+) n=(\d+)', msg)
        ev.append((hms(mm.group(2)), 'UI  ' + mm.group(1) + ' n=' + mm.group(3)))
    elif msg.startswith('TX KeyEvent') or msg.startswith('RX FramebufferUpdate') or msg.startswith('frame -> webview') or msg.startswith('TX FramebufferUpdateRequest') or msg.startswith('TX PointerEvent'):
        ev.append((hms(ts), msg[:90]))
if posts:
    for line in open(posts):
        mm = re.match(r'POST (\S+) (down|up)\s+(\d\d:\d\d:\d\d\.\d+)', line)
        if mm: ev.append((hms(mm.group(3)), 'POST ' + mm.group(1) + ' ' + mm.group(2)))
ev.sort()
if t0: ev = [e for e in ev if e[0] >= hms(t0)]
if t1: ev = [e for e in ev if e[0] <= hms(t1)]
base = ev[0][0] if ev else 0
prev = base
for t, msg in ev:
    print(f"{(t-base)*1000:9.1f}  +{(t-prev)*1000:6.1f}  {msg}")
    prev = t
