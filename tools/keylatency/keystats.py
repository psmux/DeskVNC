import re,sys
ansi=re.compile(r'\x1b\[[0-9;]*m')
def hms(s):
    h,m,sec=s.split(':'); return int(h)*3600+int(m)*60+float(sec)
def load(log,posts):
    ev=[]
    for line in open(log):
        line=ansi.sub('',line)
        m=re.match(r'\S+T(\d\d:\d\d:\d\d\.\d+)Z\s+\w+\s+\S+:\s+(.*)',line)
        if not m: continue
        ts,msg=m.groups()
        if msg.startswith('UI mark'):
            mm=re.search(r'label=(\w+) at=(\S+)',msg); ev.append((hms(mm.group(2)),'ui_'+mm.group(1)))
        elif msg.startswith('TX KeyEvent'): ev.append((hms(ts),'tx_key'))
        elif msg.startswith('RX FramebufferUpdate header'): ev.append((hms(ts),'rx_hdr'))
    P=[]
    for line in open(posts):
        mm=re.match(r'POST (\S+) down\s+(\d\d:\d\d:\d\d\.\d+)',line)
        if mm: P.append((hms(mm.group(2)),mm.group(1)))
    ev.sort(); return ev,P
def first_after(ev,t,kind):
    for e in ev:
        if e[0]>t and e[1]==kind: return e[0]
    return None
for tag in sys.argv[1:]:
    ev,P=load(f'trace_{tag}.log',f'posts_{tag}.txt')
    rows=[]
    for t,k in P:
        js=first_after(ev,t,'ui_key_down'); tx=first_after(ev,t,'tx_key'); rx=first_after(ev,tx,'rx_hdr') if tx else None
        dr=first_after(ev,rx,'ui_frame_drawn') if rx else None
        rows.append((k,(js-t)*1000 if js else None,(tx-t)*1000 if tx else None,(rx-t)*1000 if rx else None,(dr-t)*1000 if dr else None))
    print(f'== {tag}: ms from OS key event to: seen by JS | on the socket | first update back | painted')
    for r in rows: print('  %-3s '%r[0]+' | '.join('%6.0f'%x if x is not None else '   -  ' for x in r[1:]))
    import statistics
    for i,name in enumerate(['js','socket','update','painted'],1):
        xs=[r[i] for r in rows if r[i] is not None]
        if xs: print(f'  median {name:8s} {statistics.median(xs):6.0f}   max {max(xs):6.0f}')
