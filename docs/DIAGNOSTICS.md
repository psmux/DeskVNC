# Diagnostics

The interesting failures in this project are all attribution problems. The
picture is slow, and the candidates are the network, the server's encoder, our
protocol behaviour, our decoder, and the webview. Every one of them looks
exactly like the others from inside the app, and the app is the worst possible
place to stand while you work out which it is.

So there is a set of small probes, one per question, that stand outside the app
and measure one thing each. This document is how to pick one, how to run it, and
how to read what comes back.

Everything here is off by default. There is no daemon, no background sampling,
no always-on instrumentation. A probe runs when you name it and stops when it is
done.

```sh
cd tools/limbs
./limbs.py                      # list them
./limbs.py list                 # the same, with more detail
./limbs.py proxy --help         # help for one
./limbs.py typing --host 192.168.77.173 --samples 10
```

---

## 1. Start here

Pick by symptom, not by curiosity. Each row is the first thing to run, and the
first thing to run is nearly always the cheapest one that can rule something out.

| Symptom | Run first | Then |
|---|---|---|
| "It feels laggy when I type" | `typing` | If the number is bad, `phase` to find out what kind of bad. If it is fine, the problem is in rendering, not the protocol. |
| "Everyone else on this server got slow when I connected" | `proxy` | `interference` to prove it, `bandwidth` to size it. |
| "The picture is pixelated on a fast link" | `proxy` | Watch the JPEG quality line. Then `quality` to see what each rung really costs. |
| "Did my change to the quality ladder help?" | `paired` | Never compare against a baseline taken minutes ago. Section 8 explains why that invalidated several of our own runs. |
| "It freezes for half a second, repeatedly" | `stall_probe` (Rust) | `region` to find out whether a full repaint really costs that much on this server. |
| "It is slower than RealVNC Viewer against the same machine" | `scan` | Confirm you are both talking to the same server first. It is often two different servers. |
| "Is the network or the server the bottleneck?" | `wire` | `region` if the encoder looks implicated. |
| "Bandwidth seems high but I cannot prove it" | `bandwidth` | `proxy` to find the message that caused it. |
| "Am I the one saturating this server?" | `stall_probe` (Rust) | Watch the `duty` column, not a latency number. Section 7 says what healthy looks like and section 8 says why latency will mislead you here. |
| "I have no idea, the app is just wrong" | `probe` | It is read only, takes 15 seconds, and tells you the server's capabilities and round trip floor. Start from facts. |

Two rules of thumb worth stating outright.

Run `typing` before anything else when a human is complaining, because it is the
only number that maps directly onto the complaint. Everything else is a theory
about why that number is what it is.

Run `proxy` the moment you suspect the client, because it is the only probe that
shows what the client actually said rather than what it was supposed to say.
That distinction is what found the bug in section 5.

---

## 2. Credentials

No probe ever takes a password on the command line, because an argument list is
visible to every process on the machine. There are two supported ways in.

**The environment.** Set `DVV_PASS`. This is the normal case and the only one
that works on a machine with no macOS keychain.

```sh
export DVV_PASS='...'
./limbs.py probe --host 192.168.77.173
```

**The macOS keychain.** The app stores its credentials as a JSON blob under
service `com.deskvncviewer.app` with the profile UUID as the account. Give any
probe a profile id and it will read that blob, pull out the password field, and
use it.

```sh
./limbs.py probe --host 192.168.77.173 --profile 0000-your-profile-uuid
# or
export DVV_PROFILE=0000-your-profile-uuid
```

`DVV_PASS` always wins when it is set, so a probe can be pointed at a different
server without touching the keychain.

Every probe prints where its password came from and never what it was:

```
password: from macOS keychain, profile 0000-your-profile-uuid
password: from DVV_PASS (12 characters)
password: none supplied (fine for a server offering security type None)
```

That line exists because "authentication failed" against a real server is
otherwise unattributable. You cannot tell whether the wrong password was used or
the right one was rejected.

Other knobs: `DVV_KEYCHAIN_SERVICE` and `DVV_KEYCHAIN_FIELD` override the
service name and JSON field, which matters for a dev build signed with a
different bundle id. `--keychain-service` does the same on the command line.

The python probes speak security type 2 (VNC auth) and type 1 (None). A server
offering only Apple DH or VeNCrypt has to be tested through the app. Run `scan`
first if you are not sure.

---

## 3. The probes

Nine of them are python and run anywhere python3 does. Two are shell and are
macOS specific, because they use `nettop` and `lsof`.

Only `typing` and `phase` send input. Everything else is read only and cannot
disturb the remote desktop. Both of those type the letter `a` and then send
BackSpace, so the remote ends where it started, but they do require a focused
text field to have anything to measure.

### 3.1 `typing` (`type_latency.py`)

**Question:** how laggy does this server feel, in milliseconds?

This is the number a user actually perceives. It is the baseline too, because it
uses the independent RFB client in `rfb_probe.py` rather than vnc-core. Take the
same measurement while the app is running, and the difference between the two is
our client's fault.

```sh
./limbs.py typing --host 192.168.77.173 --samples 10
./limbs.py typing --host 192.168.77.173 --samples 20 --quiet   # summary only
```

Requires a focused text field on the remote desktop. A text editor, an address
bar, anything with a caret. Without focus there is no damage and every sample
times out with `no damage within 2.0s`.

Per sample it keeps one incremental request outstanding, stamps the clock, sends
the keystroke, and stops the clock when the next update carrying more than four
changed pixels arrives. The four pixel floor matters: a server answering a
probe-style request sends a 1x1 rect with no glyph in it, and counting that as
"the character appeared" reports a latency far below anything a human could see.

Output:

```
keystroke -> pixel, 10 samples (0 timed out)
  min        2.9 ms
  median     3.2 ms
  p95        4.1 ms
  max        5.0 ms
```

**Healthy:** median under about 30 ms on a LAN. The measured baseline against
the server under test was 3.2 ms.

**Unhealthy:** 250 ms or more. Worse, and more informative: a median that is
fine alone and terrible when another client is connected. That points at the
other client, not at the server, and section 3.9 is how you prove it.

### 3.2 `proxy` (`rfb_proxy.py`)

**Question:** what is the client actually asking the server for?

This is the probe that found the bug in section 5, and it is the only one that
shows the client's own words. Every other measurement here tells you a number is
bad. This one tells you which message made it bad.

It sits between a client and the real server. Upstream it does a real handshake
with VNC auth. Downstream it advertises security type 1 (None), so the client
under test connects with no password prompt, which means a release build of the
app can be pointed at it without reconfiguring stored credentials.

```sh
./limbs.py proxy --port 5901 --target 192.168.77.173
# then point the app at 127.0.0.1:5901
```

It binds loopback only by default, and it should stay that way, because it
offers no authentication to whoever connects.

Output has two kinds of line. Events, printed as they happen:

```
  [client] SetPixelFormat bpp=32 depth=24 bigendian=0 truecolour=1
  [client] SetEncodings  JPEG quality=6  compression=3   base=Tight,OpenH264,ZRLE,CopyRect,Hextile,zlib,Raw
```

And a summary every two seconds:

```
[14:27:49] down     2863 KB/s | req incr   0.5/s  req FULL   0.0/s | keys   0 ptr    0 setenc 1
           NON-INCREMENTAL -> FULL-SCREEN  x1
```

Reading it:

* `down` is server to client bytes per second, measured on the socket. This is
  the number that matters to everyone else on the server.
* `req incr` and `req FULL` separate incremental from non-incremental
  FramebufferUpdateRequests. A non-incremental request forces the server to
  encode real content immediately whether or not anything changed, so a high
  `req FULL` rate is a client burning the server's encoder on purpose.
* `NON-INCREMENTAL -> FULL-SCREEN` names the region of each non-incremental
  request. Full screen ones are the expensive ones. A `1x1+0+0` is harmless and
  is usually a client probing for liveness.
* `setenc` counts SetEncodings messages in the window. The auto quality tuner
  re-sends this every time it changes its mind, so a nonzero value here means
  the tuner just moved.

The two warnings it shouts about:

```
           ^^^ compression 0: the server will send UNCOMPRESSED tight data
           ^^^ NO JPEG quality advertised: lossless mode
```

**Healthy:** compression between 1 and 9 on every SetEncodings, `down` under
about 1000 KB/s for a mostly idle desktop, `req FULL` near zero except for the
occasional 1x1.

**Unhealthy:** `compression=0`, or `down` above 2000 KB/s while nothing on the
remote is moving, or a stream of full screen non-incremental requests.

### 3.3 `probe` (`rfb_probe.py`)

**Question:** is this server slow, or is our client slow?

An independent minimal RFB client written from the spec. It does not use
vnc-core, so it cross-checks our client rather than inheriting its assumptions.
When this probe and the app disagree about a server, the app is wrong.

It is also the library the other python probes import, which is why it holds the
pure python DES used for VNC auth and the rect skipping logic for Raw, CopyRect,
Tight, ZRLE, zlib, Hextile and the cursor pseudo-encodings.

```sh
./limbs.py probe --host 192.168.77.173 --watch 10
```

Output:

```
server name      : 'supertop'
screen           : 2880x1800
pixel format     : 32bpp depth24 LE truecolour=True max=(255,255,255) shift=(16,8,0)
ContinuousUpdates: NO  <-- every frame costs a full round trip
Fence            : NO

-- request -> update round trip, 1x1 rect, 30 samples --
  min 2.1 ms   median 2.8 ms   p95 4.0 ms   max 6.2 ms

-- watching 10s of live updates (move a window on the remote now) --
  updates        : 84 (8.4/s)
  rects          : 312 (3.7 per update)
  wire bytes     : 4210 KiB (421 KiB/s)
  encodings      : {'Tight': 300, 'CopyRect': 12}
  update gap     : min 6.1 ms  median 110.4 ms  p95 240.0 ms  max 302.1 ms
```

The 1x1 round trip is the floor. A 1x1 non-incremental request has no side
effects on the remote desktop and forces an immediate answer, so it isolates
round trip cost from encode cost.

`ContinuousUpdates: NO` is the single most important line. Without it, every
frame costs a full client to server to client round trip, which caps the frame
rate before a single pixel is encoded. No amount of client tuning gets under
that floor.

**Healthy:** round trip median under about 15 ms on a LAN.

**Unhealthy:** `ContinuousUpdates: NO` combined with a round trip over 40 ms,
which is a hard ceiling of under 25 frames per second.

Capability discovery is deliberately passive first. Sending
EnableContinuousUpdates or ClientFence to a server that does not implement them
desyncs the stream, so the probe only uses what the server has advertised.

### 3.4 `scan` (`scan.py`)

**Question:** which RFB servers are on this host, and what auth do they offer?

If another viewer is smooth against "the same machine" while we are slow, the
first thing to rule out is that it is talking to a different server process. A
macOS box can easily run the built in Screen Sharing server and a third party
one at the same time, and they perform nothing like each other.

No authentication is attempted, no password is needed, and the scan stops at the
security types list, so it cannot log in and cannot disturb a session.

```sh
./limbs.py scan --host 192.168.77.173
./limbs.py scan --host 192.168.77.173 --ports 5900,5901,5902
```

Output:

```
  port  5900 : RFB 003.008
              security: 2 (VNC auth)
```

**Healthy:** exactly one server, offering security type 2, so the python probes
can reach it.

**Unhealthy:** two servers on different ports, which means any client to client
comparison may have been comparing two different pieces of server software all
along.

### 3.5 `region` (`region_cost.py`)

**Question:** what does one update cost this server, by region size?

Everything here uses non-incremental requests, which a server must answer
immediately with real content. That is the whole trick, because an incremental
request against a still desktop tells you nothing: the server is entitled to sit
on it indefinitely.

```sh
./limbs.py region --host 192.168.77.173
```

Output:

```
          region      min   median      p95      max      KiB   rects
             1x1     2.1ms    2.6ms    3.4ms    4.0ms        0     1.0
           64x64     3.0ms    3.9ms    5.1ms    6.0ms        2     1.0
         256x256     8.2ms   10.1ms   14.0ms   16.2ms       18     1.0
         640x480    28.4ms   33.0ms   40.1ms   44.0ms       84     4.0
        1280x720    70.1ms   79.2ms   95.0ms  101.0ms      240    12.0
  2880x1800 FULL   131.0ms  148.0ms  175.0ms  182.0ms      910    43.0

sustained full-screen repaint, 15 back-to-back requests
  min 128.0 ms  median 146.0 ms  p95 172.0 ms  max 180.0 ms   -> 6.8 full frames/s ceiling
```

If answer time is flat across sizes the server has a fixed per request cost, a
capture or polling cycle, and asking for smaller regions will not help. If it
scales with area, the encoder is the cost and clipping the damage rect is worth
doing.

The last line is the number that ends arguments. `1000 / median` is the highest
full frame rate this server can produce for anybody, and it is shared with every
other client connected to it.

**Healthy:** full screen median under about 60 ms, so over 15 full frames per
second are available.

**Unhealthy:** full screen median of 120 to 180 ms, which is a 5 to 8 frames per
second ceiling. That was the reading on the 2880x1800 machine, and it is why a
client that issues full screen non-incremental requests in a loop is so
destructive there.

### 3.6 `wire` (`raw_vs_tight.py`)

**Question:** is the link slow, or is the server's encoder slow?

Those two look identical from the app and the fix for one is useless for the
other.

Raw is a known, incompressible byte count and the server does essentially no
work to produce it, so a full screen Raw pull is dominated by the wire. Then the
same screen is pulled with Tight on the same connection at the same moment, so
no drift in the network between two separate runs can be blamed.

```sh
./limbs.py wire --host 192.168.77.173
```

Output:

```
Raw full screen, expecting ~19.8 MiB of pixels
  19.8 MiB in 6800 ms -> 24.4 Mbit/s effective wire rate
  repeat: 19.8 MiB in 6600 ms -> 25.1 Mbit/s

Tight full screen: 910 KiB in 148 ms, 43 rects -> 50.3 Mbit/s of compressed bytes
  if the wire were the only limit this would take 373 ms at 20 Mbit/s
```

**Healthy:** the Raw figure lands near the link's real capacity and Tight's much
smaller payload arrives proportionally faster.

**Unhealthy:** Raw reports about 24 Mbit/s effective while the link is known
good, which means the server cannot shovel even uncompressed pixels at line
rate, and no client side change will fix that.

### 3.7 `quality` (`quality_rungs.py`)

**Question:** what does each rung of the Auto quality ladder really cost?

The Auto tuner picks a JPEG quality and Tight compression pair and assumes lower
quality means fewer bytes and less server work. That assumption holds only if
the server honours the pseudo-encodings the way the tuner expects. On the
machine in section 5 it did not.

```sh
./limbs.py quality --host 192.168.77.173
```

It walks every rung, including the pathological one, measuring bytes and latency
per full screen:

```
JPEG q9 / compress 0  (THE BUG: server stops compressing)
    median   410.0 ms   max   480.0 ms    3800 KiB per full screen
JPEG q9 / compress 1  (High preset, least server work)
    median   150.0 ms   max   180.0 ms     980 KiB per full screen
JPEG q6 / compress 3  (Auto starting point)
    median   148.0 ms   max   176.0 ms     720 KiB per full screen
JPEG disabled         (auto-lossless-refresh)
    median   390.0 ms   max   460.0 ms    3400 KiB per full screen
```

**Healthy:** bytes per full screen fall as quality falls, and compression 1
through 9 all land in the same order of magnitude.

**Unhealthy:** the compression 0 rung ships several times more bytes than every
other rung. That is the server refusing to compress at all, not a mild quality
setting, and the difference is the entire bug in section 5.

The auto lossless refresh path is measured too, because it disables JPEG,
re-sends SetEncodings, and issues a non-incremental request over the accumulated
lossy damage bounding box. On a 2880x1800 screen that box is often most of the
desktop, so the "refresh" is close to a full lossless repaint.

### 3.8 `phase` (`phase_test.py`)

**Question:** is a slow echo a polling cycle or a fixed deferral?

`typing` says 250 ms. This says what kind of 250 ms it is. The two look the same
in a latency histogram and have completely different fixes, so guessing here
wastes days.

The test varies the delay between the last screen activity and the keystroke.

* Polling on period P: the keystroke lands at a random phase in the cycle, so
  echo latency spreads roughly uniformly over 0 to P and tracks the injected
  delay.
* Fixed deferral of D: the server starts a D timer when damage appears, so echo
  latency stays flat at about D no matter when the key is pressed.

```sh
./limbs.py phase --host 192.168.77.173
./limbs.py phase --host 192.168.77.173 --delays 0,0.1,0.2,0.4 --samples 6
```

Output:

```
phase sweep, full-screen request (4 samples per delay)
  injected delay               result
  +0 ms before key             median  248.0 ms   range  240.0 to  259.0   spread  19.0 ms
  +60 ms before key            median  251.0 ms   range  242.0 to  260.0   spread  18.0 ms
  ...
  overall spread across all phases: 21.0 ms (median 249.0 ms)
```

A flat median regardless of the injected delay, as above, means fixed deferral
of about 250 ms, which is usually a server config knob. A wide spread that
tracks the delay means polling, and the period is roughly the spread, which is
about capture method and screen size instead.

The second half asks whether requesting a small region rather than the full
screen changes the answer. If it does not, the server rescans everything it is
asked for regardless, and clipping our requests is wasted effort.

Sends input. Requires a focused text field.

### 3.9 `interference` (`interference.sh`)

**Question:** does one client's behaviour wreck another client's session?

This is the question no single session measurement can answer, and it is the
exact shape of the bug in section 5: one client saturating the link while its
own picture looked perfectly acceptable.

It starts a load session, lets it reach steady state, then measures a separate
client's keystroke to pixel latency against the same server. The load session is
`stall_probe`, which is the real vnc-core client stack with no UI, no webview and
no live previews. If running it alongside the measurement reproduces the lag,
the bug is in vnc-core's protocol behaviour and everything in `ui/` is
exonerated. That attribution is the entire point.

The measured client is the python `typing` probe, which shares no code with
vnc-core at all, so it cannot inherit the same bug and mask it.

Needs a release build first:

```sh
cargo build --release -p vnc-core --example stall_probe
```

Then:

```sh
export DVV_HOST=192.168.77.173
export DVV_PROFILE=0000-your-profile-uuid
./limbs.py interference baseline
./limbs.py interference alr-off   DVV_ALR=0
./limbs.py interference pinned    DVV_ALR=0 DVV_QUALITY=medium
```

Every argument after the label is passed to the load session as an environment
variable, so any `stall_probe` knob from section 4 can be A/B tested.

Output:

```
================================================================
  LOAD: baseline   ()
  server 192.168.77.173:5900   load 160s   settle 50s
================================================================
  established connections to the server during measurement: 2
keystroke -> pixel, 8 samples (0 timed out)
  min      259.0 ms
  median   301.0 ms
  p95      402.0 ms
  max      414.0 ms
```

The connection count line is not decoration. A load arm that silently failed to
authenticate produces a beautiful latency figure and a completely wrong
conclusion, so the script checks and warns.

The 50 second settle is deliberate. The auto quality tuner takes about 40
seconds to reach its final rung, and measuring before that measures the wrong
configuration. Override with `DVV_SETTLE` if you know what you are doing.

**Healthy:** the latency under load matches the latency measured alone.

**Unhealthy:** any large gap between the two. In section 5 it was 3.2 ms alone
against 259 to 414 ms under load.

Environment: `DVV_HOST`, `DVV_PORT`, `DVV_LOAD_SECS` (default 160), `DVV_SETTLE`
(default 50), `DVV_SAMPLES` (default 8), `DVV_OUT` (default
`<repo>/target/limbs`), `DVV_STALL_PROBE`, `DVV_REPO`.

### 3.10 `bandwidth` (`bandwidth_ab.sh`)

**Question:** does a session's bandwidth climb over time, and which setting is
responsible?

It samples the kernel's per process byte counter with `nettop` rather than
trusting the client's own accounting, because a client that is confused about
what it asked for is also confused about what it received. This is how "the app
says it is fine" and "the app is moving 9.9 MB/s" were shown to be true at the
same time.

```sh
export DVV_HOST=192.168.77.173
export DVV_PROFILE=0000-your-profile-uuid
./limbs.py bandwidth
./limbs.py bandwidth "AUTO:DVV_ALR=0" "PINNED:DVV_ALR=0,DVV_QUALITY=medium"
```

Each argument is one arm, written as `LABEL:VAR=VAL,VAR=VAL`. With no arguments
it runs the two arms that isolated the auto tuner.

Output:

```
==================================================
  AUTO   (DVV_ALR=0)
==================================================
    t= 20s       2863 KB/s
    t= 30s       3104 KB/s
    t= 40s       4208 KB/s
  --- session summary ---
gap ms : median 41.0   p90 210.0   p99 540.0   max 920.5
stalls over 250 ms : 38  (0.5 per second)
```

Arms run 75 seconds by default, because earlier 20 to 45 second runs were too
short: the tuner takes about 40 seconds to settle, so a short arm measures the
ramp rather than the steady state.

**Healthy:** a flat column. Bandwidth that is the same at t=70s as at t=20s.

**Unhealthy:** a column that climbs. That is the tuner walking itself into a
worse configuration over time, which is exactly what it did.

One gotcha: `nettop` is filtered by interface and the default is `wifi`. Against
a server reached over ethernet or loopback the filter matches nothing and every
sample reads zero. Set `DVV_NETTOP_IFACE=loopback` (or the right interface) in
that case.

Environment: `DVV_HOST`, `DVV_PORT`, `DVV_ARM_SECS` (default 75), `DVV_STEP`
(default 10), `DVV_NETTOP_IFACE` (default wifi), `DVV_OUT`, `DVV_STALL_PROBE`,
`DVV_REPO`.

### 3.11 `paired` (`paired_tier.sh`)

**Question:** what does a quality setting really cost this server, and is Auto
picking a sane one?

This is the limb that verified the server-latency cap, and the one to reach for
whenever a change to the quality ladder needs proving. It is also the practical
answer to section 8: it alternates two settings in short back-to-back arms, so
remote screen activity cannot drift between them.

```sh
cd tools/limbs
DVV_HOST=192.168.77.173 DVV_PROFILE=<uuid> ./paired_tier.sh 4 30 high medium
DVV_HOST=192.168.77.173 DVV_PROFILE=<uuid> ./paired_tier.sh 3 40 auto medium
```

Arms are any `DVV_QUALITY` value: `auto`, `high`, `medium`, `low`. Each arm
reports `server_duty_cycle`, throughput and `rtt_ms`, averaged with the first
three ticks skipped because the priming full-screen paint is not steady state.

**Healthy vs unhealthy.** Measured on a TightVNC-family server at 2880x1800 over
an 82 Mbit/s link, four rounds of 30 s, before the cap existed:

```
         |         HIGH tier          |        MEDIUM tier
  round  |  duty    Mbit/s    rtt ms  |  duty    Mbit/s    rtt ms
      1  |  42.7%    36.49     428.2  |  27.9%    17.11      18.5
      2  |  42.8%    36.45     425.8  |  28.4%    17.11      20.6
      3  |  43.1%    36.33     434.4  |  27.2%    16.47     245.3
      4  |  43.2%    36.34     432.3  |  17.7%    10.53     181.6
```

High bought about twice the bandwidth and cost about twenty times the round trip.
That is the measurement behind `SERVER_LATENCY_BUDGET_MS` in
`crates/vnc-core/src/quality/mod.rs`.

After the cap, the same harness comparing Auto against Medium shows Auto tracking
Medium instead of climbing to High:

```
      1  |  19.2%    11.48     154.2  |  19.8%    11.38     140.9
      2  |  26.4%    21.04      39.0  |  18.5%     9.64      66.7
      3  |  18.3%     9.62     206.1  |  19.1%     9.62     164.0
```

Read DOWN a column for consistency and ACROSS for the effect of the setting. A
duty cycle above roughly 40% together with a round trip in the hundreds of
milliseconds means the session is monopolising the server, and that hurts its own
input echo as much as anyone else's.

Environment: `DVV_HOST`, `DVV_PORT`, `DVV_PROFILE` or `DVV_PASS`, `DVV_OUT`,
`DVV_STALL_PROBE`, `DVV_REPO`.

---

## 4. The Rust probes

These live in `crates/vnc-core/examples/` and drive the real client stack, which
is the difference that matters: the python probes tell you what a good client
would experience, and these tell you what OUR client experiences. Run both and
the gap between them is the bug.

Build once, then run the binary directly, or use `cargo run`:

```sh
cargo build --release -p vnc-core --example stall_probe
```

### 4.1 `stall_probe`

**Question:** where are the freezes, how long are they, and what causes them?

The most useful of the Rust probes. It logs every framebuffer update's arrival
and size, then reports the gap distribution and the worst stalls.

```sh
DVV_HOST=192.168.77.173 DVV_PASS=... DVV_SECONDS=60 \
  cargo run --release -p vnc-core --example stall_probe
```

Environment:

| Variable | Meaning |
|---|---|
| `DVV_HOST` | server address (default 127.0.0.1) |
| `DVV_PORT` | server port (default 5900) |
| `DVV_PASS` | password. `DVV_USER` for the username if the server wants one |
| `DVV_SECONDS` | how long to run (default 30) |
| `DVV_QUALITY` | `high`, `medium` or `low` to pin the tier. Anything else leaves it on Auto. Pin it when A/B testing something else, so the tuner's flapping does not confound the comparison |
| `DVV_ALR` | set to `0` to disable auto lossless refresh. This is the main A/B knob |
| `DVV_SLOW` | milliseconds to block per update, simulating a slow frame consumer. The shipping app applies each update through a serialized promise chain behind a Tauri IPC hop, and this stands in for that cost so the effect on the SERVER can be measured without running the whole UI |
| `DVV_ALWAYS_REFRESH` | set to `1` to enable the always refresh toolbar toggle three seconds in, which makes the one second tick send a full screen non-incremental request forever |

Output, live. A `STATS` line every second, and a `STALL` line whenever a gap
exceeds 250 ms:

```
[  1.00s] STATS duty   0.1%  rtt    0.0 ms (None)    9.83 Mbit/s   1.0 fps  decode  1.06 ms  jpegq 6
[ 39.42s] STALL   717.0 ms  2565 rects    20250 KiB  damage 2880x1800
[ 40.33s] STALL   532.3 ms    47 rects      213 KiB  damage 307x1786
```

`duty` and the source in brackets after `rtt` are the two fields worth watching.
Section 7 says how to read them.

And a summary:

```
===== 1204 updates over 60s, lossless_refresh=true =====
gap ms : median 41.0   p90 210.0   p99 540.0   max 920.5
stalls over 250 ms : 38  (0.6 per second)
stalls over 400 ms : 21

worst 8 stalls (gap, rects, KiB, seconds since connect):
    920.5 ms  2565 rects    20250 KiB   at t= 49.42s
```

Reading it: the rect count and payload size on a stall line say what kind of
stall it was. A 2565 rect, 20 MiB, full screen damage stall is a full repaint,
and if those cluster near multiples of five seconds it is the auto lossless
refresh cooldown. A 47 rect, 213 KiB stall with a tall narrow damage rect is
something else entirely, usually a window being dragged.

**Healthy:** median gap near the server's real update cadence, few or no stalls
over 250 ms.

**Unhealthy:** a p99 several times the median, or any recurring 20 MiB full
screen repaint.

### 4.2 The others

| Example | Question it answers |
|---|---|
| `link_probe` | What does the update stream actually look like on this link: rect geometry, how much of the screen each update covers, arrival timing, and what the Auto tuner would conclude from it. Takes the target as an argument, `DVV_USER` and `DVV_PASS` from the environment. |
| `live_quality` | What does Auto decide, once a second, and what measurement drove it there. The tuner's inputs are invisible from the UI: the session reports the quality it ended at, never the throughput figure behind it, so "pixelated on a LAN" is otherwise impossible to attribute. |
| `fb_probe` | Is what we accumulated over a long session still the truth? It composes the decoded rect stream into a framebuffer, then connects a second session and takes its first full paint as ground truth. Writes `A.png`, `B.png` and `diff.png`. If A matches B the decode path is correct and any display bug is in the webview renderer. If A is corrupt, the decode path is at fault. |
| `idle_session` | Idle RSS and CPU against the mock server, for the budgets in PRD/13 section 3.6. No live server needed. |
| `input_latency` | The client added input latency vnc-core owns, from handing over a pointer command to the encoded event being read off the socket. Excludes the OS event tap, the webview and the IPC hop. No live server needed. |

---

## 5. Worked example: the compression-0 bug

This is the investigation the probes were built for, start to finish. It is
worth reading once even if you never run any of them, because the shape of it
recurs.

### The complaint

One client connects and every other client on the server becomes unusable. The
client that caused it looked fine to the person using it.

### What the numbers said first

`typing` against the server alone returned a median of 3.2 ms. The server was
not slow. Then `interference` ran the same measurement with one app session as
load, and the same probe returned 259 to 414 ms.

So the server was fine, the network was fine, and our client was doing something
to the server that made it stop serving anyone else. That narrowed it to
something our client was sending, which is precisely what `proxy` is for.

### What `proxy` showed

The app was pointed at the proxy, and the summary was immediately damning:
`down` climbing past 2800 KB/s with `req incr` under 1 per second and nothing
moving on the remote desktop. The client was pulling multiple megabytes a second
to display a static screen.

The cause was two lines apart in the SetEncodings log:

```
  [client] SetEncodings  JPEG quality=6  compression=3   base=Tight,OpenH264,ZRLE,CopyRect,Hextile,zlib,Raw
[14:27:27] down      103 KB/s | req incr   1.0/s  req FULL   0.5/s | keys   0 ptr    0 setenc 1
...
  [client] SetEncodings  JPEG quality=9  compression=0   base=Tight,OpenH264,ZRLE,CopyRect,Hextile,zlib,Raw
           ^^^ compression 0: the server will send UNCOMPRESSED tight data
[14:27:31] down      993 KB/s | req incr   1.0/s  req FULL   0.5/s | keys   0 ptr    0 setenc 0
[14:27:33] down     1861 KB/s | req incr   0.0/s  req FULL   0.0/s | keys   0 ptr    0 setenc 0
[14:27:41] down     2232 KB/s | req incr   0.0/s  req FULL   0.0/s | keys   0 ptr    0 setenc 0
[14:27:49] down     2863 KB/s | req incr   0.5/s  req FULL   0.0/s | keys   0 ptr    0 setenc 1
[14:28:07] down     4669 KB/s | req incr   0.5/s  req FULL   0.0/s | keys   0 ptr    0 setenc 0
[14:28:13] down     5507 KB/s | req incr   0.5/s  req FULL   0.0/s | keys   0 ptr    0 setenc 0
```

Reduced to the two lines that matter:

```
JPEG quality=6  compression=3
JPEG quality=9  compression=0     <-- server stops compressing
```

The auto quality tuner had driven Tight compression to 0. Compression level 0 in
Tight does not mean "compress a little". It means do not compress. The server
obediently stopped compressing and started shipping raw Tight data, and the byte
count went up rather than down, which is the exact opposite of what the tuner
believed it was asking for.

At its worst the session reached 9.9 MB/s, which saturated the 82 Mbit/s link on
its own and starved every other client on the server.

Note the shape of the failure. The tuner was trying to improve quality, it
succeeded (quality went 6 to 9), and the side effect on compression is what did
the damage. Nothing in the client's own view of the world looked wrong, which is
why no amount of client side logging would have found it and why the proxy did.

### The measured consequence

| Measurement | Before | After |
|---|---|---|
| Median session bandwidth (`proxy`, `bandwidth`) | 2863 KB/s | 718 KB/s |
| A separate client's typing latency under load (`interference`) | 259 to 414 ms | 3.4 ms |
| That client's typing latency with no load, for reference (`typing`) | 3.2 ms | 3.2 ms |

3.4 ms against a 3.2 ms baseline is the result worth noticing. After the fix, a
loaded session is statistically indistinguishable from an idle one, which is the
only acceptable answer for a client that shares a server with other people.

### Confirming it stays fixed

```sh
export DVV_HOST=192.168.77.173
export DVV_PROFILE=0000-your-profile-uuid

# 1. The tuner never asks for compression 0 again.
./limbs.py proxy --port 5901 --target 192.168.77.173
#    point the app at 127.0.0.1:5901, drive it for a few minutes, and check
#    that every SetEncodings line shows a compression between 1 and 9.

# 2. Nobody else on the server can tell we are here.
./limbs.py interference fixed
#    expect a median within a millisecond or two of the standalone baseline.

# 3. Bandwidth does not climb over a long session.
./limbs.py bandwidth "FIXED:DVV_ALR=0"
#    expect a flat column, not one that doubles between t=20s and t=70s.
```

---

## 6. The in-app protocol trace

The client can trace its own protocol behaviour, which covers the gap between
the Rust examples (real stack, no UI) and `proxy` (real UI, but only what
reaches the socket). It is the right probe when a problem reproduces only in
the shipping app with the whole UI attached and you need the client's reasoning
rather than its output.

```sh
DVV_TRACE_PROTOCOL=1 <run the app>
```

Off unless the variable is set, and when it is off it costs one never taken
branch per outbound message: the flag is read once, when the run loop is built,
into a bool, so there is no formatting, no allocation and no `tracing`
machinery on the hot path.

Two things must be true or nothing appears.

1. The value must be exactly `1`. `true`, `yes` and `on` all leave it off. It is
   read when the session's run loop is constructed, so set it before the process
   starts.
2. Something must install a `tracing` subscriber that passes INFO for the
   `vnc_core` target. The app does: `src-tauri/src/lib.rs` defaults its filter to
   `info,deskvncviewer_lib=debug`, so no `RUST_LOG` is needed there. Among the
   Rust examples only `live_quality`, `link_probe` and `fb_probe` install a
   subscriber. **`stall_probe` does not**, so `DVV_TRACE_PROTOCOL=1 …
   stall_probe` prints no trace at all. Use `live_quality` when you want the
   trace out of a probe rather than out of the app.

### What it logs, per message

Every client to server message funnels through one `send`, so the trace sees the
protocol as the SERVER sees it rather than as the call sites intended it. At
INFO unless noted:

| Message | Line | Fields |
|---|---|---|
| FramebufferUpdateRequest | `TX FramebufferUpdateRequest` | `incremental`, `x`, `y`, `w`, `h`, `screen_fraction` (requested area as a fraction of the whole desktop) |
| SetEncodings | `TX SetEncodings` | `count`, `encodings` (the raw i32 list, pseudo encodings included, which is where JPEG quality and compression level actually travel) |
| SetPixelFormat | `TX SetPixelFormat` | none |
| EnableContinuousUpdates | `TX EnableContinuousUpdates` | `enable` |
| ClientFence | `TX ClientFence` | `flags` |
| SetDesktopSize | `TX SetDesktopSize` | `w`, `h` |
| ClientCutText | `TX ClientCutText` | `len` |
| KeyEvent, and the QEMU extended key event | `TX KeyEvent`, DEBUG only | none |
| PointerEvent | `TX PointerEvent`, DEBUG only | none |
| anything else | `TX (other)` | `kind`, `len` |

Input is high rate and is rarely the subject of the investigation, so it is
counted at INFO (it appears in the summary line) and printed only at DEBUG. Add
`RUST_LOG=vnc_core=debug` when you want every key and pointer move.

One gap worth knowing before you go looking for a line that never comes: the
FIRST SetPixelFormat and SetEncodings go out during the handshake, from
`session/connection.rs`, before the run loop owns the socket, so they are not
traced. Every later one is, which is what mattered for the bug in section 5,
because there it was the tuner changing compression mid-session.

### The per-second summary

One `protocol trace` line per stats tick, emitted next to the `SessionStats` the
UI receives. The tick nominally fires once a second, and every rate on the line
is divided by the REAL elapsed time, so a tick delayed by one long update does
not inflate the numbers.

| Field | Meaning |
|---|---|
| `fbur_incremental` | incremental FramebufferUpdateRequests sent this tick |
| `fbur_full` | non-incremental ones. This is the count that exposed the always-refresh problem: one per second, each one a whole screen |
| `incremental_screens`, `full_screens` | area requested this tick, counted in whole screens, so `2.0` means we asked the server to encode twice the desktop regardless of how it was split up |
| `last_incremental`, `last_full` | the most recent request of each kind as `WxH+X+Y`, or `-` if none of that kind went out this tick |
| `set_encodings` | SetEncodings sent this tick. Anything other than 0 on a quiet session is the tuner changing its mind |
| `key_events`, `pointer_events`, `other_messages` | counts of the messages that are not printed individually at INFO |
| `jpeg_quality` | the applied JPEG quality |
| `compression` | the negotiated Tight compression level. It is NOT in `SessionStats`, and it is printed here because it is the number that went to 0 in the bug this trace was written for |
| `bytes_per_sec` | received bytes per second (`throughput_bps / 8`) |
| `updates_per_sec` | complete FramebufferUpdates per second, the same figure the UI shows as fps |
| `rects_per_sec` | rects decoded this tick divided by the elapsed time |
| `duty_cycle` | `server_duty_cycle`, a fraction from 0.0 to 1.0, not a percentage. See section 7 |
| `rtt_ms`, `rtt_source` | the round trip and which instrument produced it. See section 7 |

Every counter resets after the line is printed, so each summary describes only
its own tick.

### A real capture

Against the mock server (`cargo run --release -p vnc-core --example
mock_vnc_server`, which prints the ephemeral port it bound, the port argument
is ignored), with the colour escapes stripped:

```
$ DVV_TRACE_PROTOCOL=1 RUST_LOG=vnc_core=info DVV_HOST=127.0.0.1 \
    DVV_PORT=64172 DVV_SECONDS=4 ./target/release/examples/live_quality

connecting to 127.0.0.1:64172 as Auto for 4s
INFO vnc_core::session::connection: server init complete name=DeskVNC mock server width=640 height=480 security=None quality=Auto
[  0.0s] connected
INFO vnc_core::session::run_loop: TX FramebufferUpdateRequest incremental=true x=0 y=0 w=640 h=480 screen_fraction=1.0
[  1.0s]     9.83 Mbit/s | jpeg q6 | enc 0 |   1.0 fps | decode   0.3 ms | rtt   0.0 ms | 1200 KiB
INFO vnc_core::session::run_loop: protocol trace fbur_incremental=1 fbur_full=0 incremental_screens=1.0 full_screens=0.0 last_incremental="640x480+0+0" last_full="-" set_encodings=0 key_events=0 pointer_events=0 other_messages=0 jpeg_quality=6 compression=3 bytes_per_sec=1228852.0 updates_per_sec=1.0 rects_per_sec=4.0 duty_cycle=0.0003164169902447611 rtt_ms=0.0 rtt_source=None
INFO vnc_core::session::run_loop: TX FramebufferUpdateRequest incremental=false x=0 y=0 w=1 h=1 screen_fraction=3.2552084121562075e-6
[  2.0s]     0.00 Mbit/s | jpeg q6 | enc 0 |   0.0 fps | decode   0.0 ms | rtt   0.0 ms | 1200 KiB
INFO vnc_core::session::run_loop: protocol trace fbur_incremental=0 fbur_full=1 incremental_screens=0.0 full_screens=3.2552084121562075e-6 last_incremental="-" last_full="1x1+0+0" set_encodings=0 key_events=0 pointer_events=0 other_messages=0 jpeg_quality=6 compression=3 bytes_per_sec=0.0 updates_per_sec=0.0 rects_per_sec=0.0 duty_cycle=0.0 rtt_ms=0.0 rtt_source=None
```

Three things in that capture are worth pointing at, because they are the ones
that confuse people reading their first trace.

The `1x1+0+0` non-incremental request in the second tick is the idle RTT probe,
not a bug. It asks for one pixel into a quiet gap so the answer can be timed
(section 7).

`rtt_source=None` for the whole run is the mock server, not the client: the
mock never answers that one-pixel request, so no instrument ever produces a
sample. Against any real server this becomes `Fence`, `IdleProbe` or
`UpdatePipeline` within a few seconds. The mock is fine for checking the trace
format and useless for checking latency.

`set_encodings=0` on every line even though the session obviously negotiated
encodings: that is the handshake gap described above.

---

## 7. Reading `rtt_source` and `server_duty_cycle`

Two fields carried on every `SessionStats`, so they reach the UI, `stall_probe`
and the protocol trace alike. They are recent, and they exist because of two
specific ways the older stats lied.

### `rtt_source`: why the latency figure used to be 0.0 forever

`rtt_ms` alone is not interpretable, because three different instruments can
produce it and they do not measure the same thing. `rtt_source` says which one
did. Over the Tauri boundary it serialises kebab-case: `none`, `fence`,
`idle-probe`, `update-pipeline`. In the Rust trace it prints as the enum name:
`None`, `Fence`, `IdleProbe`, `UpdatePipeline`.

| Source | What it is | How to read it |
|---|---|---|
| `Fence` | a ClientFence the server echoes with nothing else in the pipe | exact. Only the TigerVNC family implements the extension |
| `IdleProbe` | a one-pixel non-incremental request timed into a quiet gap | nearly as clean as a fence, but it only yields a sample when the screen happens to be still, so on a busy desktop it can go minutes without a fresh one |
| `UpdatePipeline` | the passive readout on the normal update path: request to next update header during a busy streak | always available and free, but it includes the time this client spent reading the intervening update, so it reads HIGH next to a fence. Read it as "how long until the next picture", which is what the user feels, rather than as a pure network round trip |
| `None` | nothing has been measured | `rtt_ms` is 0.0 and means nothing. Do not plot it, do not average it |

Preference order, in `reported_rtt()`: a fence measurement if the server has the
extension, then the idle probe while its sample is under 5 s old, then the
median of the last 16 passive samples if the newest is under 5 s old. If nothing
is fresh it falls back to a stale figure rather than 0.0, because the UI renders
0.0 as "no measurement at all".

This is the field that explains an old and very expensive symptom. Against a
server without the Fence extension the client had no instrument at all, so
`rtt_ms` sat at exactly 0.0 for the entire session and the panel showed
`0.0 ms` forever. It looked like a perfect link. It was a blank gauge, and the
compression-0 bug in section 5 went unnoticed partly because the one number
that would have shown it was reading zero. If you see `0.0 ms` today, check the
source before you celebrate: `none` means unmeasured.

### `server_duty_cycle`: the saturation signal

The fraction (0.0 to 1.0) of the last stats tick this client spent inside a
FramebufferUpdate: reading its header, pulling its rects off the socket and
decoding them. The run loop is single threaded and parks in `select!` when
nothing is arriving, so that time IS the time the client spent receiving
framebuffer data.

It is the closest honest answer to "how hard is the server working for us". A
server streaming flat out leaves the client permanently inside an update and the
figure approaches 1.0. An idle desktop leaves it parked in the select loop and
the figure approaches 0.0.

Measured reference points, against the server under test:

| Reading | Verdict |
|---|---|
| duty around 0.5% with an idle desktop | healthy. This is the normal resting state |
| duty 46%, 36.9 Mbit/s, rtt 448 ms, at the High quality tier | unhealthy. Nearly half of every second spent inside an update, and the round trip has gone with it |

The 46% sample is the shape to remember: high duty and high throughput together
means the link is loaded, and the latency is the queue you built yourself.

What it does NOT do is separate a slow link from a slow encoder, because both
keep the client inside the update. Pair it with `throughput_bps` to tell them
apart:

* high duty and high throughput: a loaded link. Drop the quality tier or the
  update rate.
* high duty and LOW throughput: the server's encoder is struggling. More
  compression will make it worse, not better.

Why prefer it to a latency number: the duty cycle is a property of our own
session and nothing else on the server can move it. Typing latency cannot say
that, which is the subject of the next section.

---

## 8. The paired-measurement pitfall

This one invalidated several of our own runs before we noticed, so it is written
down rather than learned twice.

Typing latency measured against a live desktop swings by two orders of magnitude
with how busy the remote screen happens to be. The same probe against the same
server returned 3.2 ms and 414 ms in the same afternoon. That is not noise you
can average away, it is a different experiment.

Worse, the sign is not even reliable. A session under load sometimes measures
BETTER than an idle one, because a second client hammering the server keeps its
damage detection warm: the damage is already queued when our request arrives, so
the answer comes back faster than it would on a genuinely quiet server. A
measurement that improves under load is not evidence that load helps.

Two rules follow.

Prefer `server_duty_cycle`. It describes our own session's share of the second
and has no such confound. If the question is "are we saturating anything", it is
the right instrument and wall clock latency is not.

If you must use wall clock latency, alternate the load and no-load arms within
seconds of each other, and interleave them. Never compare against a baseline
taken minutes earlier, however careful that baseline was: the remote desktop
changed in between and you are measuring that instead. `interference` (section
3.9) exists because it runs both arms back to back for exactly this reason.

---

## 9. Adding a probe

Keep the shape. One probe answers one question, it is off unless invoked, it
prints where its password came from and never what it was, and its header
comment says what a healthy reading looks like.

Python probes go in `tools/limbs/`, import `creds` for credentials and
`rfb_probe` for the protocol, expose `build_parser()` and `main(argv=None)`, and
get an entry in the `LIMBS` list in `limbs.py`. Shell probes source `_lib.sh`,
which resolves the repo root from the script's own location so they work from
any checkout and any working directory.

Then document it here, in the same order: what question it answers, how to run
it, what the output means, and what healthy and unhealthy look like. A probe
whose output cannot be read is not a diagnostic.
