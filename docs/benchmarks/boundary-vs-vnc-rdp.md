# Boundary, VNC and RDP, measured the same way

This is how I compare DeskVNC's own protocol, Boundary, with VNC and RDP. All
three are measured by the same program, against the same picture, on the same
machine, over the same link. The comparison tables are filled in by
`tools/bench/run-all.sh` on a quiet machine. Until that run, the only numbers
here are the "before" baseline at the end.

## What is measured

A small program called the stage runs on the computer being reached. It draws
five scenes:

1. Idle. A still desktop with a magenta square under the pointer.
2. Typing. A grid where every key press fills the next cell.
3. Scroll. Lines of text that slide up a quarter of a unit every frame.
4. Motion. The whole content area changes every frame, the way a video does.
5. Still. Fine detail (a one pixel checkerboard) that a lossy codec has to
   settle on once motion stops.

Two rows of black and white squares at the top of every frame carry a code:
a frame counter, the stage's clock in milliseconds, the scene, how many keys
it has seen, and a checksum. The measuring client reads that code out of
whatever pixels arrive, so frame rate, dropped frames and latency come from
the content itself, not from what the protocol says about its own updates.

The still scenes draw only when something changes, and every frame puts on
screen only the rectangles that changed. An idle stage is as quiet as an idle
desktop, so a server that follows damage (xrdp, Windows RDP) is not made to
resend the whole screen for nothing.

The client is `remote-bench`. It connects with the same protocol code the
DeskVNC viewer uses (`vnc-core`, `rdp-core`, and `boundary-driver` on top of
`boundary-session`), paints every rectangle that arrives into a framebuffer
as the viewer's canvas would, and decodes JPEG and H.264 rectangles to pixels
(H.264 through openh264, in the bench only). Then it measures:

* Pointer to screen. Move the pointer through the protocol and time until the
  magenta square is painted at the new place. 40 moves, with uneven pauses so
  the moves do not lock to a capture rhythm. Reported as p50, p90 and p99.
* Key to screen. Press a key (with its scancode, as the viewer sends it) and
  time until the next grid cell is painted. 40 presses.
* Frames delivered during scroll and motion, over 10 seconds: distinct stage
  frames seen per second, the stage's own frame rate over the same time, and
  how many frames in the span were never seen.
* Frame latency during scroll and motion: from the moment the stage drew a
  frame (its clock, in the code) to the moment the client painted it. When
  the stage and the client are on different machines the clocks are synced
  NTP style over the stage's control link, keeping the ping with the shortest
  round trip.
* Time to sharp. After 3 seconds of motion the stage switches to the still
  scene. The client records when the first still frame arrives, and when the
  detail patch last changes, which is when the picture is final. It also
  reports how much fine detail the patch holds when it first arrives and at
  the end. The checkerboard measures about 200 when it is pixel exact.
* Bandwidth, as the operating system counts the bytes the client received
  (nettop on macOS; every interface in the container's network namespace on
  Linux) and as the protocol driver counts them where it does.
* CPU: the whole stage machine's, reported by the stage once a second; the
  server processes' (`--watch-procs`); and the client's own.

Every result file records the build it came from, the load average and core
count of the measuring machine, and whether that load was above half a task
per core. A loaded run says LOADED in every table.

## Where it runs

1. Boundary on loopback on a Mac. The host and the helper run in one
   process, and the host's screen is the stage drawn offscreen. No window
   opens and nothing touches the desktop, so this can run while someone works
   on the machine. It leaves out screen capture, so it measures the protocol
   and its encoder.
2. One Linux desktop in a container, served three ways at once. xrdp makes
   the X display when the bench logs in over RDP and starts the stage on it.
   x11vnc and the Boundary host then attach to that same display. RDP, VNC
   and Boundary each get a turn against the same stage, on the same CPU, over
   the container's loopback. This is the fair three way comparison.
3. The same container with its loopback shaped by netem to a 30 ms round trip
   and 30 Mbit/s, which is roughly a good home connection.
4. Boundary to a real computer across the internet: the Customer i9 iMac from
   a MacBook in India. Over SSH macOS only lets a program capture the
   wallpaper, so the i9 runs the offscreen stage. Capture is again left out.

The container's servers are what a Linux user would install: xrdp with
xorgxrdp, and x11vnc with its defaults. The VNC client asks for Tight with
JPEG, as the viewer does. A different VNC server (TigerVNC's own X server)
or Windows' RDP server would give different numbers, so those are named
whenever they are measured.

## Running it

From a branch that has the bench:

```sh
tools/bench/run-all.sh
```

It refuses to start when this machine or the Docker VM carries more than half
a task per core. It writes the raw JSON and CSV to `docs/benchmarks/raw` and
the tables to `docs/benchmarks/latest-<branch>.md`. Each part also runs on
its own:

```sh
remote-bench loopback --bind 127.0.0.1 --label mac-loopback
PROTOS="vnc boundary" tools/bench/run-container.sh
NETEM="delay 15ms rate 30mbit limit 10000" PREFIX=wan tools/bench/run-container.sh
```

For a real host, start the stage there and point the client at it:

```sh
bench-stage --size 960x600 --pos 40,80 --control <client address>:47800
remote-bench run --proto vnc --target host:5900 --password ...
remote-bench run --proto rdp --target host:3389 --user ... --password ...
remote-bench host --bind <host address>          # on the host, for Boundary
remote-bench run --proto boundary --target @host-output.log
```

Typing is skipped, and says so, when the stage window does not have the
keyboard focus, so key presses never land in some other window.

## Baseline: Boundary before the video work

Build 183fa2c, the base of the speed work: tiles of changed screen sent as
JPEG on one QUIC stream. Customer i9 iMac (Intel, macOS 26.7.1), offscreen
stage at 1920x1080, helper on a MacBook in India. The round trip through the
SSH tunnel used for clock sync was 294 ms, and the i9 had a load average of
4.6 from an Android emulator another job left running.

| Measure | Result |
|---|---|
| Pointer to screen | p50 282 ms, p90 299, p99 309 |
| Key to screen | p50 278 ms, p90 285, p99 305 |
| Scroll | 1.3 frames a second of 60, frame latency p50 791 ms, 6.2 Mbit/s |
| Motion | 6.2 frames a second of 60, frame latency p50 321 ms, 10.4 Mbit/s |
| First still frame, and sharp | 727 ms, sharp on arrival |

Input lag sits at the round trip, which is as low as it can go. Anything that
moves is starved: at about 300 ms per round trip and JPEG tiles, a full screen
change costs too much to keep up. That is the row the video work has to beat.
Raw data: `raw/i9-wan-offscreen-base.json`.
