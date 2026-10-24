#!/bin/sh
# Runs inside the bench container: build the bench from /src, bring up the
# desktops, and measure each protocol in its best mode against the same
# stage. Results go to /out.
#
# Display :10 is xrdp's (xorgxrdp). On it, in turn:
#   rdp        DeskVNC's RDP client (graphics pipeline 8.1, no H.264 yet)
#   freerdp    FreeRDP 3 with progressive RemoteFX, a reference client,
#              drawing on Xvfb :20 and read off that display. Its H.264
#              mode against this xrdp left stale, smeared pictures on
#              screen, which no bench can read, so it is not used.
#   x11vnc     x11vnc, with XDamage
#   x0vnc      TigerVNC's x0vncserver
#   boundary   the Boundary host
# Display :1 is TigerVNC's Xvnc, its own X server, which is VNC at its
# fastest. A second stage runs there, measured by:
#   xvnc           DeskVNC's VNC client
#   xvnc-boundary  the Boundary host on that same display, for a pair
set -eu
PREFIX=${PREFIX:-container}
BUILD=${BENCH_BUILD:-unknown}
COUNT=${COUNT:-40}
SECS=${SECS:-10}
PROTOS=${PROTOS:-freerdp x11vnc x0vnc boundary xvnc xvnc-boundary}
OUT=/out
SIZE=1920x1080

cd /src
cargo build --release --locked -p bench-stage -p remote-bench --target-dir /target
install -D /target/release/bench-stage /opt/bench/bench-stage
install -D /target/release/remote-bench /opt/bench/remote-bench
B=/opt/bench/remote-bench
COMMON="--build $BUILD --out $OUT --count $COUNT --secs $SECS"

# Shape the loopback link, for example NETEM="delay 15ms rate 30mbit limit
# 10000". Every packet crosses lo once, so the round trip is twice the
# delay. X11 itself runs over a Unix socket and is not shaped.
if [ -n "${NETEM:-}" ]; then
  tc qdisc replace dev lo root netem $NETEM
  tc qdisc show dev lo
fi
NOTE_LINK="${NETEM:+netem $NETEM, }"

as_bench() { su bench -c "$*"; }
focus() { # display, window name
  for _ in $(seq 50); do
    DISPLAY=$1 XAUTHORITY=/home/bench/.Xauthority xdotool search --name "$2" windowfocus 2>/dev/null && return 0
    sleep 0.2
  done
  echo "could not focus $2 on $1" >&2
}
boundary_host() { # display, log
  as_bench "DISPLAY=$1 XAUTHORITY=/home/bench/.Xauthority nohup $B host --bind 127.0.0.1 --secs 900 > $2 2>&1 &"
  for _ in $(seq 60); do
    grep -q '^INVITATION ' "$2" && return 0
    sleep 1
  done
  echo "no invitation in $2" >&2
}

echo 127.0.0.1:47800 > /tmp/bench-control
chmod 644 /tmp/bench-control
/usr/local/sbin/xrdp-sesman
/usr/local/sbin/xrdp
sleep 2

# The first RDP login makes display :10 and starts the stage on it, so RDP
# always goes first. xrdp keeps the desktop when the client leaves.
"$B" run --proto rdp --target 127.0.0.1:3389 --user bench --password bench \
    --label "$PREFIX-rdp" --watch-procs xrdp,Xorg \
    --note "${NOTE_LINK}xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5" $COMMON

for proto in $PROTOS; do
  # One protocol failing must not lose the others' rows.
  set +e
  case $proto in
    freerdp)
      Xvfb :20 -screen 0 ${SIZE}x24 -ac -nolisten tcp > /tmp/xvfb20.log 2>&1 &
      sleep 1
      DISPLAY=:20 nohup xfreerdp3 /v:127.0.0.1 /u:bench /p:bench /cert:ignore \
          /size:$SIZE -decorations /gfx:RFX:on,AVC420:off,AVC444:off /network:lan /audio-mode:2 -clipboard \
          > /tmp/xfreerdp.log 2>&1 &
      sleep 4
      focus :20 FreeRDP
      # What xrdp chose for this client, from its own log.
      MODE=$(grep -o 'Matched [A-Za-z0-9.]* mode' /var/log/xrdp.log | tail -1)
      DISPLAY=:20 "$B" run --proto local --as rdp \
          --client "FreeRDP $(dpkg-query -W -f='${Version}' freerdp3-x11) xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap" \
          --label "$PREFIX-freerdp" --watch-procs xrdp,Xorg,xfreerdp \
          --note "${NOTE_LINK}xrdp 0.10.6.1 with x264, reference client, xrdp log: ${MODE:-no codec line}" $COMMON
      pkill xfreerdp3 || true
      pkill -f "Xvfb :20" || true
      ;;
    x11vnc)
      as_bench "x11vnc -display :10 -auth /home/bench/.Xauthority -rfbport 5900 -localhost -nopw -forever -shared -bg -o /tmp/x11vnc.log"
      sleep 2
      "$B" run --proto vnc --target 127.0.0.1:5900 --label "$PREFIX-x11vnc" \
          --watch-procs x11vnc,Xorg --note "${NOTE_LINK}x11vnc $(dpkg-query -W -f='${Version}' x11vnc) on the xrdp display" $COMMON
      pkill x11vnc || true
      ;;
    x0vnc)
      as_bench "XAUTHORITY=/home/bench/.Xauthority nohup x0vncserver -display :10 -rfbport 5902 -localhost -SecurityTypes None > /tmp/x0vnc.log 2>&1 &"
      sleep 2
      "$B" run --proto vnc --target 127.0.0.1:5902 --label "$PREFIX-x0vnc" \
          --watch-procs x0vncserver,Xorg --note "${NOTE_LINK}TigerVNC x0vncserver $(dpkg-query -W -f='${Version}' tigervnc-scraping-server) on the xrdp display" $COMMON
      pkill x0vncserver || true
      ;;
    boundary)
      boundary_host :10 /tmp/boundary-host.log
      "$B" run --proto boundary --target @/tmp/boundary-host.log --label "$PREFIX-boundary" \
          --watch-procs remote-bench,Xorg --note "${NOTE_LINK}Boundary host on the xrdp display" $COMMON
      pkill -f "remote-bench host" || true
      ;;
    xvnc|xvnc-boundary)
      if ! pgrep -f "Xvnc :1" > /dev/null; then
        as_bench "nohup Xvnc :1 -geometry $SIZE -depth 24 -rfbport 5901 -localhost -SecurityTypes None -AlwaysShared > /tmp/xvnc.log 2>&1 &"
        sleep 2
        as_bench "DISPLAY=:1 nohup /opt/bench/bench-stage --borderless --pos 0,0 --size $SIZE --control 127.0.0.1:47801 --secs 36000 > /tmp/bench-stage-xvnc.log 2>&1 &"
        sleep 2
        focus :1 "DeskVNC bench stage"
      fi
      if [ "$proto" = xvnc ]; then
        "$B" run --proto vnc --target 127.0.0.1:5901 --control 47801 --label "$PREFIX-xvnc" \
            --watch-procs Xvnc --note "${NOTE_LINK}TigerVNC Xvnc $(dpkg-query -W -f='${Version}' tigervnc-standalone-server), its own X server" $COMMON
      else
        boundary_host :1 /tmp/boundary-host-xvnc.log
        "$B" run --proto boundary --target @/tmp/boundary-host-xvnc.log --control 47801 \
            --label "$PREFIX-xvnc-boundary" --watch-procs remote-bench,Xvnc \
            --note "${NOTE_LINK}Boundary host on the Xvnc display" $COMMON
        pkill -f "remote-bench host" || true
      fi
      ;;
  esac
  set -e
done
