#!/bin/sh
# Runs inside the bench container: build the bench from /src, bring up one
# X desktop through xrdp, and measure RDP, VNC and Boundary against it in
# turn. Results go to /out.
set -eu
PREFIX=${PREFIX:-container}
BUILD=${BENCH_BUILD:-unknown}
COUNT=${COUNT:-40}
SECS=${SECS:-10}
PROTOS=${PROTOS:-vnc boundary}
OUT=/out

cd /src
cargo build --release --locked -p bench-stage -p remote-bench --target-dir /target
install -D /target/release/bench-stage /opt/bench/bench-stage
install -D /target/release/remote-bench /opt/bench/remote-bench
B=/opt/bench/remote-bench
COMMON="--build $BUILD --out $OUT --count $COUNT --secs $SECS"

echo 127.0.0.1:47800 > /tmp/bench-control
chmod 644 /tmp/bench-control
/usr/sbin/xrdp-sesman
/usr/sbin/xrdp
sleep 2

# The first RDP login makes display :10 and starts the stage on it, so RDP
# always goes first. xrdp keeps the desktop when the client leaves.
"$B" run --proto rdp --target 127.0.0.1:3389 --user bench --password bench \
    --label "$PREFIX-rdp" --watch-procs xrdp,Xorg --note "xrdp $(dpkg-query -W -f='${Version}' xrdp), xorgxrdp" $COMMON

for proto in $PROTOS; do
  case $proto in
    vnc)
      su bench -c "x11vnc -display :10 -auth /home/bench/.Xauthority -rfbport 5900 -localhost -nopw -forever -shared -bg -o /tmp/x11vnc.log"
      sleep 2
      "$B" run --proto vnc --target 127.0.0.1:5900 --label "$PREFIX-vnc" \
          --watch-procs x11vnc,Xorg --note "x11vnc $(dpkg-query -W -f='${Version}' x11vnc)" $COMMON
      pkill x11vnc || true
      ;;
    boundary)
      su bench -c "DISPLAY=:10 XAUTHORITY=/home/bench/.Xauthority nohup $B host --bind 127.0.0.1 --secs 900 > /tmp/boundary-host.log 2>&1 &"
      for _ in $(seq 60); do
        grep -q '^INVITATION ' /tmp/boundary-host.log && break
        sleep 1
      done
      INVITATION=$(awk '/^INVITATION / {print $2; exit}' /tmp/boundary-host.log)
      "$B" run --proto boundary --target "$INVITATION" --label "$PREFIX-boundary" \
          --watch-procs remote-bench,Xorg --note "Boundary host sharing the real X display" $COMMON
      pkill -f "remote-bench host" || true
      ;;
  esac
done
