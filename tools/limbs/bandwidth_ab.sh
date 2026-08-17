#!/bin/zsh
# limb: bandwidth. A/B two client configurations by their real socket byte count.
#
# Answers: "does this session's bandwidth climb over time, and which setting is
# responsible?"
#
# Why sample the socket rather than trust the client's own counter: a client
# that is confused about what it asked for is also confused about what it
# received. `nettop` reads the kernel's per-process byte counter for the socket
# to the VNC server, which no amount of client-side bookkeeping error can
# distort. This is how "the app says it is fine" and "the app is moving
# 9.9 MB/s" were shown to be true at the same time.
#
# Each arm runs long enough to see a slow degradation. Earlier runs of 20 to
# 45 s were too short: the auto quality tuner takes about 40 s to settle, so a
# short arm measures the ramp rather than the steady state. 75 s is the
# default for that reason.
#
# Usage:
#   DVV_HOST=192.168.77.173 DVV_PROFILE=<uuid> ./bandwidth_ab.sh
#   DVV_HOST=... ./bandwidth_ab.sh "AUTO:DVV_ALR=0" "PINNED:DVV_ALR=0,DVV_QUALITY=medium"
#
# Each argument is one arm, written as LABEL:VAR=VAL,VAR=VAL. With no
# arguments it runs the two arms that isolated the auto tuner: Auto with
# lossless refresh off, against a pinned medium tier.
#
# Environment:
#   DVV_HOST       server to test against (default 127.0.0.1)
#   DVV_PORT       server port (default 5900)
#   DVV_PASS       password, or DVV_PROFILE to read it from the keychain
#   DVV_ARM_SECS   seconds per arm (default 75)
#   DVV_STEP       seconds between bandwidth samples (default 10)
#   DVV_NETTOP_IFACE  nettop interface filter (default wifi; use `loopback` for
#                  a local server, or the whole column reads zero)
#   DVV_OUT        where logs land (default <repo>/target/limbs)
#   DVV_REPO       repo root override

# --help before anything else, so it works even when the repo is not built and
# no credentials are configured. The header comment above IS the help text:
# print every leading `#` line and stop at the first line that is not one,
# which keeps the two from drifting apart.
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "${(%):-%x}"
  exit 0
fi

set -e
source "${${(%):-%x}:A:h}/_lib.sh"

ARM_SECS="${DVV_ARM_SECS:-75}"
STEP="${DVV_STEP:-10}"
NETTOP_IFACE="${DVV_NETTOP_IFACE:-wifi}"

# Explicit `|| exit` rather than relying on set -e: a failing command inside a
# shell function does not always abort the caller, and running an arm with no
# load session produces a page of zeroes that looks like a real measurement.
limbs_resolve_password || exit 1
limbs_require_stall_probe || exit 1

run_arm () {
  local label="$1"; shift
  echo "=================================================="
  echo "  $label   ($*)"
  echo "=================================================="

  local log="$OUT_DIR/ab-$label.log"
  env DVV_HOST="$DVV_HOST" DVV_PORT="$DVV_PORT" DVV_SECONDS="$ARM_SECS" \
      RUST_LOG=error "$@" "$STALL_PROBE" > "$log" 2>&1 &
  local pid=$!
  # Give the session time to connect before the first sample, otherwise the
  # first delta includes the handshake and the initial full paint.
  sleep 4

  # If the session died during those 4 seconds it will never produce a byte,
  # and sampling a dead pid for another 70 s prints a column of zeroes that is
  # indistinguishable from a genuinely idle session.
  if ! kill -0 $pid 2>/dev/null; then
    echo "  ERROR: the load session exited immediately. See $log"
    return 1
  fi

  local prev=0
  local samples=$(( ARM_SECS / STEP ))
  local i
  for (( i = 1; i <= samples; i++ )); do
    if ! kill -0 $pid 2>/dev/null; then
      echo "  (load session ended early at t=$((i * STEP))s; see $log)"
      break
    fi
    # Sum bytes_in for this pid's socket to the VNC server. The interface
    # filter matters: `wifi` is right for the server this was written against,
    # but over ethernet or loopback it silently matches nothing and every
    # sample reads zero, so it is overridable.
    local now=$(nettop -x -t "$NETTOP_IFACE" -l 1 -J bytes_in -p $pid 2>/dev/null \
      | grep "$DVV_HOST:$DVV_PORT" | awk '{print $(NF)}' | head -1)
    now=${now:-0}
    if [ "$prev" -gt 0 ] 2>/dev/null; then
      local d=$(( (now - prev) / STEP ))
      printf "    t=%3ds   %8d KB/s\n" $((i * STEP)) $((d / 1024))
    fi
    prev=$now
    sleep "$STEP"
  done

  # `|| true` on both: under set -e, killing an already-exited process and
  # waiting on a session that ended with a non-zero status would both abort the
  # script before the summary is printed, throwing away the arm's result.
  kill $pid 2>/dev/null || true
  wait $pid 2>/dev/null || true
  echo "  --- session summary ---"
  grep -E "^gap ms|^stalls over 250" "$log" || echo "  (no summary in $log)"
  echo
}

if [ $# -eq 0 ]; then
  set -- "AUTO:DVV_ALR=0" "PINNED-MED:DVV_ALR=0,DVV_QUALITY=medium"
fi

for arm in "$@"; do
  label="${arm%%:*}"
  vars="${arm#*:}"
  if [ "$vars" = "$arm" ]; then
    vars=""
  fi
  # Split the comma separated VAR=VAL list into separate words for `env`.
  run_arm "$label" ${(s:,:)vars}
done
