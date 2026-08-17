#!/bin/zsh
# limb: interference. Does one client's behaviour wreck another client's session?
#
# Answers: "the app feels fine to me, so why does everyone else on this server
# complain?" That is a question no single-session measurement can answer, and
# it is the shape of the compression-0 bug: one client saturating the link at
# 9.9 MB/s while its own picture looked perfectly acceptable.
#
# Method: start a LOAD session, let it reach steady state, then measure a
# SEPARATE client's keystroke-to-pixel latency against the same server. The
# load session is stall_probe, which is the real vnc-core client stack with no
# UI, no webview and no live previews. If running it alongside the measurement
# reproduces the lag, the bug is in vnc-core's protocol behaviour and
# everything in ui/ is exonerated. That attribution is the entire point.
#
# The measured client is the python `typing` limb, which shares no code with
# vnc-core at all, so it cannot inherit the same bug and mask it.
#
# Usage:
#   DVV_HOST=192.168.77.173 DVV_PROFILE=<uuid> ./interference.sh <label> [env...]
#
#   ./interference.sh baseline
#   ./interference.sh alr-off   DVV_ALR=0
#   ./interference.sh pinned    DVV_ALR=0 DVV_QUALITY=medium
#
# Environment:
#   DVV_HOST        server to test against (default 127.0.0.1)
#   DVV_PORT        server port (default 5900)
#   DVV_PASS        password, or DVV_PROFILE to read it from the keychain
#   DVV_LOAD_SECS   how long the load session runs (default 160)
#   DVV_SETTLE      seconds to wait before measuring (default 50; the auto
#                   quality tuner needs about 40 s to reach its final rung, and
#                   measuring before that measures the wrong configuration)
#   DVV_SAMPLES     typing samples to take (default 8)
#   DVV_OUT         where logs land (default <repo>/target/limbs)
#   DVV_REPO        repo root override

set -e

# --help before anything else, so it works even when the repo is not built and
# no credentials are configured. The header comment above IS the help text:
# print every leading `#` line and stop at the first line that is not one,
# which keeps the two from drifting apart.
if [ -z "$1" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "${(%):-%x}"
  exit 0
fi

source "${${(%):-%x}:A:h}/_lib.sh"

LABEL="$1"; shift

LOAD_SECS="${DVV_LOAD_SECS:-160}"
SETTLE="${DVV_SETTLE:-50}"
SAMPLES="${DVV_SAMPLES:-8}"

# Explicit `|| exit` rather than relying on set -e: a failing command inside a
# shell function does not always abort the caller, and a measurement taken with
# no load session running is worse than no measurement, because it looks fine.
limbs_resolve_password || exit 1
limbs_require_stall_probe || exit 1

echo "================================================================"
echo "  LOAD: $LABEL   ($*)"
echo "  server $DVV_HOST:$DVV_PORT   load ${LOAD_SECS}s   settle ${SETTLE}s"
echo "================================================================"

LOG="$OUT_DIR/load-$LABEL.log"

# Start the load session in the background. RUST_LOG=error keeps the log to the
# stall lines: at trace level the logging itself perturbs the timing.
env DVV_HOST="$DVV_HOST" DVV_PORT="$DVV_PORT" DVV_SECONDS="$LOAD_SECS" \
    RUST_LOG=error "$@" "$STALL_PROBE" > "$LOG" 2>&1 &
LOAD_PID=$!

# Let it connect and reach steady state.
sleep "$SETTLE"

# Confirm the load session really is connected before trusting the numbers. A
# load arm that silently failed to authenticate produces a beautiful latency
# figure and a completely wrong conclusion.
CONNS=$(lsof -i -n -P 2>/dev/null | grep -c "$DVV_HOST:$DVV_PORT" || true)
echo "  established connections to the server during measurement: $CONNS"
if [ "$CONNS" -lt 1 ]; then
  echo "  WARNING: no connection to $DVV_HOST:$DVV_PORT was found. The load"
  echo "           session may have failed to start; see $LOG"
fi

python3 "$LIMBS_DIR/type_latency.py" \
  --host "$DVV_HOST" --port "$DVV_PORT" --samples "$SAMPLES" 2>&1 | tail -8

kill $LOAD_PID 2>/dev/null || true
wait $LOAD_PID 2>/dev/null || true
echo "  load session log: $LOG"
echo
