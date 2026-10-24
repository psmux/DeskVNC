#!/bin/sh
# Every run the published comparison uses, on this checkout's code, labelled
# with the branch and commit. Run it from any branch that has the bench
# (merge origin/fast-bench in first):
#
#   tools/bench/run-all.sh
#
# 1. Boundary on loopback on this Mac, offscreen stage (no window, no input
#    to this desktop).
# 2. RDP, VNC and Boundary on one Linux desktop in a container, loopback.
# 3. The same with the container's loopback shaped to a 30 ms round trip and
#    30 Mbit/s.
#
# Then it writes docs/benchmarks/latest-<branch>.md with the tables.
#
# It refuses to start when this machine, or the Docker VM, carries more than
# half a task per core: a busy machine measures the machine. BENCH_FORCE=1
# runs anyway, and every result records its load and says LOADED in the
# tables. To keep the container off a VM that other work shares, give it its
# own: colima start -p bench --cpu 4 --memory 4, then DOCKER_CONTEXT=colima-bench.
# colima start makes its profile the current Docker context for everyone, so
# run docker context use colima straight after it if other work uses Docker.
set -eu
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
BRANCH=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)
COMMIT=$(git -C "$ROOT" rev-parse --short HEAD)
BUILD=${BENCH_BUILD:-$BRANCH@$COMMIT}
OUT="$ROOT/docs/benchmarks/raw"
TAG="$BRANCH-$COMMIT"
mkdir -p "$OUT"

# Load and cores, as "load cores", for this machine and for the Docker VM.
here() {
  if [ "$(uname)" = Darwin ]; then
    echo "$(sysctl -n vm.loadavg | awk '{print $2}') $(sysctl -n hw.ncpu)"
  else
    echo "$(cut -d' ' -f1 /proc/loadavg) $(nproc)"
  fi
}
vm() {
  docker run --rm alpine:3.20 sh -c 'echo "$(cut -d" " -f1 /proc/loadavg) $(nproc)"'
}
busy() {
  echo "$2" | awk -v who="$1" '{ b = $1 > 0.5 * $2; printf "%s load %.1f on %d cores%s\n", who, $1, $2, b ? ", too busy" : ""; exit b }'
}
OK=1
busy "this machine:" "$(here)" || OK=0
busy "docker VM:" "$(vm)" || OK=0
if [ "$OK" = 0 ] && [ "${BENCH_FORCE:-0}" != 1 ]; then
  echo "Refusing to measure on a busy machine. Wait for it to settle, or set BENCH_FORCE=1 and the results say LOADED." >&2
  exit 1
fi

cargo build --release -p remote-bench --manifest-path "$ROOT/Cargo.toml"
"$ROOT/target/release/remote-bench" loopback --bind 127.0.0.1 \
    --label "mac-loopback-$TAG" --build "$BUILD" --out "$OUT" \
    --note "Boundary host and helper in one process on this Mac, offscreen stage, so no capture cost"

BENCH_BUILD="$BUILD" PREFIX="container-$TAG" sh "$ROOT/tools/bench/run-container.sh"
BENCH_BUILD="$BUILD" PREFIX="container-wan-$TAG" NETEM="delay 15ms rate 30mbit limit 10000" \
    sh "$ROOT/tools/bench/run-container.sh"

python3 "$ROOT/tools/bench/tables.py" "$OUT"/*-"$TAG"-*.json "$OUT"/mac-loopback-"$TAG".json \
    > "$ROOT/docs/benchmarks/latest-$BRANCH.md"
echo "tables in docs/benchmarks/latest-$BRANCH.md"
