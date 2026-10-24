#!/bin/sh
# Measure RDP, VNC and Boundary on one Linux desktop in a container, with
# this checkout's code. Results land in docs/benchmarks/raw, labelled with
# the branch and commit they came from.
#
#   tools/bench/run-container.sh                 # all three
#   PROTOS=boundary tools/bench/run-container.sh # RDP still runs first, it makes the desktop
#   COUNT=60 SECS=15 PREFIX=my-run tools/bench/run-container.sh
#   NETEM='delay 15ms rate 30mbit limit 10000' PREFIX=wan tools/bench/run-container.sh
set -eu
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
BRANCH=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)
COMMIT=$(git -C "$ROOT" rev-parse --short HEAD)
BUILD=${BENCH_BUILD:-$BRANCH@$COMMIT}
PREFIX=${PREFIX:-container-$BRANCH-$COMMIT}
mkdir -p "$ROOT/docs/benchmarks/raw"

docker build -q -t deskvnc-bench "$ROOT/tools/bench"
docker run --rm --name deskvnc-bench --cap-add NET_ADMIN \
    -v "$ROOT:/src:ro" \
    -v deskvnc-bench-target:/target \
    -v deskvnc-bench-cargo:/root/.cargo/registry \
    -v "$ROOT/docs/benchmarks/raw:/out" \
    -e BENCH_BUILD="$BUILD" -e PREFIX="$PREFIX" \
    -e COUNT="${COUNT:-40}" -e SECS="${SECS:-10}" -e PROTOS="${PROTOS:-vnc boundary}" -e NETEM="${NETEM:-}" \
    deskvnc-bench /usr/local/bin/container-run.sh
