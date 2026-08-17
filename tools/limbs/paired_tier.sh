#!/bin/zsh
# limb: paired. What does a quality setting really cost this server?
#
# Answers: "is Auto choosing a sane tier for this server, or is it spending the
# whole link on picture quality nobody asked for?" This is the limb that
# verified the server-latency cap, and it is the one to reach for whenever a
# change to the quality ladder needs proving.
#
# WHY PAIRED. Wall-clock latency against a live desktop is a treacherous
# instrument: it swings two orders of magnitude with how busy the remote screen
# happens to be. During this investigation the SAME configuration measured
# 245 ms in one window and 7 ms in another, and at one point a session measured
# BETTER under load than without it, because a second client keeps the server's
# damage detection warm. Every conclusion drawn from a baseline taken minutes
# earlier was wrong.
#
# So this limb alternates short arms of two settings back to back. Screen
# activity barely drifts across a pair, so the within-round difference is
# attributable to the setting and nothing else. Compare DOWN the columns for
# consistency and ACROSS them for the effect.
#
# WHAT IT REPORTS, per arm, averaged over the arm with the first three ticks
# skipped (the priming full-screen paint is not steady state):
#
#   duty     `server_duty_cycle`: the fraction of wall time this session keeps
#            the server encoding for us. This is the honest saturation signal,
#            because unlike latency it is about our own session and has no
#            screen-activity confound. Near 1.0 means we have taken the whole
#            encoder and left nothing for anyone else, our own input echo
#            included.
#   Mbit/s   what we are actually pulling.
#   rtt ms   `rtt_ms`, whichever source is available (see docs section 7).
#
# HEALTHY vs UNHEALTHY, measured on a real TightVNC-family server at 2880x1800
# over an 82 Mbit/s link, four rounds of 30 s:
#
#   tier    duty          Mbit/s        rtt
#   High    42.7 to 43.2% 36.3 to 36.5  426 to 434 ms   <- unhealthy
#   Medium  17.7 to 28.4% 10.5 to 17.1  18 to 20 ms     <- healthy
#
# High bought about twice the bandwidth and cost about twenty times the round
# trip. That measurement is what motivated `SERVER_LATENCY_BUDGET_MS`.
#
# Usage:
#   DVV_HOST=<server> DVV_PROFILE=<uuid> ./paired_tier.sh [rounds] [secs] [armA] [armB]
#
#   ./paired_tier.sh                      # 4 rounds, 30 s, auto vs medium
#   ./paired_tier.sh 4 30 high medium     # what does the High tier cost?
#   ./paired_tier.sh 3 40 auto medium     # is Auto behaving like Medium?
#
# Arms are QualityPreset names understood by stall_probe's DVV_QUALITY:
# auto, high, medium, low.

source "${${(%):-%x}:A:h}/_lib.sh"

ROUNDS=${1:-4}
SECS=${2:-30}
ARM_A=${3:-auto}
ARM_B=${4:-medium}

limbs_require_stall_probe
limbs_resolve_password

arm () {  # arm <quality> <round>
  local q=$1 r=$2
  env DVV_HOST="$DVV_HOST" DVV_PORT="$DVV_PORT" DVV_SECONDS=$SECS DVV_ALR=0 \
      DVV_QUALITY=$q RUST_LOG=error \
    "$STALL_PROBE" > "$OUT_DIR/paired-$q-$r.log" 2>&1

  # Field positions: the "[  1.24s]" timestamp contains a space, so awk sees
  # $1="[" $2="1.24s]" $3="STATS" $4="duty" $5="46.1%" $7=rtt $10=Mbit value.
  awk '/STATS/ {n++; if (n>3) {gsub("%","",$5); d+=$5; m+=$10; r+=$7; c++}}
       END {if (c) printf "%5.1f|%6.2f|%7.1f", d/c, m/c, r/c; else printf "  n/a|   n/a|    n/a"}' \
    "$OUT_DIR/paired-$q-$r.log"
}

echo "paired tier cost against $DVV_HOST:$DVV_PORT"
echo "$ROUNDS rounds, ${SECS}s per arm, logs in $OUT_DIR"
echo
printf "         |  %-24s |  %s\n" "$(echo $ARM_A | tr a-z A-Z)" "$(echo $ARM_B | tr a-z A-Z)"
echo "  round  |  duty    Mbit/s    rtt ms  |  duty    Mbit/s    rtt ms"
echo "  -------+----------------------------+---------------------------"
for r in $(seq 1 $ROUNDS); do
  A=$(arm $ARM_A $r)
  B=$(arm $ARM_B $r)
  printf "  %5d  | %5s%%  %7s  %8s  | %5s%%  %7s  %8s\n" "$r" \
    "$(echo $A|cut -d'|' -f1)" "$(echo $A|cut -d'|' -f2)" "$(echo $A|cut -d'|' -f3)" \
    "$(echo $B|cut -d'|' -f1)" "$(echo $B|cut -d'|' -f2)" "$(echo $B|cut -d'|' -f3)"
done
echo
echo "Read DOWN a column for consistency, ACROSS for the effect of the setting."
echo "A duty cycle above roughly 40% with a round trip in the hundreds of ms"
echo "means this session is monopolising the server. See docs/DIAGNOSTICS.md."
