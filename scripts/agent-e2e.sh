#!/usr/bin/env bash
# End to end: a person installs DeskVNCViewer, has OpenCode and Pi installed
# through nvm, opens the app once, and then asks an agent to drive a machine
# with the app closed. Nothing in between is configured by hand.
#
# Expects: the app installed (the .deb on Linux, /Applications on macOS), node,
# opencode and pi from nvm, a mock VNC server address in MOCK_PORT, and on
# Linux an X display in DISPLAY. Prints PASS or FAIL for each step and exits
# non zero on the first failure.
set -euo pipefail

OUT=${OUT:-$PWD/agent-e2e}
mkdir -p "$OUT"
step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAIL: %s\n' "$*"
  printf '\n-- what was running\n'; ps aux | grep -i -e deskvnc -e 'dvv ' | grep -v grep || true
  printf '\n-- the socket\n'; ls -la "${XDG_RUNTIME_DIR:-/nonexistent}/deskvncviewer" "$HOME/.local/share/DeskVNCViewer" "$HOME/Library/Application Support/DeskVNCViewer" 2>&1 || true
  printf '\n-- recorded app path\n'; cat "$DATA/app-path" 2>&1 || true
  printf '\n-- output of the app dvv started\n'; cat "${TMPDIR:-/tmp}/deskvncviewer-started-by-dvv.log" 2>&1 || true
  printf '\n-- first app log\n'; tail -40 "$OUT/app.log" 2>&1 || true
  printf '\n-- dvv doctor\n'; "$DVV" doctor 2>&1 | head -12 || true
  exit 1
}
pass() { printf 'PASS: %s\n' "$*"; }

case "$(uname -s)" in
  Darwin)
    APP=/Applications/DeskVNCViewer.app
    DVV="$APP/Contents/MacOS/dvv"
    DATA="$HOME/Library/Application Support/com.deskvncviewer.desktop"
    start_app() { open -a "$APP"; }
    stop_app() { osascript -e 'quit app "DeskVNCViewer"' >/dev/null 2>&1 || true; pkill -x deskvncviewer || true; pkill -f "$APP/Contents/MacOS/" || true; }
    ;;
  Linux)
    DVV=/usr/bin/dvv
    DATA="${XDG_DATA_HOME:-$HOME/.local/share}/com.deskvncviewer.desktop"
    # The way a desktop menu starts it: a bare PATH and no shell profile.
    start_app() {
      local runtime=()
      [ -n "${XDG_RUNTIME_DIR:-}" ] && runtime=(XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR")
      env -i HOME="$HOME" USER="$USER" DISPLAY="$DISPLAY" SHELL=/bin/bash \
        "${runtime[@]}" PATH=/usr/bin:/bin \
        setsid /usr/bin/deskvncviewer >"$OUT/app.log" 2>&1 &
    }
    stop_app() { pkill -x deskvncviewer || true; }
    ;;
  *) fail "unsupported platform $(uname -s)" ;;
esac

wait_for() { # seconds, description, command...
  local seconds=$1 what=$2; shift 2
  for _ in $(seq 1 "$seconds"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "$what did not happen within ${seconds}s"
}
plane_up() { "$DVV" doctor | grep -q '^ *present'; }
plane_down() { ! plane_up; }
opencode_config() { ls "$HOME/.config/opencode/"opencode.json* 2>/dev/null | head -1; }
opencode_wired() { local f; f=$(opencode_config) && grep -q '"deskvnc"' "$f" && grep -q "$DVV" "$f"; }

step "nothing is configured before the app first runs"
if [ -n "$(opencode_config)" ] && grep -q deskvnc "$(opencode_config)"; then fail "OpenCode was already wired before the app ran"; fi
pass "a clean machine"

step "open DeskVNCViewer once, the way a person does"
start_app
wait_for 60 "the agent plane coming up on its own (it is on by default)" plane_up
pass "plane is up with no setting touched"
wait_for 60 "the app wiring OpenCode at launch" opencode_wired
pass "OpenCode wired: $(opencode_config)"
cat "$(opencode_config)"
test -f "$HOME/.pi/agent/skills/deskvnc/SKILL.md" || fail "Pi's skill was not written"
PI_DIR=$(dirname "$(ls "$HOME"/.nvm/versions/node/*/bin/pi | tail -1)")
test -x "$PI_DIR/dvv" || fail "no dvv beside pi in $PI_DIR"
pass "Pi has the skill and a dvv beside pi in $PI_DIR"
grep -q "$(dirname "$DVV")" "$DATA/app-path" 2>/dev/null || [ "$(uname -s)" = Darwin ] || fail "the app did not record where it is"

step "save a machine, as a person does in the app"
DB="$DATA/deskvnc.db"
now=$(date +%s)
sqlite3 "$DB" "insert into hosts (id, friendly_name, address, port, protocol, created_at, updated_at) values ('e2e-mock', 'mock', '127.0.0.1', $MOCK_PORT, 'vnc', $now, $now);"
"$DVV" hosts | grep -q mock || fail "the saved machine is not listed"
pass "machine 'mock' saved"

step "quit the app; OpenCode must start it on its own"
stop_app
wait_for 30 "the app quitting" plane_down
python3 "$(dirname "$0")/agent_e2e_mcp.py" mock "$OUT/opencode.png"
if [ -x "$PI_DIR/opencode" ]; then
  PATH="$PI_DIR:/usr/bin:/bin" opencode mcp list 2>&1 | tee "$OUT/opencode-mcp-list.txt" | grep -q "deskvnc.*connected" \
    && pass "opencode mcp list: deskvnc connected" || fail "opencode mcp list does not show deskvnc connected"
fi

step "quit the app; Pi's shell commands must start it on its own"
stop_app
wait_for 30 "the app quitting" plane_down
# Pi's bash tool inherits the PATH Pi was started with, and Pi was started
# from the folder it lives in, so that folder and the system's are all of it.
PATH="$PI_DIR:/usr/bin:/bin:/usr/sbin:/sbin" bash -c '
  set -e
  command -v dvv
  limb=$(dvv open mock --perceive --json | python3 -c "import json,sys; print(json.load(sys.stdin)[\"limb\"][\"limb_id\"])")
  echo "limb $limb"
  dvv wait "$limb" --until connected --timeout 30000
  for i in 1 2 3 4 5; do dvv screen "$limb" --scale 0.5 --out "'"$OUT"'/pi.png" && break; sleep 2; done
  dvv close "$limb"
' 2>&1 | tee "$OUT/pi-shell.txt"
test -s "$OUT/pi.png" || fail "Pi's shell route produced no screenshot"
pass "Pi's shell route started the app, opened the machine and saved a screenshot"

step "a second launch changes nothing"
before=$(cksum < "$(opencode_config)")
stop_app
start_app
wait_for 60 "the plane coming back" plane_up
sleep 10
after=$(cksum < "$(opencode_config)")
[ "$before" = "$after" ] || fail "a launch with nothing to do rewrote OpenCode's config"
pass "OpenCode's config untouched on the second launch"
stop_app

printf '\nALL PASSED\n'
