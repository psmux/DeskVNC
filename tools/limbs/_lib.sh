#!/bin/zsh
# Shared setup for the shell limbs. Source it, do not run it.
#
# Three jobs, all of them things the scratchpad versions of these scripts had
# hardcoded and which made them useless in anyone else's checkout:
#
#   1. Find the repo root from the script's own location, so the limbs work
#      from any checkout and from any working directory.
#   2. Resolve the VNC password without ever printing it or putting it on a
#      command line where `ps` would show it.
#   3. Find the stall_probe binary, and say exactly how to build it rather
#      than failing with a confusing "no such file".

# Repo root: two levels up from tools/limbs. ${(%):-%x} is zsh for "the file
# currently being parsed", which is correct inside a SOURCED file where $0
# would be the sourcing script instead. :A makes it absolute and resolves
# symlinks, :h takes the directory, so this survives any working directory.
LIMBS_DIR="${${(%):-%x}:A:h}"
REPO="${DVV_REPO:-${LIMBS_DIR:h:h}}"

# Where per-run logs land. Defaults inside the repo's target dir, which is
# already gitignored, so a diagnostic run never leaves anything to clean up.
OUT_DIR="${DVV_OUT:-$REPO/target/limbs}"
mkdir -p "$OUT_DIR"

# The server under test. Every shell limb takes these from the environment so
# that no host address is baked into a checked-in file.
DVV_HOST="${DVV_HOST:-127.0.0.1}"
DVV_PORT="${DVV_PORT:-5900}"

# Keychain lookup parameters. The app stores its credentials as a JSON blob
# under a service name with the profile UUID as the account, so the blob has to
# be parsed. Both halves are overridable because a dev build signed with a
# different bundle id writes to a different service.
DVV_KEYCHAIN_SERVICE="${DVV_KEYCHAIN_SERVICE:-com.deskvncviewer.app}"
DVV_KEYCHAIN_FIELD="${DVV_KEYCHAIN_FIELD:-vncPassword}"

limbs_resolve_password() {
  # Already supplied: use it and do not touch the keychain. This is the only
  # path that works on a machine without a macOS keychain.
  if [ -n "${DVV_PASS+x}" ]; then
    echo "  password: from DVV_PASS" >&2
    return 0
  fi

  if [ -z "$DVV_PROFILE" ]; then
    echo "  password: none supplied. Set DVV_PASS, or set DVV_PROFILE to a" >&2
    echo "            keychain account id to look one up." >&2
    export DVV_PASS=""
    return 0
  fi

  if ! command -v security >/dev/null 2>&1; then
    echo "  ERROR: no \`security\` tool, so keychain lookup is impossible here." >&2
    echo "         Set DVV_PASS instead." >&2
    return 1
  fi

  # The value never reaches stdout, a log, or an argument list. It goes
  # straight into the environment of the child process and nowhere else.
  local raw
  if ! raw=$(security find-generic-password \
        -s "$DVV_KEYCHAIN_SERVICE" -a "$DVV_PROFILE" -w 2>/dev/null); then
    echo "  ERROR: no keychain item for service $DVV_KEYCHAIN_SERVICE" >&2
    echo "         account $DVV_PROFILE. Check the profile id, or set DVV_PASS." >&2
    return 1
  fi

  DVV_PASS=$(printf '%s' "$raw" | DVV_FIELD="$DVV_KEYCHAIN_FIELD" python3 -c '
import json, os, sys
raw = sys.stdin.read().strip()
try:
    blob = json.loads(raw)
except ValueError:
    # A hand-created keychain item may hold the bare password rather than JSON.
    sys.stdout.write(raw)
else:
    sys.stdout.write(str(blob[os.environ["DVV_FIELD"]]))
') || return 1
  export DVV_PASS
  echo "  password: from macOS keychain, profile $DVV_PROFILE" >&2
}

# The release build is the only one worth measuring: a debug build of the
# decoders is slow enough to dominate every number these limbs produce.
STALL_PROBE="${DVV_STALL_PROBE:-$REPO/target/release/examples/stall_probe}"

limbs_require_stall_probe() {
  if [ ! -x "$STALL_PROBE" ]; then
    echo "stall_probe not found at $STALL_PROBE" >&2
    echo "Build it first:" >&2
    echo "  cargo build --release -p vnc-core --example stall_probe" >&2
    return 1
  fi
}
