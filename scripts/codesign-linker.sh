#!/usr/bin/env bash
# Linker shim: run the real linker, then code-sign the app binary.
#
# cargo/tauri offer no post-build hook for `tauri dev`, and every relink
# produces a new cdhash. Without a stable signature each dev run is a new
# code identity to macOS, which invalidates keychain ACLs and TCC grants.
# Wired up by scripts/macos-codesign-setup.sh via .cargo/config.toml.
#
# Everything that is not the app binary is a pure pass-through, and a signing
# failure is never allowed to break the build.
set -euo pipefail

REAL_CC="${DESKVNC_REAL_CC:-cc}"
"$REAL_CC" "$@"

# Opt-out without regenerating .cargo/config.toml.
[ "${DESKVNC_CODESIGN:-1}" = "0" ] && exit 0

# Recover the link output from `-o <path>`.
out=""
prev=""
for arg in "$@"; do
    [ "$prev" = "-o" ] && out="$arg"
    prev="$arg"
done

# Only the app binary matters; everything else keeps the default ad-hoc
# signature, which is fine because it never touches the keychain.
#
# rustc links to target/<profile>/deps/deskvncviewer-<metadata-hash>, and
# cargo hardlinks that to target/<profile>/deskvncviewer afterwards. Signing
# the deps/ file is what counts -- the hardlink shares the inode, so the
# signature is already there by the time cargo publishes the final name.
# "deskvncviewer_lib-*" does not match: the character after the stem is "_".
case "$(basename "${out:-}")" in
    deskvncviewer | deskvncviewer-*) ;;
    *) exit 0 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=scripts/macos-identity.sh
. "$SCRIPT_DIR/macos-identity.sh"

if ! IDENTITY=$(resolve_signing_identity 2>/dev/null); then
    echo "note: no code-signing identity; leaving $out ad-hoc signed." >&2
    echo "      run scripts/macos-codesign-setup.sh to stop keychain re-prompts." >&2
    exit 0
fi

SIGN_OPTS=(--force --sign "$IDENTITY" --identifier "$BUNDLE_ID")
is_apple_identity "$IDENTITY" || SIGN_OPTS+=(--timestamp=none)

if ! codesign "${SIGN_OPTS[@]}" "$out" 2>/dev/null; then
    echo "warning: could not sign $out; keychain prompts may reappear." >&2
fi

exit 0
