#!/usr/bin/env bash
# Shared helper: resolve which code-signing identity to use on macOS.
#
# Sourced by sign-macos.sh, codesign-linker.sh and package-macos.sh.
# Not meant to be executed directly.

# Common Name of the self-signed identity created by macos-codesign-setup.sh.
LOCAL_CERT_CN="${LOCAL_CERT_CN:-DeskVNCViewer Local Dev}"

# The bundle identifier from tauri.conf.json. Signing a bare binary (dev
# builds) must force this, otherwise the linker's content-hash identifier
# (deskvncviewer-9f8756b5ff617ee8) lands in the designated requirement and the
# dev build gets a different identity than the bundled app.
BUNDLE_ID="${BUNDLE_ID:-com.deskvncviewer.desktop}"

# Prints the identity name to stdout, or returns 1 if none is available.
#
# Preference order matters: a Developer ID signature is the only one other
# Macs will accept, so it always wins when present. The local self-signed cert
# is the last resort and works on this machine only.
resolve_signing_identity() {
    if [ -n "${APPLE_SIGNING_IDENTITY:-}" ]; then
        printf '%s\n' "$APPLE_SIGNING_IDENTITY"
        return 0
    fi

    local names
    # -v lists only identities that chain to a trusted root. A self-signed
    # certificate never does (it reports CSSMERR_TP_NOT_TRUSTED), yet codesign
    # signs with it happily and produces the stable `certificate leaf = H"..."`
    # requirement we are after -- trust only governs Gatekeeper, not the
    # keychain ACL. So fall back to the unfiltered list.
    #
    # Lines look like:  1) A1B2C3 "Developer ID Application: X (TEAM)" (status)
    names=$(security find-identity -v -p codesigning 2>/dev/null \
        | sed -n 's/.*) [0-9A-F]* "\([^"]*\)".*/\1/p')
    if [ -z "$names" ]; then
        names=$(security find-identity -p codesigning 2>/dev/null \
            | sed -n 's/.*) [0-9A-F]* "\([^"]*\)".*/\1/p')
    fi

    local prefix
    for prefix in "Developer ID Application:" "Apple Development:" "$LOCAL_CERT_CN"; do
        local hit
        hit=$(printf '%s\n' "$names" | grep -m1 -F "$prefix" || true)
        if [ -n "$hit" ]; then
            printf '%s\n' "$hit"
            return 0
        fi
    done
    return 1
}

# True when the identity is issued by Apple, i.e. usable off this machine and
# eligible for hardened runtime + notarization.
is_apple_identity() {
    case "$1" in
        "Developer ID Application:"* | "Apple Development:"* | "Apple Distribution:"*) return 0 ;;
        *) return 1 ;;
    esac
}
