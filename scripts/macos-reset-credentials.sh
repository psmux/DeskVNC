#!/usr/bin/env bash
# Remove the keychain entries and permission grants left behind by unsigned
# builds.
#
# Entries created by an ad-hoc-signed build carry an ACL pinned to a cdhash
# that no longer exists, so they re-prompt forever no matter how many times
# you click Always Allow. They cannot be repaired -- only deleted and
# recreated by a properly signed build.
#
# DESTRUCTIVE: you will have to re-enter each host's VNC password once.
set -euo pipefail

cd "$(dirname "$0")/.."

SERVICE="com.deskvncviewer.app"     # keychain service (crates/vnc-store/src/creds.rs)
BUNDLE_ID="com.deskvncviewer.desktop"

echo "==> Keychain entries for service '$SERVICE':"
ACCOUNTS=$(security dump-keychain 2>/dev/null \
    | awk -v svc="\"svce\"<blob>=\"$SERVICE\"" '
        /"acct"<blob>=/ { acct = $0 }
        $0 ~ svc && acct != "" { print acct; acct = "" }
      ' \
    | sed -n 's/.*"acct"<blob>="\(.*\)"/\1/p')

if [ -z "$ACCOUNTS" ]; then
    echo "    (none)"
else
    printf '    %s\n' $ACCOUNTS
fi

COUNT=$(printf '%s\n' "$ACCOUNTS" | grep -c . || true)
echo
echo "This deletes $COUNT stored credential(s) and resets the app's Local Network"
echo "and Accessibility permissions. Host profiles themselves are not touched."
if [ "${1:-}" = "--yes" ]; then
    echo "Continue? [y/N] y   (--yes)"
else
    printf 'Continue? [y/N] '
    read -r REPLY || REPLY=""
    case "$REPLY" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

echo
echo "==> Deleting keychain entries"
# delete-generic-password removes one match per call; loop until exhausted.
DELETED=0
while security delete-generic-password -s "$SERVICE" >/dev/null 2>&1; do
    DELETED=$((DELETED + 1))
    [ "$DELETED" -gt 100 ] && break
done
echo "    Removed $DELETED entry/entries."

echo "==> Resetting TCC grants for $BUNDLE_ID"
# Stale grants are keyed to the old ad-hoc identity; clearing them lets the
# signed build ask once and be remembered.
tccutil reset All "$BUNDLE_ID" >/dev/null 2>&1 \
    && echo "    Done." \
    || echo "    Nothing to reset (or tccutil declined; harmless)."

echo
echo "Now rebuild with a signed identity:  scripts/package-macos.sh"
