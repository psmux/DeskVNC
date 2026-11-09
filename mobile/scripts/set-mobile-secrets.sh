#!/usr/bin/env bash
# Set the GitHub Actions secrets the phone app workflows read, from files on
# this machine. Values go to `gh secret set` on stdin, so they never appear in
# the process list, the shell history or this terminal.
#
#   mobile/scripts/set-mobile-secrets.sh owner/repo [options]
#
# Android (mobile-android.yml):
#   --android-keystore FILE      upload keystore (.jks), from make-android-upload-key.sh
#   --android-alias NAME         key alias in it (default: upload)
#   --android-password-file FILE store password; asked for when not given.
#                                The key password is taken to be the same unless
#   --android-key-password-file FILE says otherwise.
#   --play-json FILE             Google Play service account key (JSON)
#
# Apple (mobile-ios.yml):
#   --apple-p12 FILE             Apple Distribution certificate and key (.p12)
#   --apple-p12-password-file FILE   asked for when not given
#   --apple-profile FILE         App Store provisioning profile (.mobileprovision)
#   --apple-team-id ID           ten character team id (or asked for)
#   --asc-key FILE               App Store Connect API key, AuthKey_<KEYID>.p8
#   --asc-key-id ID              defaults to the KEYID in the file name
#   --asc-issuer-id ID           issuer id from App Store Connect, Users and Access, Integrations
#
# Only the secrets whose options are given are set, so the script can be run
# once per store. --dry-run lists what would be set without sending anything.
set -euo pipefail

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

[ $# -ge 1 ] || usage 2
case "$1" in -h|--help) usage 0 ;; esac
repo=$1; shift
[[ "$repo" == */* ]] || { echo "First argument must be owner/repo"; exit 2; }

android_keystore='' android_alias=upload android_pw_file='' android_key_pw_file='' play_json=''
apple_p12='' apple_p12_pw_file='' apple_profile='' apple_team='' asc_key='' asc_key_id='' asc_issuer='' dry=0

while [ $# -gt 0 ]; do
  case "$1" in
    --android-keystore) android_keystore=$2; shift 2 ;;
    --android-alias) android_alias=$2; shift 2 ;;
    --android-password-file) android_pw_file=$2; shift 2 ;;
    --android-key-password-file) android_key_pw_file=$2; shift 2 ;;
    --play-json) play_json=$2; shift 2 ;;
    --apple-p12) apple_p12=$2; shift 2 ;;
    --apple-p12-password-file) apple_p12_pw_file=$2; shift 2 ;;
    --apple-profile) apple_profile=$2; shift 2 ;;
    --apple-team-id) apple_team=$2; shift 2 ;;
    --asc-key) asc_key=$2; shift 2 ;;
    --asc-key-id) asc_key_id=$2; shift 2 ;;
    --asc-issuer-id) asc_issuer=$2; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option $1"; usage 2 ;;
  esac
done

command -v gh >/dev/null || { echo "gh is not installed"; exit 1; }
if [ "$dry" = 0 ]; then
  gh auth status >/dev/null 2>&1 || { echo "gh is not signed in (gh auth login)"; exit 1; }
fi

need_file() { [ -f "$1" ] || { echo "No such file: $1"; exit 1; }; }

# Read stdin into a secret. Never prints the value.
put() { # name
  if [ "$dry" = 1 ]; then cat >/dev/null; echo "would set $1"; return; fi
  gh secret set "$1" -R "$repo" >/dev/null
  echo "set $1"
}
put_file_b64() { need_file "$2"; base64 < "$2" | tr -d '\n' | put "$1"; }
put_file_raw() { need_file "$2"; put "$1" < "$2"; }
put_value() { printf '%s' "$2" | put "$1"; }

# A password from a file (first line, no newline) or typed with no echo.
secret_from() { # file prompt
  if [ -n "$1" ]; then need_file "$1"; head -n1 "$1" | tr -d '\r\n'; return; fi
  local v
  read -r -s -p "$2: " v </dev/tty; echo >&2
  printf '%s' "$v"
}

if [ -n "$android_keystore" ]; then
  put_file_b64 ANDROID_KEYSTORE_BASE64 "$android_keystore"
  store_pw=$(secret_from "$android_pw_file" "Keystore password")
  put_value ANDROID_KEYSTORE_PASSWORD "$store_pw"
  if [ -n "$android_key_pw_file" ]; then
    put_value ANDROID_KEY_PASSWORD "$(secret_from "$android_key_pw_file" "")"
  else
    put_value ANDROID_KEY_PASSWORD "$store_pw"
  fi
  put_value ANDROID_KEY_ALIAS "$android_alias"
  unset store_pw
fi

if [ -n "$play_json" ]; then
  need_file "$play_json"
  grep -q '"type": *"service_account"' "$play_json" || { echo "$play_json is not a service account key"; exit 1; }
  put_file_raw PLAY_SERVICE_ACCOUNT_JSON "$play_json"
fi

if [ -n "$apple_p12" ]; then
  put_file_b64 APPLE_DIST_CERT_P12_BASE64 "$apple_p12"
  put_value APPLE_DIST_CERT_PASSWORD "$(secret_from "$apple_p12_pw_file" "Password of the .p12")"
fi

if [ -n "$apple_profile" ]; then
  put_file_b64 APPLE_PROVISIONING_PROFILE_BASE64 "$apple_profile"
fi

if [ -n "$apple_p12$apple_profile$asc_key$apple_team" ]; then
  if [ -z "$apple_team" ]; then read -r -p "Apple team id (10 characters): " apple_team </dev/tty; fi
  [[ "$apple_team" =~ ^[A-Z0-9]{10}$ ]] || { echo "That does not look like a team id"; exit 1; }
  put_value APPLE_TEAM_ID "$apple_team"
fi

if [ -n "$asc_key" ]; then
  need_file "$asc_key"
  if [ -z "$asc_key_id" ]; then
    base=$(basename "$asc_key")
    asc_key_id=${base#AuthKey_}; asc_key_id=${asc_key_id%.p8}
  fi
  [[ "$asc_key_id" =~ ^[A-Z0-9]{10}$ ]] || { echo "Pass --asc-key-id, the file name does not hold one"; exit 1; }
  if [ -z "$asc_issuer" ]; then read -r -p "App Store Connect issuer id: " asc_issuer </dev/tty; fi
  put_file_b64 APP_STORE_CONNECT_KEY_P8_BASE64 "$asc_key"
  put_value APP_STORE_CONNECT_KEY_ID "$asc_key_id"
  put_value APP_STORE_CONNECT_ISSUER_ID "$asc_issuer"
fi

echo "Done. Check with: gh secret list -R $repo"
