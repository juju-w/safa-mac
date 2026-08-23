#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat <<'EOF'
Usage: Scripts/rollback-mvp-candidate.sh --lock-backup PATH --team-id TEAM_ID \
       [--runtime-backup PATH]

Restore a retained compatible Runtime lock and, for same-version replacement, its retained app.
The displaced candidate is retained; vault, Resource, and Keychain state are never removed.
EOF
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

lock_backup=""
runtime_backup=""
team_identifier=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --lock-backup)
      [ "$#" -ge 2 ] || fail "--lock-backup requires a value"
      lock_backup="$2"
      shift 2
      ;;
    --runtime-backup)
      [ "$#" -ge 2 ] || fail "--runtime-backup requires a value"
      runtime_backup="$2"
      shift 2
      ;;
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      team_identifier="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) fail "unexpected argument: $1" ;;
  esac
done

printf '%s\n' "$team_identifier" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$' \
  || fail "TEAM_ID must contain exactly 10 uppercase letters or digits"
[ "$(uname -s)" = "Darwin" ] || fail "MVP candidate rollback requires macOS"
[ -n "${HOME:-}" ] || fail "the current user home directory is unavailable"

data_root="${HOME}/Library/Application Support/SAFA"
runtimes_root="${data_root}/runtimes"
lock_path="${data_root}/runtime.local.json"
[ "$(dirname -- "$lock_backup")" = "$data_root" ] \
  || fail "--lock-backup must be a retained SAFA lock"
printf '%s\n' "$(basename -- "$lock_backup")" \
  | /usr/bin/grep -Eq '^runtime\.local\.previous\.[0-9]{8}T[0-9]{6}Z\.json$' \
  || fail "--lock-backup has an invalid retained-lock name"
[ -f "$lock_backup" ] && [ ! -L "$lock_backup" ] \
  || fail "--lock-backup must identify a regular file"
[ "$(/usr/bin/stat -f '%u' "$lock_backup")" -eq "$(/usr/bin/id -u)" ] \
  || fail "the retained Runtime lock has unsafe ownership"
[ "$(/usr/bin/stat -f '%Lp' "$lock_backup")" = "600" ] \
  || fail "the retained Runtime lock has unsafe permissions"
[ -f "$lock_path" ] && [ ! -L "$lock_path" ] \
  || fail "the active Runtime lock is unavailable"

lock_field() {
  /usr/bin/plutil -extract "$1" raw -o - "$lock_backup" 2>/dev/null
}

[ "$(lock_field schema)" = "dev.safa.local-runtime-lock/v1" ] \
  || fail "the retained Runtime lock has an unsupported schema"
[ "$(lock_field cli_schema)" = "dev.safa.cli/v2" ] \
  || fail "the retained Runtime lock has an incompatible CLI schema"
[ "$(lock_field platform)" = "macos" ] \
  || fail "the retained Runtime lock does not describe macOS"
[ "$(lock_field team_identifier)" = "$team_identifier" ] \
  || fail "the retained Runtime lock has an unexpected Team identity"
runtime_version=$(lock_field runtime_version) || fail "the retained lock has no Runtime version"
architecture=$(lock_field architecture) || fail "the retained lock has no architecture"
printf '%s\n' "$runtime_version" \
  | /usr/bin/grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
  || fail "the retained lock has an invalid Runtime version"
case "$architecture" in arm64 | x86_64) ;; *) fail "the retained lock has an invalid architecture" ;; esac

install_directory="${runtimes_root}/${runtime_version}"
if [ -n "$runtime_backup" ]; then
  [ "$(dirname -- "$runtime_backup")" = "$runtimes_root" ] \
    || fail "--runtime-backup must be a retained SAFA Runtime"
  printf '%s\n' "$(basename -- "$runtime_backup")" \
    | /usr/bin/grep -Eq "^\.${runtime_version}\.previous\.[0-9]{8}T[0-9]{6}Z$" \
    || fail "--runtime-backup does not match the retained Runtime version"
  [ -d "$runtime_backup" ] && [ ! -L "$runtime_backup" ] \
    || fail "--runtime-backup must identify a retained Runtime directory"
  previous_app="${runtime_backup}/SAFA.app"
else
  previous_app="${install_directory}/SAFA.app"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
/bin/sh "${script_dir}/verify-runtime-signing.sh" "$previous_app" "$team_identifier" \
  || fail "the retained Runtime failed the signing-boundary audit"
previous_cli="${previous_app}/Contents/MacOS/safa"
previous_broker_app="${previous_app}/Contents/Library/Helpers/SAFABrokerAgent.app"
previous_askpass="${previous_app}/Contents/Library/Helpers/safa-askpass"
previous_trusted_setup="${previous_app}/Contents/Library/Helpers/safa-trusted-setup"
/bin/sh "${script_dir}/verify-broker-provisioning-profile.sh" \
  "$previous_broker_app" "$team_identifier" \
  || fail "the retained Runtime failed Broker provisioning-profile verification"

signature_field() {
  component=$1
  requested_field=$2
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n "s/^${requested_field}=//p" \
    | /usr/bin/head -n 1
}

for component in "$previous_app" "$previous_cli" "$previous_broker_app" "$previous_askpass" "$previous_trusted_setup"; do
  authority=$(/usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n 's/^Authority=//p' | /usr/bin/head -n 1)
  case "$authority" in
    'Developer ID Application:'*) ;;
    *) fail "the retained Runtime is not a Developer ID distribution" ;;
  esac
done

[ "$(signature_field "$previous_app" CDHash)" = "$(lock_field app_cdhash)" ] \
  || fail "the retained app does not match its lock"
[ "$(signature_field "$previous_broker_app" CDHash)" = "$(lock_field broker_cdhash)" ] \
  || fail "the retained Broker does not match its lock"
[ "$(signature_field "$previous_askpass" CDHash)" = "$(lock_field askpass_cdhash)" ] \
  || fail "the retained AskPass does not match its lock"
[ "$(signature_field "$previous_trusted_setup" CDHash)" = "$(lock_field trusted_setup_cdhash)" ] \
  || fail "the retained trusted setup does not match its lock"
case " $(/usr/bin/lipo -archs "$previous_cli") " in
  *" ${architecture} "*) ;;
  *) fail "the retained Runtime does not contain its locked architecture" ;;
esac
[ "$("$previous_cli" --version)" = "$runtime_version" ] \
  || fail "the retained Runtime version does not match its lock"

timestamp=$(/bin/date -u '+%Y%m%dT%H%M%SZ')
lock_staging="${data_root}/.runtime.rollback.$$"
displaced_lock="${data_root}/runtime.local.replaced.${timestamp}.json"
displaced_runtime="${runtimes_root}/.${runtime_version}.replaced.${timestamp}"
runtime_swapped=0
lock_swapped=0

cleanup() {
  /bin/rm -f -- "$lock_staging"
}
trap cleanup EXIT HUP INT TERM
umask 077
/usr/bin/ditto "$lock_backup" "$lock_staging"
/bin/chmod 600 "$lock_staging"

restore_candidate() {
  if [ "$lock_swapped" -eq 1 ] && [ -f "$displaced_lock" ]; then
    /bin/mv -f "$displaced_lock" "$lock_path" 2>/dev/null || true
  fi
  if [ "$runtime_swapped" -eq 1 ]; then
    if [ -d "$install_directory" ]; then
      /bin/mv "$install_directory" "$runtime_backup" 2>/dev/null || true
    fi
    if [ -d "$displaced_runtime" ]; then
      /bin/mv "$displaced_runtime" "$install_directory" 2>/dev/null || true
    fi
  fi
}

if [ -n "$runtime_backup" ]; then
  [ -d "$install_directory" ] || fail "the currently active same-version Runtime is unavailable"
  /bin/mv "$install_directory" "$displaced_runtime"
  if ! /bin/mv "$runtime_backup" "$install_directory"; then
    /bin/mv "$displaced_runtime" "$install_directory" 2>/dev/null || true
    fail "failed to restore the retained Runtime"
  fi
  runtime_swapped=1
fi

/bin/mv "$lock_path" "$displaced_lock"
if ! /bin/mv "$lock_staging" "$lock_path"; then
  /bin/mv "$displaced_lock" "$lock_path" 2>/dev/null || true
  restore_candidate
  fail "failed to restore the retained Runtime lock"
fi
lock_swapped=1

broker_service="gui/$(/usr/bin/id -u)/dev.safa.broker"
if /bin/launchctl print "$broker_service" >/dev/null 2>&1; then
  if ! /bin/launchctl kickstart -k "$broker_service"; then
    restore_candidate
    fail "the retained Broker could not restart; candidate restored"
  fi
fi
active_cli="${install_directory}/SAFA.app/Contents/MacOS/safa"
if ! "$active_cli" doctor >/dev/null 2>&1; then
  restore_candidate
  if /bin/launchctl print "$broker_service" >/dev/null 2>&1; then
    /bin/launchctl kickstart -k "$broker_service" >/dev/null 2>&1 || true
  fi
  fail "the retained Runtime failed startup; candidate restored"
fi

printf '%s\n' "Rolled back to SAFA Runtime ${runtime_version}."
printf '%s\n' "Displaced candidate lock retained at: ${displaced_lock}"
[ "$runtime_swapped" -eq 0 ] \
  || printf '%s\n' "Displaced candidate Runtime retained at: ${displaced_runtime}"
