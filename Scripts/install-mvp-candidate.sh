#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat <<'EOF'
Usage: Scripts/install-mvp-candidate.sh --archive ZIP --evidence JSON \
       --evidence-sha256 SHA256 --team-id TEAM_ID [--replace]

Verify and atomically activate one exact notarized MVP candidate for the current user.
Existing Runtime, lock, vault, Resource, and Keychain state are retained for rollback.
EOF
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

archive_path=""
evidence_path=""
evidence_sha256=""
team_identifier=""
replace_existing=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --archive)
      [ "$#" -ge 2 ] || fail "--archive requires a value"
      archive_path="$2"
      shift 2
      ;;
    --evidence)
      [ "$#" -ge 2 ] || fail "--evidence requires a value"
      evidence_path="$2"
      shift 2
      ;;
    --evidence-sha256)
      [ "$#" -ge 2 ] || fail "--evidence-sha256 requires a value"
      evidence_sha256="$2"
      shift 2
      ;;
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      team_identifier="$2"
      shift 2
      ;;
    --replace)
      replace_existing=1
      shift
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
printf '%s\n' "$evidence_sha256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' \
  || fail "--evidence-sha256 must contain exactly 64 lowercase hexadecimal characters"
[ "$(uname -s)" = "Darwin" ] || fail "MVP candidate installation requires macOS"
[ -n "${HOME:-}" ] || fail "the current user home directory is unavailable"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier="${script_dir}/verify-mvp-candidate.sh"
signing_verifier="${script_dir}/verify-runtime-signing.sh"
"$verifier" --archive "$archive_path" --evidence "$evidence_path" \
  --evidence-sha256 "$evidence_sha256" --team-id "$team_identifier"

field() {
  /usr/bin/plutil -extract "$1" raw -o - "$evidence_path" 2>/dev/null
}

runtime_version=$(field runtime_version)
runtime_revision=$(field runtime_revision)
product_revision=$(field product_revision)
artifact_sha256=$(field artifact.sha256)
notary_submission_id=$(field notarization.submission_id)
architecture=$(uname -m)
case "$architecture" in arm64 | x86_64) ;; *) fail "unsupported macOS architecture" ;; esac

data_root="${HOME}/Library/Application Support/SAFA"
runtimes_root="${data_root}/runtimes"
install_directory="${runtimes_root}/${runtime_version}"
timestamp=$(/bin/date -u '+%Y%m%dT%H%M%SZ')
staging_directory="${runtimes_root}/.${runtime_version}.installing.$$"
lock_path="${data_root}/runtime.local.json"
lock_staging="${data_root}/.runtime.local.json.$$"
lock_backup=""
runtime_backup=""
activated=0

build_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-mvp-install.XXXXXX")
cleanup() {
  /bin/rm -rf -- "$build_root" "$staging_directory"
  /bin/rm -f -- "$lock_staging"
}
trap cleanup EXIT HUP INT TERM
umask 077
/bin/mkdir -p "$data_root" "$runtimes_root"
/bin/chmod 700 "$data_root" "$runtimes_root"

if [ -e "$lock_path" ]; then
  [ -f "$lock_path" ] && [ ! -L "$lock_path" ] \
    || fail "the active Runtime lock is not a regular file"
  [ "$(/usr/bin/stat -f '%u' "$lock_path")" -eq "$(/usr/bin/id -u)" ] \
    || fail "the active Runtime lock has unsafe ownership"
  [ "$(/usr/bin/stat -f '%Lp' "$lock_path")" = "600" ] \
    || fail "the active Runtime lock has unsafe permissions"
  lock_backup="${data_root}/runtime.local.previous.${timestamp}.json"
  [ ! -e "$lock_backup" ] || fail "the Runtime lock backup already exists"
  /usr/bin/ditto "$lock_path" "$lock_backup"
  /bin/chmod 600 "$lock_backup"
fi

/usr/bin/ditto -x -k "$archive_path" "$build_root"
[ -z "$(/usr/bin/find "$build_root" -type l -print -quit)" ] \
  || fail "candidate archive contains a symbolic link"
source_app="${build_root}/SAFA.app"
[ -d "$source_app" ] || fail "candidate archive does not contain SAFA.app"
/usr/bin/ditto "$source_app" "${staging_directory}/SAFA.app"
/bin/chmod 700 "$staging_directory"
staged_app="${staging_directory}/SAFA.app"
/bin/sh "$signing_verifier" "$staged_app" "$team_identifier" \
  || fail "staged candidate failed the final signing-boundary audit"
/bin/sh "${script_dir}/verify-broker-provisioning-profile.sh" \
  "${staged_app}/Contents/Library/Helpers/SAFABrokerAgent.app" "$team_identifier" \
  || fail "staged candidate failed Broker provisioning-profile verification"
/usr/bin/xcrun stapler validate "$staged_app"
/usr/sbin/spctl --assess --type execute --verbose=4 "$staged_app"

signature_field() {
  component=$1
  requested_field=$2
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n "s/^${requested_field}=//p" \
    | /usr/bin/head -n 1
}

cli_path="${staged_app}/Contents/MacOS/safa"
broker_app="${staged_app}/Contents/Library/Helpers/SAFABrokerAgent.app"
askpass_path="${staged_app}/Contents/Library/Helpers/safa-askpass"
trusted_setup_path="${staged_app}/Contents/Library/Helpers/safa-trusted-setup"
case " $(/usr/bin/lipo -archs "$cli_path") " in
  *" ${architecture} "*) ;;
  *) fail "candidate does not contain the current architecture" ;;
esac

app_cdhash=$(signature_field "$staged_app" CDHash)
broker_cdhash=$(signature_field "$broker_app" CDHash)
askpass_cdhash=$(signature_field "$askpass_path" CDHash)
trusted_setup_cdhash=$(signature_field "$trusted_setup_path" CDHash)

/usr/bin/plutil -create xml1 "$lock_staging"
/usr/bin/plutil -insert schema -string dev.safa.local-runtime-lock/v1 "$lock_staging"
/usr/bin/plutil -insert runtime_version -string "$runtime_version" "$lock_staging"
/usr/bin/plutil -insert cli_schema -string dev.safa.cli/v2 "$lock_staging"
/usr/bin/plutil -insert platform -string macos "$lock_staging"
/usr/bin/plutil -insert architecture -string "$architecture" "$lock_staging"
/usr/bin/plutil -insert team_identifier -string "$team_identifier" "$lock_staging"
/usr/bin/plutil -insert app_cdhash -string "$app_cdhash" "$lock_staging"
/usr/bin/plutil -insert broker_cdhash -string "$broker_cdhash" "$lock_staging"
/usr/bin/plutil -insert askpass_cdhash -string "$askpass_cdhash" "$lock_staging"
/usr/bin/plutil -insert trusted_setup_cdhash -string "$trusted_setup_cdhash" "$lock_staging"
/usr/bin/plutil -insert artifact_sha256 -string "$artifact_sha256" "$lock_staging"
/usr/bin/plutil -insert evidence_sha256 -string "$evidence_sha256" "$lock_staging"
/usr/bin/plutil -insert runtime_revision -string "$runtime_revision" "$lock_staging"
/usr/bin/plutil -insert product_revision -string "$product_revision" "$lock_staging"
/usr/bin/plutil -insert notarization_submission_id -string "$notary_submission_id" "$lock_staging"
/usr/bin/plutil -convert json "$lock_staging"
/bin/chmod 600 "$lock_staging"

rollback_activation() {
  failed_directory="${runtimes_root}/.${runtime_version}.failed.${timestamp}"
  if [ "$activated" -eq 1 ] && [ -d "$install_directory" ]; then
    /bin/mv "$install_directory" "$failed_directory" 2>/dev/null || true
  fi
  if [ -n "$runtime_backup" ] && [ -d "$runtime_backup" ]; then
    /bin/mv "$runtime_backup" "$install_directory" 2>/dev/null || true
  fi
  if [ -n "$lock_backup" ] && [ -f "$lock_backup" ]; then
    /usr/bin/ditto "$lock_backup" "$lock_staging" 2>/dev/null || true
    /bin/chmod 600 "$lock_staging" 2>/dev/null || true
    /bin/mv -f "$lock_staging" "$lock_path" 2>/dev/null || true
  else
    /bin/rm -f -- "$lock_path"
  fi
}

if [ -e "$install_directory" ]; then
  [ "$replace_existing" -eq 1 ] \
    || fail "Runtime ${runtime_version} is already installed; pass --replace to retain it as a backup"
  runtime_backup="${runtimes_root}/.${runtime_version}.previous.${timestamp}"
  [ ! -e "$runtime_backup" ] || fail "the Runtime backup already exists"
  /bin/mv "$install_directory" "$runtime_backup"
fi

if ! /bin/mv "$staging_directory" "$install_directory"; then
  rollback_activation
  fail "failed to activate the candidate Runtime"
fi
activated=1
if ! /bin/mv -f "$lock_staging" "$lock_path"; then
  rollback_activation
  fail "failed to activate the candidate Runtime lock"
fi

installed_cli="${install_directory}/SAFA.app/Contents/MacOS/safa"
broker_service="gui/$(/usr/bin/id -u)/dev.safa.broker"
if /bin/launchctl print "$broker_service" >/dev/null 2>&1; then
  if ! /bin/launchctl kickstart -k "$broker_service"; then
    rollback_activation
    fail "candidate installed but the Broker could not restart; previous Runtime restored"
  fi
fi
if ! "$installed_cli" doctor >/dev/null 2>&1; then
  rollback_activation
  if /bin/launchctl print "$broker_service" >/dev/null 2>&1; then
    /bin/launchctl kickstart -k "$broker_service" >/dev/null 2>&1 || true
  fi
  fail "candidate installed but failed Broker startup; previous Runtime restored"
fi

printf '%s\n' "Installed notarized SAFA Runtime ${runtime_version} for ${architecture}."
printf '%s\n' "Artifact SHA-256: ${artifact_sha256}"
[ -z "$lock_backup" ] || printf '%s\n' "Previous lock retained at: ${lock_backup}"
[ -z "$runtime_backup" ] || printf '%s\n' "Previous same-version Runtime retained at: ${runtime_backup}"
