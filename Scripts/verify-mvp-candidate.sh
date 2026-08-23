#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat <<'EOF'
Usage: Scripts/verify-mvp-candidate.sh --archive ZIP --evidence JSON \
       --evidence-sha256 SHA256 --team-id TEAM_ID

Verify an exact production-identity-signed, notarized SAFA Runtime candidate without installing it.
EOF
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

archive_path=""
evidence_path=""
expected_evidence_sha256=""
expected_team=""

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
      expected_evidence_sha256="$2"
      shift 2
      ;;
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      expected_team="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) fail "unexpected argument: $1" ;;
  esac
done

printf '%s\n' "$expected_team" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$' \
  || fail "TEAM_ID must contain exactly 10 uppercase letters or digits"
printf '%s\n' "$expected_evidence_sha256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' \
  || fail "--evidence-sha256 must contain exactly 64 lowercase hexadecimal characters"
[ -f "$archive_path" ] && [ ! -L "$archive_path" ] \
  || fail "--archive must identify a regular file"
[ -f "$evidence_path" ] && [ ! -L "$evidence_path" ] \
  || fail "--evidence must identify a regular file"
[ "$(uname -s)" = "Darwin" ] || fail "MVP candidate verification requires macOS"

actual_evidence_sha256=$(/usr/bin/shasum -a 256 "$evidence_path" | /usr/bin/awk '{ print $1 }')
[ "$actual_evidence_sha256" = "$expected_evidence_sha256" ] \
  || fail "candidate evidence does not match the expected SHA-256"

field() {
  /usr/bin/plutil -extract "$1" raw -o - "$evidence_path" 2>/dev/null
}

[ "$(field schema)" = "dev.safa.mvp-candidate-artifact/v1" ] \
  || fail "candidate evidence has an unsupported schema"
[ "$(field cli_schema)" = "dev.safa.cli/v2" ] \
  || fail "candidate evidence has an incompatible CLI schema"
[ "$(field platform)" = "macos" ] \
  || fail "candidate evidence does not describe macOS"
[ "$(field team_identifier)" = "$expected_team" ] \
  || fail "candidate evidence has an unexpected Team identity"
[ "$(field identity_kind)" = "Developer ID Application" ] \
  || fail "candidate evidence is not a Developer ID distribution"
[ "$(field notarization.status)" = "Accepted" ] \
  || fail "candidate evidence is not notarization-accepted"
[ "$(field notarization.stapled)" = true ] \
  || fail "candidate evidence does not record a stapled notarization ticket"
[ "$(field notarization.gatekeeper_assessed)" = true ] \
  || fail "candidate evidence does not record Gatekeeper assessment"
[ "$(field signing.designated_requirements_verified)" = true ] \
  || fail "candidate evidence does not record designated-requirement verification"
[ "$(field signing.broker_profile_verified)" = true ] \
  || fail "candidate evidence does not record Broker profile verification"
[ "$(field signing.hardened_runtime_verified)" = true ] \
  || fail "candidate evidence does not record Hardened Runtime verification"
[ "$(field secret_scan_passed)" = true ] \
  || fail "candidate evidence does not record a passing secret scan"

runtime_revision=$(field runtime_revision) || fail "candidate evidence has no Runtime revision"
product_revision=$(field product_revision) || fail "candidate evidence has no Product revision"
runtime_version=$(field runtime_version) || fail "candidate evidence has no Runtime version"
artifact_name=$(field artifact.filename) || fail "candidate evidence has no artifact name"
artifact_sha256=$(field artifact.sha256) || fail "candidate evidence has no artifact digest"
notary_submission_id=$(field notarization.submission_id) \
  || fail "candidate evidence has no notarization submission identifier"

printf '%s\n' "$runtime_revision" | /usr/bin/grep -Eq '^[0-9a-f]{40}$' \
  || fail "candidate evidence has an invalid Runtime revision"
printf '%s\n' "$product_revision" | /usr/bin/grep -Eq '^[0-9a-f]{40}$' \
  || fail "candidate evidence has an invalid Product revision"
printf '%s\n' "$runtime_version" \
  | /usr/bin/grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
  || fail "candidate evidence has an invalid Runtime version"
printf '%s\n' "$artifact_name" \
  | /usr/bin/grep -Eq '^SAFA-Runtime-[0-9]+\.[0-9]+\.[0-9]+-macos-universal\.zip$' \
  || fail "candidate evidence has an invalid artifact name"
printf '%s\n' "$artifact_sha256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' \
  || fail "candidate evidence has an invalid artifact digest"
printf '%s\n' "$notary_submission_id" \
  | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' \
  || fail "candidate evidence has an invalid notarization submission identifier"
[ "$(basename -- "$archive_path")" = "$artifact_name" ] \
  || fail "candidate archive name does not match its evidence"
[ "$(/usr/bin/plutil -extract architectures json -o - "$evidence_path" 2>/dev/null)" \
  = '["arm64","x86_64"]' ] \
  || fail "candidate evidence does not contain the exact universal architecture set"

actual_artifact_sha256=$(/usr/bin/shasum -a 256 "$archive_path" | /usr/bin/awk '{ print $1 }')
[ "$actual_artifact_sha256" = "$artifact_sha256" ] \
  || fail "candidate archive does not match its evidence"

verify_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-mvp-verify.XXXXXX")
cleanup() {
  /bin/rm -rf -- "$verify_root"
}
trap cleanup EXIT HUP INT TERM
/usr/bin/ditto -x -k "$archive_path" "$verify_root"
[ -z "$(/usr/bin/find "$verify_root" -type l -print -quit)" ] \
  || fail "candidate archive contains a symbolic link"

runtime_app="${verify_root}/SAFA.app"
[ -d "$runtime_app" ] || fail "candidate archive does not contain one root SAFA.app"
[ "$(/usr/bin/find "$verify_root" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" -eq 1 ] \
  || fail "candidate archive contains unexpected root entries"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
/bin/sh "${script_dir}/verify-runtime-signing.sh" "$runtime_app" "$expected_team" \
  || fail "candidate failed the final signing-boundary audit"

cli_path="${runtime_app}/Contents/MacOS/safa"
broker_app="${runtime_app}/Contents/Library/Helpers/SAFABrokerAgent.app"
broker_path="${broker_app}/Contents/MacOS/safa-broker"
askpass_path="${runtime_app}/Contents/Library/Helpers/safa-askpass"
trusted_setup_path="${runtime_app}/Contents/Library/Helpers/safa-trusted-setup"
/bin/sh "${script_dir}/verify-broker-provisioning-profile.sh" "$broker_app" "$expected_team" \
  || fail "candidate failed Broker provisioning-profile verification"

signature_field() {
  component=$1
  requested_field=$2
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n "s/^${requested_field}=//p" \
    | /usr/bin/head -n 1
}

for component in "$runtime_app" "$cli_path" "$broker_app" "$broker_path" "$askpass_path" "$trusted_setup_path"; do
  authority=$(/usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n 's/^Authority=//p' | /usr/bin/head -n 1)
  case "$authority" in
    'Developer ID Application:'*) ;;
    *) fail "a Runtime component is not signed by Developer ID Application: $component" ;;
  esac
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/grep -Eq '^CodeDirectory .*flags=.*\(runtime\)' \
    || fail "a Runtime component is missing Hardened Runtime: $component"
done

verify_designated_requirement() {
  component=$1
  identifier=$2
  requirement="=anchor apple generic and identifier \"${identifier}\" and certificate leaf[subject.OU] = \"${expected_team}\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --strict --test-requirement="$requirement" "$component" \
    >/dev/null 2>&1 || fail "a Runtime component has an invalid designated requirement: $component"
  actual_requirement=$(/usr/bin/codesign --display --requirements - "$component" 2>&1 \
    | /usr/bin/sed -n 's/^designated => //p')
  expected_requirement="identifier \"${identifier}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = \"${expected_team}\""
  [ "$actual_requirement" = "$expected_requirement" ] \
    || fail "a Runtime component does not carry the expected designated requirement: $component"
}
verify_designated_requirement "$runtime_app" dev.safa.cli
verify_designated_requirement "$cli_path" dev.safa.cli
verify_designated_requirement "$broker_app" dev.safa.broker
verify_designated_requirement "$broker_path" dev.safa.broker
verify_designated_requirement "$askpass_path" dev.safa.askpass
verify_designated_requirement "$trusted_setup_path" dev.safa.trusted-local

/usr/bin/xcrun stapler validate "$runtime_app"
/usr/sbin/spctl --assess --type execute --verbose=4 "$runtime_app"

architectures=$(/usr/bin/lipo -archs "$cli_path")
case " $architectures " in *' arm64 '*) ;; *) fail "candidate is missing arm64" ;; esac
case " $architectures " in *' x86_64 '*) ;; *) fail "candidate is missing x86_64" ;; esac
[ "$(printf '%s\n' "$architectures" | /usr/bin/awk '{ print NF }')" -eq 2 ] \
  || fail "candidate contains an unexpected architecture"
[ "$("$cli_path" --version)" = "$runtime_version" ] \
  || fail "candidate CLI version does not match its evidence"

[ "$(signature_field "$runtime_app" CDHash)" = "$(field signing.app_cdhash)" ] \
  || fail "candidate app CDHash does not match its evidence"
[ "$(signature_field "$broker_app" CDHash)" = "$(field signing.broker_cdhash)" ] \
  || fail "candidate Broker CDHash does not match its evidence"
[ "$(signature_field "$askpass_path" CDHash)" = "$(field signing.askpass_cdhash)" ] \
  || fail "candidate AskPass CDHash does not match its evidence"
[ "$(signature_field "$trusted_setup_path" CDHash)" = "$(field signing.trusted_setup_cdhash)" ] \
  || fail "candidate trusted-setup CDHash does not match its evidence"

printf '%s\n' "Verified SAFA Runtime ${runtime_version} candidate."
printf '%s\n' "Runtime revision: ${runtime_revision}"
printf '%s\n' "Product revision: ${product_revision}"
printf '%s\n' "Artifact SHA-256: ${artifact_sha256}"
