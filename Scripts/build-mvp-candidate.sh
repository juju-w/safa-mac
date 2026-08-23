#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat <<'EOF'
Usage: Scripts/build-mvp-candidate.sh --team-id TEAM_ID --identity-hash SHA1 \
       --keychain PATH --broker-profile PATH --notary-profile PROFILE \
       --output-dir DIRECTORY

Build one universal Developer ID signed and notarized MVP candidate from an exact clean commit.
The script never uploads, publishes, tags, or changes a Runtime installation.
EOF
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

team_identifier=""
identity_hash=""
keychain_path=""
broker_profile=""
notary_profile=""
output_directory=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      team_identifier="$2"
      shift 2
      ;;
    --identity-hash)
      [ "$#" -ge 2 ] || fail "--identity-hash requires a value"
      identity_hash="$2"
      shift 2
      ;;
    --keychain)
      [ "$#" -ge 2 ] || fail "--keychain requires a value"
      keychain_path="$2"
      shift 2
      ;;
    --broker-profile)
      [ "$#" -ge 2 ] || fail "--broker-profile requires a value"
      broker_profile="$2"
      shift 2
      ;;
    --notary-profile)
      [ "$#" -ge 2 ] || fail "--notary-profile requires a value"
      notary_profile="$2"
      shift 2
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || fail "--output-dir requires a value"
      output_directory="$2"
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
printf '%s\n' "$identity_hash" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{40}$' \
  || fail "--identity-hash must contain exactly 40 hexadecimal characters"
printf '%s\n' "$notary_profile" | /usr/bin/grep -Eq '^[A-Za-z0-9._-]{1,64}$' \
  || fail "--notary-profile must be a safe Keychain profile name"
[ -f "$keychain_path" ] && [ ! -L "$keychain_path" ] \
  || fail "--keychain must identify a regular Keychain file"
[ -f "$broker_profile" ] && [ ! -L "$broker_profile" ] \
  || fail "--broker-profile must identify a regular Developer ID provisioning profile"
case "$output_directory" in
  /*) ;;
  *) fail "--output-dir must be an absolute path" ;;
esac
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] \
  || fail "--output-dir must identify an existing directory"
[ "$(uname -s)" = "Darwin" ] || fail "MVP candidate assembly requires macOS"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
signing_verifier="${repository_root}/Scripts/verify-runtime-signing.sh"
profile_verifier="${repository_root}/Scripts/verify-broker-provisioning-profile.sh"
settings_path="${repository_root}/Apps/SAFA/Config/BuildSettings.xcconfig"
product_source="${repository_root}/conformance/product-source.json"

[ -z "$(/usr/bin/git -C "$repository_root" status --porcelain --untracked-files=all)" ] \
  || fail "the Runtime repository must be clean before candidate assembly"
runtime_revision=$(/usr/bin/git -C "$repository_root" rev-parse HEAD)
printf '%s\n' "$runtime_revision" | /usr/bin/grep -Eq '^[0-9a-f]{40}$' \
  || fail "the Runtime revision is invalid"
product_revision=$(/usr/bin/plutil -extract revision raw -o - "$product_source" 2>/dev/null) \
  || fail "the pinned Product revision is unavailable"
printf '%s\n' "$product_revision" | /usr/bin/grep -Eq '^[0-9a-f]{40}$' \
  || fail "the pinned Product revision is invalid"

runtime_version=$(/usr/bin/awk '$1 == "MARKETING_VERSION" { print $3; exit }' "$settings_path")
printf '%s\n' "$runtime_version" \
  | /usr/bin/grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
  || fail "MARKETING_VERSION must be a stable semantic version"

"${repository_root}/Scripts/scan-secrets.sh" --repository "$repository_root"

identity_count=$(/usr/bin/security find-identity -v -p codesigning "$keychain_path" 2>/dev/null \
  | /usr/bin/awk -v selected="$identity_hash" '
      toupper($2) == toupper(selected) && index($0, "Developer ID Application:") > 0 {
        count += 1
      }
      END { print count + 0 }
    ')
[ "$identity_count" -eq 1 ] \
  || fail "the selected Developer ID Application identity is not uniquely available"

build_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-mvp-candidate.XXXXXX")
cleanup() {
  /bin/rm -rf -- "$build_root"
}
trap cleanup EXIT HUP INT TERM
umask 077

/usr/bin/xcodebuild \
  -quiet \
  -project "${repository_root}/Apps/SAFA/SAFA.xcodeproj" \
  -scheme "SAFA Runtime" \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "${build_root}/DerivedData" \
  CODE_SIGNING_ALLOWED=NO \
  ONLY_ACTIVE_ARCH=NO \
  'ARCHS=arm64 x86_64' \
  build

unsigned_app="${build_root}/DerivedData/Build/Products/Release/SAFA.app"
staged_app="${build_root}/SAFA.app"
[ -d "$unsigned_app" ] || fail "Xcode did not assemble SAFA.app"
/usr/bin/ditto "$unsigned_app" "$staged_app"

cli_path="${staged_app}/Contents/MacOS/safa"
broker_app="${staged_app}/Contents/Library/Helpers/SAFABrokerAgent.app"
broker_path="${broker_app}/Contents/MacOS/safa-broker"
askpass_path="${staged_app}/Contents/Library/Helpers/safa-askpass"
trusted_setup_path="${staged_app}/Contents/Library/Helpers/safa-trusted-setup"
for component in "$staged_app" "$cli_path" "$broker_app" "$broker_path" "$askpass_path" "$trusted_setup_path"; do
  [ -e "$component" ] || fail "Runtime component is missing: $component"
done
/usr/bin/ditto "$broker_profile" "${broker_app}/Contents/embedded.provisionprofile"

broker_entitlements="${build_root}/Broker.entitlements"
/usr/bin/plutil -create xml1 "$broker_entitlements"
/usr/bin/plutil -insert 'com\.apple\.application-identifier' -string \
  "${team_identifier}.dev.safa.broker" "$broker_entitlements"
/usr/bin/plutil -insert 'com\.apple\.developer\.team-identifier' -string \
  "$team_identifier" "$broker_entitlements"
/usr/bin/plutil -insert keychain-access-groups -json \
  "[\"${team_identifier}.dev.safa.broker\"]" "$broker_entitlements"

sign_component() {
  component=$1
  identifier=$2
  entitlements=${3:-}
  if [ -n "$entitlements" ]; then
    /usr/bin/codesign --force --sign "$identity_hash" --keychain "$keychain_path" \
      --identifier "$identifier" --entitlements "$entitlements" \
      --options runtime --timestamp "$component" >/dev/null
  else
    /usr/bin/codesign --force --sign "$identity_hash" --keychain "$keychain_path" \
      --identifier "$identifier" --options runtime --timestamp "$component" >/dev/null
  fi
}

# Sign nested code inside out. The Broker entitlement is deliberately supplied to both signatures
# because re-signing the Broker app can replace the main executable's entitlement set.
sign_component "$broker_path" dev.safa.broker "$broker_entitlements"
sign_component "$broker_app" dev.safa.broker "$broker_entitlements"
sign_component "$askpass_path" dev.safa.askpass
sign_component "$trusted_setup_path" dev.safa.trusted-local
sign_component "$cli_path" dev.safa.cli
sign_component "$staged_app" dev.safa.cli

/bin/sh "$signing_verifier" "$staged_app" "$team_identifier" \
  || fail "the Developer ID candidate failed the final signing-boundary audit"
/bin/sh "$profile_verifier" "$broker_app" "$team_identifier" \
  || fail "the Developer ID candidate failed Broker provisioning-profile verification"

signature_field() {
  component=$1
  field=$2
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n "s/^${field}=//p" \
    | /usr/bin/head -n 1
}

for component in "$staged_app" "$cli_path" "$broker_app" "$broker_path" "$askpass_path" "$trusted_setup_path"; do
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

architectures=$(/usr/bin/lipo -archs "$cli_path")
case " $architectures " in *' arm64 '*) ;; *) fail "the candidate is missing arm64" ;; esac
case " $architectures " in *' x86_64 '*) ;; *) fail "the candidate is missing x86_64" ;; esac
[ "$(printf '%s\n' "$architectures" | /usr/bin/awk '{ print NF }')" -eq 2 ] \
  || fail "the candidate contains an unexpected architecture"
[ "$("$cli_path" --version)" = "$runtime_version" ] \
  || fail "the candidate CLI version does not match MARKETING_VERSION"

submission_archive="${build_root}/submission.zip"
notary_result="${build_root}/notary-result.json"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$staged_app" "$submission_archive"
/usr/bin/xcrun notarytool submit "$submission_archive" \
  --keychain-profile "$notary_profile" --keychain "$keychain_path" \
  --wait --output-format json > "$notary_result"
notary_status=$(/usr/bin/plutil -extract status raw -o - "$notary_result" 2>/dev/null) \
  || fail "notarytool returned no status"
[ "$notary_status" = "Accepted" ] || fail "Apple notarization did not accept the candidate"
notary_submission_id=$(/usr/bin/plutil -extract id raw -o - "$notary_result" 2>/dev/null) \
  || fail "notarytool returned no submission identifier"
printf '%s\n' "$notary_submission_id" \
  | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' \
  || fail "notarytool returned an invalid submission identifier"

/usr/bin/xcrun stapler staple "$staged_app"
/usr/bin/xcrun stapler validate "$staged_app"
/usr/sbin/spctl --assess --type execute --verbose=4 "$staged_app"
/bin/sh "$signing_verifier" "$staged_app" "$team_identifier" \
  || fail "the stapled candidate failed the final signing-boundary audit"
/bin/sh "$profile_verifier" "$broker_app" "$team_identifier" \
  || fail "the stapled candidate failed Broker provisioning-profile verification"

artifact_name="SAFA-Runtime-${runtime_version}-macos-universal.zip"
evidence_name="SAFA-Runtime-${runtime_version}-macos-universal.evidence.json"
artifact_staging="${build_root}/${artifact_name}"
evidence_staging="${build_root}/${evidence_name}"
artifact_target="${output_directory}/${artifact_name}"
evidence_target="${output_directory}/${evidence_name}"
[ ! -e "$artifact_target" ] || fail "candidate artifact already exists: $artifact_target"
[ ! -e "$evidence_target" ] || fail "candidate evidence already exists: $evidence_target"

/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$staged_app" "$artifact_staging"
"${repository_root}/Scripts/scan-secrets.sh" \
  --repository "$repository_root" --artifact "$artifact_staging"
artifact_sha256=$(/usr/bin/shasum -a 256 "$artifact_staging" | /usr/bin/awk '{ print $1 }')
printf '%s\n' "$artifact_sha256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' \
  || fail "the candidate archive digest is invalid"

app_cdhash=$(signature_field "$staged_app" CDHash)
broker_cdhash=$(signature_field "$broker_app" CDHash)
askpass_cdhash=$(signature_field "$askpass_path" CDHash)
trusted_setup_cdhash=$(signature_field "$trusted_setup_path" CDHash)
recorded_at=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')

/usr/bin/plutil -create xml1 "$evidence_staging"
/usr/bin/plutil -insert schema -string dev.safa.mvp-candidate-artifact/v1 "$evidence_staging"
/usr/bin/plutil -insert recorded_at -string "$recorded_at" "$evidence_staging"
/usr/bin/plutil -insert runtime_revision -string "$runtime_revision" "$evidence_staging"
/usr/bin/plutil -insert product_revision -string "$product_revision" "$evidence_staging"
/usr/bin/plutil -insert runtime_version -string "$runtime_version" "$evidence_staging"
/usr/bin/plutil -insert cli_schema -string dev.safa.cli/v2 "$evidence_staging"
/usr/bin/plutil -insert platform -string macos "$evidence_staging"
/usr/bin/plutil -insert architectures -json '["arm64","x86_64"]' "$evidence_staging"
/usr/bin/plutil -insert team_identifier -string "$team_identifier" "$evidence_staging"
/usr/bin/plutil -insert identity_kind -string 'Developer ID Application' "$evidence_staging"
/usr/bin/plutil -insert artifact -dictionary "$evidence_staging"
/usr/bin/plutil -insert artifact.filename -string "$artifact_name" "$evidence_staging"
/usr/bin/plutil -insert artifact.archive_format -string zip "$evidence_staging"
/usr/bin/plutil -insert artifact.sha256 -string "$artifact_sha256" "$evidence_staging"
/usr/bin/plutil -insert notarization -dictionary "$evidence_staging"
/usr/bin/plutil -insert notarization.status -string "$notary_status" "$evidence_staging"
/usr/bin/plutil -insert notarization.submission_id -string "$notary_submission_id" "$evidence_staging"
/usr/bin/plutil -insert notarization.stapled -bool true "$evidence_staging"
/usr/bin/plutil -insert notarization.gatekeeper_assessed -bool true "$evidence_staging"
/usr/bin/plutil -insert signing -dictionary "$evidence_staging"
/usr/bin/plutil -insert signing.app_cdhash -string "$app_cdhash" "$evidence_staging"
/usr/bin/plutil -insert signing.broker_cdhash -string "$broker_cdhash" "$evidence_staging"
/usr/bin/plutil -insert signing.askpass_cdhash -string "$askpass_cdhash" "$evidence_staging"
/usr/bin/plutil -insert signing.trusted_setup_cdhash -string "$trusted_setup_cdhash" "$evidence_staging"
/usr/bin/plutil -insert signing.designated_requirements_verified -bool true "$evidence_staging"
/usr/bin/plutil -insert signing.broker_profile_verified -bool true "$evidence_staging"
/usr/bin/plutil -insert signing.hardened_runtime_verified -bool true "$evidence_staging"
/usr/bin/plutil -insert secret_scan_passed -bool true "$evidence_staging"
/usr/bin/plutil -convert json "$evidence_staging"

evidence_sha256=$(/usr/bin/shasum -a 256 "$evidence_staging" | /usr/bin/awk '{ print $1 }')
"${repository_root}/Scripts/verify-mvp-candidate.sh" \
  --archive "$artifact_staging" --evidence "$evidence_staging" \
  --evidence-sha256 "$evidence_sha256" --team-id "$team_identifier"

/bin/mv "$artifact_staging" "$artifact_target"
/bin/mv "$evidence_staging" "$evidence_target"
/bin/chmod 600 "$artifact_target" "$evidence_target"

printf '%s\n' "Built notarized SAFA Runtime candidate ${runtime_version}."
printf '%s\n' "Artifact: ${artifact_target}"
printf '%s\n' "Evidence: ${evidence_target}"
printf '%s\n' "SHA-256: ${artifact_sha256}"
printf '%s\n' "Evidence SHA-256: ${evidence_sha256}"
