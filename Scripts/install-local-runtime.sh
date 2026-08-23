#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat <<'EOF'
Usage: Scripts/install-local-runtime.sh --team-id TEAM_ID [--allow-provisioning-updates] [--replace]
       Scripts/install-local-runtime.sh --source-preview --identity-hash SHA1 [--replace]

Build, verify, and install the signed macOS SAFA Runtime for the current user.
This development installer does not publish, notarize, tag, or upload an artifact.

--source-preview uses an existing Apple Development identity for manual local signing and does not
require an Xcode account or provisioning-profile update. It is not Developer ID distribution.
EOF
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

verify_local_http_client() {
  curl_path=/usr/bin/curl
  [ -x "$curl_path" ] || fail "the reviewed local HTTP client is unavailable: /usr/bin/curl"
  /usr/bin/codesign --verify --strict \
    --test-requirement='=anchor apple and identifier "com.apple.curl"' \
    "$curl_path" >/dev/null 2>&1 \
    || fail "the local HTTP client failed Apple platform-signature verification"

  curl_version=$("$curl_path" --version 2>/dev/null) \
    || fail "the local HTTP client could not report its capabilities"
  printf '%s\n' "$curl_version" | /usr/bin/grep -Eq '^Protocols: .*\bhttp\b' \
    || fail "the local HTTP client does not support HTTP"
  printf '%s\n' "$curl_version" | /usr/bin/grep -Eq '^Protocols: .*\bhttps\b' \
    || fail "the local HTTP client does not support HTTPS"

  curl_help=$("$curl_path" --help all 2>/dev/null) \
    || fail "the local HTTP client could not report its reviewed options"
  for required_option in \
    --config \
    --connect-timeout \
    --fail-with-body \
    --max-time \
    --no-progress-meter
  do
    printf '%s\n' "$curl_help" | /usr/bin/grep -F -- "$required_option" >/dev/null \
      || fail "the local HTTP client is missing a reviewed option: $required_option"
  done
}

select_source_preview_broker_profile() {
  selected_profile=""
  for profile_root in \
    "${HOME}/Library/Developer/Xcode/UserData/Provisioning Profiles" \
    "${HOME}/Library/MobileDevice/Provisioning Profiles"
  do
    [ -d "$profile_root" ] || continue
    for candidate in "$profile_root"/*.provisionprofile
    do
      [ -f "$candidate" ] || continue
      profile_xml=$(/usr/bin/security cms -D -i "$candidate" 2>/dev/null) || continue
      profile_team=$(printf '%s' "$profile_xml" \
        | /usr/bin/plutil -extract TeamIdentifier.0 raw -o - - 2>/dev/null) || continue
      [ "$profile_team" = "$team_identifier" ] || continue
      profile_application_identifier=$(printf '%s' "$profile_xml" \
        | /usr/bin/plutil -extract 'Entitlements.com\.apple\.application-identifier' raw -o - - \
          2>/dev/null) || continue
      [ "$profile_application_identifier" = "${team_identifier}.dev.safa.broker" ] || continue
      profile_certificate_count=$(printf '%s' "$profile_xml" \
        | /usr/bin/plutil -extract DeveloperCertificates raw -o - - 2>/dev/null) || continue
      printf '%s\n' "$profile_certificate_count" | /usr/bin/grep -Eq '^[1-9][0-9]*$' \
        || continue
      profile_certificate_matches=0
      profile_certificate_index=0
      while [ "$profile_certificate_index" -lt "$profile_certificate_count" ]; do
        profile_identity=$(printf '%s' "$profile_xml" \
          | /usr/bin/plutil \
            -extract "DeveloperCertificates.${profile_certificate_index}" raw -o - - 2>/dev/null \
          | /usr/bin/base64 -D 2>/dev/null \
          | /usr/bin/openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
          | /usr/bin/sed 's/^SHA1 Fingerprint=//; s/://g') || true
        if [ "$(printf '%s' "$profile_identity" | /usr/bin/tr '[:lower:]' '[:upper:]')" \
          = "$(printf '%s' "$identity_hash" | /usr/bin/tr '[:lower:]' '[:upper:]')" ]; then
          profile_certificate_matches=$((profile_certificate_matches + 1))
        fi
        profile_certificate_index=$((profile_certificate_index + 1))
      done
      [ "$profile_certificate_matches" -eq 1 ] || continue
      profile_expiration=$(printf '%s' "$profile_xml" \
        | /usr/bin/plutil -extract ExpirationDate raw -o - - 2>/dev/null) || continue
      profile_expiration_epoch=$(/bin/date -j -u -f '%Y-%m-%dT%H:%M:%SZ' \
        "$profile_expiration" '+%s' 2>/dev/null) || continue
      [ "$profile_expiration_epoch" -gt "$(/bin/date '+%s')" ] || continue
      selected_profile="$candidate"
      break
    done
    [ -z "$selected_profile" ] || break
  done
  [ -n "$selected_profile" ] \
    || fail "no unexpired development provisioning profile matches dev.safa.broker and the selected identity"
  source_preview_broker_profile="$selected_profile"
}

team_identifier=""
identity_hash=""
allow_provisioning_updates=0
replace_existing=0
source_preview=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --team-id)
      [ "$#" -ge 2 ] || fail "--team-id requires a value"
      team_identifier="$2"
      shift 2
      ;;
    --allow-provisioning-updates)
      allow_provisioning_updates=1
      shift
      ;;
    --source-preview)
      source_preview=1
      shift
      ;;
    --identity-hash)
      [ "$#" -ge 2 ] || fail "--identity-hash requires a value"
      identity_hash="$2"
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

[ "$source_preview" -eq 0 ] || [ "$allow_provisioning_updates" -eq 0 ] \
  || fail "--source-preview and --allow-provisioning-updates are mutually exclusive"
if [ "$source_preview" -eq 1 ]; then
  [ -z "$team_identifier" ] || fail "--team-id is not accepted with --source-preview"
  /usr/bin/printf '%s\n' "$identity_hash" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{40}$' \
    || fail "--source-preview requires a 40-character --identity-hash"
  identity_count=$(/usr/bin/security find-identity -v -p codesigning 2>/dev/null \
    | /usr/bin/awk -v selected="$identity_hash" '
        toupper($2) == toupper(selected) && index($0, "Apple Development:") > 0 {
          count += 1
        }
        END { print count + 0 }
      ')
  [ "$identity_count" -eq 1 ] \
    || fail "the selected Apple Development signing identity is not available"
else
  [ -z "$identity_hash" ] || fail "--identity-hash requires --source-preview"
  [ -n "$team_identifier" ] || fail "--team-id is required"
  if ! /usr/bin/printf '%s\n' "$team_identifier" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$'; then
    fail "TEAM_ID must contain exactly 10 uppercase letters or digits"
  fi
fi

[ "$(uname -s)" = "Darwin" ] || fail "the local Runtime installer requires macOS"
[ -n "${HOME:-}" ] || fail "the current user home directory is unavailable"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
signing_verifier="${repository_root}/Scripts/verify-runtime-signing.sh"
tree_hasher="${repository_root}/Scripts/runtime-tree-sha256.sh"
settings_path="${repository_root}/Apps/SAFA/Config/BuildSettings.xcconfig"
runtime_version=$(/usr/bin/awk '$1 == "MARKETING_VERSION" { print $3; exit }' "$settings_path")
[ -n "$runtime_version" ] || fail "MARKETING_VERSION is missing"
verify_local_http_client
if ! printf '%s\n' "$runtime_version" \
  | /usr/bin/grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  fail "MARKETING_VERSION must be a stable semantic version"
fi

architecture=$(uname -m)
case "$architecture" in
  arm64 | x86_64) ;;
  *) fail "unsupported macOS architecture: $architecture" ;;
esac

build_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-runtime-build.XXXXXX")
data_root="${HOME}/Library/Application Support/SAFA"
runtimes_root="${data_root}/runtimes"
install_directory="${runtimes_root}/${runtime_version}"
staging_directory="${runtimes_root}/.${runtime_version}.installing.$$"
lock_path="${data_root}/runtime.local.json"
lock_staging="${data_root}/.runtime.local.json.$$"
[ ! -d "$lock_path" ] || fail "Runtime lock path is a directory"

cleanup() {
  rm -rf -- "$build_root" "$staging_directory"
  rm -f -- "$lock_staging"
}
trap cleanup EXIT HUP INT TERM

rollback_runtime_activation() {
  if [ -d "$install_directory" ] && [ ! -e "$staging_directory" ]; then
    /bin/mv "$install_directory" "$staging_directory" 2>/dev/null || true
  fi
  if [ -n "${backup_directory:-}" ] && [ -d "$backup_directory" ]; then
    /bin/mv "$backup_directory" "$install_directory" 2>/dev/null || true
  fi
}

set -- \
  -quiet \
  -project "${repository_root}/Apps/SAFA/SAFA.xcodeproj" \
  -scheme "SAFA Runtime" \
  -configuration Release \
  -derivedDataPath "${build_root}/DerivedData" \
  SAFA_DEVELOPMENT_TEAM="$team_identifier" \
  CODE_SIGNING_ALLOWED=YES \
  build

if [ "$source_preview" -eq 1 ]; then
  set -- \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY="$identity_hash" \
    PROVISIONING_PROFILE_SPECIFIER= \
    CODE_SIGN_ENTITLEMENTS= \
    "$@"
elif [ "$allow_provisioning_updates" -eq 1 ]; then
  set -- -allowProvisioningUpdates "$@"
fi

/usr/bin/xcodebuild "$@"

source_app="${build_root}/DerivedData/Build/Products/Release/SAFA.app"
cli_path="${source_app}/Contents/MacOS/safa"
broker_app="${source_app}/Contents/Library/Helpers/SAFABrokerAgent.app"
broker_path="${broker_app}/Contents/MacOS/safa-broker"
askpass_path="${source_app}/Contents/Library/Helpers/safa-askpass"
trusted_setup_path="${source_app}/Contents/Library/Helpers/safa-trusted-setup"

for component in "$source_app" "$cli_path" "$broker_app" "$broker_path" "$askpass_path" "$trusted_setup_path"; do
  [ -e "$component" ] || fail "Runtime component is missing: $component"
done

signature_field() {
  component="$1"
  field="$2"
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n "s/^${field}=//p" \
    | /usr/bin/head -n 1
}

if [ "$source_preview" -eq 1 ]; then
  # Xcode may leave the outer host ad-hoc when no provisioning profile exists. Re-sign every local
  # preview component explicitly, inside out, with the already selected Apple Development identity.
  # The final Broker signature must retain its Team-scoped Keychain access group.
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.broker \
    --options runtime --timestamp=none "$broker_path" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview broker"
  team_identifier=$(signature_field "$broker_path" TeamIdentifier)
  /usr/bin/printf '%s\n' "$team_identifier" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$' \
    || fail "the Source Preview signing identity has no valid Apple Team identifier"
  select_source_preview_broker_profile
  source_preview_broker_entitlements="${build_root}/Broker.entitlements"
  /usr/bin/plutil -create xml1 "$source_preview_broker_entitlements" \
    || fail "failed to create Source Preview broker entitlements"
  /usr/bin/plutil -insert 'com\.apple\.application-identifier' -string \
    "${team_identifier}.dev.safa.broker" "$source_preview_broker_entitlements" \
    || fail "failed to bind the Source Preview broker application identifier"
  /usr/bin/plutil -insert 'com\.apple\.developer\.team-identifier' -string \
    "$team_identifier" "$source_preview_broker_entitlements" \
    || fail "failed to bind the Source Preview broker Team identifier"
  /usr/bin/plutil -insert keychain-access-groups -json \
    "[\"${team_identifier}.dev.safa.broker\"]" "$source_preview_broker_entitlements" \
    || fail "failed to scope Source Preview broker Keychain access"
  /usr/bin/ditto "$source_preview_broker_profile" \
    "${broker_app}/Contents/embedded.provisionprofile" \
    || fail "failed to embed the Source Preview broker provisioning profile"
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.broker \
    --entitlements "$source_preview_broker_entitlements" \
    --options runtime --timestamp=none "$broker_path" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview broker Keychain boundary"
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.broker \
    --entitlements "$source_preview_broker_entitlements" \
    --options runtime --timestamp=none "$broker_app" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview broker app"
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.askpass \
    --options runtime --timestamp=none "$askpass_path" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview AskPass helper"
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.trusted-local \
    --options runtime --timestamp=none "$trusted_setup_path" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview trusted setup helper"
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.cli \
    --options runtime --timestamp=none "$cli_path" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview CLI"
  /usr/bin/codesign --force --sign "$identity_hash" --identifier dev.safa.cli \
    --options runtime --timestamp=none "$source_app" >/dev/null 2>&1 \
    || fail "failed to sign the Source Preview app"
fi

for component in "$source_app" "$cli_path" "$broker_app" "$broker_path" "$askpass_path" "$trusted_setup_path"; do
  /usr/bin/codesign --verify --strict "$component" >/dev/null 2>&1 \
    || fail "Runtime component failed code-signature verification: $component"
done
/usr/bin/codesign --verify --deep --strict "$source_app" >/dev/null 2>&1 \
  || fail "SAFA.app failed deep code-signature verification"

[ "$(signature_field "$cli_path" Identifier)" = "dev.safa.cli" ] \
  || fail "CLI signing identifier is invalid"
[ "$(signature_field "$broker_path" Identifier)" = "dev.safa.broker" ] \
  || fail "Broker signing identifier is invalid"
[ "$(signature_field "$askpass_path" Identifier)" = "dev.safa.askpass" ] \
  || fail "AskPass signing identifier is invalid"
[ "$(signature_field "$trusted_setup_path" Identifier)" = "dev.safa.trusted-local" ] \
  || fail "trusted setup signing identifier is invalid"

for component_role in \
  "app|${source_app}" \
  "cli|${cli_path}" \
  "broker-app|${broker_app}" \
  "broker|${broker_path}" \
  "askpass|${askpass_path}" \
  "trusted-setup|${trusted_setup_path}"
do
  role=${component_role%%|*}
  component=${component_role#*|}
  [ "$(signature_field "$component" TeamIdentifier)" = "$team_identifier" ] \
    || fail "Runtime ${role} component has an unexpected Team identity"
done

/bin/sh "$signing_verifier" "$source_app" "$team_identifier" \
  || fail "Built Runtime failed the final signing-boundary audit"

binary_architectures=$(/usr/bin/lipo -archs "$cli_path")
case " ${binary_architectures} " in
  *" ${architecture} "*) ;;
  *) fail "Runtime does not contain the local architecture: $architecture" ;;
esac

installed_version=$("$cli_path" --version) \
  || fail "Runtime returned an invalid version response"
[ "$installed_version" = "$runtime_version" ] \
  || fail "Runtime version ${installed_version} does not match ${runtime_version}"

app_cdhash=$(signature_field "$source_app" CDHash)
broker_cdhash=$(signature_field "$broker_app" CDHash)
askpass_cdhash=$(signature_field "$askpass_path" CDHash)
trusted_setup_cdhash=$(signature_field "$trusted_setup_path" CDHash)
for cdhash in "$app_cdhash" "$broker_cdhash" "$askpass_cdhash" "$trusted_setup_cdhash"; do
  if ! printf '%s\n' "$cdhash" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'; then
    fail "Runtime returned an invalid code-directory hash"
  fi
done

umask 077
/bin/mkdir -p "$runtimes_root"
/bin/chmod 700 "$data_root" "$runtimes_root"

/usr/bin/ditto "$source_app" "${staging_directory}/SAFA.app"
/bin/chmod 700 "$staging_directory"
/bin/sh "$signing_verifier" "${staging_directory}/SAFA.app" "$team_identifier" \
  || fail "Staged Runtime failed the final signing-boundary audit"

if [ "$source_preview" -eq 1 ]; then
  runtime_tree_sha256=$("$tree_hasher" "${staging_directory}/SAFA.app") \
    || fail "Staged Runtime file tree could not be locked"
  printf '%s\n' "$runtime_tree_sha256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' \
    || fail "Staged Runtime returned an invalid file-tree digest"
  printf '%s\n' "{\"schema\":\"dev.safa.local-runtime-lock/v1\",\"runtime_version\":\"${runtime_version}\",\"cli_schema\":\"dev.safa.cli/v2\",\"platform\":\"macos\",\"architecture\":\"${architecture}\",\"team_identifier\":\"${team_identifier}\",\"app_cdhash\":\"${app_cdhash}\",\"broker_cdhash\":\"${broker_cdhash}\",\"askpass_cdhash\":\"${askpass_cdhash}\",\"trusted_setup_cdhash\":\"${trusted_setup_cdhash}\",\"installation_channel\":\"source-preview\",\"verification_fallback\":\"source-preview-tree-sha256-v1\",\"runtime_tree_sha256\":\"${runtime_tree_sha256}\"}" \
    > "$lock_staging"
else
  printf '%s\n' "{\"schema\":\"dev.safa.local-runtime-lock/v1\",\"runtime_version\":\"${runtime_version}\",\"cli_schema\":\"dev.safa.cli/v2\",\"platform\":\"macos\",\"architecture\":\"${architecture}\",\"team_identifier\":\"${team_identifier}\",\"app_cdhash\":\"${app_cdhash}\",\"broker_cdhash\":\"${broker_cdhash}\",\"askpass_cdhash\":\"${askpass_cdhash}\",\"trusted_setup_cdhash\":\"${trusted_setup_cdhash}\"}" \
    > "$lock_staging"
fi
/bin/chmod 600 "$lock_staging"

if [ -e "$install_directory" ]; then
  [ "$replace_existing" -eq 1 ] \
    || fail "Runtime ${runtime_version} is already installed; pass --replace to retain it as a backup"
  backup_directory="${runtimes_root}/.${runtime_version}.previous.$(/bin/date -u +%Y%m%dT%H%M%SZ)"
  /bin/mv "$install_directory" "$backup_directory"
  printf '%s\n' "Previous Runtime retained at: ${backup_directory}"
fi

if ! /bin/mv "$staging_directory" "$install_directory"; then
  rollback_runtime_activation
  fail "Failed to activate the staged Runtime"
fi

if ! /bin/mv "$lock_staging" "$lock_path"; then
  rollback_runtime_activation
  fail "Failed to activate the local Runtime lock"
fi

installed_cli="${install_directory}/SAFA.app/Contents/MacOS/safa"
broker_service="gui/$(/usr/bin/id -u)/dev.safa.broker"
if /bin/launchctl print "$broker_service" >/dev/null 2>&1; then
  /bin/launchctl kickstart -k "$broker_service" \
    || fail "Installed Runtime but could not restart the loaded Broker"
fi
"$installed_cli" --version
printf '%s\n' "Installed SAFA Runtime ${runtime_version} for ${architecture}."
printf '%s\n' "Run: ${installed_cli} doctor"
if ! "$installed_cli" doctor >/dev/null 2>&1; then
  printf '%s\n' \
    "Broker is installed but not reachable; unlock the macOS session, then inspect 'safa setup status' and System Settings > General > Login Items if it remains unavailable." >&2
fi
