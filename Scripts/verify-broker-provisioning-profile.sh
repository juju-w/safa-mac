#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  printf '%s\n' 'Usage: Scripts/verify-broker-provisioning-profile.sh BROKER_APP_PATH TEAM_ID'
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

[ "$#" -eq 2 ] || {
  usage >&2
  exit 2
}

broker_app=$1
expected_team=$2
printf '%s\n' "$expected_team" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$' \
  || fail "TEAM_ID must contain exactly 10 uppercase letters or digits"
[ -d "$broker_app" ] || fail "Broker app is missing: $broker_app"

broker_path="${broker_app}/Contents/MacOS/safa-broker"
profile_path="${broker_app}/Contents/embedded.provisionprofile"
[ -f "$broker_path" ] || fail "Broker executable is missing"
[ -f "$profile_path" ] && [ ! -L "$profile_path" ] \
  || fail "Broker Developer ID provisioning profile is missing"

verify_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-profile-verify.XXXXXX")
cleanup() {
  /bin/rm -rf -- "$verify_root"
}
trap cleanup EXIT HUP INT TERM
profile_plist="${verify_root}/profile.plist"
/usr/bin/security cms -D -i "$profile_path" > "$profile_plist" 2>/dev/null \
  || fail "Broker provisioning profile cannot be decoded"

profile_team=$(/usr/bin/plutil -extract TeamIdentifier.0 raw -o - "$profile_plist" 2>/dev/null) \
  || fail "Broker provisioning profile has no Team identifier"
[ "$profile_team" = "$expected_team" ] \
  || fail "Broker provisioning profile has an unexpected Team identifier"
[ "$(/usr/bin/plutil -extract Platform json -o - "$profile_plist" 2>/dev/null)" = '["OSX"]' ] \
  || fail "Broker provisioning profile is not for macOS"
[ "$(/usr/bin/plutil -extract ProvisionsAllDevices raw -o - "$profile_plist" 2>/dev/null)" = true ] \
  || fail "Broker provisioning profile is not a Developer ID distribution profile"
if /usr/bin/plutil -type ProvisionedDevices "$profile_plist" >/dev/null 2>&1; then
  fail "Broker provisioning profile is device-scoped rather than Developer ID distribution"
fi

expected_application_identifier="${expected_team}.dev.safa.broker"
profile_application_identifier=$(
  /usr/bin/plutil -extract 'Entitlements.com\.apple\.application-identifier' raw -o - \
    "$profile_plist" 2>/dev/null
) || fail "Broker provisioning profile has no application identifier"
[ "$profile_application_identifier" = "$expected_application_identifier" ] \
  || fail "Broker provisioning profile has an unexpected application identifier"
profile_entitlement_team=$(
  /usr/bin/plutil -extract 'Entitlements.com\.apple\.developer\.team-identifier' raw -o - \
    "$profile_plist" 2>/dev/null
) || fail "Broker provisioning profile has no entitlement Team identifier"
[ "$profile_entitlement_team" = "$expected_team" ] \
  || fail "Broker provisioning profile entitlement has an unexpected Team identifier"
profile_groups=$(
  /usr/bin/plutil -extract 'Entitlements.keychain-access-groups' json -o - \
    "$profile_plist" 2>/dev/null
) || fail "Broker provisioning profile does not authorize Keychain access groups"
printf '%s\n' "$profile_groups" \
  | /usr/bin/grep -Eq "\"${expected_team}\.(dev\.safa\.broker|\*)\"" \
  || fail "Broker provisioning profile does not authorize the Broker Keychain group"

profile_expiration=$(/usr/bin/plutil -extract ExpirationDate raw -o - "$profile_plist" 2>/dev/null) \
  || fail "Broker provisioning profile has no expiration date"
profile_expiration_epoch=$(/bin/date -j -u -f '%Y-%m-%dT%H:%M:%SZ' \
  "$profile_expiration" '+%s' 2>/dev/null) \
  || fail "Broker provisioning profile has an invalid expiration date"
[ "$profile_expiration_epoch" -gt "$(/bin/date '+%s')" ] \
  || fail "Broker provisioning profile is expired"

certificate_prefix="${verify_root}/codesign-cert-"
/usr/bin/codesign --display --extract-certificates="$certificate_prefix" "$broker_path" \
  >/dev/null 2>&1 || fail "Broker signing certificate cannot be extracted"
[ -f "${certificate_prefix}0" ] || fail "Broker signing leaf certificate is missing"
broker_identity=$(/usr/bin/openssl x509 -inform DER -in "${certificate_prefix}0" \
  -noout -fingerprint -sha1 2>/dev/null \
  | /usr/bin/sed 's/^SHA1 Fingerprint=//; s/://g') \
  || fail "Broker signing certificate fingerprint cannot be read"
printf '%s\n' "$broker_identity" | /usr/bin/grep -Eq '^[0-9A-F]{40}$' \
  || fail "Broker signing certificate fingerprint is invalid"

profile_certificate_count=$(
  /usr/bin/plutil -extract DeveloperCertificates raw -o - "$profile_plist" 2>/dev/null
) || fail "Broker provisioning profile has no developer certificates"
printf '%s\n' "$profile_certificate_count" | /usr/bin/grep -Eq '^[1-9][0-9]*$' \
  || fail "Broker provisioning profile developer certificate list is invalid"
certificate_matches=0
certificate_index=0
while [ "$certificate_index" -lt "$profile_certificate_count" ]; do
  profile_identity=$(
    /usr/bin/plutil -extract "DeveloperCertificates.${certificate_index}" raw -o - \
      "$profile_plist" 2>/dev/null \
    | /usr/bin/base64 -D 2>/dev/null \
    | /usr/bin/openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
    | /usr/bin/sed 's/^SHA1 Fingerprint=//; s/://g'
  ) || true
  if [ "$profile_identity" = "$broker_identity" ]; then
    certificate_matches=$((certificate_matches + 1))
  fi
  certificate_index=$((certificate_index + 1))
done
[ "$certificate_matches" -eq 1 ] \
  || fail "Broker provisioning profile does not authorize its signing certificate"

signed_entitlements=$(
  /usr/bin/codesign --display --xml --entitlements - "$broker_path" 2>&1 \
    | /usr/bin/sed -n '/<?xml/,$p'
)
[ -n "$signed_entitlements" ] || fail "Broker signed entitlements are unavailable"
signed_entitlements_path="${verify_root}/signed-entitlements.plist"
printf '%s\n' "$signed_entitlements" > "$signed_entitlements_path"
[ "$(/usr/bin/plutil -extract 'com\.apple\.application-identifier' raw -o - \
  "$signed_entitlements_path" 2>/dev/null)" = "$expected_application_identifier" ] \
  || fail "Broker signed application identifier is invalid"
[ "$(/usr/bin/plutil -extract 'com\.apple\.developer\.team-identifier' raw -o - \
  "$signed_entitlements_path" 2>/dev/null)" = "$expected_team" ] \
  || fail "Broker signed entitlement Team identifier is invalid"
[ "$(/usr/bin/plutil -extract keychain-access-groups json -o - \
  "$signed_entitlements_path" 2>/dev/null)" = "[\"${expected_team}.dev.safa.broker\"]" ] \
  || fail "Broker signed Keychain access group is invalid"

printf '%s\n' "Broker Developer ID provisioning profile verified for Team ${expected_team}."
