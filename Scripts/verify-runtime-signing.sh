#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  printf '%s\n' "Usage: Scripts/verify-runtime-signing.sh SAFA_APP_PATH TEAM_ID"
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

[ "$#" -eq 2 ] || {
  usage >&2
  exit 2
}

runtime_app=$1
expected_team=$2

/usr/bin/printf '%s\n' "$expected_team" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$' \
  || fail "TEAM_ID must contain exactly 10 uppercase letters or digits"
[ -d "$runtime_app" ] || fail "SAFA app is missing: $runtime_app"

cli_path="${runtime_app}/Contents/MacOS/safa"
broker_app="${runtime_app}/Contents/Library/Helpers/SAFABrokerAgent.app"
broker_path="${broker_app}/Contents/MacOS/safa-broker"
askpass_path="${runtime_app}/Contents/Library/Helpers/safa-askpass"
trusted_setup_path="${runtime_app}/Contents/Library/Helpers/safa-trusted-setup"

signature_field() {
  component=$1
  field=$2
  /usr/bin/codesign --display --verbose=4 "$component" 2>&1 \
    | /usr/bin/sed -n "s/^${field}=//p" \
    | /usr/bin/head -n 1
}

for component in \
  "$runtime_app" \
  "$cli_path" \
  "$broker_app" \
  "$broker_path" \
  "$askpass_path" \
  "$trusted_setup_path"
do
  [ -e "$component" ] || fail "Runtime component is missing: $component"
  /usr/bin/codesign --verify --strict "$component" >/dev/null 2>&1 \
    || fail "Runtime component failed code-signature verification: $component"
  [ "$(signature_field "$component" TeamIdentifier)" = "$expected_team" ] \
    || fail "Runtime component has an unexpected Team identity: $component"
done

/usr/bin/codesign --verify --deep --strict "$runtime_app" >/dev/null 2>&1 \
  || fail "SAFA.app failed deep code-signature verification"

[ "$(signature_field "$cli_path" Identifier)" = "dev.safa.cli" ] \
  || fail "CLI signing identifier is invalid"
[ "$(signature_field "$broker_path" Identifier)" = "dev.safa.broker" ] \
  || fail "Broker signing identifier is invalid"
[ "$(signature_field "$askpass_path" Identifier)" = "dev.safa.askpass" ] \
  || fail "AskPass signing identifier is invalid"
[ "$(signature_field "$trusted_setup_path" Identifier)" = "dev.safa.trusted-local" ] \
  || fail "trusted setup signing identifier is invalid"

# `codesign --force` replaces a component's entitlement set. Read the entitlement from the final
# signed Broker rather than trusting the Xcode project or the plist supplied to an earlier sign.
broker_entitlement_plist=$(
  /usr/bin/codesign --display --xml --entitlements - "$broker_path" 2>&1 \
    | /usr/bin/sed -n '/<?xml/,$p'
)
[ -n "$broker_entitlement_plist" ] \
  || fail "Broker has no readable signed entitlements"
broker_keychain_groups=$(
  /usr/bin/printf '%s\n' "$broker_entitlement_plist" \
    | /usr/bin/plutil -extract keychain-access-groups json -o - - 2>/dev/null
) || fail "Broker is missing its Keychain access-group entitlement"
expected_keychain_groups="[\"${expected_team}.dev.safa.broker\"]"
[ "$broker_keychain_groups" = "$expected_keychain_groups" ] \
  || fail "Broker Keychain access group does not match its Team identity"

for non_broker_component in "$runtime_app" "$cli_path" "$askpass_path" "$trusted_setup_path"; do
  non_broker_entitlements=$(
    /usr/bin/codesign --display --xml --entitlements - "$non_broker_component" 2>&1 || true
  )
  if /usr/bin/printf '%s\n' "$non_broker_entitlements" \
    | /usr/bin/grep -F 'keychain-access-groups' >/dev/null; then
    fail "A non-Broker component has Keychain access-group authority: $non_broker_component"
  fi
done

printf '%s\n' "Runtime signing boundary verified for Team ${expected_team}."
