#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
installer="${repository_root}/Scripts/install-local-runtime.sh"
signing_verifier="${repository_root}/Scripts/verify-runtime-signing.sh"
tree_hasher="${repository_root}/Scripts/runtime-tree-sha256.sh"

sh -n "$installer" "$signing_verifier" "$tree_hasher"

help_output=$("$installer" --help)
printf '%s\n' "$help_output" | grep -F -- '--source-preview --identity-hash SHA1' >/dev/null
grep -F 'rollback_runtime_activation' "$installer" >/dev/null
grep -F 'Failed to activate the local Runtime lock' "$installer" >/dev/null
grep -F 'launchctl kickstart -k "$broker_service"' "$installer" >/dev/null
grep -F 'source_preview_broker_entitlements=' "$installer" >/dev/null
grep -F 'select_source_preview_broker_profile' "$installer" >/dev/null
grep -F 'DeveloperCertificates raw -o -' "$installer" >/dev/null
grep -F 'DeveloperCertificates.${profile_certificate_index}' "$installer" >/dev/null
grep -F '/bin/date -j -u -f' "$installer" >/dev/null
grep -F 'com\.apple\.application-identifier' "$installer" >/dev/null
grep -F 'com\.apple\.security\.get-task-allow' "$installer" >/dev/null
grep -F -- '-bool true \' "$installer" >/dev/null
grep -F 'embedded.provisionprofile' "$installer" >/dev/null
grep -F 'keychain-access-groups' "$installer" >/dev/null
grep -F -- '--entitlements "$source_preview_broker_entitlements"' "$installer" >/dev/null
grep -F 'unlock the macOS session' "$installer" >/dev/null
grep -F 'verify-runtime-signing.sh' "$installer" >/dev/null
grep -F 'verify_local_http_client' "$installer" >/dev/null
grep -F -- '--test-requirement=' "$installer" >/dev/null
grep -F 'identifier "com.apple.curl"' "$installer" >/dev/null
grep -F -- '--fail-with-body' "$installer" >/dev/null
grep -F 'Built Runtime failed the final signing-boundary audit' "$installer" >/dev/null
grep -F 'Staged Runtime failed the final signing-boundary audit' "$installer" >/dev/null
grep -F 'runtime-tree-sha256.sh' "$installer" >/dev/null
grep -F 'runtime_tree_sha256' "$installer" >/dev/null
grep -F 'source-preview-tree-sha256-v1' "$installer" >/dev/null
grep -F 'installation_channel' "$installer" >/dev/null
grep -F 'keychain-access-groups' "$signing_verifier" >/dev/null
grep -F 'expected_keychain_groups=' "$signing_verifier" >/dev/null
grep -F 'A non-Broker component has Keychain access-group authority' "$signing_verifier" >/dev/null
restart_line=$(grep -n 'launchctl kickstart -k "$broker_service"' "$installer" | cut -d: -f1)
runtime_line=$(grep -n 'if ! /bin/mv "$staging_directory" "$install_directory"' "$installer" | cut -d: -f1)
[ "$restart_line" -gt "$runtime_line" ]
lock_line=$(grep -n '> "$lock_staging"' "$installer" | head -n 1 | cut -d: -f1)
[ "$lock_line" -lt "$runtime_line" ]
tree_digest_line=$(grep -n 'runtime_tree_sha256=' "$installer" | cut -d: -f1)
staged_verify_line=$(grep -n 'Staged Runtime failed the final signing-boundary audit' "$installer" | cut -d: -f1)
[ "$tree_digest_line" -gt "$staged_verify_line" ]
[ "$tree_digest_line" -lt "$lock_line" ]

expiration_epoch=$(TZ=Asia/Shanghai /bin/date -j -u \
  -f '%Y-%m-%dT%H:%M:%SZ' '2026-08-23T14:28:37Z' '+%s')
[ "$expiration_epoch" = 1787495317 ]

assert_fails_with() {
  expected="$1"
  shift
  set +e
  output=$("$installer" "$@" 2>&1)
  result=$?
  set -e
  [ "$result" -eq 1 ]
  printf '%s\n' "$output" | grep -F -- "$expected" >/dev/null
}

assert_fails_with \
  '--source-preview requires a 40-character --identity-hash' \
  --source-preview
assert_fails_with \
  '--source-preview and --allow-provisioning-updates are mutually exclusive' \
  --source-preview --identity-hash 0000000000000000000000000000000000000000 \
  --allow-provisioning-updates
assert_fails_with \
  '--identity-hash requires --source-preview' \
  --team-id ABCDEFGHIJ --identity-hash 0000000000000000000000000000000000000000
assert_fails_with \
  '--team-id is not accepted with --source-preview' \
  --source-preview --identity-hash 0000000000000000000000000000000000000000 \
  --team-id ABCDEFGHIJ

printf '%s\n' 'Source Preview installer argument contract passed.'
