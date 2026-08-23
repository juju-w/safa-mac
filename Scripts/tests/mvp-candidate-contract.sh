#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
builder="${repository_root}/Scripts/build-mvp-candidate.sh"
verifier="${repository_root}/Scripts/verify-mvp-candidate.sh"
installer="${repository_root}/Scripts/install-mvp-candidate.sh"
rollback="${repository_root}/Scripts/rollback-mvp-candidate.sh"
profile_verifier="${repository_root}/Scripts/verify-broker-provisioning-profile.sh"
secret_scanner="${repository_root}/Scripts/scan-secrets.sh"
pin_verifier="${repository_root}/Scripts/verify-product-source-pinning.py"

sh -n "$builder" "$verifier" "$installer" "$rollback" "$profile_verifier" "$secret_scanner"
python3 -m py_compile "$pin_verifier"

builder_help=$($builder --help)
printf '%s\n' "$builder_help" | grep -F -- '--identity-hash SHA1' >/dev/null
printf '%s\n' "$builder_help" | grep -F -- '--notary-profile PROFILE' >/dev/null
printf '%s\n' "$builder_help" | grep -F -- '--broker-profile PATH' >/dev/null
printf '%s\n' "$builder_help" | grep -F -- 'never uploads, publishes, tags' >/dev/null
grep -F 'Developer ID Application:' "$builder" >/dev/null
grep -F 'CODE_SIGNING_ALLOWED=NO' "$builder" >/dev/null
grep -F -- '--options runtime --timestamp' "$builder" >/dev/null
grep -F 'notarytool submit' "$builder" >/dev/null
grep -F 'stapler staple' "$builder" >/dev/null
grep -F 'stapler validate' "$builder" >/dev/null
grep -F 'spctl --assess' "$builder" >/dev/null
grep -F 'verify-runtime-signing.sh' "$builder" >/dev/null
grep -F 'verify-broker-provisioning-profile.sh' "$builder" >/dev/null
grep -F 'embedded.provisionprofile' "$builder" >/dev/null
grep -F 'com\.apple\.application-identifier' "$builder" >/dev/null
grep -F 'com\.apple\.developer\.team-identifier' "$builder" >/dev/null
grep -F 'scan-secrets.sh' "$builder" >/dev/null
grep -F 'artifact.sha256' "$builder" >/dev/null
grep -F 'product_revision' "$builder" >/dev/null
grep -F 'runtime_revision' "$builder" >/dev/null
if grep -Eq -- '(--skip-notarization|latest|upload-artifact)' "$builder"; then
  printf '%s\n' 'builder contains a forbidden candidate bypass or publication path' >&2
  exit 1
fi

grep -F -- '--evidence-sha256' "$verifier" >/dev/null
grep -F 'Developer ID Application:' "$verifier" >/dev/null
grep -F 'notarization.status' "$verifier" >/dev/null
grep -F 'candidate archive does not match its evidence' "$verifier" >/dev/null
grep -F 'verify-runtime-signing.sh' "$verifier" >/dev/null
grep -F 'verify-broker-provisioning-profile.sh' "$verifier" >/dev/null
grep -F -- '--test-requirement=' "$verifier" >/dev/null
grep -F 'certificate leaf[subject.OU]' "$verifier" >/dev/null
grep -F '1.2.840.113635.100.6.1.13' "$verifier" >/dev/null
grep -F '1.2.840.113635.100.6.2.6' "$verifier" >/dev/null
grep -F -- '--requirements -' "$verifier" >/dev/null
grep -F 'spctl --assess' "$verifier" >/dev/null

grep -F 'rollback_activation' "$installer" >/dev/null
grep -F 'previous Runtime restored' "$installer" >/dev/null
grep -F 'artifact_sha256' "$installer" >/dev/null
grep -F 'evidence_sha256' "$installer" >/dev/null
grep -F 'notarization_submission_id' "$installer" >/dev/null
grep -F 'verify-mvp-candidate.sh' "$installer" >/dev/null
grep -F 'runtime.local.previous.' "$installer" >/dev/null
grep -F 'verify-broker-provisioning-profile.sh' "$installer" >/dev/null
grep -F '/bin/date -j -u -f' "$profile_verifier" >/dev/null
if grep -Ei '(vault|keychain).*(rm|delete|reset)|(rm|delete|reset).*(vault|keychain)' "$installer"; then
  printf '%s\n' 'installer contains a forbidden durable-state deletion path' >&2
  exit 1
fi
verify_line=$(grep -n '"$verifier" --archive' "$installer" | cut -d: -f1)
extract_line=$(grep -n 'ditto -x -k "$archive_path"' "$installer" | cut -d: -f1)
[ "$verify_line" -lt "$extract_line" ]

grep -F 'Developer ID Application:' "$rollback" >/dev/null
grep -F 'candidate restored' "$rollback" >/dev/null
grep -F 'Displaced candidate Runtime retained' "$rollback" >/dev/null
grep -F 'verify-broker-provisioning-profile.sh' "$rollback" >/dev/null
if grep -Ei '(vault|keychain).*(rm|delete|reset)|(rm|delete|reset).*(vault|keychain)' "$rollback"; then
  printf '%s\n' 'rollback contains a forbidden durable-state deletion path' >&2
  exit 1
fi

assert_fails_with() {
  command_path=$1
  expected=$2
  shift 2
  set +e
  output=$($command_path "$@" 2>&1)
  result=$?
  set -e
  [ "$result" -eq 1 ]
  printf '%s\n' "$output" | grep -F -- "$expected" >/dev/null
}

assert_fails_with "$builder" \
  'TEAM_ID must contain exactly 10 uppercase letters or digits' \
  --team-id invalid --identity-hash 0000000000000000000000000000000000000000 \
  --keychain /missing --broker-profile /missing --notary-profile safa --output-dir /tmp
assert_fails_with "$verifier" \
  '--evidence-sha256 must contain exactly 64 lowercase hexadecimal characters' \
  --archive /missing --evidence /missing --evidence-sha256 invalid --team-id ABCDEFGHIJ
assert_fails_with "$installer" \
  '--evidence-sha256 must contain exactly 64 lowercase hexadecimal characters' \
  --archive /missing --evidence /missing --evidence-sha256 invalid --team-id ABCDEFGHIJ
assert_fails_with "$rollback" \
  'TEAM_ID must contain exactly 10 uppercase letters or digits' \
  --lock-backup /missing --team-id invalid

grep -F 'ProvisionsAllDevices' "$profile_verifier" >/dev/null
grep -F 'DeveloperCertificates' "$profile_verifier" >/dev/null
grep -F 'ExpirationDate' "$profile_verifier" >/dev/null
grep -F 'keychain-access-groups' "$profile_verifier" >/dev/null
grep -F 'com\.apple\.application-identifier' "$profile_verifier" >/dev/null
grep -F 'com\.apple\.developer\.team-identifier' "$profile_verifier" >/dev/null
grep -F -- '--extract-certificates' "$profile_verifier" >/dev/null

python3 "$pin_verifier"
"$secret_scanner" --repository "$repository_root"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/safa-mvp-contract.XXXXXX")
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

plist_fixture="$test_root/candidate.json"
plutil -create xml1 "$plist_fixture"
plutil -insert artifact -dictionary "$plist_fixture"
plutil -insert artifact.sha256 -string \
  0000000000000000000000000000000000000000000000000000000000000000 "$plist_fixture"
plutil -insert architectures -json '["arm64","x86_64"]' "$plist_fixture"
plutil -convert json "$plist_fixture"
[ "$(plutil -extract artifact.sha256 raw -o - "$plist_fixture")" \
  = 0000000000000000000000000000000000000000000000000000000000000000 ]
[ "$(plutil -extract architectures json -o - "$plist_fixture")" = '["arm64","x86_64"]' ]

mkdir -p "$test_root/source"
git -C "$test_root/source" init -q
{
  printf '%s%s\n' '-----BEGIN ' 'PRIVATE KEY-----'
  printf '%s\n' 'synthetic-test-only'
  printf '%s%s\n' '192.168.' '50.10'
} > "$test_root/source/leak.txt"
git -C "$test_root/source" add leak.txt
set +e
scan_output=$($secret_scanner --repository "$test_root/source" 2>&1)
scan_result=$?
set -e
[ "$scan_result" -eq 1 ]
printf '%s\n' "$scan_output" | grep -F 'private-key material found in tracked source' >/dev/null
printf '%s\n' "$scan_output" | grep -F 'private-ipv4 material found in tracked source' >/dev/null
if printf '%s\n' "$scan_output" | grep -F -- "$(printf '%s%s' '-----BEGIN ' 'PRIVATE KEY-----')" \
  >/dev/null; then
  printf '%s\n' 'secret scanner printed matched material' >&2
  exit 1
fi

mkdir -p "$test_root/artifact-root/SAFA.app/Contents/Resources"
{
  printf '%s%s\n' '-----BEGIN ' 'PRIVATE KEY-----'
  printf '%s%s\n' '10.20.' '30.40'
} > "$test_root/artifact-root/SAFA.app/Contents/Resources/leak.txt"
ditto -c -k --keepParent "$test_root/artifact-root/SAFA.app" "$test_root/leaking.zip"
set +e
artifact_scan_output=$(
  $secret_scanner --repository "$repository_root" --artifact "$test_root/leaking.zip" 2>&1
)
artifact_scan_result=$?
set -e
[ "$artifact_scan_result" -eq 1 ]
printf '%s\n' "$artifact_scan_output" \
  | grep -F 'private-key material found in candidate artifact' >/dev/null
printf '%s\n' "$artifact_scan_output" \
  | grep -F 'private-ipv4 material found in candidate artifact' >/dev/null

printf '%s\n' '{"revision":"0000000000000000000000000000000000000000"}' \
  > "$test_root/product-source.json"
printf '%s\n' 'repository: juju-w/safa' \
  'ref: 1111111111111111111111111111111111111111' > "$test_root/ci.yml"
set +e
pin_output=$(python3 "$pin_verifier" "$test_root/product-source.json" "$test_root/ci.yml" 2>&1)
pin_result=$?
set -e
[ "$pin_result" -eq 1 ]
printf '%s\n' "$pin_output" | grep -F 'CI Product checkout does not match' >/dev/null

printf '%s\n' 'MVP candidate packaging contract passed.'
