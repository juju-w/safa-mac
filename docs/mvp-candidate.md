# MVP candidate assembly and replacement

This path produces one internal, immutable macOS candidate for the Core MVP acceptance smoke. It
does not create a tag, GitHub Release, public manifest, installer publication, or support claim.
The publication hold remains active.

## Trust boundary

Run candidate assembly only in protected publisher automation with auditable human approval. The
automation must expose a temporary Keychain containing exactly one `Developer ID Application`
identity and one `notarytool` profile, plus the Broker's Developer ID distribution provisioning
profile. Certificate private-key material, notary API keys, and Keychain passwords must never enter
source, ordinary developer machines, command output, or the candidate evidence file. The embedded
distribution profile and its public certificate chain are part of the signed app and are verified.

The script refuses a dirty source tree, Apple Development identity, missing universal
architecture, missing Hardened Runtime, incorrect role identifier, non-Broker Keychain authority,
failed notarization, unstapled ticket, Gatekeeper rejection, or secret scan. It signs nested code
inside out and runs the final signing-boundary verifier again after stapling.

## Build in protected automation

The values below are public identifiers or paths inside the protected runner. Do not substitute a
Developer certificate or add a notarization bypass.

```sh
Scripts/build-mvp-candidate.sh \
  --team-id ABCDEFGHIJ \
  --identity-hash 0000000000000000000000000000000000000000 \
  --keychain /absolute/protected/path/signing.keychain-db \
  --broker-profile /absolute/protected/path/SAFABroker.provisionprofile \
  --notary-profile safa-mvp \
  --output-dir /absolute/protected/path/output
```

The output directory receives exactly one stapled zip and one JSON evidence record. The record
binds the archive SHA-256 to the Runtime revision, pinned Product revision, Runtime version, CLI
schema, universal architecture set, Developer Team, notarization submission, and final component
CDHashes. Transfer of either file is outside this repository and must preserve both immutable
digests.

The Broker profile is mandatory because `keychain-access-groups` is a restricted macOS entitlement.
The build and verification paths require a non-device-scoped Developer ID profile whose Team, exact
Broker application identifier, Keychain allowlist, expiration, and Developer ID signing certificate
match the final Broker. A development profile or a signature without that profile is rejected even
when ordinary `codesign --verify` succeeds.

## Independent verification

Obtain the evidence-file SHA-256 through the protected review channel, not from the same untrusted
transfer that supplied the files.

```sh
Scripts/verify-mvp-candidate.sh \
  --archive /absolute/path/SAFA-Runtime-0.1.0-macos-universal.zip \
  --evidence /absolute/path/SAFA-Runtime-0.1.0-macos-universal.evidence.json \
  --evidence-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --team-id ABCDEFGHIJ
```

Verification checks both hashes before trusting the archive, rejects symlinks or extra root
entries, and rechecks Developer ID authority, role identifiers, Broker-only Keychain entitlement,
Hardened Runtime, universal architectures, version, stapling, Gatekeeper acceptance, and component
CDHashes.

## Non-destructive replacement

Install only after independent verification and before changing any existing Resource or vault
state:

```sh
Scripts/install-mvp-candidate.sh \
  --archive /absolute/path/SAFA-Runtime-0.1.0-macos-universal.zip \
  --evidence /absolute/path/SAFA-Runtime-0.1.0-macos-universal.evidence.json \
  --evidence-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --team-id ABCDEFGHIJ \
  --replace
```

The installer stages on the same filesystem, retains the previous lock and any displaced
same-version Runtime, activates the app and lock atomically, restarts the Broker, and runs
`doctor`. Startup failure restores the previous lock and Runtime automatically. It never deletes or
resets the vault, Resource records, Keychain items, or retained Runtime.

For the explicit rollback smoke, use the retained paths printed by the installer:

```sh
Scripts/rollback-mvp-candidate.sh \
  --lock-backup '/absolute/path/runtime.local.previous.TIMESTAMP.json' \
  --runtime-backup '/absolute/path/.0.1.0.previous.TIMESTAMP' \
  --team-id ABCDEFGHIJ
```

Omit `--runtime-backup` when rolling back to a different version that remains in the version store.
The rollback path validates the retained production identity and lock before activation, keeps the
displaced candidate, restarts the Broker, and restores the candidate automatically if the old
Runtime cannot start.

## Acceptance evidence

The candidate is not accepted from script success alone. Run the Product repository's
`specs/006-core-mvp/tasks.md` against the exact revisions in the evidence record, including the
previous-state replacement, SSH/HTTP, privilege, approval, denial, cancellation, restart, hostile
output, and rollback matrix. Record sanitized pass/fail evidence only; never record a real endpoint,
account, credential, fingerprint, command transcript, or production Resource alias.
