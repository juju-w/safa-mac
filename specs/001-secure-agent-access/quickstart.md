# Quickstart Validation: Diagnostic MVP

Use synthetic data only. Do not register a production host or enter a real password while validating
this feature branch.

## 1. Run the automated MVP gates

```bash
xcrun swift-format lint --recursive --strict \
  Sources Tests Apps/SAFA/Targets Package.swift
swift test
swift build -c release
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme "SAFA Runtime" \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

The test journey constructs only `nas.home` with documentation-only address `203.0.113.10`; its
transport is an in-memory fake and does not open a network connection. The native Xcode build checks
the broker, CLI, AskPass, and trusted-setup assembly without pretending that an unsigned XPC build
can run.

## 2. Inspect the stable CLI surface

```bash
swift run safa --version
swift run safa --help
swift run safa resource --help
swift run safa resource ls --help
swift run safa resource add --help
swift run safa resource edit --help
swift run safa resource remove --help
swift run safa exec --help
```

An unsigned `doctor` must fail closed because it cannot derive a Developer Team identity. It must
not fall back to raw SSH or ask for a credential.

## 3. Build and activate the signed development runtime

The product has no custom windows, menus, or SwiftUI/AppKit workflow. Apple requires a GUI-less app
container for `SMAppService` to register the per-user LaunchAgent, so the Xcode aggregate embeds the
CLI, nested broker app, AskPass helper, trusted-setup helper, and launch-agent plist in `SAFA.app`.
Build every component with the same configured Apple Developer Team:

```bash
xcodebuild -project Apps/SAFA/SAFA.xcodeproj -scheme "SAFA Runtime" \
  -configuration Debug -derivedDataPath build/SAFADev \
  SAFA_DEVELOPMENT_TEAM=YOUR_TEAM_ID build
```

Run the CLI from the resulting app container, then activate only its bundled per-user broker:

```bash
SAFA_APP_PATH="build/SAFADev/Build/Products/Debug/SAFA.app"
"$SAFA_APP_PATH/Contents/MacOS/safa" setup status
"$SAFA_APP_PATH/Contents/MacOS/safa" setup activate
"$SAFA_APP_PATH/Contents/MacOS/safa" doctor
"$SAFA_APP_PATH/Contents/MacOS/safa" resource list
```

`doctor` must report both broker and vault as ready. Registration is per user and idempotent. If
macOS reports `requires_approval`, enable SAFA in Login Items before retrying. The broker rejects
clients whose Developer Team, signing identifier, effective user, or audit session does not match.
Use `setup deactivate` only as a local human lifecycle or uninstall operation; the Skill must not
call it automatically.

For a repeatable local installation, use the repository script instead of copying the app by hand:

```bash
Scripts/install-local-runtime.sh \
  --team-id YOUR_TEAM_ID \
  --allow-provisioning-updates
```

For the free Source Preview, an existing Apple Development identity can sign locally without an
Xcode account or provisioning-profile update:

```bash
Scripts/install-local-runtime.sh \
  --source-preview \
  --identity-hash YOUR_LOCAL_APPLE_DEVELOPMENT_SHA1
```

This mode uses manual local signing. The installer derives the effective Team identifier from the
signed Mach-O rather than the certificate display name, then applies the Broker-only Keychain access
group `<TeamIdentifier>.dev.safa.broker`. It audits the final built and staged app so a later
re-signing step cannot silently strip that entitlement or grant it to the CLI, AskPass, or trusted
setup helper. It also verifies every component's Team identity, identifiers, CDHashes, architecture,
and Runtime version. Replacements must keep the same Developer Team to retain access to existing
Keychain-backed vault state. Source Preview signing is not Developer ID distribution or notarization.

The script builds and verifies all signed components, installs the exact version under the current
user's Application Support directory, and writes a local lock containing the architecture, Team ID,
and Code Directory hashes. Pass `--replace` only when intentionally replacing the same development
version; the previous Runtime is retained as a backup. This does not notarize or publish an asset.

## 4. Validate resource lifecycle through tests

The CLI-first preview has no custom registration UI. Its signed runtime exposes the five-command
resource surface; add/edit/remove each require a macOS Touch ID/login authorization. Add/edit accept
only logical aliases, safe template/type choices, and an optional active/disabled state:

```bash
safa resource add nas.home --from-ssh-config home-nas \
  --type host.linux
safa resource add new.host --type host.linux
safa resource edit nas.home --from-ssh-config home-nas
safa resource edit nas.home --state disabled
safa resource edit nas.home --state active
safa resource remove nas.home
```

The broker resolves endpoint and username locally through `ssh -G`. Add creates a private draft and
then, in the same command, uses an existing `known_hosts` entry and available OpenSSH
identity-file/agent route to verify the account and declared platform, write a bounded read-only
hardware/system probe into the encrypted directory, and atomically return `active`. A remediable
failure may retain the draft; edit resumes it. `ProxyJump` and `ProxyCommand` remain unsupported.

When the alias is not present in OpenSSH configuration, the same `resource add` command launches the
separately signed `safa-trusted-setup` helper. It opens its own controlling terminal and disables
echo for host, port, username, independently verified SHA-256 host fingerprint, and password. None
of those fields enters argv, environment, Agent-controlled stdin, stdout, or stderr. The Broker
binds the setup session to the signed helper, verifies password login as the declared account,
pinned host identity, target platform, and bounded inventory, then stores the password in the Data
Protection Keychain and activates the resource atomically. If the Agent has no controlling terminal,
the response provides the same command as `safe_for_agent: false` for the user to run locally.

The adapter accepts `host.linux`, `host.macos`, and `host.windows`; a Windows target must
already expose OpenSSH and follows the same pinned-host verification path. Service templates can be
selected with `--template` from the built-in registry, including Kafka, RabbitMQ, and MongoDB. Their protected local configuration client
is still required, so the Agent-facing CLI fails closed with `user_action_required` rather than
accepting an endpoint or credential.
`ResourceLifecycleTests`, `ReadOnlySSHJourneyTests`, and `ResourceOnboardingTests` validate this
boundary using synthetic fixtures and contact no real host.

The safe read surface is:

```bash
swift run safa resource list
swift run safa resource ls
```

The response may contain alias, resource type, state, capabilities, health, and explicitly
allowlisted summary metadata only. It must not contain host, port, username, host fingerprint,
credential reference or Keychain locator.

Use `resource show nas.home` for the same non-interactive safe projection. Use
`resource show nas.home --details` only when protected endpoint or probed inventory metadata is needed;
macOS asks the local user for Touch ID/login authentication. A denial returns no detail object, and
an approval still returns no credential, key material, Keychain locator, or host fingerprint.

## 5. Validate the diagnostic MVP

```bash
swift test --filter ReadOnlySSHJourneyTests
```

The broker permits only its small read-only allowlist, writes a private isolated SSH configuration,
enforces the pinned host identity, issues one child-bound askpass response, bounds time/output,
preserves the remote exit code, redacts a matching credential from output and emits a sanitized audit
event. A changed host identity or unsupported command fails closed.

## MVP boundary

This checkpoint enables signed per-user broker activation, reviewed setup of an existing direct
OpenSSH identity/agent route, and hidden password enrollment with manual first-use host-fingerprint
confirmation. It does not yet enable managed Secure Enclave SSH enrollment, private-key import,
sudo, shell programs, arbitrary remote mutations, approval grants, recovery, notarized
distribution, or the final packaged Skill. Those remain separate Spec Kit phases; do not bypass the
diagnostic allowlist to simulate them.
