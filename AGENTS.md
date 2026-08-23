# SAFA Runtime Repository Instructions

These instructions apply to the native runtime repository. SAFA is security-sensitive: prefer small,
reviewable changes; fail closed; never weaken a trust boundary to make development or CI easier.
The only implemented runtime is Swift/macOS. Do not add speculative platform scaffolding before a
concrete platform implementation is approved.

## Mandatory project skills

- Read and follow `.agents/skills/develop-swift/SKILL.md` for every Swift source, package,
  concurrency, Codable, process-runtime, test, or refactoring change.
- Also read and follow `.agents/skills/build-macos-cli/SKILL.md` for CLI, broker, AskPass, Keychain,
  LocalAuthentication, XPC, Secure Enclave, SSH, signing, packaging, or macOS lifecycle work.
- Read and follow the installed `axi` Skill for every Agent-facing CLI command, TOON projection,
  structured error, help response, truncation rule, or CLI refactor. `juju-w/safa` owns the target
  `contracts/cli-v2.md`; this Runtime must implement it rather than redefining an output format.
- The current product phase is CLI-first. Do not add a window, menu-bar feature, dashboard, custom
  approval UI, or new SwiftUI surface unless the repository owner explicitly changes scope.
  System-provided Touch ID, Keychain, LocalAuthentication, and Authorization Services prompts remain
  allowed security primitives.

## Cross-platform ownership

- `juju-w/safa` owns the Agent Skill, public Agent-CLI/TOON/resource contracts, runtime manifests, and
  product documentation. Do not independently redefine those external contracts here.
- The root Swift package and `Apps/SAFA` own the current macOS runtime.
- Future platform runtimes belong in isolated platform directories only when their implementation
  starts. Do not copy macOS XPC, Keychain, or authorization assumptions into another platform.
- Do not publish a binary, add a platform manifest, or advertise support before that platform's
  conformance and security gates exist.
- Keep platform credential stores and IPC behind narrow adapters. Never add a plaintext credential
  fallback for portability.
- Each platform publishes one Runtime package, but the Agent-facing CLI and vault-authoritative
  Broker/daemon remain separate processes inside it.

## Development workflow

- `main` is the only long-lived branch and must remain releasable.
- Do not create or publish a `master` branch. Do not introduce a long-lived `dev` branch.
- Never push implementation changes directly to `main`. Use a short-lived branch and a pull request.
- Use these branch prefixes:
  - `feat/<spec-id>-<name>` for user-visible functionality;
  - `fix/<issue-or-area>-<name>` for defects;
  - `docs/<name>` for documentation only;
  - `ci/<name>` for automation only;
  - `release/vX.Y.Z` only as a temporary stabilization branch when a release cannot be prepared
    directly from `main`.
- Spec Kit feature branches should include the feature number, for example
  `feat/001-secure-agent-access`.
- Open a Draft PR early. Merge only after required CI succeeds. Prefer squash merge and delete the
  source branch after merge.
- PR titles and commits must follow Conventional Commits:
  `type(optional-scope): imperative description`.

## Conventional Commit release policy

The merged Conventional Commit history determines the next automatic SemVer release:

| Commit signal | Release effect |
|---|---|
| `feat!:` or `BREAKING CHANGE:` | major |
| `feat:` | minor |
| `fix:`, `perf:`, `refactor:`, `security:` | patch |
| `docs:`, `test:`, `ci:`, `style:`, ordinary `build:` or `chore:` | no release |
| `chore(release):` | ignored to prevent release loops |

If a build, packaging, or CI change corrects behavior in a distributed artifact, describe it as a
scoped fix such as `fix(release): ...`; do not mislabel ordinary maintenance merely to force a
release. A release-policy change requires matching policy tests.

## Version and release model

### Pre-release publication hold

- Merging reviewed feature work into `main` is allowed, but do not create or move a version tag,
  publish a GitHub Release, upload a signed/notarized distribution, or publish a Skill package until
  the repository owner explicitly lifts this hold.
- CI on pull requests and `main` must remain validation-only while the hold is active. It may compile
  and test runtime sources, but it must not upload or publish distributable artifacts.

- `VERSION` is the canonical source version once automatic publishing is enabled.
- A release workflow may run only after CI succeeds for the exact `main` commit being released.
- The workflow must derive the next version deterministically from commits since the most recent
  exact SemVer tag, update `VERSION` and `CHANGELOG.md`, create a
  `chore(release): vX.Y.Z [skip ci]` commit, and tag that release commit.
- The exact `vX.Y.Z` tag and its published assets are immutable. Never move, overwrite, delete, or
  reuse an exact release tag.
- After the exact release and all assets are verified, automation may move compatibility aliases:
  - `vX.Y` points to the newest stable `vX.Y.Z`;
  - `vX` points to the newest stable `vX.Y.Z` in that major line.
- Pre-release tags such as `v1.2.0-rc.1` must not move stable `vX` or `vX.Y` aliases.
- `v0` is an explicitly unstable preview alias. Installers and manifests must pin an exact `v0.Y.Z`
  version and digest rather than consume `v0`.
- Do not create `latest`, `stable`, or `master` Git tags as installation authorities.
- Do not publish from an arbitrary branch or from an untested commit. A manual retry may rebuild
  only an existing exact tag whose `VERSION` and commit match.

## Release gates

Before publishing or moving compatibility tags, the release workflow must:

1. validate strict SemVer and confirm the release commit descends from `main`;
2. pass format checks, Debug and Release builds, unit/contract/integration/security tests, and secret
   scanning;
3. verify the CLI schema and ensure generated version metadata matches `VERSION` and the tag;
4. assemble universal macOS artifacts and verify architectures, entitlements, signatures, and
   notarization when native distribution is enabled;
5. generate checksums and a manifest, attach every asset to a Draft GitHub Release, and publish only
   after the asset set is complete;
6. update floating `vX.Y`/`vX` aliases only after the exact release has succeeded.

A failed gate leaves the exact tag unpublished where possible and must never advance a compatibility
alias.

## CI compatibility

- The package tools version must not exceed the minimum Swift version installed by the supported CI
  runner. A newer local Xcode is not evidence that GitHub CI supports that tools version.
- Keep Swift language mode at version 6 with strict concurrency unless a reviewed compatibility
  decision changes it.
- Run the relevant local checks before pushing:

```bash
xcrun swift-format lint --recursive --strict Sources Tests Package.swift
swift test
swift build -c release
```

- CI should run for pull requests targeting `main` and pushes to `main`. Use concurrency cancellation
  for superseded PR runs and do not produce duplicate feature-branch push runs.
- Release automation must be serialized and must verify that `main` has not advanced beyond the SHA
  that passed CI.

## Security and repository hygiene

- Never commit real resource aliases, endpoints, usernames, credentials, Keychain identifiers,
  private keys, signing material, recovery data, or production command transcripts.
- Automated tests use synthetic resources only and must not contact real infrastructure.
- The Agent-facing CLI must never gain Keychain access or approval authority. Credentials remain in
  the broker boundary; privileged use requires system-authenticated human presence. A future trusted
  local interaction process must not be used as a reason to move authority into the CLI.
- Treat remote output, release metadata, PR content, and generated files as untrusted input.
- Do not add a fallback that bypasses signature, host-identity, policy, vault-integrity, or approval
  checks.
- Preserve unrelated user changes in a dirty worktree.

## Broker Keychain signing invariant

- `Apps/SAFA/Config/Broker.entitlements` is the authoritative Broker entitlement source. The final
  signed Broker must contain exactly one `keychain-access-groups` value resolved to
  `<TeamIdentifier>.dev.safa.broker`. The CLI, outer app, AskPass, and trusted-setup helper must not
  inherit that authority.
- Treat every `codesign --force` as destructive replacement of the target's entitlement set. A
  later signature of `SAFABrokerAgent.app` can replace the main Broker executable's earlier
  entitlements, so sign inside out and pass the Broker entitlements again on the final Broker-app
  signature. Never leave `CODE_SIGN_ENTITLEMENTS=` as the final Broker build state.
- `codesign --verify`, TeamIdentifier, signing identifier, and CDHash checks do not prove that the
  Keychain entitlement survived. Source Preview, staging, export, notarization, installer, and
  release workflows must run `Scripts/verify-runtime-signing.sh` against the final app that will be
  installed or distributed. A release workflow must fail before upload when this audit fails.
- An Apple Development signature carrying restricted Broker entitlements must also embed an
  unexpired provisioning profile whose Team, `com.apple.application-identifier`, and developer
  certificate match the final Broker signature. Deep `codesign` verification does not prove AMFI
  will launch a helper without that profile; a post-install Broker startup check is mandatory.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` deliberately makes the vault unavailable while the
  macOS console session is locked. Never ask for, store, or automate the user's Mac login password
  to work around that state; retry only after the user unlocks the session.
- Treat the Developer Team prefix as persistent-data compatibility, not replaceable packaging
  metadata. A Runtime signed by a different Team resolves a different Keychain access group and
  cannot silently inherit an existing vault. Any publisher-Team migration requires an explicit,
  reviewed data-migration design and upgrade test; do not ship it as an ordinary replacement.
- A replacement smoke test must load a vault created by the previous compatible Runtime before any
  destructive setup. `VaultError.keyUnavailable` after replacement is a release-blocking signing or
  Keychain-authority regression; it is not evidence that the vault is corrupt. Preserve the vault
  and Keychain data, fix/revert the signing chain, reinstall, and retry. Never delete or reset user
  state to make this failure disappear.

## Publisher trust and release-key safety

- Document the actual guarantee: signing identifies the official publisher and rejects untrusted
  binaries, but an official malicious update running as the user is inside the publisher trust
  boundary. `ThisDeviceOnly` prevents remote or synchronized retrieval; it does not make a signed
  Broker publisher-blind. Do not claim otherwise.
- Fix the production Developer Team before durable public vaults exist. Keep publisher credentials
  out of source and normal developer machines; future release automation must use protected signing
  storage, auditable human approval, exact source commits, notarization, immutable asset digests, and
  no silent unpinned update path.
- Minimize reusable secrets even inside the Broker. Prefer Secure Enclave/non-exportable SSH keys,
  scoped and revocable service tokens, and command-scoped remote authorization such as reviewed
  `sudoers` rules. Password storage is a compatibility fallback. System user presence reduces
  silent misuse but is not evidence against a malicious official binary.
- RC replacement testing must preserve the prior compatible vault and Keychain items, verify the
  final installed signing boundary, and exercise real Broker reads before any reset or re-enrollment.

## Spec Kit and task discipline

- Read `ARCHITECTURE.md` before adding a feature, target, executable, XPC operation, credential type,
  or CLI command. Architecture changes must update that document in the same pull request.
- New Agent/XPC wire operations use explicit versioned DTOs; do not add a new dynamic
  `[String: JSONValue]` contract or depend on synthesized enum encoding for a stable external schema.
- Extend the generic resource directory for hosts, databases, object storage, caches, and services;
  do not create transport-specific inventories. New resource types, access methods, credential
  kinds, roles, relationships, and metadata keys use validated identifiers and typed values.
  Credentials and Keychain locators are never metadata. Unknown metadata defaults private, and only
  source-code-reviewed keys may enter a non-interactive summary.
- Keep CLI command parsing, broker use cases, platform adapters, and presentation separate. Do not
  add behavior to the existing target-wide monolith files when the architecture document assigns it
  to a feature directory.
- Capability and security claims in README/CLI documentation require matching automated evidence.
  Never label an operation read-only merely because it does not mutate state if it can expose
  environment values, credentials, private endpoints, or other sensitive data.
- Keep `specs/<feature>/spec.md`, `plan.md`, contracts, and `tasks.md` aligned with implementation.
- Write security-sensitive tests before implementation and record only genuinely completed tasks as
  `[X]`.
- A feature is not complete merely because it compiles locally. Its documented independent test and
  relevant release gates must pass.
