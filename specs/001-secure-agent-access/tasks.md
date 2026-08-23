# Tasks: Secure Agent Access

> Repository split: paths under `Skills/safa` have moved to `juju-w/safa/skills/safa`. Historical
> task text below is retained for traceability and must not recreate a Skill in this Runtime repo.

**Input**: Design documents from `specs/001-secure-agent-access/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`

**Tests**: Required by the project constitution for security-sensitive behavior. Write the listed
tests first and confirm they fail before the matching implementation.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel because it changes separate files and has no incomplete dependency.
- **[Story]**: Maps work to a user story in `spec.md`.
- Every task names its target file or directory.

## Phase 1: Setup

**Purpose**: Establish the native project, test layout, and reproducible build surface.

- [X] T001 Create SwiftPM products and dependency graph from `plan.md` in `Package.swift`
- [X] T002 Create the broker, CLI, AskPass, and native runtime aggregate targets in `Apps/SAFA/SAFA.xcodeproj/project.pbxproj`
- [X] T003 [P] Add Debug and Release signing/build settings in `Apps/SAFA/Config/BuildSettings.xcconfig`
- [X] T004 [P] Add component Info.plist and entitlement templates in `Apps/SAFA/Config/`
- [X] T005 [P] Create unit, contract, integration, security, and fixture directories under `Tests/`
- [X] T006 [P] Add Swift format/lint and strict-concurrency configuration in `.swift-format` and `Package.swift`
- [X] T007 [P] Add macOS build and test workflow without signing secrets in `.github/workflows/ci.yml`
- [X] T008 Document third-party license obligations for Swift Argument Parser in `THIRD_PARTY_NOTICES.md`

---

## Phase 2: Foundational

**Purpose**: Implement contracts and security abstractions that block every user story.

**⚠️ CRITICAL**: No user story implementation starts until this phase passes its tests.

- [X] T009 [P] Add the historical v1 envelope snapshots (superseded and removed by the coordinated
  T101/T106 v2 migration)
- [X] T010 [P] Add failing domain validation and state-transition tests in `Tests/Unit/DomainStateTests.swift`
- [X] T011 [P] Add failing canonical request fingerprint tests in `Tests/Security/RequestFingerprintTests.swift`
- [X] T012 Implement versioned CLI/XPC envelope, status, error, and next-action types in `Sources/SAFAProtocol/`
- [X] T013 Implement Resource, CredentialReference, HostIdentity, Request, Assessment, Grant, Policy, Result, and Audit entities in `Sources/SAFADomain/`
- [X] T014 Implement bounded decoding, validation, canonical encoding, and request fingerprints in `Sources/SAFAProtocol/CanonicalCodec.swift`
- [X] T015 [P] Define stable SAFA process exit mappings in `Sources/SAFAProtocol/ExitCode.swift`
- [X] T016 [P] Add failing encrypted-envelope tamper/copy/rollback tests in `Tests/Security/VaultEnvelopeTests.swift`
- [X] T017 [P] Add failing Keychain access-class and opaque-locator tests in `Tests/Integration/KeychainIntegrationTests.swift`
- [X] T018 Implement broker-only data-protection Keychain abstraction in `Sources/SAFACrypto/KeychainStore.swift`
- [X] T019 Implement AES-GCM vault envelope, atomic persistence, schema revisions, and rollback marker in `Sources/SAFACrypto/EncryptedVault.swift`
- [X] T020 [P] Add failing XPC peer identity and unauthorized-client tests in `Tests/Integration/XPCPeerValidationTests.swift`
- [X] T021 Define separate Agent-client and trusted-local XPC protocols in `Sources/SAFAProtocol/BrokerXPCProtocol.swift`
- [X] T022 Implement peer signing, effective-user, and audit-session validation in `Sources/SAFABroker/PeerValidator.swift`
- [X] T023 Implement the per-user broker listener and bounded request dispatcher in `Sources/SAFABroker/BrokerService.swift`
- [X] T024 [P] Implement sanitized OSLog events with private-by-default fields in `Sources/SAFABroker/SecurityLog.swift`
- [X] T025 [P] Add an in-memory fake vault, fake approval provider, and fake transport in `Tests/Fixtures/Fakes/`
- [X] T026 Wire the broker launch-agent payload to a reviewed, system-authenticated no-GUI
  activation flow

**Checkpoint**: Protocol, encrypted state, peer validation, and deterministic test doubles work
without a real server or credential.

---

## Phase 3: User Story 1 - Check a Registered Resource Without Sharing Secrets (Priority: P1) 🎯 MVP

**Goal**: Privately register one SSH resource and let an Agent complete a read-only diagnostic by
logical alias without learning connection metadata or credentials.

**Independent Test**: Register synthetic `nas.home`, run a service status command, and prove no
endpoint or credential appears in Agent input/output, argv, environment, audit, or package files.

### Tests for User Story 1

- [X] T027 [P] [US1] Add failing safe resource-list CLI contract tests in `Tests/Contract/ResourceCLIContractTests.swift`
- [X] T028 [P] [US1] Add failing private onboarding and unknown-resource tests in `Tests/Integration/ResourceOnboardingTests.swift`
- [X] T029 [P] [US1] Add failing strict host identity and changed-key tests in `Tests/Security/SSHHostIdentityTests.swift`
- [X] T030 [P] [US1] Add failing Secure Enclave key lifecycle tests with capability checks in `Tests/Integration/SecureEnclaveKeyTests.swift`
- [X] T031 [P] [US1] Add failing password askpass binding and leakage tests in `Tests/Security/AskPassTests.swift`
- [X] T032 [P] [US1] Add failing read-only synthetic SSH journey in `Tests/Integration/ReadOnlySSHJourneyTests.swift`

### Implementation for User Story 1

- [X] T033 [P] [US1] Implement resource alias validation, safe projections, and registry queries in `Sources/SAFADomain/ResourceRegistry.swift`
- [X] T034 [US1] Implement private add/edit/disable/enable/remove resource transactions in `Sources/SAFABroker/ResourceService.swift`
- [X] T035 [P] [US1] Implement a trusted, system-authenticated no-GUI resource registration and
  credential-entry flow without adding secret flags or Agent-controlled stdin
- [X] T036 [P] [US1] Implement device-bound P-256 key creation and public-key enrollment export in `Sources/SAFACrypto/SecureEnclaveSSHKey.swift`
- [X] T037 [P] [US1] Implement Keychain password credential creation and lookup in `Sources/SAFACrypto/PasswordCredential.swift`
- [X] T038 [US1] Implement isolated SSH configuration and strict known-host management in `Sources/SAFASSH/SSHConfiguration.swift`
- [X] T039 [US1] Implement broker-controlled per-execution SSH signing adapter in `Sources/SAFASSH/ConstrainedSSHAgent.swift`
- [X] T040 [US1] Implement signed one-shot password response helper in `Sources/SAFAAskPass/AskPassRuntime.swift` and `Sources/SAFAAskPassExecutable/main.swift`
- [X] T041 [US1] Implement bounded process launch, cancellation, stdout/stderr capture, and exit preservation in `Sources/SAFATransport/ProcessRunner.swift`
- [X] T042 [US1] Implement read-only SSH execution orchestration in `Sources/SAFASSH/SSHTransport.swift`
- [X] T043 [P] [US1] Implement `doctor`, `setup status`, and the public
  `resource list|ls/show/add/edit/remove` CLI surface in `Sources/SAFACLI/`; keep protected inspect,
  setup, verification, and state transitions as options or internal stages
- [X] T043b [US1] Implement the system-authenticated SSH-config draft import lifecycle without
  endpoint, username, password, key, token, or sudo-password CLI fields
- [X] T043c [US1] Implement system-authenticated setup for an existing direct OpenSSH
  identity-file/agent route with prior `known_hosts` trust, bounded verification, and atomic draft
  activation
- [X] T043d [US1] Extend the signed template registry and encrypted CRUD transaction to Windows
  OpenSSH, database, object-storage, cache, graph, search, and HTTP resources; require
  revision-bound protocol verification before a service reports ready
- [X] T043e [US1] Normalize resource kind/template/platform/roles, retire `host.nas` with compatible
  vault migration, add Kafka/RabbitMQ/MongoDB templates, and persist a bounded first-connection host
  inventory probe atomically with SSH activation
- [X] T043a [US1] Implement the generic encrypted resource directory, alternate-alias collision
  checks, typed metadata, open credential kinds, typed `list/show/inspect` XPC DTOs, and macOS
  user-presence protection for detailed inspection
- [X] T044 [US1] Implement argument-based `exec` submission and result rendering in `Sources/SAFACLI/SAFACommand.swift`
- [X] T045 [US1] Add request/decision/execution audit emission for the MVP path in `Sources/SAFABroker/AuditService.swift`
- [X] T046 [US1] Complete the synthetic end-to-end MVP and leakage assertions in `Tests/Integration/ReadOnlySSHJourneyTests.swift`
- [X] T046a [P] [US1] Add permutation-invariance, parallel-edge, provenance, freshness, visibility,
  and no-secret topology domain tests in `Tests/Unit/TopologyGraphTests.swift` and
  `Tests/Security/TopologyProjectionLeakageTests.swift`
- [X] T046b [P] [US1] Add contract fixtures for node/edge tables, reachability adjacency,
  dependency-impact reverse adjacency, bounded dense matrices, proofs, and truncation in
  `Tests/Contract/TopologyProjectionContractTests.swift`
- [X] T046c [US1] Implement the revisioned desired/observed/derived topology domain and relation
  validation in `Sources/SAFADomain/Topology/TopologyGraph.swift`
- [X] T046d [US1] Implement deterministic bounded neighborhood, path, reachability, cycle, and
  dependency-set operations with proof edge IDs in `Sources/SAFADomain/Topology/TopologyQueryEngine.swift`
- [X] T046e [US1] Implement task-specific safe projections and stable ordering in
  `Sources/SAFAProtocol/TopologyProjectionV1.swift`; diagrams remain derived non-authoritative
  output and are not required for this task
- [X] T046f [US1] Bind Agent proposals only to desired/asserted edges and require signed adapter or
  Broker evidence for verified observed/derived edges in
  `Sources/SAFABroker/Topology/TopologyGraphService.swift`
- [X] T046g [US1] Bind explicit topology query/mutation DTOs through peer-validated Agent XPC and
  expose only `show`, `path`, `impact`, `link`, and `unlink` in
  `Sources/SAFACLI/Commands/Topology/`
- [X] T046h [US1] Mirror the canonical answer-first CLI fixtures, update the SAFA Skill routing
  rules, and document the complex-inside/simple-outside algorithm and decision diagrams in the
  public product repository
- [X] T046i [US1] Make encrypted resource relationships canonical for resource-to-resource
  `hosted-on`, `depends-on`, and `backed-by` declarations and reconcile stable desired graph edges
- [X] T046j [US1] Serialize matching topology link/unlink and resource lifecycle writes through one
  Broker transaction gate, with backward-compatible relationship provenance
- [X] T046k [US1] Refresh short-lived verified `runtime.local can-reach` evidence only after bounded
  SSH setup or an execution result that is not OpenSSH transport/authentication exit `255`
- [X] T046l [US1] Cover relationship reconciliation, lifecycle synchronization, observation refresh,
  transport-failure rejection, and synthetic execution with unit and integration tests
- [X] T046la [US1] Add separate five-minute in-memory approval leases for similar resource setup and
  desired topology link operations while requiring fresh authorization for destructive/state actions
- [X] T046m [US1] Install the locally signed Runtime, import the existing SSH alias catalog, run only
  bounded read-only probes, and verify the packaged resource/topology closure without committing any
  real infrastructure coordinates to the repository
- [X] T046n [US1] Adapt strict OpenSSH setup to quoted Application Support paths, non-default-port
  host-key aliases, portable POSIX hostname probes, and single-layer UTF-8 Windows inventory

**Checkpoint**: User Story 1 is independently demonstrable and is the first releasable diagnostic
MVP, even before arbitrary elevated command approval is added.

---

## Phase 4: User Story 2 - Run an Arbitrary Command with Scoped Approval (Priority: P2)

**Goal**: Preserve arbitrary `exec`, shell, pipeline, redirect, TTY, and sudo capability while binding
authority to a reviewed request and trusted local approval.

**Independent Test**: Automatically run one low-risk command, approve one exact sudo restart, grant
a 15-minute command scope, reject command/target mutation, and revoke the grant.

### Tests for User Story 2

- [X] T047 [P] [US2] Add failing policy finding and precedence tests in `Tests/Unit/PolicyClassifierTests.swift`
- [X] T048 [P] [US2] Add failing POSIX quoting and shell fingerprint property tests in `Tests/Security/CommandCanonicalizationTests.swift`
- [X] T049 [P] [US2] Add failing replay, mutation, caller, resource, expiry, and clock rollback tests in `Tests/Security/ApprovalBindingTests.swift`
- [ ] T050 [P] [US2] Add failing Touch ID cancel/fallback and forged-approval tests in `Tests/Integration/TrustedApprovalTests.swift`
- [ ] T051 [P] [US2] Add failing sudo injection and stdin isolation tests in `Tests/Security/SudoExecutionTests.swift`
- [ ] T052 [P] [US2] Add failing shell/pipeline/timeout/output-bound journey in `Tests/Integration/ArbitraryCommandJourneyTests.swift`

### Implementation for User Story 2

- [X] T053 [P] [US2] Implement command tokenization metadata, POSIX rendering, and immutable fingerprints in `Sources/SAFAPolicy/CommandCanonicalizer.swift`
- [X] T054 [P] [US2] Implement deterministic risk findings and deny/approval precedence in `Sources/SAFAPolicy/PolicyEngine.swift`
- [ ] T055 [US2] Implement request state machine and asynchronous wait/cancel lifecycle in `Sources/SAFABroker/RequestService.swift`
- [X] T056 [US2] Implement exact, prefix, and full-access scope matching with monotonic expiry in `Sources/SAFAPolicy/GrantMatcher.swift`
- [ ] T057 [US2] Implement LocalAuthentication-backed approval decisions behind a broker-owned
  protocol in `Sources/SAFABroker/ApprovalAuthenticator.swift`
- [ ] T058 [P] [US2] Specify an immutable, system-authenticated no-GUI approval presentation and
  scope-selection workflow before implementation
- [ ] T059 [US2] Implement separately signed trusted-local approval IPC and grant issuance in
  `Sources/SAFABroker/ApprovalService.swift`
- [ ] T060 [US2] Implement explicit sudo command composition and protected stdin injection in `Sources/SAFASSH/SudoExecutor.swift`
- [ ] T061 [US2] Implement `shell`, request wait/get/cancel, and risk-review fields in `Sources/SAFACLI/Commands/`
- [ ] T062 [US2] Integrate policy, grants, approval, exec/shell, TTY, timeout, cancellation, and sudo in `Sources/SAFABroker/ExecutionService.swift`
- [ ] T063 [US2] Add active grant list/revoke commands and broker methods in `Sources/SAFACLI/Commands/GrantCommands.swift` and `Sources/SAFABroker/GrantService.swift`
- [ ] T064 [US2] Complete adversarial approval and arbitrary-command end-to-end assertions in `Tests/Integration/ArbitraryCommandJourneyTests.swift`

**Checkpoint**: Arbitrary operational work is usable with Codex-like low-risk automation and trusted
approval for elevated authority.

---

## Phase 5: User Story 3 - Protect Inventory and Limit Compromise Impact (Priority: P3)

**Goal**: Demonstrate that open source, copied local files, and compromise of one managed host do not
expose the remaining infrastructure or reusable cross-host credentials.

**Independent Test**: Copy/tamper/rollback the vault and compromise one of two synthetic hosts; verify
no other endpoint-and-credential combination becomes usable.

### Tests for User Story 3

- [ ] T065 [P] [US3] Add failing copied-device, corrupted-vault, and rollback recovery tests in `Tests/Security/VaultCompromiseTests.swift`
- [ ] T066 [P] [US3] Add failing cross-host credential isolation and reuse-warning tests in `Tests/Security/BlastRadiusTests.swift`
- [ ] T067 [P] [US3] Add failing encrypted recovery and device-key reenrollment tests in `Tests/Integration/RecoveryTests.swift`

### Implementation for User Story 3

- [ ] T068 [P] [US3] Implement security-domain credential reuse detection in `Sources/SAFABroker/CredentialIsolationService.swift`
- [ ] T069 [US3] Add reuse warnings and explicit acceptance to the trusted local registration flow
- [ ] T070 [US3] Implement vault integrity, rollback, copied-installation, and fail-closed health states in `Sources/SAFACrypto/VaultIntegrityService.swift`
- [ ] T071 [US3] Implement encrypted recovery export/import excluding device-bound private keys in `Sources/SAFACrypto/RecoveryPackage.swift`
- [ ] T072 [US3] Build a system-authenticated no-GUI recovery and reenrollment flow
- [ ] T073 [US3] Surface explicit threat-model/security-state limits through
  `Sources/SAFACLI/Commands/DoctorCommand.swift`

**Checkpoint**: Security claims are supported by tests and do not overpromise protection after full
local administrator compromise.

---

## Phase 6: User Story 4 - Install and Use SAFA as a Skill (Priority: P4)

**Goal**: Deliver the Skill-first installation and Agent workflow without Homebrew, raw secrets,
unverified downloads, or unsafe interpretation of remote output.

**Independent Test**: Install the built Skill into a clean profile, trigger it with a NAS health
request, complete trusted setup, and execute through the pinned signed runtime.

### Tests for User Story 4

- [ ] T074 [P] [US4] Add failing Skill trigger and no-secret-request scenarios in `Tests/Contract/SkillBehaviorTests.md`
- [ ] T075 [P] [US4] Add failing platform/version/hash/signature/publisher package tests in `Tests/Security/SkillPackageVerificationTests.sh`
- [ ] T076 [P] [US4] Add failing remote-output prompt-injection scenarios in `Tests/Security/RemoteOutputInjectionTests.swift`

### Implementation for User Story 4

- [ ] T077 [US4] Write concise trigger and safe-operation instructions in `Skills/safa/SKILL.md`
- [ ] T078 [P] [US4] Generate matching display metadata in `Skills/safa/agents/openai.yaml`
- [ ] T079 [P] [US4] Write the versioned compact Agent CLI reference in `Skills/safa/references/cli.md`
- [ ] T080 [US4] Implement the macOS-only thin runtime resolver and verifier in `Skills/safa/scripts/safa`
- [ ] T081 [US4] Implement universal runtime assembly, per-component manifest generation, and pinned
  Skill packaging in `Scripts/build-release.sh` and `Scripts/package-skill.sh`
- [X] T081a [US4] Add manual Apple Development signing for the exact local Source Preview without
  requiring an Xcode account/provisioning update in `Scripts/install-local-runtime.sh`
- [ ] T082 [US4] Implement package, signature, entitlement, architecture, schema, and source-only verification in `Scripts/verify-package.sh`
- [X] T083 [US4] Implement repository and artifact secret/infrastructure scanning in `Scripts/scan-secrets.sh`
- [ ] T084 [US4] Run an independent clean-profile Skill journey and record fixtures in `Tests/Contract/SkillBehaviorTests.md`

**Checkpoint**: A user installs one Skill artifact and the Agent reliably uses SAFA without external
package-manager setup.

---

## Phase 7: User Story 5 - Review and Revoke Access (Priority: P5)

**Goal**: Let the user reconstruct sanitized activity, verify audit continuity, inspect grants, and
revoke authority immediately.

**Independent Test**: Generate allowed, denied, approved, failed, expired, and revoked actions; verify
the chain and prove no credential appears in UI, CLI, or export.

### Tests for User Story 5

- [ ] T085 [P] [US5] Add failing audit chain, gap, rollback, rotation, and redaction tests in `Tests/Security/AuditIntegrityTests.swift`
- [ ] T086 [P] [US5] Add failing grant review/revocation concurrency tests in `Tests/Integration/GrantRevocationTests.swift`
- [ ] T087 [P] [US5] Add failing CLI audit pagination and export contracts in `Tests/Contract/AuditCLIContractTests.swift`

### Implementation for User Story 5

- [ ] T088 [US5] Implement canonical sanitized audit events, chained integrity, rotation, and Keychain anchors in `Sources/SAFABroker/AuditStore.swift`
- [ ] T089 [US5] Implement audit list/verify pagination and export commands in `Sources/SAFACLI/Commands/AuditCommands.swift`
- [ ] T090 [P] [US5] Build activity, integrity, active-grant, and revoke-all CLI projections plus a
  system-authenticated local revocation path
- [ ] T091 [US5] Enforce immediate revocation against pending/running request boundaries in `Sources/SAFABroker/GrantService.swift`
- [ ] T092 [US5] Complete mixed-event incident reconstruction assertions in `Tests/Integration/GrantRevocationTests.swift`

**Checkpoint**: Every privileged action is attributable and every active grant is visible and
revocable without exposing secrets.

---

## Phase 8: Polish and Cross-Cutting Security

**Purpose**: Validate the combined product, distribution, performance, and constitutional guarantees.

- [ ] T093 [P] Add concurrency, 500-resource, 10-request, memory, output, and latency tests in `Tests/Integration/PerformanceTests.swift`
- [ ] T094 [P] Add fuzz/property corpus for decoding, quoting, policy, redaction, and vault envelopes in `Tests/Security/FuzzCorpus/`
- [ ] T095 Harden release entitlements, sandbox/runtime exceptions, logging privacy, and launch environment in `Apps/SAFA/Config/`
- [ ] T096 Add signed/notarized release workflow with external secret references only in `.github/workflows/release.yml`
- [ ] T097 Run every scenario in `specs/001-secure-agent-access/quickstart.md` and record pass/fail evidence in `Tests/QuickstartResults.md`
- [ ] T098 Validate every functional requirement and success criterion against test evidence in `specs/001-secure-agent-access/checklists/release-readiness.md`
- [ ] T099 Perform final MIT/dependency license, source-secret, artifact-secret, signature, architecture, and schema compatibility checks in `Scripts/verify-package.sh`

### Agent CLI v2 migration (release blocking)

- [X] T100 Read and apply the installed `axi` Skill, pin its reviewed upstream commit plus the
  normative TOON v4.1 specification, and record the encoder ownership/conformance decision in
  `specs/001-secure-agent-access/research.md`
- [X] T101 [P] Add failing canonical TOON fixtures for home, resource, topology, execution, empty,
  no-op, truncation, usage error, protected-action, transport-error, and hostile-output cases in
  `Tests/Contract/AgentCLIV2ContractTests.swift`
- [X] T102 [P] Add strict TOON cross-decoding and official v4.1 conformance fixtures to CI without
  exposing runtime IPC or vault persistence as public formats
- [X] T103 Implement explicit `dev.safa.cli/v2` public DTOs and the first canonical TOON
  presentation adapter (`resource.list`) in `Sources/SAFAProtocol/Agent/` and
  `Sources/SAFACLI/Presentation/`
- [X] T104 Implement AXI minimal fields, allowlisted `--fields`, bounded preview/`--full`, aggregates,
  definitive empty states, contextual safe next commands, and content-first roots
- [X] T105 Replace v1 exit mapping with `0` success/accepted/no-op, `1` incomplete/error, and `2`
  usage-before-side-effect while preserving stable lifecycle/error codes inside TOON
- [X] T106 Remove public JSON/human format switches and completion generation, update the Skill and
  exact Runtime schema range atomically, and keep the launcher TOON failure paths deterministic
- [X] T107 Benchmark representative synthetic SAFA tasks against compact JSON v1 across the selected
  Agent models; require no task-completion regression and record token/turn/latency results

---

## Dependencies and Execution Order

### Phase dependencies

- **Setup**: starts immediately.
- **Foundational**: depends on Setup and blocks all user stories.
- **US1**: depends only on Foundational and defines the diagnostic MVP.
- **US2**: depends on Foundational; integrates with US1 transport/resource services but its policy,
  grant, and approval components can be developed against fakes.
- **US3**: depends on Foundational; recovery UI builds on US1 onboarding but cryptographic and blast-
  radius tests can start independently.
- **US4**: depends on a runnable US1 runtime for full validation; Skill files and package tests can
  begin after Foundational.
- **US5**: depends on Foundational; full incident reconstruction validation uses US1/US2 events.
- **Polish**: depends on every story selected for the release.

### User story completion order

```text
Setup -> Foundational -> US1 (MVP)
                        ├-> US2 -> US5 full validation
                        ├-> US3
                        └-> US4
All selected stories -> Polish
```

### Within each user story

1. Write the listed tests and confirm they fail for the intended reason.
2. Implement independent models/services in parallel where marked `[P]`.
3. Integrate through the versioned contracts.
4. Run the story's independent test before starting a dependent story.

## Parallel Execution Examples

### User Story 1

```text
T027 resource CLI contract || T028 onboarding || T029 host identity || T030 enclave || T031 askpass
T033 registry || T035 trusted no-GUI registration || T036 enclave key || T037 password credential
```

### User Story 2

```text
T047 policy || T048 command canonicalization || T049 grant binding || T050 approval || T051 sudo
T053 canonicalizer || T054 policy engine || T058 trusted local approval workflow
```

### User Stories 3-5 after the MVP

```text
US3 vault/recovery hardening || US4 Skill packaging || US5 audit and revocation
```

## Implementation Strategy

### MVP first

1. Complete T001-T026.
2. Complete T027-T046.
3. Stop and validate the P1 journey with synthetic `nas.home`.
4. Do not call the build production-ready yet: arbitrary approval, recovery, packaging hardening, and
   complete audit UX are intentionally later increments.

### Incremental delivery

1. **0.1 diagnostic preview**: Foundation + US1 on synthetic/test resources.
2. **0.2 controlled operations**: add US2 and exact/session approvals.
3. **0.3 security preview**: add US3, US4, and US5.
4. **1.0**: complete Phase 8, notarized Skill artifact, adversarial evidence, and release checklist.

## Notes

- Never place real hostnames, IPs, usernames, passwords, keys, tokens, host fingerprints, or jump
  routes in source, tests, fixtures, issues, CI output, or task evidence.
- Development-only peer/signature bypasses must be compile-time excluded from Release builds.
- An approved root shell is intentionally powerful; scope, expiry, visibility, and audit are the
  mitigation, not misleading command classification.
- Commit after each task or coherent test-first group. Keep the unpublished Skill and Runtime on the
  reviewed `dev.safa.cli/v2` contract without restoring a second public output mode.
