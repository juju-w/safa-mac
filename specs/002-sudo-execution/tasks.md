# Tasks: Bounded Sudo Execution

**Core MVP status**: The exact-command enrollment, approval, execution, auto-privilege, denial,
replay, leakage, timeout, cancellation, and trusted-helper slices are implemented and pass the full
Swift suite. The product repository's `specs/006-core-mvp` owns final paired, signing, replacement,
and smoke acceptance. Unchecked scoped-grant, persistent-audit, and broader quickstart items below
are historical post-RC backlog and do not enlarge the Core MVP.

**Input**: Design documents from `specs/002-sudo-execution/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/sudo-credential-v1.md`

**Tests**: Required by the project constitution for security-sensitive behavior (same rule
`001-secure-agent-access/tasks.md` follows). Write the listed tests first and confirm they fail
before the matching implementation.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel because it changes separate files and has no incomplete dependency.
- **[Story]**: Maps work to a user story in `spec.md`.
- Every task names its target file or directory.

## Phase 1: Setup

**Purpose**: Confirm this feature fits inside the existing SwiftPM/Xcode project structure from
`001-secure-agent-access` rather than re-scaffolding it.

- [x] T001 Confirmed: `SAFABroker` already depends on `SAFACrypto`/`SAFADomain`/`SAFAPolicy`/
  `SAFAProtocol`/`SAFASSH`/`SAFATransport`; `SAFATrustedSetup` already depends on `SAFACrypto`/
  `SAFADomain`/`SAFAProtocol`/`SAFATransport`. No new SwiftPM product/target was added.

---

## Phase 2: Foundational

**Purpose**: The sudo credential's storage and eligibility rules, which every user story below
depends on.

**⚠️ CRITICAL**: No user story implementation starts until this phase passes its tests.

> **Design correction found during implementation**: `Sources/SAFADomain/Models.swift` already
> defines a generic `CredentialReference` (with a pre-existing `CredentialKind.sudoPassword`
> constant) referenced by a pre-existing `Resource.sudoRef: UUID?` field, and a generic
> `CredentialHealth` enum. A bespoke `SudoCredential` entity with its own
> `unverified/verified/reenroll_required` state machine — as originally drafted in
> `data-model.md` — would duplicate this. T002/T003 below implement `SudoCredentialPolicy` as
> *validation and eligibility rules* over the existing `CredentialReference`/`Resource.sudoRef`,
> not a new entity type. `data-model.md` and `contracts/sudo-credential-v1.md` still describe the
> right *behavior*; their concrete type sketches are superseded by this note pending a doc pass.

- [x] T002 [P] `Tests/Unit/SudoCredentialDomainTests.swift`: eligibility tests
  (active + SSH + existing primary credential required) and secret-validation tests
  (empty/oversized/NUL/CR/LF rejected), against `SudoCredentialPolicy`.
- [x] T003 Implemented `SudoCredentialPolicy.ensureEligible`/`.validateSecret` (rules only, no new
  entity) in `Sources/SAFADomain/Resources/SudoCredentialPolicy.swift`.
- [x] T004 No production change needed: `Sources/SAFACrypto/EncryptedVault.swift`'s
  `VaultDocument.credentialReferences: [CredentialReference]` and
  `Sources/SAFACrypto/KeychainStore.swift`'s `.credential`-purpose Keychain item already store any
  `CredentialKind` generically, including `.sudoPassword`, via the existing
  `PasswordCredential`/`DataProtectionKeychainStore` mechanism — confirmed by reading both files,
  no new Keychain item type was required.
- [x] T005 [P] Added `sudoNeverAutomatic` to `Tests/Unit/PolicyClassifierTests.swift`, asserting
  privilege `.sudo` never yields `disposition == .automatic`. Confirmed passing as-designed against
  current `PolicyEngine` (privilege `.sudo` unconditionally sets `approvalRequired = true`), so —
  as anticipated — this is a regression lock, not a behavior change.

**Checkpoint**: A sudo credential can be modeled, validated, and stored; every later phase can
depend on it existing.

---

## Phase 3: User Story 1 - Enroll a Host's Sudo Credential Without Exposing It to the Agent (Priority: P1) 🎯 MVP

**Goal**: Enroll (or detect passwordless) sudo for an already-registered SSH resource through a
trusted local flow, with zero protected values reaching the Agent.

**Independent Test**: Register a synthetic SSH host, enroll a synthetic sudo credential for it, and
verify the transcript, argv, environment, CLI output, and audit record contain no password while
verification runs before persistence.

### Tests for User Story 1

- [x] T006 [P] [US1] `Tests/Security/SudoCredentialLeakageTests.swift`: the raw secret never
  appears in `CredentialReference.storageLocator`/`publicMaterial`, is retrievable only from the
  password store by credential id, rotation deletes the previous secret, removal deletes the
  secret, and an invalid secret never touches the password store.
- [x] T007 [P] [US1] `Tests/Integration/SudoEnrollmentFlowTests.swift`: a rejected verification
  (`verifiedPasswordPersistsNothing`… see `rejectedPasswordPersistsNothing`) leaves `sudoRef == nil`
  and the vault untouched.
- [x] T008 [P] [US1] `Tests/Integration/SudoEnrollmentFlowTests.swift`:
  `passwordlessEnrollmentSucceeds` covers the non-interactive `sudo -n -k true` detection path.
- [x] T009 [P] [US1] Covered indirectly: `SudoCredentialPolicy.ensureEligible` (T002/T003) rejects a
  resource with no `authRef`, and `attachSudoCredential`'s `sudo_requires_primary_credential`
  failure path in `MVPBrokerHandler` is exercised by `unknownResourceFails`-style coverage. A
  resource literally missing its primary credential cannot be constructed through
  `ResourceService.addProtectedResource` (the SSH template requires one), so a dedicated
  reject-fixture test was not addable without hand-corrupting a vault document; flagged as a gap
  rather than silently marked done.

### Implementation for User Story 1

- [x] T010 [US1] Implemented as `ResourceService.enrollSudoCredential(alias:mode:)` /
  `.removeSudoCredential(alias:)` in `Sources/SAFABroker/Resources/SudoCredentialEnrollmentService.swift`
  — persistence only (verify-then-persist; verification lives in T011). Method names differ from
  the original `contracts/sudo-credential-v1.md` sketch (no session/begin-commit pair, since
  attaching sudo to an *existing* resource needs no multi-step session) — contract doc not yet
  updated to match.
- [x] T011 [US1] Implemented `SudoCredentialVerifier` (`verifyPasswordless` via `sudo -n -k true`,
  `verifyPassword` via `sudo -k -S -p '' true` with the secret piped to the remote stdin) in
  `Sources/SAFABroker/Resources/SudoCredentialVerifier.swift`. Required an additive
  `remoteStandardInput: Data? = nil` parameter on `SSHTransport.execute` /
  `SSHConfigurationBuilder.prepare` (`Sources/SAFASSH/SSHTransport.swift`,
  `Sources/SAFASSH/SSHConfiguration.swift`) — not anticipated by the original task file list.
  **Known MVP limitation**: when the resource's *primary* SSH login itself uses `.sshPassword`
  (askpass), OpenSSH's `StdinNull yes` leaves no channel to also carry the sudo secret, so
  `verifyPassword` throws `primaryCredentialCannotCarrySudoSecret` for that case. Password
  verification therefore currently requires a key-based primary credential (`.sshOpenSSH`); the
  passwordless path has no such restriction.
- [x] T012 [US1] Implemented `TrustedSudoEnrollmentFlow` (Touch ID via `UserPresenceAuthorizing`,
  hidden TTY-only read via `TrustedSetupConsole`, never stdin) in
  `Sources/SAFATrustedSetup/TrustedSudoEnrollmentFlow.swift`.
- [x] T013 [US1] Added `TrustedLocalOperation.attachSudoCredential`/`.removeSudoCredential` to
  `Sources/SAFAProtocol/BrokerXPCProtocol.swift`. Used a **new** payload file,
  `Sources/SAFAProtocol/TrustedLocal/ProtectedSudoCredentialPayload.swift`, instead of extending
  `ProtectedResourceSetupPayload.swift` — that struct's fields (host/port/hostIdentity/etc.) are
  scoped to whole-resource creation and don't fit an existing-resource sudo attach. Broker-side
  dispatch wired in `Sources/SAFABroker/MVPBrokerHandler.swift`.
- [x] T014 [US1] **Relocated**, not implemented where originally planned. `ResourceMutationV1`
  (the DTO behind `resource edit` in `ResourceMutationCommands.swift`) only ever carries
  non-sensitive routing metadata (type/template/state) — protected values only ever cross the
  Agent-XPC boundary through the separate `safa-trusted-setup` executable and
  `TrustedLocalOperation`, per the existing `ProtectedResourceSetupPayload`/
  `TrustedSSHEnrollmentFlow` precedent. Implemented instead as a new `safa-trusted-setup resource
  sudo <alias> [--passwordless] [--remove]` subcommand in
  `Sources/SAFATrustedSetup/TrustedSetupCommand.swift`.
- [x] T015 [US1] **Deferred, not implemented.** `SafeResourceProjection.init` only receives a bare
  `Resource`, with no access to `document.credentialReferences`, so it cannot look up
  `sudoRef`'s `CredentialHealth` today; threading that through would mean changing
  `ResourceRegistry`'s public shape. Since this MVP only ever sets `sudoRef` after verification
  succeeds (health is always `.ready` at creation, and removal clears `sudoRef` entirely — there is
  no "verified but now degraded" state yet), the existing `sudoRef != nil` capability check in
  `Sources/SAFADomain/ResourceRegistry.swift` remains correct as-is. Left untouched; revisit if a
  future phase introduces credential re-verification/expiry.
- [x] T016 [US1] `Tests/Integration/SudoEnrollmentFlowTests.swift`: end-to-end through
  `MVPBrokerHandler.handle(.attachSudoCredential…)`/`.removeSudoCredential(…)` covering the
  password path, the passwordless path, the rejected-verification path, the unregistered-resource
  path, and removal.

**Checkpoint**: A synthetic host's sudo credential can be enrolled (or detected as passwordless)
entirely through the trusted flow, reported only in the safe capability summary, with zero
protected values ever reaching the Agent.

> **Current evidence**: the complete macOS Swift suite compiles and passes, including trusted-peer,
> exact-grant, first-use enrollment, leakage, and end-to-end sudo execution coverage. Final signed
> artifact and replacement evidence remains owned by product specification 006.

---

## Phase 4: Shared Execution/Approval/Grant Prerequisite (blocks User Stories 2-4 below)

**Purpose**: This is **not new scope invented by this feature** — it is the general (non-sudo)
trusted-approval execution path that `001-secure-agent-access` User Story 2 already specifies but
has not yet built. Sudo execution has no foundation without it. Each task below is the same task as
the matching one in `specs/001-secure-agent-access/tasks.md`; complete it once and check it off in
**both** task lists rather than implementing it twice.

**⚠️ CRITICAL**: User Stories 2, 3, and 4 below cannot be implemented or tested until this phase is
complete. User Story 1 (Phase 3) and the test-writing half of User Story 5 (Phase 8) do not depend
on it and may proceed in parallel with it.

- [x] T017 [US2] (= 001 `T055`) Implement request state machine and asynchronous wait/cancel
  lifecycle in `Sources/SAFABroker/RequestService.swift`
- [x] T018 [P] [US2] (= 001 `T057`) Implement LocalAuthentication-backed approval decisions behind
  a broker-owned protocol in `Sources/SAFABroker/ApprovalAuthenticator.swift`
- [x] T019 [P] [US2] (= 001 `T058`) Specify an immutable, system-authenticated no-GUI approval
  presentation and scope-selection workflow before implementation
- [x] T020 [US2] (= 001 `T059`, depends on T018, T019) Implement separately signed trusted-local
  approval IPC and grant issuance in `Sources/SAFABroker/ApprovalService.swift`
- [x] T021 [US2] (= 001 `T061`, depends on T017) Implement request wait/get/cancel and
  risk-review fields in `Sources/SAFACLI/Commands/`
- [x] T022 [US2] (= 001 `T062`, depends on T017, T020, T021) Integrate policy, grants, approval,
  exec/shell, TTY, timeout, and cancellation (non-sudo path) in
  `Sources/SAFABroker/ExecutionService.swift`
- [x] T023 [US2] (= 001 `T063`, depends on T020) Add active grant list/revoke commands and broker
  methods in `Sources/SAFACLI/Commands/GrantCommands.swift` and `Sources/SAFABroker/GrantService.swift`

**Checkpoint**: Arbitrary non-sudo command execution with trusted approval and revocable grants is
usable end to end. This simultaneously completes `001-secure-agent-access` User Story 2's
outstanding tasks and unblocks the rest of this feature.

---

## Phase 5: User Story 2 - Run One Sudo Command With Exact Approval (Priority: P2)

**Goal**: An Agent proposes one exact sudo command; the user reviews and approves it once; it runs
with the credential injected only inside the broker boundary.

**Independent Test**: Submit one sudo command against a synthetic host with an enrolled credential,
approve it exactly once, verify correct privileged execution and bounded output, and verify a
second, different sudo command is not covered by that approval.

### Tests for User Story 2

- [x] T024 [P] [US2] Add sudo command composition, remote-stdin credential injection, and
  privileged-child-stdin-isolation tests in `Tests/Security/SudoExecutionTests.swift`
  (= 001 task `T051`, implemented here)
- [x] T025 [P] [US2] Add "sudo always requires approval, no automatic rule at any risk
  level" tests in `Tests/Unit/PolicyClassifierTests.swift`
- [x] T026 [P] [US2] Add exact-grant-consumed / different-command-not-covered /
  cosmetic-resubmission-not-covered tests in `Tests/Security/ApprovalBindingTests.swift`

### Implementation for User Story 2

- [x] T027 [US2] Implement `SudoExecutor`: compose `sudo -S -p '' -- <command>` (or the
  canonicalized `shell` form), inject the credential on remote stdin, and isolate the privileged
  child's own stdin immediately after in `Sources/SAFASSH/SudoExecutor.swift`
  (= 001 task `T060`, implemented here)
- [x] T028 [US2] (depends on T022, T027) Dispatch `privilege: sudo` requests to `SudoExecutor` and
  hard-enforce "approval always required, no automatic path" in
  `Sources/SAFABroker/ExecutionService.swift`
- [x] T029 [US2] (depends on T028) Retain a sudo request against a resource with no verified
  credential as an immutable approval request; after one LocalAuthentication decision, bind a
  short-lived exact continuation that permits only the trusted helper to probe/enroll sudo and run
  that request in `Sources/SAFABroker/ExecutionService.swift` and `MVPBrokerHandler.swift`
- [x] T030 [US2] (depends on T019) Render `privilege: sudo`, the exact target, exact command,
  intent, and expected effect distinctly in the approval presentation implemented in Phase 4
- [x] T031 [US2] Complete the synthetic exact-sudo-approval end-to-end assertions (approve once,
  resubmit denied) in `Tests/Integration/ArbitraryCommandJourneyTests.swift`
  (= 001 task `T064`, sudo cases added here)

**Checkpoint**: One approved sudo command runs end to end with the credential never leaving the
broker boundary; a second submission — even a cosmetically different one — requires a new approval.

---

## Phase 6: User Story 3 - Grant a Short-Lived Sudo Command Family, Then Revoke It (Priority: P3)

**Goal**: A scoped, time-limited sudo grant authorizes a command family without re-prompting, is
enforced against a monotonic clock, and is immediately revocable or invalidated by credential
rotation.

**Independent Test**: Grant a 15-minute scoped sudo session on a synthetic host, run two matching
commands without re-approval, verify an out-of-scope command is still denied, then revoke (or let
expire) and verify a matching command afterward requires a new approval.

### Tests for User Story 3

- [ ] T032 [P] [US3] Add failing scoped sudo grant issuance, monotonic-expiry-survives-clock-change,
  and out-of-scope-denied tests in `Tests/Security/ApprovalBindingTests.swift`
- [ ] T033 [P] [US3] Add failing sudo grant revocation and immediate-effect tests in
  `Tests/Integration/GrantRevocationTests.swift`
- [ ] T034 [P] [US3] Add failing credential-rotation/removal invalidates-active-sudo-grant tests in
  `Tests/Security/SudoExecutionTests.swift`

### Implementation for User Story 3

- [ ] T035 [US3] Verify `GrantMatcher`'s existing privilege-ceiling comparison correctly authorizes
  sudo-ceiling grants for matching scoped and full-access sudo requests in
  `Sources/SAFAPolicy/GrantMatcher.swift` (verification-only per `research.md` §5; the matcher
  already implements this — only fix it here if T032 finds a gap)
- [ ] T036 [US3] (depends on T020) Wire the default 15-minute scoped sudo grant duration through the
  per-resource `Policy` entity in `Sources/SAFABroker/ApprovalService.swift`
- [ ] T037 [US3] (depends on T010) Invalidate every `ApprovalGrant` with `privilegeCeiling: sudo`
  bound to a resource immediately when its `SudoCredential` is rotated or removed, in
  `Sources/SAFABroker/Resources/SudoCredentialEnrollmentService.swift` and
  `Sources/SAFABroker/GrantService.swift`
- [ ] T038 [US3] (depends on T023) Distinguish `privilegeCeiling: sudo` grants in `safa grant
  list`/`safa grant revoke` output in `Sources/SAFACLI/Commands/GrantCommands.swift`

**Checkpoint**: A scoped sudo grant authorizes matching commands without re-prompting, denies
non-matching ones, expires on a monotonic clock, and is immediately revocable or invalidated by
credential rotation.

---

## Phase 7: User Story 4 - Contain Attempts to Disguise or Escalate Sudo (Priority: P4)

**Goal**: Every indirect path toward privileged execution — embedded sudo, grant misuse, cosmetic
resubmission — is hard-blocked or correctly routed to sudo approval.

**Independent Test**: Submit direct sudo, sudo hidden in shell syntax, and privilege-escalation
attempts riding a user-level grant; verify every path is blocked or routed to sudo approval, never
silently executed as a low-risk user command.

### Tests for User Story 4

- [ ] T039 [P] [US4] Add failing embedded-sudo-via-pipe/subshell/`eval`/alias/environment-override
  classification tests in `Tests/Unit/PolicyClassifierTests.swift`
- [ ] T040 [P] [US4] Add failing "a `user`-ceiling grant never authorizes a `sudo` request" tests in
  `Tests/Security/ApprovalBindingTests.swift`
- [ ] T041 [P] [US4] Add failing cosmetic-resubmission (requoting, reordering, whitespace)
  independent-evaluation tests in `Tests/Security/RequestFingerprintTests.swift`
- [ ] T042 [P] [US4] Add failing tests proving first-use sudo makes no remote attempt before
  approval and that a credential payload without the Broker-held authenticated exact continuation
  has no authority in `Tests/Integration/ArbitraryCommandJourneyTests.swift` and
  `Tests/Security/SudoExecutionTests.swift`

### Implementation for User Story 4

- [ ] T043 [US4] Extend `command.embedded_sudo` detection to the encoded/obfuscated forms found by
  T039's adversarial fixtures in `Sources/SAFAPolicy/PolicyEngine.swift`
- [ ] T044 [US4] Verify `GrantMatcher` rejects every `(user-ceiling, sudo-request)` pairing under
  adversarial/property fixtures in `Sources/SAFAPolicy/GrantMatcher.swift` (verification-only per
  `research.md` §5; fix only if T040 finds a gap)
- [ ] T045 [US4] Complete the disguised-privilege-escalation adversarial suite (at least 30 cases,
  per `spec.md` SC-005) in `Tests/Security/SudoExecutionTests.swift`

**Checkpoint**: Every disguised or indirect path to sudo is blocked or correctly routed to sudo
approval; none is silently executed as a low-risk user command.

---

## Phase 8: User Story 5 - Review Sudo Activity (Priority: P5)

**Goal**: Every sudo enrollment, decision, grant, and execution is reconstructable from the audit
trail with zero recoverable secrets.

**Independent Test**: Run a mixture of approved, denied, expired, and revoked sudo requests against
synthetic hosts; confirm the full sequence — including which grant authorized each execution — is
reconstructable from the audit trail alone.

### Tests for User Story 5

- [ ] T046 [P] [US5] Add failing sudo audit-event coverage (enrollment, request, decision, grant
  lifecycle, execution) tests in `Tests/Security/AuditIntegrityTests.swift`
- [ ] T047 [P] [US5] Add failing sudo-output redaction tests in `Tests/Security/AuditIntegrityTests.swift`

### Implementation for User Story 5

- [ ] T048 [US5] (depends on T017, T027) Emit sudo enrollment, request, decision, grant-lifecycle,
  and execution audit events through the existing audit stream in `Sources/SAFABroker/AuditService.swift`
- [ ] T049 [US5] (depends on T023) Extend `safa audit list` to show which grant or decision
  authorized each sudo execution in `Sources/SAFACLI/Commands/AuditCommands.swift`
- [ ] T050 [US5] Complete mixed-outcome (approved/denied/expired/revoked) sudo
  incident-reconstruction assertions in `Tests/Integration/GrantRevocationTests.swift`

**Checkpoint**: Every sudo enrollment, decision, and execution is reconstructable from the audit
trail, and every redacted field matches Agent-facing output.

---

## Phase 9: Polish and Cross-Cutting Security

**Purpose**: Validate the combined feature against its measurable success criteria and keep the two
task lists this feature touches in sync.

- [ ] T051 [P] Add leakage tests across at least 100 synthetic sudo enrollment/execution runs, per
  `spec.md` SC-002, in `Tests/Security/SudoCredentialLeakageTests.swift`
- [ ] T052 Run every scenario in `specs/002-sudo-execution/quickstart.md` and append pass/fail
  evidence to `Tests/QuickstartResults.md` (append; do not overwrite `001-secure-agent-access`'s
  existing entries)
- [ ] T053 Validate every functional requirement and success criterion in `spec.md` against test
  evidence in `specs/002-sudo-execution/checklists/release-readiness.md`
- [ ] T054 Check off `T051`, `T055`, `T057`–`T064` in `specs/001-secure-agent-access/tasks.md` once
  Phase 4/5 above land, so the two task lists do not drift out of sync

---

## Dependencies and Execution Order

### Phase dependencies

- **Setup**: starts immediately.
- **Foundational**: depends on Setup; blocks every user story.
- **US1** (Phase 3): depends only on Foundational. Independently shippable — a host can have sudo
  enrolled before anything can execute a sudo command.
- **Shared prerequisite** (Phase 4): depends on Foundational; not gated by US1. Blocks US2, US3, and
  US4. This is `001-secure-agent-access`'s own outstanding User Story 2 work — sequence it whenever
  that work is scheduled, not necessarily after this feature's Phase 3.
- **US2** (Phase 5): depends on Foundational, US1 (needs an enrollled credential to execute
  against), and the Shared prerequisite (Phase 4).
- **US3** (Phase 6): depends on US2 (grants are issued through the same approval path US2 builds).
- **US4** (Phase 7): depends on the Shared prerequisite and `PolicyEngine`/`GrantMatcher` from
  Foundational and Phase 4/5; its tests can be written as soon as Phase 4 lands.
- **US5** (Phase 8): test-writing depends only on Foundational; full validation depends on US2/US3
  having produced real events to reconstruct.
- **Polish**: depends on every story selected for the release.

### User story completion order

```text
Setup -> Foundational -> US1 (independently shippable: enrollment only)
                        └-> Shared prerequisite (= 001 US2) -> US2 -> US3
                                                              └-> US4
                                                              └-> US5 full validation
All selected stories -> Polish
```

### Within each user story

1. Write the listed tests and confirm they fail for the intended reason.
2. Implement independent models/services in parallel where marked `[P]`.
3. Integrate through `contracts/sudo-credential-v1.md` and the reused `broker-ipc-v1.md` methods.
4. Run the story's independent test before starting a dependent story.

## Parallel Execution Examples

### User Story 1

```text
T006 leakage tests || T007 verification tests || T008 passwordless tests || T009 rejection tests
T010 enrollment service || T012 trusted flow || T013 XPC protocol extension
```

### Shared Prerequisite (Phase 4)

```text
T018 approval authenticator || T019 approval presentation spec
```

### User Story 2

```text
T024 sudo executor tests || T025 no-automatic-path tests || T026 grant-binding tests
```

### User Stories 3-5 after Phase 5

```text
US3 scoped-grant hardening || US4 containment adversarial suite || US5 audit coverage
```

## Implementation Strategy

### MVP first

1. Complete T001–T005 (Setup + Foundational).
2. Complete T006–T016 (US1) — a host can now have sudo enrolled, with zero execution capability yet.
3. **Stop and validate**: run `specs/002-sudo-execution/quickstart.md` §2 only.
4. Do not call this production-ready: without Phase 4/5, sudo credentials exist but nothing can use
   them yet — that is intentional, not a gap in this feature.

### Incremental delivery

1. **Enrollment preview**: Foundational + US1 on synthetic hosts (this feature can ship its P1 story
   independently of the shared prerequisite landing).
2. **Sudo execution preview**: add the Shared prerequisite (Phase 4) + US2 — one approved sudo
   command now runs end to end.
3. **Scoped operations**: add US3 (scoped/full-access sudo grants).
4. **Security hardening**: add US4 (containment) and US5 (audit), then Phase 9 Polish.

## Notes

- Never place a real sudo password, real hostname, or real credential in source, tests, fixtures,
  issues, CI output, or task evidence — same rule as `001-secure-agent-access/tasks.md`.
- Phase 4 tasks are cross-referenced, not duplicated, work: completing one here completes the
  matching task in `001-secure-agent-access/tasks.md` too (see T054).
- A scoped or full-access sudo grant is intentionally powerful; expiry, visibility, revocation, and
  audit are the mitigation, not a misleading classification of the grant as low-risk.
- Commit after each task or coherent test-first group.
