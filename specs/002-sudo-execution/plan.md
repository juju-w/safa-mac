# Implementation Plan: Bounded Sudo Execution

**Branch**: `002-sudo-execution` | **Date**: 2026-08-18 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/002-sudo-execution/spec.md`

## Summary

SAFA's Core MVP sudo slice is implemented end to end: a trusted local flow enrolls a per-host sudo credential
(or records passwordless sudo) without ever exposing it to the Agent, and a broker-owned execution
path that classifies any privileged command as `privilege: sudo`, always requires trusted local
approval (exact, scoped, or explicit full-access), injects the credential only inside the execution
boundary, and audits the full lifecycle secret-free. The data and policy model for this already
exists (`Resource.sudoRef`, `ExecutionRequest.privilege`, `ApprovalGrant.privilegeCeiling`,
`PolicyEngine`'s `command.sudo_requested`/`command.embedded_sudo` findings, `GrantMatcher`'s
privilege-ceiling matching). The implementation now lives in `SudoExecutor`, `RequestService`,
`ApprovalService`, `GrantService`, and `ExecutionService`, with contract, integration, and security
coverage for exact approval, first-use enrollment, denial, replay resistance, and automatic
least-privilege selection.

**Resolved dependency**: sudo execution uses the general trusted-approval
execution path that `001-secure-agent-access` User Story 2 specified
(`RequestService`, `ApprovalAuthenticator`, `ApprovalService`, `ExecutionService`, `GrantCommands` —
tasks T055, T057–T059, T061–T063 in `specs/001-secure-agent-access/tasks.md`). Those services are now
implemented and tested. Historical unchecked task lists do not override the product repository's
smaller Core MVP boundary; broader scoped-grant and persistent-audit work is post-RC.

## Technical Context

**Language/Version**: Swift 6.3 language mode, unchanged from `001-secure-agent-access`

**Primary Dependencies**: Foundation, Security/SecItem, LocalAuthentication, XPC — all already
in use; no new external dependency. Sudo credential delivery reuses the existing `SAFAAskPass`
one-shot helper pattern rather than introducing a second credential-delivery mechanism.

**Storage**: Extends the existing AES-GCM encrypted vault document with one new credential-reference
kind (`sudo`) bound to a resource, stored as a separate Data Protection Keychain item from the SSH
login credential; no new storage subsystem.

**Testing**: Swift Testing/XCTest, extending the existing suites. This feature is the implementation
target for the currently-empty `Tests/Security/SudoExecutionTests.swift` and completes
`Tests/Integration/ArbitraryCommandJourneyTests.swift` (both already named as placeholders in
`001-secure-agent-access` tasks T051/T052/T064); adds `Tests/Integration/SudoEnrollmentFlowTests.swift`
and `Tests/Security/SudoCredentialLeakageTests.swift`. Only synthetic SSH fixtures; no real
infrastructure or real sudo password in any automated test.

**Target Platform**: macOS 14.4 or newer, unchanged.

**Project Type**: Native macOS CLI + per-user broker/launch agent + AskPass helper + trusted-setup
helper, unchanged. Sudo enrollment is a new mode of the existing trusted-setup helper family, not a
new executable target.

**Performance Goals**: Sudo policy classification and grant matching under the same 100 ms p95
budget as other policy decisions; sudo credential verification (`sudo -v`) bounded by the same
connection/command timeout used for other diagnostic execution.

**Constraints**: A sudo password MUST NOT appear in process arguments, environment variables,
Agent-visible stdout/stderr, logs, or audit records at any point (extends the existing general
secret-handling constraint with an explicit sudo case); sudo execution MUST NOT have any automatic
(no-approval) policy path, unlike ordinary diagnostic commands.

**Scale/Scope**: One sudo credential per resource; the existing MVP scale bounds (500 resources, 10
concurrent requests, 100 active/pending grants) are unchanged and already accommodate sudo-privilege
requests and grants as a subset of the existing `ExecutionRequest`/`ApprovalGrant` volumes.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

| Principle | Pre-design gate | Post-design evidence |
|---|---|---|
| Secrets never cross the Agent boundary | PASS | Sudo password is collected only by the trusted-setup helper family and injected only inside the broker's execution boundary, mirroring the existing SSH login credential path; no new Agent-facing field carries it |
| Useful command execution with scoped authority | PASS | Sudo remains full-strength `exec`/`shell`, but every sudo request unconditionally requires trusted approval (exact, scoped, or explicit full-access) — no automatic path exists at any risk level for `privilege: sudo` |
| macOS-native trust boundary | PASS | Enrollment and approval both route through LocalAuthentication/Touch ID via the already-signed broker and trusted-setup helper; no new unsigned surface is introduced |
| Open design, encrypted user state | PASS | Sudo credential is a Keychain-backed record like the SSH login credential, per-installation encrypted, no obscurity-dependent property, synthetic fixtures only in tests |
| Deterministic contracts and complete auditability | PASS | Sudo enrollment, request, decision, grant lifecycle, and execution are recorded through the existing hash-chained audit event stream with the same redaction rules; `PolicyEngine` findings for sudo are already deterministic and tested (`command.sudo_requested`, `command.embedded_sudo`) |

No constitution exception is required. The design deliberately rejects: a sudo-specific bypass of
the approval requirement, a shared credential-delivery path between SSH login and sudo, and any
automatic-policy rule that could match a `privilege: sudo` request.

## Project Structure

### Documentation (this feature)

```text
specs/002-sudo-execution/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── quickstart.md         # Phase 1 output
├── contracts/
│   └── sudo-credential-v1.md
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

Reuses the existing SwiftPM module layout from `001-secure-agent-access` (see its
`specs/001-secure-agent-access/plan.md`); this feature adds the following files inside that
structure and does not introduce a new module boundary:

```text
Sources/
├── SAFADomain/
│   └── Resources/SudoCredentialPolicy.swift        # NEW: per-resource sudo credential rules
├── SAFABroker/
│   ├── RequestService.swift                        # SHARED prerequisite (001 T055) — sudo requests
│   │                                                  flow through the same request state machine
│   ├── ApprovalAuthenticator.swift                  # SHARED prerequisite (001 T057)
│   ├── ApprovalService.swift                        # SHARED prerequisite (001 T059)
│   ├── ExecutionService.swift                       # SHARED prerequisite (001 T062) — dispatches to
│   │                                                  SudoExecutor when privilege == .sudo
│   ├── GrantService.swift                           # SHARED prerequisite (001 T063)
│   └── Resources/
│       ├── SudoCredentialEnrollmentService.swift     # NEW: verify + persist a sudo credential
│       └── SudoCredentialVerifier.swift              # NEW: non-mutating `sudo -v` / `sudo -n true` check
├── SAFASSH/
│   └── SudoExecutor.swift                           # NEW (001 task T060, implemented here): composes
│                                                        `sudo -S`, injects credential on remote stdin,
│                                                        isolates the privileged child's own stdin
├── SAFATrustedSetup/
│   └── TrustedSudoEnrollmentFlow.swift               # NEW: hidden-input sudo password collection,
│                                                        mirrors TrustedSSHEnrollmentFlow.swift
└── SAFACLI/
    └── Commands/
        ├── Resource/ResourceMutationCommands.swift   # EXTEND: `resource edit ALIAS --sudo ...` stage
        └── GrantCommands.swift                       # SHARED prerequisite (001 T063), sudo grants
                                                          appear in the same list/revoke surface

Tests/
├── Integration/
│   ├── ArbitraryCommandJourneyTests.swift            # COMPLETE (001 T064) with sudo cases
│   └── SudoEnrollmentFlowTests.swift                 # NEW
└── Security/
    ├── SudoExecutionTests.swift                      # NEW (001 T051, implemented here)
    └── SudoCredentialLeakageTests.swift               # NEW
```

**Structure Decision**: No new module or executable target. Sudo enrollment is a new flow inside the
existing `SAFATrustedSetup` helper (same signed, no-custom-GUI, hidden-input pattern already used for
SSH password setup) rather than a separate helper binary, and sudo execution is a new adapter inside
the existing `SAFASSH` module rather than a new transport. This keeps one signed trusted-input
surface and one signed remote-execution surface instead of doubling either.

## Security Boundaries

Reuses the five boundaries defined in `specs/001-secure-agent-access/plan.md` unchanged, with one
addition specific to this feature:

6. **Sudo credential boundary**: the sudo credential is a distinct Keychain record from the SSH
   login credential, readable only by the broker, and is never held by the CLI, the Agent process,
   or an intermediate file. Its enrollment, verification, and delivery are three separate operations
   (collect-and-verify in the trusted-setup helper, persist in the broker, inject-and-isolate in the
   `SudoExecutor`), so no single compromised component can both read and exfiltrate it.

## Delivery Phases

- **Phase A — shared execution/approval/grant foundation** *(prerequisite, owned by
  `001-secure-agent-access` User Story 2, not new scope of this feature)*: request state machine,
  Touch ID-backed approval authenticator and service, exact/prefix/full-access grant issuance and
  listing/revocation. Sudo cannot ship before this phase is complete; sequence it first in
  `/speckit-tasks`.
- **Phase B — sudo credential enrollment**: `TrustedSudoEnrollmentFlow`, `SudoCredentialVerifier`,
  `SudoCredentialEnrollmentService`, passwordless-sudo detection, and the `resource edit --sudo`
  CLI surface. Independently testable and independently valuable (User Story 1 of spec.md) even
  before execution is wired up.
- **Phase C — sudo execution and approval integration**: `SudoExecutor`, `ExecutionService`
  privilege dispatch, mandatory-approval enforcement for `privilege: sudo` (no automatic path),
  and sudo-ceiling grant issuance/matching through the already-implemented `GrantMatcher`. Delivers
  User Stories 2 and 3 of spec.md.
- **Phase D — containment and audit hardening**: embedded-sudo detection edge cases beyond the
  existing `command.embedded_sudo` finding (aliasing, encoded forms), cross-privilege grant-reuse
  denial tests, credential rotation/removal invalidating active grants, and the sudo-specific audit
  and redaction coverage. Delivers User Stories 4 and 5 of spec.md.

## Complexity Tracking

No constitution violations require justification. This feature deliberately reuses existing
modules (`SAFASSH`, `SAFATrustedSetup`, `SAFABroker`) rather than adding new ones; the only new
executable-adjacent surface is a new *flow* inside an already-signed helper, which keeps the signed
attack surface flat instead of growing it per feature.
