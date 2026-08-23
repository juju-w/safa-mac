# Phase 1 Data Model: Bounded Sudo Execution

This feature adds one new entity (`SudoCredential`) and reuses four entities already defined in
`specs/001-secure-agent-access/data-model.md` without modification: `Resource` (via its existing
`sudoRef` field), `ExecutionRequest` (via its existing `privilege` field), `ApprovalGrant` (via its
existing `privilegeCeiling` field), and `AuditEvent`. Only the delta from that document is described
below; field tables already present there are not repeated.

## SudoCredential (new)

Refines the `sudoRef: CredentialReference ID?` field already present on `Resource`. A
`SudoCredential` is a `CredentialReference` whose `role` is `sudo`, plus the fields below that are
specific to sudo's verify-then-persist lifecycle.

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Immutable; this is the value stored in `Resource.sudoRef` |
| `resourceID` | UUID | Exact resource this credential authorizes; one sudo credential per resource |
| `remoteAccount` | String | Must equal the resource's existing SSH login `username`; sudo enrollment never introduces a second remote account |
| `mode` | Enum | `password`, `passwordless` |
| `keychainLocator` | Opaque | Present only when `mode == .password`; distinct Keychain item from the resource's SSH login credential; never Agent-visible |
| `verificationState` | Enum | `unverified`, `verified`, `reenroll_required` — see state transitions below |
| `lastVerifiedAt` | Timestamp? | Set on successful `verify`/passwordless-detection; used to detect remote sudo-policy drift, not to re-authorize a stale credential automatically |
| `createdAt` / `updatedAt` | Timestamp | UTC |

### State transitions

```text
(none) -> unverified      candidate collected (password mode) or passwordless check begins
unverified -> verified    non-mutating remote check succeeds (`sudo -v` or `sudo -n true`)
unverified -> (discarded) verification fails; resource and any prior sudo credential are unchanged
verified -> reenroll_required   credential rotated/removed, remote account/platform changed, or a
                                  later verification attempt fails
reenroll_required -> unverified  user restarts enrollment
```

A `SudoCredential` in any state other than `verified` MUST NOT be usable to authorize execution.
For first use, "no sudo credential" means the exact request remains pending until one authenticated
trusted-local continuation verifies and persists a credential; it never authorizes execution by
itself.

### Validation rules

- Enrollment MUST fail before persisting anything if the resource has no active SSH login credential
  (`Resource.authRef` unhealthy or absent).
- `remoteAccount` MUST match the resource's current SSH `username`; if the SSH login username later
  changes through `resource edit`, the existing `SudoCredential` transitions to `reenroll_required`
  rather than silently continuing to authorize the old account.
- At most one `SudoCredential` exists per `Resource` at a time; re-enrollment replaces the prior
  record only after the new candidate independently verifies, mirroring the existing SSH credential
  rotation rule in `001-secure-agent-access` FR-003g (verify before atomic replace; prior credential
  preserved on failure).
- Removing a resource's `SudoCredential` (or removing the resource itself) MUST immediately
  invalidate every `ApprovalGrant` whose `privilegeCeiling` is `sudo` and whose `resourceID` matches,
  per FR-016 in `spec.md`.

## Reused entities — sudo-specific usage notes

- **`ExecutionRequest.privilege`**: already `user | sudo` in `001-secure-agent-access/data-model.md`.
  This feature is what makes `privilege: sudo` reachable end to end: `PolicyEngine` already emits
  `command.sudo_requested`/`command.embedded_sudo` findings for it, and `RiskAssessment.requiredApproval`
  for any such finding MUST resolve to `userPresence` or `explicitFullAccess` — never `none` (FR-007
  in `spec.md`). No field changes.
- **`ApprovalGrant.privilegeCeiling`**: already `user | sudo`. A "Sudo Approval Grant" in `spec.md`'s
  Key Entities is simply an `ApprovalGrant` with `privilegeCeiling: sudo`; `GrantMatcher`'s existing
  ceiling comparison already enforces FR-012 (a `user`-ceiling grant never authorizes a `sudo`
  request). No field changes.
- **`AuditEvent`**: sudo enrollment (candidate collected, verified, persisted, discarded,
  reenroll-required transition) and sudo execution (request, decision, grant issuance/consumption/
  revocation, execution outcome) are recorded as `AuditEvent` records using the categories already
  defined in `001-secure-agent-access`, redacted by the same rules. No new audit schema.
- **`Resource.sudoRef`**: unchanged type (`CredentialReference ID?`); this feature is what makes it
  resolvable to a real `SudoCredential` instead of remaining "modeled only," per the
  `ARCHITECTURE.md` "ssh-hosts parity plan" row for per-host sudo.
