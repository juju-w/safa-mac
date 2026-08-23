# Phase 0 Research: Bounded Sudo Execution

No `[NEEDS CLARIFICATION]` markers remain in `spec.md`; the questions below were already resolved
either by reusing a decision already made in `specs/001-secure-agent-access/research.md` or by a new
decision specific to sudo.

## 1. Reused decisions (no new research needed)

These decisions from `001-secure-agent-access` apply to sudo without modification and are not
re-derived here:

- **Approval and capability model** (research.md §6): asynchronous broker-created requests, a
  future/now-being-built separately signed approval presentation, LocalAuthentication for user
  presence, random capability with only a stored hash persisted, exact grants one-shot, scoped/full
  grants visible and revocable. Sudo grants are the same `ApprovalGrant` shape with
  `privilegeCeiling: sudo`; no separate grant type is introduced.
- **Command representation and policy** (research.md §7): `exec`/`shell` modes, deterministic
  `PolicyEngine` findings, Agent review as advisory-only evidence. The `command.sudo_requested` and
  `command.embedded_sudo` findings and the "broker owns remote stdin, writes the sudo password
  directly to `sudo -S`, never in the command string" decision already cover the sudo execution
  shape; this feature implements what that decision specified but did not yet build.
- **Output, redaction, and audit** (research.md §8): hash-chained JSONL audit, exact + heuristic
  redaction, TOON v2 Agent boundary. Sudo audit events reuse this stream and these redaction rules
  unchanged; no sudo-specific audit format is introduced.

## 2. Sudo credential enrollment trigger and shape

**Decision**: Sudo enrollment is a new mode of the existing trusted-setup helper family
(`SAFATrustedSetup`), invoked as a stage of `resource edit ALIAS` rather than a new top-level
command, consistent with FR-003a in `001-secure-agent-access/spec.md` ("adapter setup... MUST be
expressed as stages or options of [`add`/`edit`] rather than separate top-level resource
commands"). It requires the resource to already have an active SSH login credential; enrollment
without one is rejected before any password prompt.

**Rationale**: Reusing the edit-stage pattern keeps the Agent-facing verb surface unchanged (still
`list`/`show`/`add`/`edit`/`remove`) and reuses the already-reviewed hidden-input mechanics (echo
disabled, terminal-only, never argv/env/Agent-stdin) instead of inventing a second collection
pattern.

**Alternatives considered**:

- **A new top-level `sudo` command**: rejected — duplicates the CRUD-oriented resource surface
  FR-003a already established and gives the Agent a second mental model for essentially the same
  "add protected data to a resource" action.
- **Fold sudo password collection into initial SSH `add`**: rejected — FR-003e in
  `001-secure-agent-access` explicitly requires SSH setup and sudo enrollment to remain separate
  capabilities; a host is very often registered before anyone decides it needs sudo access.

## 3. Passwordless sudo detection

**Decision**: Enrollment first runs a non-interactive, non-mutating remote check equivalent to
`sudo -n true` (exit 0 means passwordless sudo is available for that account). Only if that check
fails does enrollment prompt for a password, then verifies it with `sudo -v` before persisting.

**Rationale**: Avoids asking for a password the account does not need, and avoids a false negative
where a password is stored for an account that actually has `NOPASSWD` configured (which would
create an unnecessary Keychain secret and a misleading "credential required" health state).

**Alternatives considered**:

- **Always require a password if one is not explicitly declined by the user**: rejected — adds
  friction and a stored secret for accounts that do not need one, without a corresponding security
  benefit.
- **Parse remote `/etc/sudoers`**: rejected — requires privileged read access to determine, which is
  circular (you need sudo to inspect the sudo policy), and remote-file parsing is exactly the kind of
  untrusted-output-as-instruction pattern the constitution prohibits relying on.

## 4. Credential delivery and privileged-child stdin isolation

**Decision**: `SudoExecutor` composes the remote command as `sudo -S -p '' -- <command>` (or the
canonicalized shell form for `shell` mode), writes the Keychain-resolved sudo password to the SSH
session's stdin stream at the point `sudo` requests it, and immediately redirects the *privileged
child's own* stdin to `/dev/null` once the password has been consumed so the executed command itself
never inherits an open, Agent-influenced stdin.

**Rationale**: This matches the exact behavior already documented as the migration baseline in
`001-secure-agent-access/research.md` §11 ("sudo password delivery on remote stdin followed by
`/dev/null` for the privileged child's stdin") and keeps sudo password handling inside one narrow,
already-reasoned-about code path (`SudoExecutor`) rather than general-purpose stdin plumbing shared
with ordinary commands.

**Alternatives considered**:

- **A remote constrained helper that owns sudo invocation**: noted in 001 research as a possible
  future reduction of sudo password handling, but explicitly not required for MVP; deferred, not
  part of this feature.
- **`sudo -A` with a local askpass-over-SSH bridge**: adds a second remote process and a network
  round-trip per privileged command for no isolation benefit over direct stdin injection, given the
  broker already exclusively owns the SSH session.

## 5. Cross-privilege grant isolation

**Decision**: `GrantMatcher`'s existing privilege-ceiling comparison (`(.user, .user)`,
`(.sudo, .user)`, `(.sudo, .sudo)` authorize; `(.user, .sudo)` does not — i.e. a `sudo`-ceiling grant
may cover a `user`-privilege request, but a `user`-ceiling grant may never cover a `sudo`-privilege
request) is reused verbatim. No new grant-matching logic is introduced by this feature.

**Rationale**: This logic is already implemented and unit-tested (`Sources/SAFAPolicy/GrantMatcher.swift`).
Sudo containment (spec.md User Story 4) is therefore a verification/testing task against existing
code, not new matching logic — the risk this feature adds is in *exercising* the embedded-sudo and
grant-ceiling paths with realistic adversarial fixtures, not in inventing new policy.

**Alternatives considered**: None — reusing tested existing logic was the only reasonable option;
building a parallel sudo-specific matcher would create two authorization code paths to keep in sync.

## 6. Default scoped-grant duration

**Decision**: A scoped (prefix/command-family) sudo grant defaults to 15 minutes unless the user
selects a shorter duration during approval, matching the illustrative value already used in
`001-secure-agent-access/spec.md` User Story 2's independent test ("grant a 15-minute scoped session
for a command family"). This is a policy default, not a hard ceiling; it is read from the same
per-resource `Policy` entity already modeled in `001-secure-agent-access/data-model.md`.

**Rationale**: Consistency with the value already used elsewhere in the product's own test language
avoids introducing a second, unexplained number into the codebase and test suite.

**Alternatives considered**:

- **A shorter default (e.g., 5 minutes)**: rejected as the initial default — the existing five-minute
  value in the codebase is reserved for a specifically narrower, lower-risk reuse lease
  (`FR-003ac` in 001, resource add/edit/topology-link only) and is explicitly barred from covering
  execution or sudo; reusing that number for a different purpose risked conflating the two.
- **No default, force explicit duration every time**: rejected — adds friction to the P3 story
  without a security benefit, since the ceiling is still user-chosen and always visible before
  approval.
