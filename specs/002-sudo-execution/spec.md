# Feature Specification: Bounded Sudo Execution

> Extends `001-secure-agent-access`. That spec models sudo at the data/policy layer (`privilege`,
> `sudoRef`, `privilegeCeiling`, the `command.sudo_requested` / `command.embedded_sudo` policy
> findings) and reserves the executor (`Sources/SAFASSH/SudoExecutor.swift`, tasks T057–T063) as
> unimplemented. This document is the feature-level specification for actually shipping that
> capability: enrolling a sudo credential and running an approved sudo command end to end.

**Feature Branch**: `002-sudo-execution`

**Created**: 2026-08-18

**Status**: Core-MVP exact-command slice implemented and covered by automated tests. Scoped command
family grants and persistent audit review require post-RC rebaseline under the product repository's
`PRODUCT.md`; they are not Core MVP release blockers.

**Input**: User description: "Design bounded sudo execution for SAFA: let an Agent request a sudo
command against a registered SSH host without ever seeing or supplying the sudo password, require
trusted local user approval scoped to the exact command or a short-lived command family, and follow
the same security posture already specified for SSH host access."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Enroll a Host's Sudo Credential Without Exposing It to the Agent (Priority: P1)

A user has already registered an SSH host (`app.prod`) using the existing `ssh` template. They now
want SAFA to be able to run sudo commands on it. They start a distinct, trusted local flow to enroll
that host's sudo credential (or confirm it uses passwordless sudo). The Agent never sees, requests,
or transmits the sudo password.

**Why this priority**: Without a safely enrolled credential there is nothing to authorize execution
against; this is the prerequisite for every other sudo scenario, and it is the step most likely to
leak a highly privileged secret if built carelessly.

**Independent Test**: Register a synthetic SSH host, enroll a synthetic sudo credential for it
through the trusted flow, and verify the transcript, process arguments, environment, CLI output, and
audit record contain no sudo password while the credential is verified as usable before it is
stored.

**Acceptance Scenarios**:

1. **Given** `app.prod` is an active SSH resource with no sudo credential, **When** the user starts
   sudo enrollment through the trusted local flow, **Then** the password field is collected with
   terminal echo disabled by the trusted flow, never by the Agent-facing CLI, and is not visible in
   Agent argv, environment, stdin, stdout, or stderr.
2. **Given** a candidate sudo credential has been entered, **When** enrollment runs its verification
   step, **Then** SAFA performs a read-only, non-mutating check (equivalent to `sudo -v`) against the
   real remote account before persisting anything, and a failed check leaves the resource exactly as
   it was.
3. **Given** verification succeeds, **When** the credential is persisted, **Then** it is stored as a
   separate device-protected credential record distinct from the resource's login/SSH credential,
   bound to that exact resource and remote account.
4. **Given** a host's remote account already has passwordless sudo, **When** enrollment detects this
   non-interactively, **Then** SAFA records a passwordless sudo capability without prompting for or
   storing a password.
5. **Given** a resource has no SSH login credential yet, **When** sudo enrollment is attempted,
   **Then** SAFA rejects it and directs the user to complete SSH setup first; sudo enrollment never
   creates or edits the login credential or a remote account.
6. **Given** an Agent asks SAFA (on the user's behalf) to add sudo access for a host, **When** the
   Agent expresses that request in conversation, **Then** the Skill directs the user to the trusted
   local enrollment flow and does not collect, relay, or infer any part of the sudo password.

---

### User Story 2 - Run One Sudo Command With Exact Approval (Priority: P2)

An Agent has diagnosed that a service needs a privileged restart. It proposes the exact sudo command
to the user, who reviews the target, command, and effect, and approves it once. SAFA runs that exact
command and only that command.

**Why this priority**: This is the smallest complete expression of useful sudo capability: it proves
the approval-then-execute path without which sudo is either unusable or unsafely automatic.

**Independent Test**: Using synthetic hosts with both an enrolled and a missing sudo credential,
submit one sudo command, approve it exactly once through the trusted local prompt, verify first-use
credential setup continues in that same flow when needed, verify execution has the correct privilege
and bounded output, and verify a second, different sudo command is not covered by that approval.

**Acceptance Scenarios**:

1. **Given** a resource has an enrolled sudo credential, **When** the Agent submits a sudo command
   with its intent and expected effect, **Then** SAFA classifies it as `privilege: sudo`, and policy
   evaluation for that privilege level always resolves to a required trusted approval — no automatic
   or policy-only path exists for sudo.
2. **Given** SAFA requests approval, **When** the trusted local prompt is shown, **Then** it displays
   the exact target resource, exact command, stated intent, expected effect, and risk, and the
   decision is made through a macOS user-presence mechanism the Agent cannot script, repeat-spam, or
   satisfy from chat.
3. **Given** the user approves the exact command once, **When** execution proceeds, **Then** the
   sudo credential is delivered only inside the broker's execution boundary directly to the remote
   privileged prompt, is immediately followed by isolating the privileged child's own stdin, and
   never appears in the command string, CLI output, or audit record.
4. **Given** that same one-time approval has been consumed, **When** the Agent submits a different
   sudo command (even a trivially reworded or re-quoted one) or resubmits against a different
   resource, **Then** SAFA requires a new approval; the earlier grant does not extend to it.
5. **Given** the sudo command is denied, cancelled, or the approval prompt times out, **Then** SAFA
   does not execute the command, reports a stable denial reason, and does not fall back to running it
   without privilege or bypassing SAFA.
6. **Given** an Agent's own self-review labels a sudo command as safe or low-risk, **When** SAFA
   evaluates the request, **Then** that review is advisory only and cannot substitute for or skip the
   trusted approval.
7. **Given** the exact request targets a resource without a sudo credential, **When** the user opens
   its trusted review, **Then** one macOS user-presence check authorizes the immutable request and the
   same helper session probes NOPASSWD or reads a required hidden password, verifies and stores it,
   and immediately executes that request without a separate Agent-managed enrollment/retry loop.

---

### User Story 3 - Grant a Short-Lived Sudo Command Family, Then Revoke It (Priority: P3)

A user expects to need several related sudo commands over the next few minutes (for example,
restarting and then checking a service). Instead of approving each command individually, they grant
a bounded, time-limited scope for that command family on that one resource, and can revoke it early.

**Why this priority**: Real remediation is rarely a single exact command; without a scoped grant,
useful sudo work forces either constant re-approval or an unsafe standing allowance.

**Independent Test**: Grant a 15-minute scoped sudo session for one command family on a synthetic
host, run two matching commands inside the window without re-approval, verify a command outside the
granted scope is still denied, let the grant expire (or revoke it), and verify subsequent matching
commands require a new approval.

**Acceptance Scenarios**:

1. **Given** the user grants a bounded prefix/command-family scope with an explicit expiry, **When**
   the Agent submits a matching sudo command on the exact granted resource and revision before
   expiry, **Then** SAFA executes it without a new approval prompt and records that the grant, not a
   fresh decision, authorized it.
2. **Given** the same grant, **When** the Agent submits a sudo command outside the granted family, a
   different resource, or a full-shell/unrestricted form, **Then** SAFA denies it and requires
   separate approval or an explicit full-access grant.
3. **Given** the grant's expiry passes, **When** the Agent retries a previously matching command,
   **Then** SAFA denies it and requires a new approval; expiry is enforced against a monotonic clock
   and is not defeated by changing the system time.
4. **Given** an active sudo grant, **When** the user revokes it, **Then** subsequent matching
   requests stop using it immediately, and any request already denied by that revocation is recorded
   as denied, not as a race won by the Agent.
5. **Given** a full-access sudo grant is explicitly requested and approved, **When** it is issued,
   **Then** it is visibly distinguished from a scoped grant, still resource-bound and time-limited,
   and equally revocable.
6. **Given** the resource's sudo credential is rotated or removed while a grant referencing it is
   active, **When** the next matching request arrives, **Then** SAFA invalidates the grant and
   requires new enrollment or approval rather than executing with a stale credential reference.

---

### User Story 4 - Contain Attempts to Disguise or Escalate Sudo (Priority: P4)

An Agent (or a compromised/careless one) tries to reach privileged execution through an indirect
path: hiding `sudo` inside a shell pipeline, using an approved user-level grant to imply sudo, or
retrying a denied request with cosmetic changes. SAFA blocks every path that does not go through
explicit sudo classification and approval.

**Why this priority**: A sudo capability is only as safe as its hardest-to-see bypass; this story
protects the guarantee the first three stories establish.

**Independent Test**: Submit direct sudo commands, sudo hidden inside shell syntax (subshell, `eval`,
pipe, alias, environment override), and privilege-escalation attempts riding on an existing
user-level grant, and verify every path is either hard-blocked by policy or correctly routed through
sudo approval — never silently executed as a low-risk user command.

**Acceptance Scenarios**:

1. **Given** a shell-mode command embeds `sudo` anywhere in its text (directly, through a pipe, a
   subshell, `eval`, or an alias/function), **When** policy evaluates it, **Then** it is classified
   at least as high-risk with a stable "embedded sudo" finding and cannot be satisfied by a
   user-level automatic or approval rule.
2. **Given** a user-level (non-sudo) approval grant is active, **When** the Agent submits a sudo
   request against the same resource and command family, **Then** the user-level grant does not
   authorize it; sudo authorization always requires its own `privilegeCeiling: sudo` grant.
3. **Given** a sudo request is denied, **When** the Agent resubmits it with different quoting,
   whitespace, argument order, or a functionally equivalent rewrite, **Then** the new submission is
   evaluated independently and is not authorized by the prior denial's absence of a grant, nor does
   repeated resubmission itself pressure approval.
4. **Given** a resource has no enrolled sudo credential, **When** a sudo-classified command is
   submitted against it, **Then** SAFA freezes the exact request and requires trusted local review;
   no remote connection or secret input occurs until macOS authenticates the user for that request.
5. **Given** a request is a genuine ambiguous case (for example, a command whose privilege intent
   cannot be determined from the argument vector), **When** policy evaluates it, **Then** it
   escalates to the sudo/high-risk approval path rather than defaulting to automatic execution.

---

### User Story 5 - Review Sudo Activity (Priority: P5)

The user wants to see what sudo access has been requested, approved, executed, or denied on their
machine, and reconstruct that history without finding a credential in it.

**Why this priority**: Sudo is the highest-privilege capability SAFA grants; visibility into its use
is what makes ongoing trust in the feature possible, but it is not required for the capability to
function correctly, so it is lower priority than the execution and containment stories.

**Independent Test**: Run a mixture of approved, denied, expired, and revoked sudo requests against
synthetic hosts, then confirm the user can reconstruct the full sequence — including which grant (if
any) authorized each execution — from the audit trail alone, with zero recoverable secrets.

**Acceptance Scenarios**:

1. **Given** several sudo requests have occurred, **When** the user reviews activity, **Then** each
   record identifies the caller, resource alias, sanitized command or fingerprint, privilege level,
   policy decision, approval or grant reference, timing, and outcome.
2. **Given** a sudo command's output or error text contains a value matching the credential redaction
   rules, **When** the record is displayed or exported, **Then** that value is redacted in the audit
   record exactly as it is in Agent-facing output.
3. **Given** a grant authorized several executions before expiring or being revoked, **When** the
   user inspects that grant, **Then** every execution it authorized is traceable back to it.

### Edge Cases

- The remote host's sudo configuration changes after enrollment (password requirement removed or
  added, account removed from the sudoers group, `NOPASSWD` toggled).
- The remote sudo prompt behaves non-standardly: no TTY available, a custom prompt string, or a
  sudo implementation that does not support `-S`.
- The sudo credential is correct but the account's sudo grant has been revoked entirely on the
  remote system (authenticates, but authorization fails remotely).
- Two Agents or processes concurrently request sudo execution against the same resource, or one
  submits while a grant covering the same scope is mid-revocation.
- The user cancels or fails Touch ID during a sudo approval prompt, or approval is requested while
  the Mac is locked.
- A previously enrolled sudo credential is rotated while an in-flight (already-approved, currently
  running) execution is using the old value.
- The sudo command times out mid-execution on the remote host after privilege has already been
  invoked.
- A sudo command produces unbounded, binary, or credential-shaped output.
- System clock changes while a time-limited sudo grant is active.
- The resource itself is disabled or removed while a sudo grant or in-flight request references it.
- A host is registered under multiple aliases; a grant issued through one alias is submitted against
  the same resource through a different alias.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Sudo credential enrollment MUST be a distinct trusted local flow, separate from SSH
  host setup/edit, and MUST require an existing active SSH login credential on the target resource
  before it can run.
- **FR-002**: The Agent-facing CLI MUST NOT accept, request, echo, or return a sudo password at any
  point, in any command, argument, environment variable, stdin, stdout, stderr, log, or audit field.
- **FR-003**: Enrollment MUST verify a candidate sudo credential with a non-mutating remote check
  before persisting it, and MUST leave the resource unchanged if that check fails.
- **FR-004**: A verified sudo credential MUST be persisted as a separate device-protected credential
  record bound to the exact resource and remote account, distinct from that resource's login
  credential, and independently rotatable and removable without affecting SSH login.
- **FR-005**: Enrollment MUST support non-interactive detection and recording of passwordless sudo
  without prompting for or storing a password in that case.
- **FR-006**: Every execution request whose target command requires elevated privilege MUST be
  classified with `privilege: sudo` before policy evaluation, independent of whether the Agent
  labeled it that way.
- **FR-007**: Policy evaluation MUST NOT provide an automatic (no-approval) path for any request
  classified `privilege: sudo`; a trusted local user-presence approval is always required.
- **FR-008**: A command whose shell text embeds `sudo` through any indirection (pipe, subshell,
  `eval`, alias, function, encoded form, or environment override intended to invoke it) MUST be
  classified at least high-risk with a stable finding and MUST NOT be satisfiable by a user-level
  automatic or approval rule.
- **FR-009**: A sudo-classified request against a resource with no enrolled sudo credential MUST be
  retained as an immutable approval request. After one macOS user-presence check, its trusted-local
  continuation MAY probe and enroll the credential and MUST execute only that exact request; the
  Agent MUST NOT orchestrate a separate credential enrollment and resubmission loop.
- **FR-010**: The trusted local approval prompt for a sudo request MUST display the exact target
  resource, exact command, stated intent, and expected effect, and MUST be satisfied only through a
  macOS user-presence mechanism the Agent cannot invoke, script, or repeat-spam into approval.
- **FR-010a**: First-use sudo MUST combine approval and credential establishment into one continuous
  trusted-local workflow. NOPASSWD MUST be probed first; only a positive password-required result
  may open hidden password input. A protected credential payload without the Broker's short-lived
  authenticated exact grant MUST have no execution authority.
- **FR-011**: Approval MUST support an exact one-time sudo grant, a bounded prefix/command-family
  sudo grant with explicit expiry, and an explicit full-access sudo grant that is visibly
  distinguished from a scoped grant; every grant type MUST bind to a caller, exact resource and
  revision, and a `sudo` privilege ceiling.
- **FR-012**: A grant issued for `privilege: user` MUST NOT authorize any request classified
  `privilege: sudo`; sudo authorization always requires its own sudo-ceiling grant.
- **FR-013**: An exact one-time sudo grant MUST be consumed after one matching execution and MUST NOT
  authorize a different command, a re-quoted or reordered rewrite of the same command, or the same
  command against a different resource.
- **FR-014**: A scoped (prefix/command-family) sudo grant MUST enforce its expiry against a monotonic
  clock in addition to wall-clock time, so that changing the system clock cannot extend it.
- **FR-015**: The user MUST be able to list active or pending sudo grants and revoke any of them
  immediately; a revoked grant MUST NOT authorize any request submitted after revocation, including
  one already in flight when revocation is confirmed.
- **FR-016**: Rotating or removing a resource's sudo credential MUST immediately invalidate every
  grant that was bound to it; the next matching request MUST be denied pending re-enrollment or a
  fresh approval, never executed with a stale credential reference.
- **FR-017**: The sudo credential MUST be injected only inside the broker's execution boundary,
  delivered directly to the remote privileged prompt, and MUST NOT appear in the composed command
  string, process arguments, CLI output, logs, or audit records; the privileged child's own stdin
  MUST be isolated immediately after credential delivery.
- **FR-018**: An Agent-provided self-review or risk assessment MUST be advisory only for a sudo
  request and MUST NOT be capable of skipping, downgrading, or substituting for the trusted approval
  requirement.
- **FR-019**: Denial, cancellation, timeout, or resubmission with cosmetic changes MUST each be
  evaluated on their own terms; none may be combined or repeated to obtain authorization that a
  single clean request would not receive, and SAFA MUST NOT fall back to running a denied sudo
  command without privilege or by any path that bypasses SAFA.
- **FR-020**: Every sudo enrollment, request, policy decision, approval, denial, grant issuance,
  grant consumption, revocation, and execution outcome MUST be captured in the same secret-free audit
  trail used for other executions, with output and errors redacted using the same rules as
  Agent-facing responses.
- **FR-021**: When a Skill-driven Agent conversation requests sudo enrollment or a sudo capability
  that does not yet exist for a resource, the Skill MUST direct the user to the trusted local
  enrollment flow and MUST NOT collect, relay, infer, or repeat any part of a sudo password on the
  user's behalf.

### Key Entities

- **Sudo Credential**: A device-protected credential record bound to one resource and remote
  account, distinct from that resource's login credential, with a health/verification state and an
  optional "passwordless" marker in place of a stored secret. This refines the `sudoRef` reference
  already modeled on `Resource` in `001-secure-agent-access`.
- **Sudo Execution Request**: An `Execution Request` (as defined in `001-secure-agent-access`) whose
  `privilege` is `sudo`; it always carries a required risk assessment and always requires an
  approval decision before it may run.
- **Sudo Approval Grant**: An `Approval Grant` (as defined in `001-secure-agent-access`) whose
  `privilegeCeiling` is `sudo`; scoped as exact, bounded prefix/command-family, or explicit full
  access, always resource- and revision-bound, always expiring, and independently listable and
  revocable from user-level grants.
- **Sudo Audit Event**: An `Audit Event` covering sudo enrollment, request, decision, grant
  lifecycle, and execution outcome, secret-free by the same redaction rules as other audit events.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Across end-to-end tests, 100% of sudo execution attempts that lack a currently valid
  approval or grant are denied, with zero exceptions from any automatic or policy-only path.
- **SC-002**: Automated leakage tests find zero occurrences of a sudo password in process arguments,
  environment snapshots, Agent-visible output, logs, or audit records across at least 100 synthetic
  sudo enrollment and execution runs.
- **SC-003**: A user can enroll a synthetic host's sudo credential and get one approved sudo command
  running in under two minutes, with zero protected values appearing in Agent-visible input or
  output during that flow.
- **SC-004**: In a security test suite of at least 50 request variations (mutated command, replayed
  request, expired/revoked grant, wrong resource, wrong caller, cosmetic rewrite), zero variations
  are authorized by a grant that does not exactly match them.
- **SC-005**: Across at least 30 disguised-privilege-escalation test cases (embedded sudo via pipe,
  subshell, `eval`, alias, environment override, and reuse of a user-level grant), 100% are blocked
  or correctly routed to sudo approval rather than executed as a low-risk user command.
- **SC-006**: Rotating or removing a synthetic host's sudo credential invalidates 100% of grants
  bound to it before the next request is evaluated, with no window in which a stale credential
  reference can still authorize execution.
- **SC-007**: Every sudo request outcome in the test suite (approved, denied, expired, revoked,
  failed) can be reconstructed from the audit trail alone, including which grant or decision
  authorized or blocked it, with zero recoverable secrets in the record.
- **SC-008**: Passwordless-sudo synthetic hosts still require an explicit approval decision for
  100% of tested sudo requests; passwordless status removes only the stored-secret step, never the
  approval requirement.

## Assumptions

- This feature extends the resource, execution-request, policy, grant, and audit model already
  specified in `001-secure-agent-access` rather than introducing a new resource kind or a parallel
  authorization system.
- Initial scope is sudo on already-registered `ssh` template hosts running Linux or macOS; a
  Windows privilege-elevation equivalent (for example `runas`) is out of scope for this feature.
- The sudo credential is scoped per resource (per remote host and account), consistent with the
  existing one-credential-per-security-domain default; shared or team sudo accounts are out of
  scope.
- Approval continues to use the same macOS user-presence mechanism (Touch ID / LocalAuthentication)
  already specified for other high-risk operations; this feature does not introduce a new approval
  UI paradigm.
- This feature does not add sudoers policy authoring (editing `/etc/sudoers` or equivalent) as an
  Agent or SAFA capability; SAFA operates within whatever sudo configuration already exists on the
  remote host.
- A default scoped-grant duration on the order of minutes (illustrated as 15 minutes in the user
  stories) is a reasonable default subject to policy configuration, not a hard-coded ceiling this
  spec mandates.
