# Quickstart Validation: Bounded Sudo Execution

Use synthetic data only. Do not enroll a real sudo password or target a production host while
validating this feature branch. This guide assumes `001-secure-agent-access`'s diagnostic MVP is
already built and its Phase A prerequisites (request/approval/grant services — see `plan.md`) are
in place; sudo-specific steps below cannot pass before that foundation exists.

## 1. Run the automated gates

```bash
xcrun swift-format lint --recursive --strict \
  Sources Tests Apps/SAFA/Targets Package.swift
swift test --filter SudoExecutionTests
swift test --filter SudoEnrollmentFlowTests
swift test --filter SudoCredentialLeakageTests
swift test --filter ArbitraryCommandJourneyTests
swift build -c release
```

All sudo-related tests construct only synthetic hosts and an in-memory fake transport; none opens a
real network connection or reads a real Keychain item.

## 2. Enroll a synthetic host's sudo credential

Prerequisite: a synthetic host already registered and active via the existing SSH flow (see
`specs/001-secure-agent-access/quickstart.md` §4).

```bash
safa resource sudo synth.host
```

Expected: the CLI reports `user_action_required` and directs the user to a trusted local prompt (the
`SAFATrustedSetup` sudo-enrollment mode). In that trusted terminal:

- if the synthetic account has passwordless sudo, enrollment records `mode: passwordless` with no
  password prompt;
- otherwise, the password is collected with echo disabled and never appears in the Agent-facing
  terminal, argv, or logs;
- verification (`sudo -v` against the synthetic fixture) runs before anything is persisted.

Confirm the result contains no protected value:

```bash
safa resource show synth.host --details
```

Expected: `capabilities` includes `sudo`; no password, Keychain locator, or credential value appears
anywhere in the output.

## 3. Run one sudo command with exact approval

```bash
safa exec synth.host --intent "Restart the demo service" \
  --expected-effect "demo restarts" --privilege sudo -- systemctl restart demo
```

Expected: the request returns `approval_required` (never executes automatically) and exactly one
human action, `safa request review <id>`. The trusted flow shows the exact resource, command, intent,
effect, and `privilege: sudo`; after one macOS user-presence check the command runs with the sudo
credential injected only inside the broker boundary. `safa request wait <id>` must return the
terminal state, remote exit code, and bounded output rather than only the request ID.

Repeat after removing the synthetic sudo credential. The same review action must first probe
NOPASSWD, ask for a hidden password only after a positive password-required result, verify/store it,
and execute the already-approved request without a separate Agent resubmission.

## 4. Scoped sudo boundary

Scoped and full-access sudo grants remain a later phase. This checkpoint validates exact one-time
approval only; do not invent `--request-scope`, `--sudo`, or public grant commands to simulate it.

## 5. Validate containment

```bash
swift test --filter DiagnosticPolicyJourneyTests
swift test --filter SudoExecutionTests
```

Confirm, using synthetic fixtures only:

- `sudo` embedded in a pipe, subshell, `eval`, or alias is classified at least high-risk and is not
  satisfiable by a user-level automatic or approval rule;
- an active user-privilege grant does not authorize a `privilege: sudo` request against the same
  resource and command family;
- removing the synthetic host's sudo credential (`safa resource sudo synth.host --remove`) prevents
  stale-credential execution; the next exact request must return to trusted first-use review.

## 6. Audit boundary

Persistent public audit listing remains a later phase. Automated tests must still prove that the
current in-memory audit records for enrollment, approval, and execution contain no protected value.

## Feature boundary

This checkpoint enables per-host sudo credential enrollment (including passwordless detection),
unified first-use setup, exact sudo approval, request inspection/waiting, and sudo-specific
containment coverage. It does not add scoped/full-access sudo grants, public audit listing, sudoers
policy authoring, a Windows privilege-
elevation equivalent, or shared/team sudo credentials — those remain out of scope per `spec.md`
Assumptions. Do not bypass the approval requirement to simulate any of this manually.
