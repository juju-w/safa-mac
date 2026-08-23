# Sudo Credential Contract v1

Extends `specs/001-secure-agent-access/contracts/broker-ipc-v1.md`. Read that document first; this
file only adds the sudo-specific interface and states explicitly where nothing changes.

## Agent client interface — unchanged

Sudo execution requires **no new Agent-facing method**. It reuses the existing agent client
interface exactly as already contracted:

```text
submitExecution(ExecutionSubmission) -> RequestSnapshot   # ExecutionSubmission.privilege may be `sudo`
getRequest(RequestID) -> RequestSnapshot
waitRequest(RequestID, deadline) -> RequestSnapshot
cancelRequest(RequestID) -> RequestSnapshot
listGrants(GrantQuery) -> GrantPage                        # sudo-ceiling grants appear alongside others
revokeGrant(GrantID) -> GrantSnapshot
listAudit(AuditQuery) -> AuditPage
```

An `ExecutionSubmission` with `privilege: sudo` against a resource with no verified
`SudoCredential` MUST still create an immutable approval request. It makes no remote connection
until the trusted-local role authenticates the user for that exact request. The resulting
short-lived exact continuation permits credential verification and execution only for that request.

## Reserved trusted local interface — new methods

Extends the trusted-local-only interface already defined in `broker-ipc-v1.md` (same `dev.safa.trusted-local`
peer, same code-signing/user/audit-session requirements, same session binding and expiry rules):

```text
attachSudoCredential(ResourceAlias, ProtectedSudoCredentialPayload) -> ResourceSnapshot
removeSudoCredential(ResourceAlias) -> ResourceSnapshot
getApprovalPresentation(RequestID) -> ApprovalPresentation
decideApproval(RequestID, Decision, Scope?) -> ApprovalDecision
completeSudoApproval(RequestID, ProtectedSudoCredentialPayload) -> ExecutionResult
```

- `attachSudoCredential` requires the target resource to already have a healthy SSH login
  credential (`Resource.authRef`). A passwordless payload runs the fixed non-interactive probe; a
  password payload is accepted only through this typed trusted-local operation. Both verify before
  persistence, and a failure leaves any prior sudo credential unchanged.
- `getApprovalPresentation` renders only immutable Broker-held request and risk data.
- `decideApproval` performs Broker-owned LocalAuthentication. For first-use sudo it returns a
  credential-required continuation instead of executing with missing authority.
- `completeSudoApproval` verifies/persists the payload and immediately runs the exact pending
  request. NOPASSWD rejection is the only response that permits the helper to read a password.
- `removeSudoCredential` deletes the resource's `SudoCredential` and, in the same broker transaction,
  invalidates every `ApprovalGrant` with `privilegeCeiling: sudo` bound to that resource (FR-016).

`completeSudoApproval` succeeds only while the Broker holds the unexpired exact grant created by a
successful macOS user-presence decision for the same immutable request. A request ID or protected
payload alone has no authority. This interface accepts no endpoint, SSH password, private key, or
host key; protected sudo values remain typed and secret-free in every reply.

## Approval binding — no change

The approval-binding envelope defined in `broker-ipc-v1.md` ("Approval binding") already carries
`privilege` as one of its bound fields. A sudo approval decision binds to that envelope exactly as a
user-privilege one does; no new field is added for sudo. The presentation shown to the user
(`getApprovalPresentation`) MUST render `privilege: sudo` distinctly (per FR-010 in `spec.md`,
"display the exact target resource, exact command, stated intent, and expected effect") but this is
a presentation-layer requirement, not a new wire field.

## Failure behavior — no change

Sudo enrollment and execution failures use the same stable-error, fail-closed, no-fallback behavior
already specified in `broker-ipc-v1.md` ("Failure behavior"). A sudo verification failure, a
credential-locator mismatch, or an approval-fingerprint mismatch on a sudo request records a
sanitized security audit event exactly as any other peer-validation or vault-integrity failure does.
