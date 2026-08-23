# Feature Specification: Local-Client Execution for Non-SSH Resources

> Extends `001-secure-agent-access` and `002-sudo-execution`. Those specs model and (partially)
> implement execution against `host.*` resources over `SSHTransport`. Every other registered
> resource template (`mysql`, `postgresql`, `sqlserver`, `s3`, `minio`, `oss`, `kafka`, `rabbitmq`,
> `mongodb`, `redis`, `elasticsearch`, `neo4j`, `http`) already exists in
> `Sources/SAFADomain/ResourceTemplates.swift` with a registered `accessMethod` and connection/
> credential fields. HTTP now has one curl-backed read slice; the other non-SSH templates remain
> capability-inert. This document specifies how that gap gets closed without adding a bespoke
> protocol client per resource kind to the runtime.

**Feature Branch**: `003-local-resource-execution`

**Created**: 2026-08-19

**Status**: Core-MVP direct HTTP GET/HEAD slice implemented and tested. Broker-managed routed
reachability, complex protocols, and additional adapters are post-RC and do not block the product
repository's `specs/006-core-mvp` acceptance.

**Input**: User description: "For non-SSH resources, resolve them through the existing topology/
resource-directory layer and run the operation as a local process on the user's machine using
already-installed client tools (curl, mysql, redis-cli, etc.) instead of building a dedicated
client for each protocol inside the runtime. Do SSH sudo execution (002) first; adapt non-SSH
protocols incrementally afterward."

## Why a typed local-client adapter, not an in-Runtime protocol client

The runtime already solves "reach a resource safely" for SSH: resolve the resource, keep the secret
inside the broker's execution boundary, bound output/time, audit the lifecycle. Re-solving that
per protocol (an HTTP client, MySQL wire-protocol client, Redis client, or MongoDB client) would
duplicate a large, security-sensitive surface and lag behind maintained clients. The macOS Runtime
therefore uses reviewed, source-pinned clients already present on the Runtime machine. A typed
binding still resolves the registered endpoint and credential inside the Broker, applies bounds and
policy, and never forwards Agent argv as client argv. Using Foundation/`URLSession` would avoid a
process dependency but would still make SAFA own HTTP request, redirect, proxy, authentication,
streaming, and error semantics; it is not an escape from client maintenance.

## Client availability and routed reachability decision (2026-08-21)

1. A local-resource adapter runs on the machine hosting the SAFA Runtime. The service machine does
   not need `curl`, `wget`, Python, or another diagnostic client for a direct HTTP operation.
2. The macOS HTTP binding remains the fixed local `/usr/bin/curl`. Before RC, installer/doctor and
   conformance evidence treat its absence, invalid Apple platform signature, or incompatible
   behavior as HTTP-adapter unavailability rather than searching for another client. SSH and other
   independently ready adapters remain usable.
3. A service reachable only from a registered host or private network is a route problem, not a
   client-discovery problem. The Broker must use an explicit verified topology relationship and a
   Broker-managed tunnel/forward, then run the local typed adapter. It must not execute a cascade of
   `curl`, `wget`, Python, shell `/dev/tcp`, or PowerShell commands on the remote host.
4. Complex database/cache/object-store clients remain per-template dependencies. SAFA probes only
   reviewed absolute paths and advertises executable readiness only after a compatible client is
   verified. Missing clients fail closed with safe local remediation; SAFA does not auto-install,
   download, containerize, or substitute a different binary.
5. Supporting multiple client brands requires separate conformance-tested bindings with identical
   semantic operations and secret-injection guarantees. PATH lookup or best-effort fallback is not
   client compatibility.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run One Bounded Local Command Against a Registered Non-SSH Resource (Priority: P1)

A user has registered a resource with a non-SSH template (for example `redis` or `mysql`) that
already has an active credential. An Agent asks to run one read-only diagnostic command (a `redis-cli
PING`, a `mysql`/`SELECT` health check, a `curl` health endpoint) against it.

**Why this priority**: Without one bounded local run working end to end, the template registrations
for these resource kinds are inert data — this is the smallest capability that makes them useful.

**Independent Test**: Register a synthetic non-SSH resource (for example a local Redis or a mock
HTTP server) with a synthetic credential, run one bounded command through the new local-execution
path, and verify it produces bounded output within the timeout while the credential never appears in
Agent-visible argv, environment dump, stdout, stderr, or audit record.

**Acceptance Scenarios**:

1. **Given** a resource registered under a template whose effective capabilities include `exec`,
   **When** the Agent submits a command through that path, **Then** SAFA resolves the resource's
   protected connection fields, runs its exact typed adapter on the Runtime machine (not as a remote
   shell command), and returns bounded output through the existing execution result contract.
2. **Given** the resource has a `secret`-sensitivity credential field, **When** the adapter runs,
   **Then** the credential is delivered only through broker-controlled stdin or a mode-`0600`
   ephemeral file. Secrets and protected endpoints MUST NOT appear in argv or environment, and MUST
   be redacted from Agent-visible output and audit records.
3. **Given** a resource template with `capabilities: []` (no local-exec capability registered),
   **When** the Agent submits a command against it, **Then** SAFA rejects the request with a stable
   `capability_not_supported` reason rather than attempting a best-effort execution.
4. **Given** the same bounded timeout/output-limit controls `exec` already enforces for SSH,
   **When** a local-client command runs, **Then** those same bounds apply (a runaway or oversized
   local process is truncated/killed the same way a runaway remote command is).

---

### User Story 2 - Constrain Local Execution to an Allow-Listed Client Binary Per Template (Priority: P1)

An Agent (or a compromised/careless one) submits a command against a `mysql` resource whose intent
is nominally a database query, but the argument vector names a different local executable.

**Why this priority**: SSH exec's blast radius is bounded by "the remote host"; a local-client
transport runs on the user's own machine, so without a binary allow-list this feature would let any
registered non-SSH resource be used to launch an arbitrary local program under the guise of a
database or cache operation.

**Independent Test**: Attempt to submit a command against a synthetic `mysql` resource whose first
argument is not `mysql` (or `mysqldump`, if that is also allow-listed), and verify SAFA rejects it
before spawning any process.

**Acceptance Scenarios**:

1. **Given** a resource template defines an allow-listed executable and operation set, **When** a
   submitted command is not an exact reviewed operation for that adapter,
   **Then** SAFA rejects it with a stable reason and does not spawn a process.
2. **Given** the allow-listed executable is resolved, **When** SAFA locates it on the local
   filesystem, **Then** it resolves from a fixed, non-Agent-controlled search path (not an
   Agent-supplied absolute path and not the ambient `PATH` of an arbitrary caller) to prevent a
   same-named binary earlier on `PATH` from being substituted.
3. **Given** a command would otherwise name an allow-listed client, **When** it adds a URL, endpoint,
   authentication/config option, shell mode, stdin, working directory, or an unreviewed argument,
   **Then** SAFA rejects it before policy evaluation or process launch. Agent argv never becomes
   local-client argv.

---

### User Story 3 - Gate Write/Admin-Tier Local Operations Behind Trusted Approval (Priority: P2)

A resource has both a lower-privilege credential (read-only query access) and a higher-privilege
credential (write/admin/schema access), mirroring the `-admin` credential-reference tier already used
for SSH-adjacent service access today. An Agent needs to run a write or administrative operation.

**Why this priority**: Reusing one trusted-approval mechanism for every privileged path (sudo, and
now non-SSH admin-tier access) is simpler and more auditable than inventing a second one; this story
has no independent value until the shared approval/grant runtime from `002-sudo-execution` Phase 4
exists, so it is explicitly sequenced after that work.

**Independent Test**: Using a synthetic resource with both a read-only and an admin-tier credential
reference, submit an admin-tier command and verify it requires the same trusted local approval path
sudo commands require, while a read-only command on the same resource does not.

**Acceptance Scenarios**:

1. **Given** a command is classified as requiring the resource's admin-tier credential, **When**
   policy evaluates the request, **Then** it always resolves to a required trusted approval, the same
   way `privilege: sudo` always does — no automatic path exists for admin-tier local execution.
2. **Given** the same command is classified as using only the read-only credential tier, **When**
   policy evaluates it, **Then** it follows the existing bounded, non-approval `exec` path unchanged.
3. **Given** an admin-tier command is approved once, **When** the Agent resubmits a different
   command (even a cosmetically similar one), **Then** a new approval is required, consistent with
   the exact-command consumption rule `002-sudo-execution` already specifies for sudo.

---

### User Story 4 - Confirm Reachability Before Spawning a Local Client (Priority: P3)

A resource's `connection.host`/`connection.port` fields point at an endpoint that is only reachable
through an established route (for example a Core Tunnel forward to `127.0.0.1`). The Agent asks to
run a command against it.

**Why this priority**: Running an adapter against an endpoint that is not actually reachable
produces a confusing connection failure instead of an actionable diagnosis; this story is a
quality-of-diagnosis improvement, not a security boundary, so it is lower priority than Stories 1-3.

**Independent Test**: Submit a command against a synthetic resource whose configured endpoint is not
listening, and verify SAFA reports an actionable pre-flight reachability failure rather than only the
raw client-tool error.

**Acceptance Scenarios**:

1. **Given** the resource's endpoint is a loopback address associated with a `route.*` topology
   context, **When** a command is submitted, **Then** SAFA MAY use the existing `topology`
   read-only query surface to check whether that route has been recently confirmed reachable, and
   include that in the pre-flight result.
2. **Given** the endpoint is not currently reachable, **When** SAFA detects this before executing the
   operation, **Then** it reports a stable `endpoint_unreachable` reason instead of only surfacing a
   route or local-client failure.

### Edge Cases

- What happens when a local-client binding is not installed or fails its conformance probe on the
  Runtime machine? SAFA reports a stable `client_not_installed` reason and does not advertise
  effective execution readiness; it does not fall back to installing, downloading, or substituting
  another binary.
- How does the system handle a template whose credential is optional (for example `redis` and
  `mongodb`, where `credentialRequired: false`) when no credential has been enrolled? The client
  process runs without an injected credential, exactly mirroring the template's existing
  `credentialRequired` semantics used elsewhere.
- What happens if the same resource alias has both an `ssh` reachability path (for tunnel setup) and
  a non-SSH template? Local-client execution and SSH execution are independent capabilities on the
  resource; using one does not require or imply the other is configured.
- How does this interact with `resource show --details`? Unchanged — this feature does not add any
  new way to reveal a raw credential value to the Agent.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST introduce a typed local-resource execution path distinct from remote
  command execution. Each binding uses a reviewed source-pinned client on the Runtime machine; it
  MUST NOT depend on a diagnostic client installed on the service host.
- **FR-002**: System MUST NOT implement an HTTP, database, cache, object-store, messaging, graph, or
  search protocol client merely to avoid a missing external client. A protocol requires a separately
  reviewed local-client binding or remains non-executable.
- **FR-003**: System MUST separate a template's candidate `"exec"` capability from effective Runtime
  readiness. A resource advertises effective `exec` only when its exact adapter and required route
  are currently usable. Local-client versus SSH routing remains Broker-private; templates without a
  candidate capability reject execution, while a missing/raced dependency returns a stable safe
  error rather than attempting best-effort execution.
- **FR-004**: When a binding uses an external executable, the system MUST restrict it to a fixed,
  per-template allow-list resolved from a non-Agent-controlled path, and MUST reject any request
  whose semantic operation or executable binding is not reviewed before spawning a process.
- **FR-005**: System MUST reject shell metacharacters, pipes, redirection, and subshell forms in a
  local-exec command's arguments, matching the existing non-shell constraint on SSH `exec`.
- **FR-006**: System MUST deliver secret and protected connection material to an external client
  only through a per-template broker-controlled stdin convention or mode-`0600` ephemeral file. It
  MUST NOT place either in argv or environment, and MUST redact both from Agent-visible output and
  audit.
- **FR-007**: System MUST apply the same timeout and output-limit bounds to local-exec commands that
  `exec` already applies to SSH commands.
- **FR-008**: System MUST classify any command that uses a resource's admin/write-tier credential as
  requiring trusted approval, using the shared approval/grant runtime `002-sudo-execution` Phase 4
  establishes, with no automatic-approval path for that tier.
- **FR-009**: System MUST audit local-exec requests, decisions, and outcomes with the same
  secret-free guarantee already required of SSH exec and sudo audit records.

### Key Entities

- **LocalClientBinding**: Per-`ResourceTemplateIdentifier` mapping from the template to its
  source-pinned executable, exact reviewed operations, endpoint construction, route requirements,
  and protected-input convention. It is runtime-private and derives eligibility from the public
  template capability plus current adapter readiness.
- **LocalProcessTransport**: The local-client execution counterpart to `SSHTransport` — spawns,
  bounds, and captures output from a local child process instead of a remote SSH command while
  reusing the existing execution result contract.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Each template may advertise `exec` only after its own adapter passes an end-to-end
  bounded read-only test and at least 100 synthetic leakage runs. The first delivery slice covers
  only `http`; `mysql`, `postgresql`, `redis`, and other templates remain capability-inert until
  their independent evidence exists.
- **SC-002**: An unreviewed semantic operation or executable override against any non-SSH resource is
  rejected before process launch, in 100% of adversarial test cases.
- **SC-003**: Admin/write-tier commands against a non-SSH resource require the same trusted-approval
  interaction as a sudo command; zero automatic-approval paths exist for that tier.

## Assumptions

- The supported macOS baseline is expected to provide a compatible fixed `/usr/bin/curl`; the
  Runtime still verifies that dependency instead of assuming it. Other protocols may need reviewed
  clients such as `mysql`, `redis-cli`, `psql`, or `mongosh`. Installing or vendoring them remains
  out of scope.
- Live Core Tunnel port discovery/refresh (reading Core Tunnel's own routing state, as the
  `ssh-hosts` skill's `core_tunnel_inventory.py` does today) is out of scope for v1; a resource's
  `connection.port` is a static field set at registration time.
- This feature is sequenced after `002-sudo-execution` Phase 4 (the shared request/approval/grant
  runtime), which User Story 3 here depends on directly; User Stories 1, 2, and 4 do not require
  Phase 4 and could ship first if resequenced.
- `kafka` and `rabbitmq` are registered templates today but have no obvious single-shot diagnostic
  client analogous to `mysql`/`redis-cli`/`curl`; this spec does not commit to a specific allow-listed
  binary for every template, only to the mechanism. Per-template binary/injection mappings are a
  planning-phase decision, not specified here.

## Current HTTP proof slice

- Public command remains `safa exec ALIAS -- curl` for GET and
  `safa exec ALIAS -- curl --head` for HEAD.
- The runtime executes the source-pinned `/usr/bin/curl`; Agent argv is never forwarded. The only
  child argv is `-q --config -`, the environment is a fixed non-secret locale, and URL/Bearer input
  arrives through broker-controlled stdin.
- `-q` disables ambient `.curlrc`; redirects are not enabled; the registered endpoint cannot be
  overridden by the Agent.
- Only the built-in `http` template advertises `exec` in this slice. All other non-SSH templates
  continue returning `capability_not_supported` until separately implemented and tested.
- Generic non-SSH trusted setup/onboarding is a follow-on dependency for product-wide usability;
  this slice proves execution against an already registered HTTP resource without claiming that
  every template has an Agent-facing enrollment flow.
- Installer/doctor and packaged conformance must verify the fixed curl dependency before RC. The
  checked-in Skill remains truthful about the exact local curl binding; no remote curl/wget fallback
  is implied.
- Curl conformance requires an executable at the exact path, an Apple platform signature for
  `com.apple.curl`, HTTP and HTTPS protocol support, and the reviewed config/timeout/failure options.
  A failed probe removes effective HTTP `exec` readiness and returns a stable remediation; it does
  not disable independently healthy SSH execution.
