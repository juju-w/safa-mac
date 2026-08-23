# SAFA Runtime Architecture

Status: **Accepted for pre-release development**  
Last reviewed: **2026-08-18**

This document is the implementation guide for SAFA's native runtimes. It defines the trust
boundaries, module responsibilities, source organization, CLI conventions, and delivery order.
Feature specifications describe behavior; this document decides where runtime behavior belongs and
which component is trusted to perform it.

## 0. Product/runtime boundary

The canonical Agent Skill, public Agent-CLI/TOON/resource contracts, release manifests, and product-level
architecture live in [`juju-w/safa`](https://github.com/juju-w/safa). This repository owns native
runtime implementations and their platform-specific security adapters.

```mermaid
flowchart TB
    Product["safa product repository\nSkill · contracts · manifests"]
    Product --> Mac["Swift macOS runtime\ncurrent implementation"]
    Mac --> Contract["Shared conformance fixtures"]
    Product -. future .-> Other["Additional native runtimes\nimplemented only when needed"]
    Other -.-> Contract
```

All runtimes must implement the same external contract. Their private implementation is expected to
differ: XPC/Keychain/SMAppService on macOS, Unix sockets with peer credentials and an OS keyring on
Linux, and Named Pipes with DPAPI/Credential Manager on Windows. Internal IPC is never exposed as an
Agent-facing compatibility surface.

Each platform produces one installable Runtime package. The package keeps multiple trust roles:
the Agent-facing CLI parses and presents but has no vault authority; the Broker/daemon owns policy,
credentials, and transport; a narrowly scoped helper may deliver a child-bound credential. Package
unity simplifies installation, while process separation prevents a modified frontend from inheriting
Broker authority.

Source availability is part of the threat model. Security depends on native publisher identity,
Broker-side policy, OS-protected keys, user authorization, and least-privilege resource accounts—not
on implementation secrecy or binary obfuscation.

The Swift package remains at the repository root while the macOS implementation is stabilizing.
Moving it into a deeper directory would be a large mechanical change with no security benefit.
Another platform directory is introduced only when its Runtime implementation starts; an empty
cross-platform scaffold is not an architecture boundary.

Cross-platform Runtime selection belongs to the product repository's script resolver. This
repository does not provide another universal launcher binary. Swift remains the macOS Runtime.

## 1. macOS runtime goal and current priority

The current SAFA macOS runtime is a native security boundary that lets an Agent discover and operate
registered resources without receiving reusable credentials. Its core is a generic encrypted resource
directory; SSH hosts are the first executable profile, not the limit of the model. Database,
object-storage, cache, and service adapters can reuse the same alias, metadata, relationship,
credential-reference, authorization, and policy boundaries.

The immediate goal is functional parity with the existing local `ssh-hosts` workflow while moving
its sensitive operations behind native macOS controls. Persistent tamper-evident audit history is
useful, but it is deliberately later than:

1. importing and resolving existing SSH hosts and jump routes;
2. reliable public-key SSH and Core Tunnel preflight;
3. Keychain-backed sudo and service credentials;
4. broker-owned execution with human-friendly system approval;
5. safe operational workflows such as scoped sudo and atomic user creation.

Delivery is CLI-first and the current product has no custom GUI target. System-provided Touch ID,
Keychain, LocalAuthentication, and Authorization Services prompts are security controls rather than
product UI. If a safe operation cannot yet be completed through those controls, SAFA returns
`user_action_required` instead of accepting a secret or approval through the Agent-facing CLI.

Release and Skill-package publication remain frozen until the repository owner explicitly enables
them.

## 2. macOS architecture principles

1. **The CLI is a parser and presenter, not a security boundary.** It has no Keychain entitlement,
   cannot approve requests, and never receives a credential-bearing pipe. It may launch the
   separately signed trusted-setup executable only by safe alias/type; that helper opens its own
   controlling terminal, suppresses echo for every protected field, and communicates directly with
   the Broker.
2. **The broker owns authority.** It resolves encrypted resource metadata, enforces policy, obtains
   credentials, launches transports, and returns bounded results.
3. **macOS owns human presence.** During the CLI-first phase, privileged credential use and human
   confirmation rely on system-provided Keychain and LocalAuthentication interaction. That
   authority never moves into the Agent-facing CLI.
4. **Use macOS primitives directly.** Prefer Data Protection Keychain, Secure Enclave,
   LocalAuthentication, signed XPC peers, and `SMAppService` over a custom password store or daemon
   installer.
5. **Use a functional core and imperative shell.** Domain validation, canonicalization, scope
   matching, and policy are deterministic. Keychain, XPC, files, clocks, processes, and UI are
   adapters behind narrow protocols.
6. **Typed boundaries over dictionaries.** Public TOON is encoded from explicit versioned DTOs at
   the CLI boundary; XPC payloads use separate typed DTOs with explicit coding keys. Domain
   persistence models are not wire contracts.
7. **Fail closed without becoming hostile.** A rejection must contain a stable code and a safe next
   action; it must not silently fall back to raw SSH, password prompts, mutable SSH config, or weaker
   host verification.
8. **Claims follow evidence.** README capability claims require an executable contract or
   integration test.
9. **Profiles extend the directory; they do not fork it.** Resource kinds, access methods,
   credential roles, and metadata keys are validated namespaced identifiers. New adapters do not
   add arbitrary JSON to the vault or put credentials in metadata.

## 3. System context and trust boundaries

```mermaid
flowchart LR
    Agent["Agent"] -->|validated argv| CLI["Signed safa CLI\nno secret entitlement"]
    CLI -->|canonical TOON| Agent
    CLI -->|Agent XPC\nsigned peer check| Broker["Per-user SAFA broker\nauthority boundary"]
    CLI -->|safe alias + type only| Setup["Signed trusted setup helper\nno custom GUI"]
    Human["Local human"] -->|Touch ID / system prompt| Native["macOS Security UI\nno custom product GUI"]
    Human -->|hidden protected input| Setup
    Setup -->|trusted-local XPC\nsigned peer check| Broker
    Native -->|user presence result| Broker
    Broker --> Policy["Deterministic policy\nand use cases"]
    Broker --> Vault["Encrypted resource vault"]
    Broker --> Keychain["Data Protection Keychain"]
    Broker --> Enclave["Secure Enclave keys"]
    Broker --> Adapters["Typed resource adapters\nSSH first; DB/S3/cache/service later"]
    Adapters --> SSH["Isolated OpenSSH adapter"]
    Adapters --> Local["Typed local-client bindings\nsource-pinned · no shell"]
    SSH --> Remote["Untrusted SSH host"]
    Local --> Service["Registered non-SSH service"]
    SSH --> AskPass["One-shot signed AskPass helper"]
    AskPass -->|child-bound XPC| Broker
```

### Boundary rules

- Agent/CLI data may choose a resource alias and command, but cannot provide an endpoint,
  credential reference, approval decision, or trusted identity. `resource show --details` is the one
  read-only disclosure path: after a macOS-owned user-presence prompt, it may return non-secret
  connection and inventory metadata. It never returns a credential reference, Keychain locator,
  private/public key material, host fingerprint, password, or token.
- XPC listeners require the expected signing identifier, Developer Team, effective user, and audit
  session. The broker derives peer identity from the connection, not message fields.
- The Agent-facing CLI cannot submit a secret or approval. A system-authenticated local workflow may
  confirm a broker-computed request but cannot rewrite its target, command, or policy result.
- The shipped trusted resource-setup helper has the distinct `dev.safa.trusted-local` signing
  identity and a typed XPC contract. It has no custom product UI, accepts no protected CLI flags,
  accepts no protected value from Agent stdin or environment, and emits no protected field.
  Execution approval presentation carries only an opaque request ID from the CLI, renders immutable
  Broker-held command/risk data, and returns its decision through the trusted-local XPC role. For
  first-use sudo, the same helper session may continue into hidden credential enrollment only after
  Broker-owned LocalAuthentication succeeds for that exact request.
- The broker writes a per-request SSH config and pinned `known_hosts`, disables ambient forwarding,
  and does not inherit the user's mutable SSH configuration during execution.
- Remote output is untrusted data. It is bounded before returning to the Agent and must never be
  interpreted as new instructions by the Skill.
- Non-SSH execution retains the same public `exec` capability. The Broker selects a typed adapter
  and replaces the reviewed semantic command with source-pinned local-client argv. Protected
  endpoint/credential material reaches the client only through broker-controlled stdin or a
  mode-`0600` ephemeral file. Agent input never selects a local path, URL, auth/config option,
  environment, or working directory. Future private-service reachability must resolve from verified
  topology through a Broker-owned tunnel; the current direct adapter does not claim routed support
  and never falls back to whatever diagnostic command happens to exist on a remote host.

## 4. Module map and dependency direction

The current SwiftPM target split is appropriate because several modules coincide with real trust or
test seams. The targets must remain one-way dependencies; not every target needs to be an externally
vended library product.

| Module | Owns | Must not own |
|---|---|---|
| `SAFADomain` | Generic resource directory, typed metadata, value types, invariants, state transitions | Keychain, XPC, files, process launch, CLI formatting |
| `SAFAProtocol` | Explicit versioned CLI/XPC DTOs and stable error codes | Vault models, policy logic, Security-framework helpers |
| `SAFACrypto` | Keychain, encrypted vault, Secure Enclave adapters | Resource workflows, SSH command construction |
| `SAFAPolicy` | Pure command classification and grant matching | UI, clocks without injection, credential access |
| `SAFATransport` | Bounded subprocess lifecycle and cancellation | SSH policy or credentials |
| `SAFASSH` | OpenSSH config, host identity, SSH-agent/AskPass and sudo transport adapters | Keychain lookup, approvals, resource persistence |
| `SAFABroker` | Application use cases, XPC adapters, orchestration/composition root | CLI parsing, product presentation |
| `SAFACLI` | ArgumentParser commands, typed request mapping, canonical TOON presentation | Secrets, policy, direct SSH, approval, human rendering |
| `SAFAAskPass` | One-shot child-bound credential response | Resource lookup or general Keychain queries |
| `SAFATrustedSetup` | LocalAuthentication, hidden `/dev/tty` enrollment, host-key scan/confirmation, typed trusted XPC client | Keychain persistence, direct SSH login, Agent output |

The intended dependency shape is:

```text
SAFACLI ───────────────► SAFAProtocol
SAFABroker ────────────► SAFAProtocol + SAFADomain + SAFAPolicy + SAFACrypto + SAFASSH
SAFASSH ───────────────► SAFADomain + SAFATransport
SAFACrypto ────────────► SAFADomain
SAFAPolicy ────────────► SAFADomain
SAFATransport ─────────► SAFADomain
SAFATrustedSetup ──────► SAFAProtocol + SAFADomain + SAFACrypto + SAFATransport
```

`SAFAProtocol` must gradually stop importing persistence-oriented domain aggregates. Map explicit
wire DTOs to domain types at the broker edge. This prevents a domain refactor from silently changing
the XPC or CLI schema.

## 5. Source organization

Organize files by responsibility inside each target. Do not return to target-wide `Models.swift`,
`SAFACommand.swift`, or `BrokerService.swift` monoliths.

```text
Sources/
├── SAFADomain/
│   ├── Resources/
│   ├── Execution/
│   ├── Credentials/
│   └── Authorization/
├── SAFAProtocol/
│   ├── Agent/
│   ├── TrustedLocal/
│   ├── AskPass/
│   └── CLI/
├── SAFABroker/
│   ├── UseCases/
│   ├── XPC/
│   ├── Resources/
│   └── Runtime/
├── SAFACLI/
│   ├── Commands/Resource/
│   ├── Commands/Exec/
│   ├── Commands/Credential/
│   └── Presentation/
├── SAFATrustedSetup/
│   ├── TrustedSetupConsole.swift
│   ├── TrustedSSHEnrollmentFlow.swift
│   └── TrustedLocalSetupClient.swift
└── SAFASSH/
    ├── Configuration/
    ├── Authentication/
    ├── Tunnel/
    └── Sudo/
```

Guidelines:

- Prefer one primary type per file. A file over roughly 300 lines should have an explicit cohesion
  reason; otherwise split it before adding behavior.
- Command types parse arguments and call an injected client/use case. They do not scan dynamic JSON
  dictionaries or implement resource business rules.
- Broker XPC exports adapt bytes to typed operations. Use cases remain testable without an XPC
  connection.
- Mutable security state is actor-isolated. `@unchecked Sendable` is limited to small Foundation/XPC
  bridges with their synchronization visible in the same file.
- Composition happens only in executable runtime roots. Do not create global service
  locators or singletons for credentials.

## 6. Swift Agent CLI conventions

SAFA uses Apple's `swift-argument-parser` and follows these rules:

- The root and every asynchronous subtree use `AsyncParsableCommand`.
- Each command family is a separate file/directory with `CommandConfiguration`, `abstract`, argument
  help, and examples where the operation is non-obvious.
- Shared limits and execution options use `@OptionGroup`. There is no public output-format option.
- Validated scalar arguments such as resource alias and state conform to
  `ExpressibleByArgument`; cross-field constraints use `validate()`.
- `run()` performs only: parse/validate → create typed request → call client → present response.
- Every non-version path writes exactly one canonical TOON v4.1 document to stdout. There is no
  human/table/color renderer, `--json`, or `--toon` switch. Redacted debug/progress belongs on
  stderr and is not Agent input.
- The bare `-v`, `-V`, and `--version` path prints only SemVer and returns before Broker startup or
  the full command graph is initialized.
- Exit-code mapping is centralized: `0` for success/accepted/unambiguous no-op, `1` for an operation
  that did not complete, and `2` for usage failure before Broker work. Stable TOON status/error codes
  carry lifecycle detail.
- Root and noun-only invocations return bounded live safe data, not help. Each subtree still owns
  concise `--help` output and rejects unknown input before side effects.
- Default list projections expose at most four reviewed fields. `--fields` is command-specific and
  allowlisted; it cannot request protected or unknown metadata.
- Long content includes a bounded preview, original size, and truncation state. `--full` raises the
  soft presentation limit but cannot bypass Broker hard caps, redaction, or binary-output policy.
- Include cheap aggregates, definitive zero states, Broker-computed answers, and a few parameterized
  next commands when they eliminate a predictable Agent round trip.
- Version information comes from generated build metadata, never a literal repeated across CLI and
  Xcode settings.
- `--` remains the boundary before a remote argument vector. Shell programs are explicit and never
  inferred by concatenating arguments.
- The CLI never reads a secret, approval, or missing option from stdin. macOS-owned authorization UI
  may appear only for an explicitly requested protected operation.

An optional Agent session hook may be installed only by an explicit setup operation and may emit
only the safe no-argument home view. SAFA does not capture transcripts, command history, protected
topology, or remote output for later ambient context.

## 7. Agent-native CLI flows

### Discover and inspect a resource

1. `safa resource list` and `resource show ALIAS` return a safe summary: canonical
   alias, resource kind, template/version, host platform when applicable, safe roles, state, health,
   capabilities, and only source-code-allowlisted metadata. `resource_type` remains an additive v1
   compatibility projection, not the internal template key.
2. Unknown or newly imported metadata keys fail closed as private. A configuration file cannot mark
   its own field public.
3. `safa resource show ALIAS --details` asks macOS to verify the local user with Touch ID or
   login credentials. Denial and prompt-rate-limiting return no detail object.
4. An approved inspection may return alternate aliases, access methods, endpoint, username,
   security domain, non-secret typed metadata, relationships by alias, and identity status. It never
   returns secrets or credential/key locators.
5. Canonical and alternate aliases occupy one collision namespace and resolve to the same stable
   resource identity for inspection and execution.

### Manage resource lifecycle from the CLI

1. `safa resource add ALIAS [--from-ssh-config SSH_ALIAS]` and `resource edit` carry only logical
   aliases, safe template/type choices, and an optional active/disabled state across the mutation
   XPC method.
2. The broker asks macOS for device-owner authentication, then runs bounded `ssh -G SSH_ALIAS`
   locally and persists the resolved endpoint and username inside the encrypted vault. Private
   connection values never become CLI arguments or mutation DTO fields.
3. When an explicit OpenSSH alias exists, add creates a private draft, then in the same authorized workflow imports a previously trusted
   `known_hosts` identity and an available existing OpenSSH identity/agent route, verifies the exact
   remote username and registered Linux/macOS/Windows platform, and runs a bounded read-only host
   inventory probe before atomically committing `active` with the probe metadata. A remediable
   failure may retain the draft; `resource edit` resumes it without exposing a separate setup
   command.
4. When no explicit OpenSSH alias exists, the same add command launches the separately signed
   trusted helper. All connection fields and the password are read with terminal echo disabled;
   the helper accepts only alias/type in argv, performs LocalAuthentication, scans the live SSH host
   key, and requires the user to enter the independently verified SHA-256 fingerprint. The Broker
   binds the setup session to that exact signed peer and audit session, verifies password login,
   exact remote account, pinned identity, platform, and inventory, then atomically stores the
   credential in Keychain and activates the resource. A non-interactive invocation returns a
   `safe_for_agent: false` command for the user to run in a trusted local terminal.
5. Setup currently accepts direct routes, including a local Core Tunnel listener expressed as the
   resolved endpoint. `ProxyJump` and `ProxyCommand` fail with `user_action_required` until SAFA can
   review and snapshot their complete route rather than inherit mutable SSH configuration.
6. Refreshing a draft is allowed. Retargeting a resource that already has a credential or trusted
   identity is rejected so a mutable SSH config cannot silently redirect trusted access.
7. `resource edit --state disabled|active` changes access state while preserving the trusted route;
   `resource remove` deletes the resource. Both require macOS user presence. All resource writes pass
   through one serialized broker transaction gate. Removal preserves relationship integrity and
   deletes an unshared credential reference through the same transaction.
8. Production add/edit/setup and desired topology link operations may reuse a scoped, in-memory
   approval for at most five minutes within their own Broker service. The lease is capped at 300
   seconds, is lost on Broker restart, cannot cross from resource setup to topology, and is cleared
   by a denial or sensitive state change. Remove, disable, enable, unlink, credential use, protected
   inspection, sudo, and arbitrary execution never consume this convenience lease.

### Resource directory extension model

- Classification has independent validated dimensions: resource kind (`host`, `database`,
  `object-storage`, `cache`, `messaging`, `search`, `graph`, or `service`), immutable template ID and
  version, optional host platform (`linux`, `macos`, or `windows`), and safe roles such as `nas`.
  `host.nas` is not a platform; legacy vault records migrate to a Linux SSH host with the `nas`
  role, and new mutations reject that retired value.
- Access methods are independent identifiers such as `ssh`, `database.mysql`, `object-storage.s3`,
  `cache.redis`, and `http`. Supporting an identifier in storage does not claim its adapter is
  implemented.
- Metadata is an ordered set of typed key/value entries (`text`, `integer`, `boolean`, `byte_count`,
  or `text_list`). Passwords, API tokens, private keys, access keys, and Keychain locators are never
  metadata.
- Resource-to-resource relationships `hosted-on`, `depends-on`, and `backed-by` are canonical in
  the encrypted resource profile. Reconciliation materializes them as stable desired/asserted graph
  edges without copying endpoints into dependent records. `topology link`/`unlink` updates both
  representations through the same broker transaction gate; resource CRUD reconciles the graph in
  that same encrypted write.
- Credential kinds and roles are also extensible identifiers, while secret material stays in
  Keychain/Secure Enclave and the encrypted directory keeps only opaque references.
- Development/source-preview Broker signing carries both the Team-scoped Keychain entitlement and
  a matching embedded provisioning profile. `codesign --verify` is necessary but not sufficient:
  AMFI launch and a post-install Broker health check are separate gates. The vault remains
  intentionally unavailable while the macOS console session is locked.
- Built-in templates currently cover SSH (including Windows OpenSSH), MySQL, PostgreSQL,
  SQL Server, MongoDB, S3, MinIO, OSS, Redis, Kafka, RabbitMQ, Elasticsearch, Neo4j, and HTTP. Their
  protected setup payload enters only through the separately signed trusted-local XPC role. HTTP
  uses the fixed local macOS curl binding after its Apple platform signature, HTTP/HTTPS protocols,
  and reviewed options pass one Broker-startup probe. Complex protocols require independently
  probed and conformance-tested local-client bindings. The Agent-facing CLI cannot substitute for
  the trusted peer or auto-install a missing client.
- A stored service connection is `needs_verification`, not `ready`. Only its typed broker adapter
  may record revision-bound verification evidence. Changing endpoint, username, access method, or
  credential clears the evidence before the edited revision is returned.

### Topology graph and LLM projection

Resource placement, dependencies, storage relationships, network membership, routes, and
reachability form a directed typed multigraph. They are not stored as a tree or inferred from a
Mermaid/SVG layout. The graph separates desired claims, Broker-observed evidence, and deterministic
derived paths; only the latter two may be verified.

The Agent never receives the whole protected graph. A task projector returns a bounded connected
subgraph using stable aliases:

| Task | Projection |
|---|---|
| inventory and placement | node table plus typed edge list |
| reachability and route explanation | adjacency list plus Broker-computed proof paths |
| dependency impact | reverse adjacency plus computed affected set |
| small homogeneous dense comparison | bounded relation matrix plus stable legend |

Persisted ordering is normalized before projection. Reachability views use source-rooted
breadth-first order, dependency views use target-rooted reverse order, and every projection declares
its ordering and graph revision. The Broker computes exact graph operations; the LLM plans,
explains, and may propose desired logical edges but does not calculate or self-verify operational
authority.

The Agent-facing surface is deliberately limited to `topology show`, `path`, `impact`, `link`, and
`unlink`. Query results place a simple `answer.outcome` before supporting graph evidence. Protected
link mutations may create one constrained semantic context alias under `site.*`, `domain.*`,
`network.*`, `runtime.*`, or `route.*`; they cannot encode IP, CIDR, or DNS coordinates. Dense
comparison and cycle detection stay inside the Broker rather than becoming more Agent commands.

Successful bounded SSH setup and execution refresh a five-minute observed/verified
`runtime.local can-reach <resource>` edge. The evidence is written only by the Broker/adapter after
the connection succeeds; OpenSSH's transport/authentication failure exit `255` is never promoted.
This evidence explains current reachability but does not select a credential, change a desired
route, or authorize execution. Expiry turns it stale until another real operation refreshes it.

Abstract aliases and reviewed logical edges may be Agent-visible. IPs, CIDRs, ports, usernames,
physical route coordinates, evidence records, security policy, and credential bindings remain
protected. Human diagrams and optional multimodal views are derived from the same projection and
cannot be parsed back into verified graph state. The normative DTO and trust rules are in
`specs/001-secure-agent-access/contracts/topology-projection-v1.md`.

The normative schema and initial host keys are defined in
`specs/001-secure-agent-access/contracts/resource-directory-v1.md`.

### Import an existing SSH host

1. A local human adds an explicitly declared OpenSSH `Host` alias. The broker resolves it through a
   bounded read-only `ssh -G <alias>` adapter without importing private-key or password bytes.
2. The add/edit workflow imports an existing entry from the user's configured `known_hosts` files.
   Absence is not silently accepted: the command returns
   `host_identity_setup_required`.
3. Setup references only existing readable identity-file paths or an existing SSH-agent socket. The
   path/socket locator remains encrypted in the broker vault and is never returned by list, default
   show, or protected details. Private-key bytes do not enter SAFA storage.
4. Each execution uses a private temporary config and `known_hosts`. Paths are OpenSSH-quoted, and
   the random host-key alias is normalized as `[alias]:port` for non-default ports before hashing,
   so Core Tunnel listeners retain strict host-key verification without exposing endpoints in argv.
5. Windows inventory emits UTF-8 JSON and uses one trusted, bounded encoded-PowerShell layer. The
   generic Agent command wrapper remains separate, preventing nested base64 from exceeding the
   Windows OpenSSH command-line limit.
6. The broker constructs an isolated, pinned OpenSSH configuration, verifies the expected account,
   and runs one fixed read-only platform probe. Linux/macOS report architecture, OS/kernel, CPU,
   memory, root-filesystem capacity, hardware model, and Docker availability; Windows reports the
   equivalent bounded CIM data. Authentication or platform mismatch fails setup; unavailable
   optional fields are omitted.
7. Only after successful verification does one revision-checked transaction add the OpenSSH
   credential reference, persist validated inventory metadata, and mark the resource active.

Execution snapshots the direct endpoint, remote username, trusted host key, and approved local
OpenSSH credential locator. Later retargeting through `~/.ssh/config` is rejected. Managed Secure
Enclave onboarding and `ProxyJump`/`ProxyCommand` snapshotting remain later work. Password entry and
manual first-use fingerprint confirmation are implemented by the trusted helper.

### Add sudo capability

1. The Agent-facing CLI never requests or accepts a sudo password.
2. Runtime probes the current remote account before every eligible automatic privilege decision.
   Root and fresh direct Docker authorization stay at user privilege; failed, stale, contradictory,
   or hostile evidence never selects greater privilege.
3. First-use password sudo is enrolled only inside the trusted review of one immutable request. The
   helper authenticates local user presence, tries NOPASSWD first, and reads one hidden remote
   password only after NOPASSWD is rejected. No password enters Agent argv, environment, stdin,
   output, logs, or fixtures.
4. The broker stores sudo as a separate `ThisDeviceOnly` Keychain item and verifies it with a
   read-only `sudo -v` operation.
5. Sudo remains independently removable. Every privileged request is command-scoped and requires
   system-authenticated user presence; a ready credential removes repeated remote-password entry,
   not approval.

### Agent execution

```text
safa resource list
safa resource show app.prod
safa exec app.prod --intent "Check Docker service state" -- systemctl status docker
```

The Agent sees aliases, capabilities, health, stable errors, and bounded output. If Core Tunnel is
down, the response directs the user to start it instead of asking for an IP or password.

## 8. `ssh-hosts` parity plan

| Existing workflow capability | Current SAFA state | Native target state | Priority |
|---|---|---|---|
| Business-name/alias resolution | Canonical and alternate alias resolution implemented | Search and import UX over the encrypted directory | P0 |
| `ssh -G` route inspection | Explicit-host import implemented for direct routes | Reviewed `ProxyJump`/`ProxyCommand` snapshot | P0 |
| Core Tunnel listener preflight | Direct local-listener routes execute; dedicated health check missing | Route-health adapter and actionable `tunnel_unavailable` result | P0 |
| Public-key `BatchMode=yes` SSH | Existing identity-file/agent route wired end-to-end | Managed Secure Enclave identity | P0 |
| Strict host-key checking | Existing `known_hosts` import plus hidden first-use fingerprint confirmation and pinned execution implemented | Rotation flow | P0 |
| Password SSH onboarding | Signed hidden-input helper, caller-bound XPC session, account/platform/inventory verification, and atomic Keychain activation implemented | Credential rotation through the same trusted flow | P0 |
| Read-only diagnosis | Narrow allowlist exists | Argument-aware policy that excludes secret-dumping forms | P0 |
| Per-host sudo in Keychain | Separate verified `ThisDeviceOnly` credential implemented | Keep lifecycle and replacement evidence green | P1 |
| One scoped sudo command | Immutable request, exact approval, protected stdin, and auto privilege implemented | Final signed smoke across password/NOPASSWD/root/Docker profiles | P1 |
| Atomic user creation | Missing | Reviewed operational recipe over scoped sudo | P1 |
| Service credential status/injection | Typed templates and protected Broker commit exist; the shipped trusted client currently handles password SSH only | Least-privilege client adapters with credential injection and health probes | P2 |
| Credential discovery/import | External Python tooling | Explicit local migration assistant; never background scanning | P2 |
| Core Tunnel inventory refresh | External Python tooling | Read-only optional import adapter | P2 |
| Persistent tamper-evident audit UI | In-memory event sketch | Deferred until core operations are useful and safe | Later |

## 9. macOS security controls

- **Keychain:** use the Data Protection Keychain and the most restrictive accessibility compatible
  with broker operation. Device-bound values use a `ThisDeviceOnly` class. The final signed Broker,
  including after any outer-app re-signing or export step, must retain exactly the Team-scoped
  `<TeamIdentifier>.dev.safa.broker` Keychain access group; other Runtime roles must not inherit it.
  The Developer Team prefix is persistent-data compatibility state, so changing publisher Team
  requires an explicit Keychain/vault migration rather than an in-place package replacement.
- **User presence:** privileged credentials and authorization decisions use
  `SecAccessControl`/LocalAuthentication. A CLI flag or stdin confirmation is never approval.
- **Secure Enclave:** private key material is generated and used on-device. Do not claim managed
  Secure Enclave SSH until the constrained SSH-agent socket protocol is implemented and tested
  end-to-end.
- **XPC:** both sides set peer code-signing requirements; the listener also validates user and audit
  session. Agent, broker, AskPass, and trusted setup use role-specific signing identifiers. Setup
  sessions additionally bind the begin/commit pair to the same caller and expire within five minutes.
- **Service lifecycle:** register the per-user broker through `SMAppService`; show registration state
  and a direct System Settings remediation path. Before initializing runtime services, the broker
  replaces its own process image with an explicit minimal environment. Removing variables only after
  startup does not remove them from the operating system's initial process metadata.
- **Files:** application-support directories are `0700`; vault/config/known-host files are `0600`;
  temporary request directories are removed after execution.

## 10. Delivery gates

No new authorization or audit feature starts until the architecture remediation gate is green:

1. split the four current monolith files by feature/responsibility;
2. replace dynamic broker reply maps for touched operations with typed DTOs;
3. correct advertised capabilities and README claims;
4. remove secret-dumping command forms from the automatic diagnostic policy;
5. add SSH-config import, tunnel preflight, and public-key execution contract tests;
6. keep the canonical TOON v2 fixtures strict-decoding against pinned official TOON sources, then
   validate the signed broker/CLI/AskPass/trusted-setup boundaries without adding GUI work or publishing
   artifacts.

After every slice: format, build, test, unsigned Xcode assembly, Draft PR, CI, squash merge. Signed
preview and future release artifacts additionally run `Scripts/verify-runtime-signing.sh` against
the final staged app, because signature validity alone does not prove that Broker entitlements
survived re-signing. No tag, GitHub Release, notarized artifact, or Skill package is created while
the publication hold is active.

## References

- [Swift Package Manager: Introducing Packages](https://docs.swift.org/swiftpm/documentation/packagemanagerdocs/introducingpackages/)
- [Apple Swift Argument Parser](https://github.com/apple/swift-argument-parser)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Accessing Keychain items with Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [XPC peer requirements](https://developer.apple.com/documentation/xpc/xpcpeerrequirement)
