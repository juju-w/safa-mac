# SAFA Runtime

The native security boundary for [SAFA](https://github.com/juju-w/safa). This repository implements
the processes that hold local authority: protected resource resolution, credential use, native user
authorization, policy enforcement, remote transport, and bounded output.

[![CI](https://github.com/juju-w/safa-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/juju-w/safa-runtime/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Swift 6](https://img.shields.io/badge/Swift-6-F05138)
![macOS preview](https://img.shields.io/badge/macOS-preview-black)

> [!IMPORTANT]
> The Swift/macOS Runtime is an implementation preview. No signed/notarized public package, tag, or
> GitHub Release is available. Linux and Windows Runtimes are not implemented or claimed as
> supported.

## Repository responsibility

This is not the SAFA Skill or the public product specification.

| Repository | Responsibility |
|---|---|
| [`juju-w/safa`](https://github.com/juju-w/safa) | Agent Skill, public CLI/resource contracts, product documentation, conformance fixtures, Runtime resolver, and exact release manifests |
| [`juju-w/safa-runtime`](https://github.com/juju-w/safa-runtime) | Native CLI, Broker, credential helper, OS security adapters, transport implementations, tests, signing, and packaging |

Public behavior starts in the product repository. Runtime changes that affect the Agent-facing
TOON contract or resource model must first update the canonical contract and compatibility fixtures
there. The coordinated migration branch emits the Agent-only `dev.safa.cli/v2` contract; it remains
unpublished until conformance and human review finish.

## Runtime boundary

```mermaid
flowchart LR
    Skill["SAFA Skill + resolver"] --> CLI["safa CLI\nAgent-facing"]
    CLI -->|"authenticated XPC"| Broker["safa-broker\npolicy + vault authority"]
    CLI -->|"launch only\nno input or output pipe"| Setup["safa-trusted-setup\nhidden local enrollment"]
    Setup -->|"trusted-local XPC"| Broker
    Broker --> Keychain["Keychain + user authorization"]
    Broker --> AskPass["safa-askpass\none-shot helper"]
    AskPass --> Target["registered target"]
    Target -->|"untrusted output"| Broker
    Broker -->|"bounded typed evidence"| CLI
    CLI -->|"canonical TOON"| Skill
```

One macOS installation is packaged as `SAFA.app`, but authority is split between processes:

| Component | Purpose | Credential authority |
|---|---|---|
| `safa` | Parse Agent commands and encode one stable TOON result | None |
| `safa-broker` | Resolve protected records, enforce policy, authorize, connect, and sanitize | Keychain/vault owner |
| `safa-askpass` | Deliver one child-bound, short-lived SSH secret | One-shot only |
| `safa-trusted-setup` | Collect hidden protected SSH fields after local user authentication and submit one caller-bound setup transaction | No persistent storage; typed setup session only |
| `SAFA.app` | Signed container and `SMAppService` lifecycle host | No Agent-facing GUI |

An Agent-facing process cannot retrieve a raw secret. Local IPC does not use plaintext credentials;
the Broker resolves credentials internally after validating peer identity and policy.

## Implemented macOS preview

- encrypted resource directory with safe and protected projections;
- Linux, macOS, and Windows OpenSSH host registration from trusted local SSH configuration;
- first-use password SSH registration through a separately signed, no-custom-GUI helper whose
  protected fields never use argv, environment, Agent-controlled stdin, stdout, or stderr;
- bounded first-connection system and hardware inventory probes;
- deterministic topology projections for placement, reachability, and dependency impact;
- strict pinned-host SSH configuration and bounded non-sudo diagnostics;
- exact registered HTTP GET/HEAD execution through the reviewed local adapter, with Agent
  endpoint, header, token, redirect, config, and shell overrides rejected;
- Keychain password bindings, child-bound AskPass, output limits, and credential redaction;
- LocalAuthentication/Touch ID for protected resource lifecycle actions;
- synthetic unit, contract, integration, and security tests that contact no real infrastructure.

Database, object-storage, cache, messaging, graph, and search resources can be registered as typed
records, but their protocol operations are not implemented Agent capabilities.

## Agent-only CLI

The thin CLI follows the [AXI principles](https://axi.md/) and is not a human terminal product. Its
public behavior is one canonical TOON document on stdout for success, empty state, no-op, and
error; stderr is debug-only, and the bare version path is the only non-TOON exception. There is no
human mode or public format selector. Internal Codable and XPC types remain private.

Default collections contain no more than four reviewed fields, large content is previewed with
explicit size/truncation metadata, cheap aggregates and Broker-computed answers are returned inline,
and output includes only relevant parameterized next commands. `--full` never bypasses redaction or
the Broker hard limit. The normative contract is
[`contracts/cli-v2.md`](https://github.com/juju-w/safa/blob/main/contracts/cli-v2.md).

## Build and test

Requirements: macOS, Xcode with Swift 6 support, and `xcrun swift-format`.

```bash
xcrun swift-format lint --recursive --strict \
  Sources Tests Apps/SAFA/Targets Package.swift
swift test --parallel
swift build -c release
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme "SAFA Runtime" \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

The unsigned Xcode build validates assembly only. XPC peer identity, Keychain,
LocalAuthentication, and `SMAppService` require all native components to be signed by the same
configured Apple Developer Team. Follow the
[signed development quickstart](specs/001-secure-agent-access/quickstart.md) for that path.
The production-identity, notarized, non-destructive internal candidate path is documented in
[MVP candidate assembly and replacement](docs/mvp-candidate.md). It remains unavailable until run
inside protected publisher automation; the scripts do not publish an artifact.

### Free local trial

An Apple Developer Program membership is not required to try SAFA on the developer's own Mac. Xcode
must first create an `Apple Development` identity and a development provisioning profile for
`dev.safa.broker`. The Source Preview installer then performs manual same-Team signing, verifies the
Broker-only Keychain boundary, preserves existing local state on replacement, and publishes
nothing:

```bash
security find-identity -v -p codesigning
Scripts/install-local-runtime.sh \
  --source-preview \
  --identity-hash YOUR_LOCAL_APPLE_DEVELOPMENT_SHA1 \
  --replace
```

A free Personal Team profile normally expires after seven days. When it expires, refresh the
development signing assets through Xcode and run the same replacement command again. This is a
single-Mac development path, not a Developer ID signed/notarized build for other users. See the
[signed development quickstart](specs/001-secure-agent-access/quickstart.md) for activation and
verification.

## Security assumptions

- source code is public and is not a security boundary;
- the CLI never gains Keychain or approval authority;
- modified or unsigned clients cannot become trusted Broker peers;
- host identity, policy, vault integrity, or authorization failures fail closed;
- remote output, release metadata, fixtures, and pull-request content are untrusted input;
- complete compromise of the local administrator/root account is outside the guarantee of a purely
  local vault.

The complete model and component boundaries are documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Repository map

```text
Apps/SAFA/                      signed macOS app container and native targets
Sources/                        CLI, Broker domain/application/platform code
Tests/                          unit, contract, integration, and security tests
specs/001-secure-agent-access/  Spec Kit requirements, design, research, and quickstart
docs/architecture/reviews/      dated implementation audits
```

## Development documentation

- [Runtime architecture](ARCHITECTURE.md)
- [Signed development quickstart](specs/001-secure-agent-access/quickstart.md)
- [MVP candidate assembly and replacement](docs/mvp-candidate.md)
- [Runtime specification](specs/001-secure-agent-access/spec.md)
- [Research and design decisions](specs/001-secure-agent-access/research.md)
- [Initial Swift architecture audit](docs/architecture/reviews/2026-08-16-initial-code-audit.md)
- [Repository contribution rules](AGENTS.md)
- [Canonical SAFA contracts and product documentation](https://github.com/juju-w/safa)

SAFA Runtime is licensed under the [MIT License](LICENSE).
