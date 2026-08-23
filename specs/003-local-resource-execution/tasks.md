# Tasks: Local-Client Execution

**Core MVP status**: Every HTTP GET/HEAD task through packaged direct execution is complete. The
remaining unchecked routed/private-service, complex-protocol, and additional-adapter tasks are
post-RC backlog under `PRODUCT.md`, not Core MVP blockers.

- [x] Add security-first HTTP execution and target-override tests.
- [x] Add `LocalProcessTransport` over bounded `ProcessRunner`.
- [x] Add source-pinned HTTP adapter with exact GET/HEAD operations.
- [x] Deliver endpoint/token through curl stdin config; sanitize child environment.
- [x] Redact token, URL, and host from returned output.
- [x] Record successful HTTP adapter verification.
- [x] Add trusted-local HTTP registration with optional Bearer token enrollment.
- [x] Run the full Swift unit/contract/integration/security suite.
- [x] Add 100-run leakage regression coverage.
- [x] Update public CLI v2 contract, fixtures, and SAFA Skill.
- [x] Validate the installed Skill and product/runtime consistency.
- [x] Smoke the exact curl stdin-config convention against a synthetic local HTTP server.
- [x] Make installer/doctor verify `/usr/bin/curl`, Apple `com.apple.curl` platform signing,
  HTTP/HTTPS support, and every reviewed config/timeout/failure option.
- [x] Treat a missing/incompatible required macOS curl as HTTP-adapter readiness failure without
  fallback or impact on healthy SSH execution.
- [x] Separate template candidate capability from effective per-adapter readiness without disabling
  healthy SSH execution.
- [x] Reject Bearer credentials over direct plaintext HTTP without verified protected-route evidence.
- [ ] Add a Broker-managed route/tunnel model for HTTP resources that are not directly reachable.
- [ ] Make complex-protocol `exec` readiness depend on a verified compatible local client binding.
- [x] Reject curl/wget/python/shell/PowerShell remote fallback and unreviewed client substitution.
- [x] Complete packaged Runtime HTTP smoke after the local user re-enables the SAFA background item.
  The final installed Source Preview passed signing-boundary verification, reported Broker, vault,
  and HTTP client readiness, completed bounded GET and HEAD operations against a synthetic loopback
  service, transitioned the temporary resource from `needs_verification` to `ready`, and removed the
  resource without retaining its protected endpoint.
- [ ] Extend trusted setup beyond the HTTP template to required and multi-field credentials.
- [ ] Implement Redis adapter with independent conformance evidence.
- [ ] Implement SQL adapters with independent conformance evidence.
