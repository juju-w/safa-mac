# Implementation Plan: Local-Client Execution

The availability and route decision record is in `research.md`. On macOS, `/usr/bin/curl` is the
reviewed HTTP client binding; the service host does not need its own HTTP diagnostic tool.

## Compatibility decision

Keep `dev.safa.cli/v2` and the existing `safa exec ALIAS -- ...` command. The public capability is
`exec`; choosing SSH or a source-pinned local client is Broker-private. The existing execution reply
shape remains additive-compatible, including the legacy `remote_exit_code` field for v2.

## Delivery order

1. Build a shell-free bounded local-process transport on the existing `ProcessRunner` seam.
2. Ship one exact HTTP read adapter (`curl`, `curl --head`) with protected URL/token input over stdin.
3. Gate eligibility through the built-in template's `exec` capability and preserve custom
   deny/approval policy precedence.
4. Record successful adapter verification and topology reachability against the canonical alias.
5. Update the product contract and Skill only for evidence-backed HTTP behavior.
6. **Completed:** add installer/doctor/package conformance for the Apple-signed fixed curl dependency and project
   candidate versus effective adapter readiness without weakening independently healthy SSH.
7. Add explicit direct and Broker-managed routed reachability; never fall back to client commands on
   a remote host when a private service needs an SSH/network route.
8. Add Redis, PostgreSQL/MySQL, and object-storage adapters independently, each with a probed
   compatible local client, safe input mechanism, exact operation vocabulary, executable pin, and
   leakage suite. Missing clients make that adapter unavailable rather than triggering substitution.
9. Complete generic trusted setup for non-SSH service credentials before claiming end-user parity.

## Security invariants

- No shell and no Agent-controlled executable path, endpoint, auth/config flag, stdin, or working
  directory.
- No secret or protected endpoint in argv/environment/audit/Agent-visible output.
- No ambient `PATH`, proxy variables, or client configuration.
- HTTP pins `/usr/bin/curl`, disables ambient curl configuration and proxy environment, disables
  redirects, and supplies its complete protected request through Broker-controlled stdin.
- Direct plaintext HTTP never carries a Bearer token. A protected routed exception requires explicit
  verified route evidence; hostname shape alone is not proof.
- Unknown adapter, unavailable client, invalid endpoint/route, and unsupported privilege fail closed
  with stable non-sensitive errors. No download, auto-install, container, PATH, or remote-tool
  fallback is permitted.
- Remote/client output remains bounded and untrusted.
