# Research: Non-SSH Client Availability and HTTP Routing

**Reviewed**: 2026-08-21

## Clarify where a client runs

The current HTTP proof invokes `/usr/bin/curl` on the Mac running SAFA, not on the machine hosting
the HTTP service. A target server therefore does not need `curl` or `wget` for direct HTTP resource
execution. Two independent questions were previously conflated:

1. **Adapter availability**: can the local Runtime speak the registered protocol?
2. **Route availability**: can the local Runtime reach the protected endpoint directly or through a
   verified route?

Client substitution cannot repair a missing route, and a route cannot provide a missing protocol
adapter.

## Options considered

| Option | Availability | Security/operational cost | Decision |
|---|---|---|---|
| Pin local `/usr/bin/curl` | Present at the fixed path on the supported macOS Runtime baseline | Requires protected config injection, behavior conformance, and process redaction | Chosen for macOS HTTP; verify in installer/doctor and packaged smoke |
| Fall back through local `curl` → `wget` → Python | Varies by machine | Each tool has different redirect, proxy, config, TLS, auth, and output behavior; PATH/tool discovery increases substitution risk | Reject |
| Run whatever HTTP tool exists on the service host | Highly variable | Requires remote shell/tool probing, leaks more platform detail, and makes credentials depend on unreviewed remote programs | Reject |
| Auto-download/install or start a containerized client | Can manufacture availability | Adds package provenance, mutable code, container socket authority, network supply-chain, and cleanup risks | Reject |
| Bundle a general client | Predictable | Expands release assets, patch responsibility, SBOM, signing, and publication scope | Defer; unnecessary for HTTP |
| Native Foundation HTTP transport | Avoids an external process | Still makes SAFA own request, redirect, proxy, cookie/cache, authentication, streaming, TLS-challenge, and error semantics | Defer; not simpler than the reviewed curl binding for MVP |
| Verified route/tunnel plus local curl | Does not require a remote HTTP client | Requires explicit topology binding, lifecycle, cancellation, TLS-name preservation, and tunnel evidence | Chosen direction for private/routed HTTP; detailed design pending |

## HTTP binding security requirements

The curl adapter is not a generic command runner. It exposes only Broker-reviewed GET and HEAD
semantics against the registered endpoint.

- Build the URL only from validated protected resource fields. Agent input cannot provide or
  override scheme, host, port, path, query, header, proxy, or credential.
- Pin the Apple-provided executable at `/usr/bin/curl`; never search ambient `PATH` or substitute
  `wget`, Python, a shell, or another curl binary.
- Verify the Apple platform signature and `com.apple.curl` identifier plus HTTP/HTTPS and every
  reviewed option used by the binding. A path match alone is not conformance.
- Use `-q --config -`, a fixed minimal environment, no redirect option, and no Agent-controlled curl
  flag. Do not inherit `.curlrc`, proxy environment, cookies, client certificates, or ambient auth.
- Use curl's default platform TLS trust and hostname verification. Do not add an insecure or
  trust-all option.
- Disable redirects. A redirect is a new endpoint and must never receive a registered Bearer token
  automatically.
- Do not send a Bearer token over a direct plaintext `http://` route. Any exception for loopback or
  a verified encrypted tunnel must be modeled as route evidence, not inferred from the hostname.
- Apply the generic process timeout, cancellation, and bounded stdout/stderr capture. A response may
  be truncated but must never grow Broker memory without bound.
- Bound and sanitize response headers and body separately. Treat both as untrusted data and redact
  the registered endpoint, host, and credential before any Agent-visible or audit projection.
- Keep GET and HEAD response/status mapping deterministic so the execution result contract does not
  depend on ambient curl configuration.

## Routed HTTP direction

A service resource may reference a verified host/tunnel route through the canonical topology model.
Execution resolves that relationship inside the Broker; the Agent never supplies a jump host or
endpoint.

The routed adapter should:

1. validate that the route resource is active, identity-pinned, and fresh enough for the operation;
2. establish a per-request Broker-owned forward with no ambient SSH configuration or forwarding;
3. preserve the original HTTP hostname for TLS Server Name Indication and certificate validation;
4. expose the forward only to the requesting Broker operation, preferably on loopback with a
   randomly allocated port or private connected stream;
5. terminate the forward on completion, timeout, cancellation, Broker restart, or validation
   failure; and
6. record reachability only after both the route and HTTP operation succeed.

Selecting SSH local forwarding, a dynamic proxy, or a connected-stream bridge remains an
implementation decision. It must be tested specifically for DNS handling, TLS hostname/SNI,
loopback exposure, port races, cancellation, and credential leakage before it can advertise routed
HTTP execution.

## Complex non-HTTP protocols

For MySQL, PostgreSQL, Redis, MongoDB, and similar protocols, absence of a compatible local client
means the adapter is unavailable. SAFA does not pretend that a different binary is equivalent.

- Probe only reviewed absolute executable paths and compatible versions.
- Separate semantic operations from raw client argv; the Agent never supplies local-client flags.
- Advertise effective `exec` readiness only after the binding probe succeeds.
- Keep readiness adapter-specific: a missing database client cannot disable SSH or an independently
  healthy HTTP binding.
- Treat each supported client brand/version family as its own tested binding.
- Return a stable safe remediation when no binding exists. Installation is a human/package-manager
  action outside Agent execution.

This preserves truthful capability discovery: registration describes a resource; executable
readiness describes whether this Runtime currently has a safe adapter and route for an operation.
