import Foundation
import SAFACrypto
import SAFADomain
import SAFAPolicy
import SAFAProtocol
import SAFASSH
import SAFATransport

public enum ExecutionServiceError: Error, Equatable, Sendable {
    case resourceNotReady
    case sudoCredentialRequired
    case requestNotFound
    case credentialUnavailable
}

public enum ExecutionSubmissionOutcome: Sendable {
    case completed(requestID: UUID, result: ExecutionResult)
    case awaitingApproval(requestID: UUID)
    case denied(requestID: UUID, findings: [Finding])
}

/// Integrates `PolicyEngine`, `GrantMatcher`, `RequestService`, and `GrantService` into the
/// one execution pipeline both non-sudo and sudo commands go through: evaluate, then either
/// run immediately (policy-automatic or an existing grant already authorizes it), deny
/// outright, or park the request `.awaitingApproval` for the trusted-local flow. This
/// replaces the MVP's previous unconditional "diagnostic allow-list, no policy" gate.
public actor ExecutionService {
    private enum ExecutionRoute: Equatable {
        case ssh
        case localClient
    }

    /// No per-resource `Policy` is configurable yet (out of scope for this pass — nothing in
    /// `specs/002-sudo-execution` Phase 4/5 asks for policy CRUD). This is deliberately
    /// conservative: no automatic rules, so `PolicyEngine`'s `policy.no_automatic_rule`
    /// fallback still requires approval for anything not on the diagnostic allow-list,
    /// matching the posture the MVP already had.
    public static let defaultPolicy = Policy(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000042")!,
        version: "mvp-v1",
        automaticRules: [],
        approvalRules: [],
        denyRules: [],
        limits: ExecutionLimits(
            maximumTimeoutSeconds: 300,
            maximumOutputBytes: 4_194_304,
            maximumConcurrentRequests: 8,
            allowsTTY: false
        )
    )

    private let vault: any VaultDocumentStoring
    private let passwordStore: any PasswordSecretStoring
    private let bindingStore: ChildCredentialBindingStore
    private let transport: SSHTransport
    private let localTransport: LocalProcessTransport
    private let localClientAdapter: LocalClientAdapter
    private let sudoExecutor: any SudoExecuting
    private let resourceService: ResourceService
    private let audit: AuditService
    private let askPassExecutable: URL
    private let workingDirectory: URL
    private let requests: RequestService
    private let grants: GrantService
    private let topologyReachabilityRecorder: (any TopologyReachabilityRecording)?
    private let policyEngine: PolicyEngine
    private let grantMatcher: GrantMatcher
    private let autoPrivilegeResolver: AutoPrivilegeResolver

    public init(
        vault: any VaultDocumentStoring,
        passwordStore: any PasswordSecretStoring,
        bindingStore: ChildCredentialBindingStore,
        transport: SSHTransport,
        localProcessRunner: any ProcessRunning = ProcessRunner(),
        localClientAdapter: LocalClientAdapter = LocalClientAdapter(),
        sudoExecutor: any SudoExecuting,
        resourceService: ResourceService,
        audit: AuditService,
        askPassExecutable: URL,
        workingDirectory: URL,
        requests: RequestService,
        grants: GrantService,
        topologyReachabilityRecorder: (any TopologyReachabilityRecording)? = nil,
        policyEngine: PolicyEngine = PolicyEngine(),
        grantMatcher: GrantMatcher = GrantMatcher(),
        autoPrivilegeResolver: AutoPrivilegeResolver = AutoPrivilegeResolver()
    ) {
        self.vault = vault
        self.passwordStore = passwordStore
        self.bindingStore = bindingStore
        self.transport = transport
        localTransport = LocalProcessTransport(runner: localProcessRunner)
        self.localClientAdapter = localClientAdapter
        self.sudoExecutor = sudoExecutor
        self.resourceService = resourceService
        self.audit = audit
        self.askPassExecutable = askPassExecutable
        self.workingDirectory = workingDirectory
        self.requests = requests
        self.grants = grants
        self.topologyReachabilityRecorder = topologyReachabilityRecorder
        self.policyEngine = policyEngine
        self.grantMatcher = grantMatcher
        self.autoPrivilegeResolver = autoPrivilegeResolver
    }

    public func submit(
        alias: ResourceAlias,
        command: CommandSpec,
        privilege: AgentExecutionPrivilegeV2,
        intent: String,
        expectedEffect: String?,
        rollback: String?,
        caller: CallerIdentity,
        now: Date = Date(),
        monotonicNowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) async throws -> ExecutionSubmissionOutcome {
        let document = try await vault.readDocument()
        let registry = try ResourceRegistry(resources: document.resources)
        let resource = try registry.resource(alias: alias)
        let effectivePrivilege = try await resolvePrivilege(
            requested: privilege,
            command: command,
            resource: resource,
            document: document,
            now: now
        )
        let route = try executionRoute(
            resource: resource,
            command: command,
            privilege: effectivePrivilege,
            document: document
        )
        let sudoCredentialReady =
            effectivePrivilege != .sudo
            || resource.sudoRef.map { sudoCredentialID in
                document.credentialReferences.contains(where: {
                    $0.id == sudoCredentialID && $0.health == .ready
                })
            } == true

        let storedPolicy = document.policies.first ?? Self.defaultPolicy
        let policy =
            route == .localClient
            ? Self.policyAllowingRegisteredLocalRead(storedPolicy)
            : storedPolicy
        let fingerprint = try CanonicalCodec.requestFingerprint(
            RequestFingerprintMaterial(
                caller: caller,
                resourceID: resource.id,
                resourceRevision: resource.revision,
                command: command,
                privilege: effectivePrivilege
            )
        )
        let requestID = UUID()
        let request = ExecutionRequest(
            id: requestID,
            caller: caller,
            resourceID: resource.id,
            resourceRevision: resource.revision,
            command: command,
            privilege: effectivePrivilege,
            intent: intent,
            expectedEffect: expectedEffect,
            rollback: rollback,
            fingerprint: fingerprint,
            state: .created,
            createdAt: now,
            deadline: now.addingTimeInterval(TimeInterval(command.timeoutSeconds) + 600)
        )
        await requests.create(request, resourceAlias: alias)
        try await requests.transition(id: requestID, to: .evaluating)
        await audit.recordRequest(alias: alias, fingerprint: fingerprint, now: now)

        let evaluation = try policyEngine.evaluate(
            command: command, privilege: effectivePrivilege, policy: policy)
        let assessment = evaluation.riskAssessment(id: UUID(), evaluatedAt: now)
        await requests.attachRiskAssessment(requestID: requestID, assessment: assessment)

        switch evaluation.disposition {
        case .denied:
            try await requests.transition(id: requestID, to: .denied)
            await audit.recordDecision(
                alias: alias, fingerprint: fingerprint, decision: "denied", now: now)
            return .denied(requestID: requestID, findings: evaluation.findings)

        case .automatic:
            try await requests.transition(id: requestID, to: .approvedByPolicy)
            await audit.recordDecision(
                alias: alias, fingerprint: fingerprint, decision: "allowed_automatic", now: now)
            let result = try await runAndRecord(
                requestID: requestID, resource: resource, alias: alias, document: document)
            return .completed(requestID: requestID, result: result)

        case .approvalRequired:
            // A grant can suppress a new approval prompt, but it can never manufacture a
            // missing sudo credential. Park the exact request for the trusted-local flow so
            // first-use enrollment and approval can complete together.
            for grant in sudoCredentialReady
                ? await grants.candidates(callerBinding: caller, resourceID: resource.id) : []
            {
                let current = await requests.get(id: requestID) ?? request
                guard
                    case .authorized = grantMatcher.match(
                        grant: grant,
                        request: current,
                        policyVersion: policy.version,
                        now: now,
                        monotonicNowNanoseconds: monotonicNowNanoseconds
                    )
                else { continue }
                try await grants.consume(id: grant.id)
                try await requests.transition(id: requestID, to: .approvedByPolicy)
                await audit.recordDecision(
                    alias: alias, fingerprint: fingerprint,
                    decision: "allowed_by_grant:\(grant.id.uuidString)", now: now)
                let result = try await runAndRecord(
                    requestID: requestID, resource: resource, alias: alias, document: document)
                return .completed(requestID: requestID, result: result)
            }
            try await requests.transition(id: requestID, to: .awaitingApproval)
            await audit.recordDecision(
                alias: alias, fingerprint: fingerprint, decision: "awaiting_approval", now: now)
            return .awaitingApproval(requestID: requestID)
        }
    }

    private func resolvePrivilege(
        requested: AgentExecutionPrivilegeV2,
        command: CommandSpec,
        resource: Resource,
        document: VaultDocument,
        now: Date
    ) async throws -> Privilege {
        switch requested {
        case .user:
            return .user
        case .sudo:
            return .sudo
        case .auto:
            guard let commandClass = autoPrivilegeResolver.commandClass(for: command) else {
                return .user
            }
            let observation = try await observeAccountForAutoPrivilege(
                resource: resource,
                document: document,
                includeDockerAuthorization: commandClass == .dockerRead,
                observedAt: now
            )
            return autoPrivilegeResolver.resolve(
                command: command,
                observation: observation,
                now: now
            ).effectivePrivilege
        }
    }

    private func observeAccountForAutoPrivilege(
        resource: Resource,
        document: VaultDocument,
        includeDockerAuthorization: Bool,
        observedAt: Date
    ) async throws -> AutoPrivilegeAccountObservation {
        let insufficient = AutoPrivilegeAccountObservation(
            isRoot: nil,
            dockerAuthorized: nil,
            observedAt: nil
        )
        guard resource.state == .active,
            resource.hostIdentity?.status == .trusted,
            resource.resolvedAccessMethods.contains(.ssh),
            resource.resolvedHostPlatform == .linux || resource.resolvedHostPlatform == .macOS
        else {
            return insufficient
        }

        let probeID = UUID()
        var bindingToRevoke: String?
        do {
            let resolved = try await resolveCredential(
                resource: resource,
                document: document,
                requestID: probeID
            )
            bindingToRevoke = resolved.binding
            let observation = try await OpenSSHAutoPrivilegeAccountProbe(
                transport: transport,
                workingDirectory: workingDirectory
            ).probe(
                resource: resource,
                credential: resolved.credential,
                includeDockerAuthorization: includeDockerAuthorization,
                observedAt: observedAt,
                didLaunch: resolved.launchHandler
            )
            if bindingToRevoke != nil { bindingStore.revoke(requestID: probeID) }
            return observation
        } catch {
            if bindingToRevoke != nil { bindingStore.revoke(requestID: probeID) }
            if error is CancellationError || Task.isCancelled { throw CancellationError() }
            return insufficient
        }
    }

    /// Called by the broker's trusted-local handler once `ApprovalService.decide` issues a
    /// grant for a request that was `.awaitingApproval`. Re-reads the vault so credential/
    /// resource state reflects whatever is true right now, not what was true at submission
    /// time — real time may have passed while the user reviewed the approval prompt.
    @discardableResult
    public func runApproved(
        requestID: UUID,
        grant: ApprovalGrant,
        expectedResourceRevision: UInt64? = nil
    ) async throws -> ExecutionResult {
        await grants.store(grant)
        try await grants.consume(id: grant.id)
        guard let request = await requests.get(id: requestID) else {
            throw ExecutionServiceError.requestNotFound
        }
        guard let alias = await requests.resourceAlias(requestID: requestID) else {
            throw ExecutionServiceError.requestNotFound
        }
        let document = try await vault.readDocument()
        let registry = try ResourceRegistry(resources: document.resources)
        let resource = try registry.resource(alias: alias)
        guard resource.id == request.resourceID,
            resource.revision == (expectedResourceRevision ?? request.resourceRevision)
        else {
            _ = try? await requests.transition(id: requestID, to: .expired)
            throw ExecutionServiceError.resourceNotReady
        }
        return try await runAndRecord(
            requestID: requestID, resource: resource, alias: alias, document: document)
    }

    private func runAndRecord(
        requestID: UUID,
        resource: Resource,
        alias: ResourceAlias,
        document: VaultDocument
    ) async throws -> ExecutionResult {
        guard let request = await requests.get(id: requestID) else {
            throw ExecutionServiceError.requestNotFound
        }
        try await requests.transition(id: requestID, to: .running)

        let workingRoot = workingDirectory.appendingPathComponent(
            requestID.uuidString, isDirectory: true)
        let processResult: ProcessExecutionResult
        var redactionValues: [Data] = []
        var bindingToRevoke: String?
        do {
            if resource.resolvedAccessMethods.contains(.ssh) {
                let resolved = try await resolveCredential(
                    resource: resource, document: document, requestID: requestID)
                redactionValues = resolved.redactionSecret.map { [$0] } ?? []
                bindingToRevoke = resolved.binding
                if request.privilege == .sudo {
                    let sudoSecret = try await resolveSudoSecret(
                        resource: resource, document: document)
                    processResult = try await sudoExecutor.execute(
                        resource: resource,
                        command: request.command,
                        primaryCredential: resolved.credential,
                        sudoSecret: sudoSecret,
                        workingRoot: workingRoot,
                        didLaunch: resolved.launchHandler
                    )
                } else {
                    processResult = try await transport.execute(
                        resource: resource,
                        command: request.command,
                        credential: resolved.credential,
                        workingRoot: workingRoot,
                        didLaunch: resolved.launchHandler
                    )
                }
            } else {
                let secret = try await resolveLocalCredential(
                    resource: resource,
                    document: document
                )
                let plan = try localClientAdapter.prepare(
                    resource: resource,
                    command: request.command,
                    privilege: request.privilege,
                    credential: secret
                )
                redactionValues = plan.redactionValues
                processResult = try await localTransport.execute(plan.invocation)
            }
        } catch {
            if bindingToRevoke != nil { bindingStore.revoke(requestID: requestID) }
            _ = try? await requests.transition(id: requestID, to: .failed)
            await audit.recordExecution(
                alias: alias, fingerprint: request.fingerprint, outcome: "transport_failed")
            throw error
        }
        if bindingToRevoke != nil { bindingStore.revoke(requestID: requestID) }

        if resource.resolvedAccessMethods.contains(.ssh),
            processResult.termination == .exit,
            processResult.exitCode != 255
        {
            // Reachability is recorded against the canonical alias, not whichever alternate
            // alias the caller resolved the resource through, matching how the resource's
            // identity is tracked in topology regardless of which name reached it.
            try? await topologyReachabilityRecorder?.recordSuccessfulReachability(
                to: resource.alias, observedAt: processResult.finishedAt)
        }
        if !resource.resolvedAccessMethods.contains(.ssh),
            processResult.termination == .exit,
            processResult.exitCode == 0,
            resource.verification?.status != .verified
                || resource.verification?.adapter != .http
        {
            _ = try? await resourceService.recordServiceVerification(
                alias: resource.alias,
                expectedRevision: resource.revision,
                adapter: .http,
                succeeded: true,
                now: processResult.finishedAt
            )
            try? await topologyReachabilityRecorder?.recordSuccessfulReachability(
                to: resource.alias,
                observedAt: processResult.finishedAt
            )
        }

        let redactedStdout = redactionValues.reduce(processResult.stdout) {
            Self.redact($1, from: $0)
        }
        let redactedStderr = redactionValues.reduce(processResult.stderr) {
            Self.redact($1, from: $0)
        }
        let executionResult = ExecutionResult(
            startedAt: processResult.startedAt,
            finishedAt: processResult.finishedAt,
            remoteExitCode: processResult.exitCode,
            termination: Self.terminationKind(processResult.termination),
            stdout: BoundedOutput(
                text: String(decoding: redactedStdout, as: UTF8.self),
                capturedBytes: UInt(redactedStdout.count),
                totalBytes: UInt(processResult.stdoutTotalBytes),
                truncated: processResult.stdoutTruncated
            ),
            stderr: BoundedOutput(
                text: String(decoding: redactedStderr, as: UTF8.self),
                capturedBytes: UInt(redactedStderr.count),
                totalBytes: UInt(processResult.stderrTotalBytes),
                truncated: processResult.stderrTruncated
            ),
            redactionCount: UInt(redactionValues.count)
        )

        let outcome = processResult.exitCode == 0 ? "completed" : "remote_failure"
        await audit.recordExecution(
            alias: alias, fingerprint: request.fingerprint, outcome: outcome)
        try await requests.transition(id: requestID, to: .completed) {
            $0.executionResult = executionResult
        }
        return executionResult
    }

    private func executionRoute(
        resource: Resource,
        command: CommandSpec,
        privilege: Privilege,
        document: VaultDocument
    ) throws -> ExecutionRoute {
        guard resource.state == .active else {
            throw ExecutionServiceError.resourceNotReady
        }
        if resource.resolvedAccessMethods.contains(.ssh) {
            guard resource.hostIdentity?.status == .trusted else {
                throw ExecutionServiceError.resourceNotReady
            }
            return .ssh
        }

        try localClientAdapter.validate(
            resource: resource,
            command: command,
            privilege: privilege
        )
        try validateLocalCredentialReference(resource: resource, document: document)
        return .localClient
    }

    private func validateLocalCredentialReference(
        resource: Resource,
        document: VaultDocument
    ) throws {
        guard
            let template = ResourceTemplateRegistry.builtIn.template(
                classification: resource.resolvedClassification
            )
        else {
            throw LocalClientAdapterError.capabilityNotSupported
        }
        guard let credentialID = resource.authRef else {
            if template.credentialRequired {
                throw LocalClientAdapterError.credentialUnavailable
            }
            return
        }
        guard let reference = document.credentialReferences.first(where: { $0.id == credentialID }),
            reference.health == .ready,
            reference.securityDomains.contains(resource.securityDomain),
            template.credentialKinds.contains(reference.kind)
        else {
            throw LocalClientAdapterError.credentialUnavailable
        }
    }

    private func resolveLocalCredential(
        resource: Resource,
        document: VaultDocument
    ) async throws -> Data? {
        try validateLocalCredentialReference(resource: resource, document: document)
        guard let credentialID = resource.authRef else { return nil }
        guard let secret = try await passwordStore.readSecret(id: credentialID) else {
            throw LocalClientAdapterError.credentialUnavailable
        }
        return secret
    }

    private static func policyAllowingRegisteredLocalRead(_ policy: Policy) -> Policy {
        let rule = PolicyRule(
            code: "local-client.http.registered-read",
            commandPrefix: ["curl"]
        )
        let automaticRules =
            policy.automaticRules.contains(rule)
            ? policy.automaticRules
            : policy.automaticRules + [rule]
        return Policy(
            id: policy.id,
            version: policy.version,
            automaticRules: automaticRules,
            approvalRules: policy.approvalRules,
            denyRules: policy.denyRules,
            limits: policy.limits
        )
    }

    private struct ResolvedCredential {
        let credential: SSHCredentialContext
        let redactionSecret: Data?
        let binding: String?
        let launchHandler: (@Sendable (Int32) -> Void)?
    }

    private func resolveCredential(
        resource: Resource,
        document: VaultDocument,
        requestID: UUID
    ) async throws -> ResolvedCredential {
        guard let credentialID = resource.authRef,
            let reference = document.credentialReferences.first(where: { $0.id == credentialID }
            )
        else {
            throw ExecutionServiceError.credentialUnavailable
        }
        switch reference.kind {
        case .sshPassword:
            guard let secret = try await passwordStore.readSecret(id: credentialID) else {
                throw ExecutionServiceError.credentialUnavailable
            }
            let token = bindingStore.issue(
                secret: secret,
                requestID: requestID,
                childProcessID: 0,
                expiresAt: Date().addingTimeInterval(60)
            )
            let launchHandler: @Sendable (Int32) -> Void = { [bindingStore] childProcessID in
                try? bindingStore.bind(token: token, childProcessID: childProcessID)
            }
            return ResolvedCredential(
                credential: .password(childBinding: token, askPassExecutable: askPassExecutable),
                redactionSecret: secret,
                binding: token,
                launchHandler: launchHandler
            )
        case .sshOpenSSH:
            let locator = try CanonicalCodec.decode(
                OpenSSHCredentialLocatorV1.self, from: reference.storageLocator,
                maxBytes: 32 * 1_024)
            return ResolvedCredential(
                credential: try locator.credentialContext(),
                redactionSecret: nil,
                binding: nil,
                launchHandler: nil
            )
        default:
            throw ExecutionServiceError.credentialUnavailable
        }
    }

    private func resolveSudoSecret(
        resource: Resource,
        document: VaultDocument
    ) async throws -> Data? {
        guard let sudoCredentialID = resource.sudoRef,
            let reference = document.credentialReferences.first(where: {
                $0.id == sudoCredentialID
            })
        else {
            throw ExecutionServiceError.sudoCredentialRequired
        }
        if reference.publicMaterial == "passwordless" { return nil }
        guard let secret = try await passwordStore.readSecret(id: sudoCredentialID) else {
            throw ExecutionServiceError.sudoCredentialRequired
        }
        return secret
    }

    private static func redact(_ secret: Data, from data: Data) -> Data {
        guard !secret.isEmpty else { return data }
        var result = data
        let replacement = Data("[REDACTED]".utf8)
        while let range = result.range(of: secret) {
            result.replaceSubrange(range, with: replacement)
        }
        return result
    }

    private static func terminationKind(_ termination: ProcessTermination) -> TerminationKind {
        switch termination {
        case .exit: return .exit
        case .signal: return .signal
        case .timeout: return .timeout
        case .cancelled: return .cancel
        }
    }
}
