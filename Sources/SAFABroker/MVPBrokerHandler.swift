import Foundation
import OSLog
import SAFACrypto
import SAFADomain
import SAFAPolicy
import SAFAProtocol
import SAFASSH
import SAFATransport

public actor MVPBrokerHandler: AgentOperationHandling, TrustedLocalOperationHandling {
    private static let log = Logger(subsystem: "dev.safa.broker", category: "sudo-enrollment")
    private let vault: any VaultDocumentStoring
    private let passwordStore: any PasswordSecretStoring
    private let resourceService: ResourceService
    private let bindingStore: ChildCredentialBindingStore
    private let transport: SSHTransport
    private let diagnosticPolicy: DiagnosticCommandPolicy
    private let audit: AuditService
    private let askPassExecutable: URL
    private let workingDirectory: URL
    private let trustedResourceSetup: TrustedResourceSetupService
    private let topologyReachabilityRecorder: (any TopologyReachabilityRecording)?
    private let sudoVerifier: any SudoCredentialVerifying
    private let requestService: RequestService
    private let grantService: GrantService
    private let executionService: ExecutionService
    private let approvalService: ApprovalService
    private let localClientAvailability: LocalClientAvailability
    /// Exact grants whose user-presence check succeeded but whose first sudo execution is
    /// waiting for a verified credential from the same trusted-local workflow.
    private var pendingSudoApprovalGrants: [UUID: ApprovalGrant] = [:]

    public init(
        vault: any VaultDocumentStoring,
        passwordStore: any PasswordSecretStoring,
        bindingStore: ChildCredentialBindingStore,
        resourceService: ResourceService? = nil,
        transport: SSHTransport = SSHTransport(),
        localProcessRunner: any ProcessRunning = ProcessRunner(),
        localClientAdapter: LocalClientAdapter = LocalClientAdapter(),
        diagnosticPolicy: DiagnosticCommandPolicy = DiagnosticCommandPolicy(),
        audit: AuditService = AuditService(),
        trustedSSHVerifier: (any TrustedSSHResourceVerifying)? = nil,
        sudoVerifier: (any SudoCredentialVerifying)? = nil,
        sudoExecutor: (any SudoExecuting)? = nil,
        topologyReachabilityRecorder: (any TopologyReachabilityRecording)? = nil,
        requestService: RequestService? = nil,
        grantService: GrantService? = nil,
        approvalAuthenticator: (any ApprovalAuthenticating)? = nil,
        askPassExecutable: URL,
        workingDirectory: URL
    ) {
        self.vault = vault
        self.passwordStore = passwordStore
        let resolvedResourceService =
            resourceService
            ?? ResourceService(vault: vault, passwordStore: passwordStore)
        self.resourceService = resolvedResourceService
        trustedResourceSetup = TrustedResourceSetupService(
            resources: resolvedResourceService,
            sshVerifier: trustedSSHVerifier
        )
        self.bindingStore = bindingStore
        self.transport = transport
        self.diagnosticPolicy = diagnosticPolicy
        self.audit = audit
        self.topologyReachabilityRecorder = topologyReachabilityRecorder
        self.sudoVerifier =
            sudoVerifier
            ?? SudoCredentialVerifier(transport: transport, workingDirectory: workingDirectory)
        self.askPassExecutable = askPassExecutable
        self.workingDirectory = workingDirectory
        localClientAvailability = localClientAdapter.availability

        let resolvedRequestService = requestService ?? RequestService()
        let resolvedGrantService = grantService ?? GrantService()
        self.requestService = resolvedRequestService
        self.grantService = resolvedGrantService
        executionService = ExecutionService(
            vault: vault,
            passwordStore: passwordStore,
            bindingStore: bindingStore,
            transport: transport,
            localProcessRunner: localProcessRunner,
            localClientAdapter: localClientAdapter,
            sudoExecutor: sudoExecutor ?? SudoExecutor(transport: transport),
            resourceService: resolvedResourceService,
            audit: audit,
            askPassExecutable: askPassExecutable,
            workingDirectory: workingDirectory,
            requests: resolvedRequestService,
            grants: resolvedGrantService,
            topologyReachabilityRecorder: topologyReachabilityRecorder
        )
        approvalService = ApprovalService(
            requests: resolvedRequestService,
            authenticator: approvalAuthenticator ?? ApprovalAuthenticator()
        )
    }

    public func handle(
        _ operation: AgentClientOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) async -> BrokerReply {
        do {
            switch operation {
            case .runtimeStatus:
                _ = try await vault.readDocument()
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: [
                        "broker": .string("ready"),
                        "vault": .string("ready"),
                        "http_client": .string(localClientAvailability.http.rawValue),
                    ]
                )
            case let .listResources(state):
                let registry = try ResourceRegistry(
                    resources: try await vault.readDocument().resources)
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: [
                        "resources": .array(
                            registry.list(state: state).map {
                                Self.jsonProjection(
                                    $0,
                                    localClientAvailability: localClientAvailability
                                )
                            }
                        )
                    ]
                )
            case let .submitExecution(
                resourceAlias,
                command,
                privilege,
                intent,
                expectedEffect,
                rollback
            ):
                return try await handleSubmitExecution(
                    alias: resourceAlias,
                    command: command,
                    privilege: privilege,
                    intent: intent,
                    expectedEffect: expectedEffect,
                    rollback: rollback,
                    caller: caller,
                    messageID: messageID
                )
            case let .getRequest(id):
                return try await requestReply(id: id, messageID: messageID)
            case let .waitRequest(id, timeoutSeconds):
                return try await waitRequestReply(
                    id: id, timeoutSeconds: timeoutSeconds, messageID: messageID)
            case let .cancelRequest(id):
                return try await cancelRequestReply(id: id, messageID: messageID)
            case .listGrants:
                return await listGrantsReply(caller: caller, messageID: messageID)
            case let .revokeGrant(id):
                return await revokeGrantReply(id: id, messageID: messageID)
            case .listAudit, .verifyAudit:
                return unsupported(messageID: messageID)
            }
        } catch ResourceRegistryError.notFound(let alias) {
            return failure(
                messageID: messageID,
                code: "resource_not_found",
                message: "The requested resource is not registered.",
                details: ["resource": .string(alias)]
            )
        } catch {
            return failure(
                messageID: messageID,
                code: "runtime_failure",
                message: "The broker could not complete the request."
            )
        }
    }

    public func handle(
        _ operation: TrustedLocalOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) async -> BrokerReply {
        do {
            switch operation {
            case let .beginPrivateSetup(resourceAlias):
                let sessionID = await trustedResourceSetup.begin(
                    alias: resourceAlias,
                    caller: caller
                )
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["setup_session_id": .string(sessionID.uuidString)]
                )
            case let .commitPrivateSetup(sessionID, protectedPayload):
                let resource = try await trustedResourceSetup.commit(
                    sessionID: sessionID,
                    caller: caller,
                    protectedPayload: protectedPayload
                )
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["resource": .string(resource.alias.rawValue)]
                )
            case let .attachSudoCredential(resourceAlias, protectedPayload):
                return try await attachSudoCredential(
                    alias: resourceAlias,
                    protectedPayload: protectedPayload,
                    messageID: messageID
                )
            case let .removeSudoCredential(resourceAlias):
                let resource = try await resourceService.removeSudoCredential(alias: resourceAlias)
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["resource": .string(resource.alias.rawValue)]
                )
            case let .getApprovalPresentation(requestID):
                return try await approvalPresentationReply(
                    requestID: requestID, messageID: messageID)
            case let .decideApproval(requestID, approved, scope):
                return try await decideApprovalReply(
                    requestID: requestID, approved: approved, scope: scope, messageID: messageID)
            case let .completeSudoApproval(requestID, protectedPayload):
                return try await completeSudoApprovalReply(
                    requestID: requestID,
                    protectedPayload: protectedPayload,
                    messageID: messageID
                )
            case .listSensitiveResourceDetails, .rotateHostIdentity, .exportRecovery,
                .importRecovery:
                return unsupported(messageID: messageID)
            }
        } catch TrustedResourceSetupError.invalidSession {
            return failure(
                messageID: messageID,
                code: "setup_session_invalid",
                message: "The private setup session is invalid or expired."
            )
        } catch TrustedResourceSetupError.invalidPayload {
            return failure(
                messageID: messageID,
                code: "invalid_setup",
                message: "The trusted setup values are invalid."
            )
        } catch TrustedResourceSetupError.unsupportedTemplate {
            return failure(
                messageID: messageID,
                code: "resource_template_unknown",
                message: "The requested resource template is not installed."
            )
        } catch {
            return failure(
                messageID: messageID,
                code: "private_setup_failed",
                message: "The trusted setup transaction failed."
            )
        }
    }

    /// Verifies a sudo credential against the resource's already-established
    /// SSH login before persisting anything, mirroring the verify-then-write
    /// ordering `TrustedResourceSetupService` uses for the primary
    /// credential. The secret only ever reaches `SudoCredentialVerifier`
    /// (broker-internal) and `ResourceService.enrollSudoCredential`
    /// (Keychain write) — never audit, never a reply payload.
    private func attachSudoCredential(
        alias: ResourceAlias,
        protectedPayload: Data,
        messageID: UUID
    ) async throws -> BrokerReply {
        let payload = try CanonicalCodec.decode(
            ProtectedSudoCredentialPayload.self,
            from: protectedPayload,
            maxBytes: 32 * 1_024
        )
        let document = try await vault.readDocument()
        guard
            let resource = document.resources.first(where: {
                $0.alias == alias && $0.state != .deleted
            })
        else {
            return failure(
                messageID: messageID,
                code: "resource_not_found",
                message: "The requested resource is not registered."
            )
        }
        guard let primaryCredentialID = resource.authRef,
            let primaryReference = document.credentialReferences.first(where: {
                $0.id == primaryCredentialID
            })
        else {
            return failure(
                messageID: messageID,
                code: "sudo_requires_primary_credential",
                message: "Enroll the resource's primary SSH credential before adding sudo."
            )
        }

        let requestID = UUID()
        let primaryCredential: SSHCredentialContext
        var issuedBinding = false
        switch primaryReference.kind {
        case .sshPassword:
            guard let secret = try await passwordStore.readSecret(id: primaryCredentialID) else {
                return failure(
                    messageID: messageID,
                    code: "resource_not_ready",
                    message: "The resource needs trusted setup or repair."
                )
            }
            let token = bindingStore.issue(
                secret: secret,
                requestID: requestID,
                childProcessID: 0,
                expiresAt: Date().addingTimeInterval(60)
            )
            primaryCredential = .password(childBinding: token, askPassExecutable: askPassExecutable)
            issuedBinding = true
        case .sshOpenSSH:
            let locator = try CanonicalCodec.decode(
                OpenSSHCredentialLocatorV1.self,
                from: primaryReference.storageLocator,
                maxBytes: 32 * 1_024
            )
            primaryCredential = try locator.credentialContext()
        default:
            return failure(
                messageID: messageID,
                code: "resource_not_ready",
                message: "The resource authentication adapter is not available."
            )
        }

        let verified: Bool
        do {
            if payload.passwordlessConfirmed {
                verified = try await sudoVerifier.verifyPasswordless(
                    resource: resource,
                    primaryCredential: primaryCredential
                )
            } else if let secret = payload.secret {
                verified = try await sudoVerifier.verifyPassword(
                    resource: resource,
                    primaryCredential: primaryCredential,
                    sudoSecret: secret
                )
            } else {
                verified = false
            }
        } catch {
            if issuedBinding { bindingStore.revoke(requestID: requestID) }
            Self.log.error(
                "sudo verification threw: \(error) for \(alias.rawValue, privacy: .public)"
            )
            return failure(
                messageID: messageID,
                code: "sudo_verification_failed",
                message: "The sudo credential could not be verified over SSH."
            )
        }
        if issuedBinding { bindingStore.revoke(requestID: requestID) }

        guard verified else {
            Self.log.error(
                "sudo verification returned false for \(alias.rawValue, privacy: .public)"
            )
            return failure(
                messageID: messageID,
                code: "sudo_credential_invalid",
                message: "The sudo credential was rejected by the remote host."
            )
        }

        let mode: ResourceService.SudoEnrollmentMode =
            payload.passwordlessConfirmed ? .passwordless : .password(payload.secret ?? Data())
        let updated = try await resourceService.enrollSudoCredential(alias: alias, mode: mode)
        return BrokerReply(
            messageID: messageID,
            status: .completed,
            data: ["resource": .string(updated.alias.rawValue)]
        )
    }

    private func handleSubmitExecution(
        alias: ResourceAlias,
        command: CommandSpec,
        privilege: AgentExecutionPrivilegeV2,
        intent: String,
        expectedEffect: String?,
        rollback: String?,
        caller: CallerIdentity,
        messageID: UUID
    ) async throws -> BrokerReply {
        guard !intent.isEmpty else {
            return failure(
                messageID: messageID,
                code: "intent_required",
                message: "An intent is required to submit execution."
            )
        }
        let outcome: ExecutionSubmissionOutcome
        do {
            outcome = try await executionService.submit(
                alias: alias,
                command: command,
                privilege: privilege,
                intent: intent,
                expectedEffect: expectedEffect,
                rollback: rollback,
                caller: caller
            )
        } catch ExecutionServiceError.resourceNotReady, ExecutionServiceError.credentialUnavailable
        {
            return failure(
                messageID: messageID,
                code: "resource_not_ready",
                message: "The resource needs trusted setup or repair."
            )
        } catch ResourceRegistryError.notFound {
            return failure(
                messageID: messageID,
                code: "resource_not_found",
                message: "No registered resource matches that alias."
            )
        } catch ExecutionServiceError.sudoCredentialRequired {
            return failure(
                messageID: messageID,
                code: "sudo_credential_required",
                message:
                    "Enroll a verified sudo credential for this resource before requesting sudo execution."
            )
        } catch LocalClientAdapterError.capabilityNotSupported {
            return failure(
                messageID: messageID,
                code: "capability_not_supported",
                message: "This resource does not expose the requested execution capability."
            )
        } catch LocalClientAdapterError.clientNotInstalled {
            return failure(
                messageID: messageID,
                code: "client_not_installed",
                message: "The required verified local client is unavailable or incompatible."
            )
        } catch LocalClientAdapterError.commandNotAllowed {
            return failure(
                messageID: messageID,
                code: "local_command_not_allowed",
                message: "The requested operation is not allowed for this resource adapter."
            )
        } catch LocalClientAdapterError.endpointInvalid {
            return failure(
                messageID: messageID,
                code: "resource_endpoint_invalid",
                message: "The registered resource endpoint needs repair."
            )
        } catch LocalClientAdapterError.credentialUnavailable {
            return failure(
                messageID: messageID,
                code: "resource_not_ready",
                message: "The resource needs trusted setup or repair."
            )
        } catch LocalClientAdapterError.credentialTransportInsecure {
            return failure(
                messageID: messageID,
                code: "credential_transport_insecure",
                message: "The registered credential requires HTTPS or a verified protected route."
            )
        } catch LocalClientAdapterError.privilegeNotSupported {
            return failure(
                messageID: messageID,
                code: "privilege_not_supported",
                message: "The requested privilege is not supported by this resource adapter."
            )
        }

        switch outcome {
        case let .completed(requestID, result):
            return BrokerReply(
                messageID: messageID,
                status: .completed,
                data: [
                    "request_id": .string(requestID.uuidString),
                    "resource": .string(alias.rawValue),
                    "intent": .string(String(intent.prefix(1_024))),
                    "expected_effect": expectedEffect.map { .string(String($0.prefix(1_024))) }
                        ?? .null,
                    "rollback": rollback.map { .string(String($0.prefix(1_024))) } ?? .null,
                    "execution": Self.jsonProjection(result),
                ]
            )
        case let .awaitingApproval(requestID):
            var data: [String: JSONValue] = [
                "request_id": .string(requestID.uuidString),
                "resource": .string(alias.rawValue),
            ]
            // The effective privilege is already frozen in the Broker-held immutable request.
            // Exposing only this non-secret label lets the CLI distinguish a prompt-only
            // registered-account review from a sudo review that may require protected terminal
            // input. Missing request state fails closed to the existing human handoff.
            if let request = await requestService.get(id: requestID) {
                data["privilege"] = .string(request.privilege.rawValue)
            }
            return BrokerReply(
                messageID: messageID,
                status: .userActionRequired,
                data: data,
                error: SAFAErrorPayload(
                    code: "approval_required",
                    message: "This command requires trusted local approval before it can run.",
                    retryable: false,
                    details: ["request_id": .string(requestID.uuidString)]
                )
            )
        case let .denied(requestID, findings):
            return failure(
                messageID: messageID,
                code: "policy.denied",
                message: "Policy denied this command.",
                details: [
                    "request_id": .string(requestID.uuidString),
                    "findings": .array(findings.map { .string($0.code) }),
                ]
            )
        }
    }

    private func requestReply(id: UUID, messageID: UUID) async throws -> BrokerReply {
        guard let request = await requestService.get(id: id) else {
            return failure(
                messageID: messageID,
                code: "request_not_found",
                message: "The requested execution request is not registered."
            )
        }
        return Self.jsonProjection(
            request,
            resourceAlias: await requestService.resourceAlias(requestID: id),
            messageID: messageID
        )
    }

    private func waitRequestReply(
        id: UUID, timeoutSeconds: UInt, messageID: UUID
    ) async throws -> BrokerReply {
        do {
            let request = try await requestService.wait(id: id, timeoutSeconds: timeoutSeconds)
            return Self.jsonProjection(
                request,
                resourceAlias: await requestService.resourceAlias(requestID: id),
                messageID: messageID
            )
        } catch RequestServiceError.notFound {
            return failure(
                messageID: messageID,
                code: "request_not_found",
                message: "The requested execution request is not registered."
            )
        }
    }

    private func cancelRequestReply(id: UUID, messageID: UUID) async throws -> BrokerReply {
        do {
            let request = try await requestService.cancel(id: id)
            pendingSudoApprovalGrants.removeValue(forKey: id)
            return Self.jsonProjection(
                request,
                resourceAlias: await requestService.resourceAlias(requestID: id),
                messageID: messageID
            )
        } catch RequestServiceError.notFound {
            return failure(
                messageID: messageID,
                code: "request_not_found",
                message: "The requested execution request is not registered."
            )
        } catch RequestServiceError.invalidTransition {
            return failure(
                messageID: messageID,
                code: "request_not_cancellable",
                message: "This request has already reached a terminal state."
            )
        }
    }

    private func listGrantsReply(caller: CallerIdentity, messageID: UUID) async -> BrokerReply {
        let activeGrants = await grantService.list(callerBinding: caller)
        return BrokerReply(
            messageID: messageID,
            status: .completed,
            data: ["grants": .array(activeGrants.map(Self.jsonProjection))]
        )
    }

    private func revokeGrantReply(id: UUID, messageID: UUID) async -> BrokerReply {
        do {
            let grant = try await grantService.revoke(id: id)
            return BrokerReply(
                messageID: messageID,
                status: .completed,
                data: ["grant": Self.jsonProjection(grant)]
            )
        } catch {
            return failure(
                messageID: messageID,
                code: "grant_not_found",
                message: "The requested grant is not registered."
            )
        }
    }

    private func approvalPresentationReply(
        requestID: UUID, messageID: UUID
    ) async throws -> BrokerReply {
        do {
            let presentation = try await approvalService.presentation(requestID: requestID)
            let credentialState = try await sudoCredentialState(requestID: requestID)
            var data = Self.jsonProjection(presentation)
            data["sudo_credential_state"] = credentialState.map(JSONValue.string) ?? .null
            data["approval_state"] = .string(
                pendingSudoApprovalGrants[requestID] == nil
                    ? "awaiting_user_presence" : "credential_required"
            )
            return BrokerReply(
                messageID: messageID,
                status: .completed,
                data: data
            )
        } catch ApprovalServiceError.requestNotFound {
            return failure(
                messageID: messageID,
                code: "request_not_found",
                message: "The requested execution request is not registered."
            )
        } catch ApprovalServiceError.requestNotAwaitingApproval {
            return failure(
                messageID: messageID,
                code: "request_not_awaiting_approval",
                message: "This request is not currently awaiting approval."
            )
        } catch ApprovalServiceError.riskAssessmentMissing {
            return failure(
                messageID: messageID,
                code: "risk_assessment_missing",
                message: "No risk assessment is recorded for this request."
            )
        }
    }

    private func decideApprovalReply(
        requestID: UUID,
        approved: Bool,
        scope: ApprovalScope?,
        messageID: UUID
    ) async throws -> BrokerReply {
        let document = try await vault.readDocument()
        let policy = document.policies.first ?? ExecutionService.defaultPolicy
        do {
            guard
                let grant = try await approvalService.decide(
                    requestID: requestID,
                    approved: approved,
                    scope: scope,
                    policyVersion: policy.version
                )
            else {
                pendingSudoApprovalGrants.removeValue(forKey: requestID)
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["decision": .string("denied")]
                )
            }

            if try await sudoCredentialState(requestID: requestID) == "missing" {
                pendingSudoApprovalGrants[requestID] = grant
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: [
                        "decision": .string("approved"),
                        "continuation": .string("sudo_credential_required"),
                    ]
                )
            }
            let result = try await executionService.runApproved(
                requestID: requestID, grant: grant)
            return BrokerReply(
                messageID: messageID,
                status: .completed,
                data: ["decision": .string("approved"), "execution": Self.jsonProjection(result)]
            )
        } catch ApprovalServiceError.requestNotFound {
            return failure(
                messageID: messageID,
                code: "request_not_found",
                message: "The requested execution request is not registered."
            )
        } catch ApprovalServiceError.requestNotAwaitingApproval {
            return failure(
                messageID: messageID,
                code: "request_not_awaiting_approval",
                message: "This request is not currently awaiting approval."
            )
        } catch ApprovalServiceError.authorizationDenied {
            return failure(
                messageID: messageID,
                code: "authorization_denied",
                message: "Local authentication did not succeed."
            )
        } catch ApprovalServiceError.invalidScope {
            return failure(
                messageID: messageID,
                code: "invalid_scope",
                message: "The requested approval scope is not valid for this request."
            )
        } catch ApprovalServiceError.riskAssessmentMissing {
            return failure(
                messageID: messageID,
                code: "risk_assessment_missing",
                message: "No risk assessment is recorded for this request."
            )
        } catch ExecutionServiceError.resourceNotReady {
            return failure(
                messageID: messageID,
                code: "request_resource_changed",
                message: "The resource changed after this request was approved."
            )
        }
    }

    /// Completes the credential half of a single trusted-local approval. The caller cannot
    /// reach this operation through the Agent XPC role, and possession of a request id is not
    /// authority: the broker must also hold the unexpired exact grant created after successful
    /// LocalAuthentication for this request.
    private func completeSudoApprovalReply(
        requestID: UUID,
        protectedPayload: Data,
        messageID: UUID
    ) async throws -> BrokerReply {
        guard let request = await requestService.get(id: requestID),
            request.privilege == .sudo,
            request.state == .approvedByUser,
            let grant = pendingSudoApprovalGrants[requestID]
        else {
            return failure(
                messageID: messageID,
                code: "approval_session_invalid",
                message: "The authenticated sudo approval session is unavailable."
            )
        }
        guard grant.expiresAt > Date(),
            grant.monotonicDeadlineNanoseconds > DispatchTime.now().uptimeNanoseconds
        else {
            pendingSudoApprovalGrants.removeValue(forKey: requestID)
            _ = try? await requestService.transition(id: requestID, to: .expired)
            return failure(
                messageID: messageID,
                code: "approval_session_expired",
                message: "The authenticated sudo approval session expired."
            )
        }
        guard let alias = await requestService.resourceAlias(requestID: requestID) else {
            return failure(
                messageID: messageID,
                code: "request_not_found",
                message: "The requested execution request is not registered."
            )
        }

        let beforeDocument = try await vault.readDocument()
        let beforeResource = try ResourceRegistry(resources: beforeDocument.resources).resource(
            alias: alias)
        guard beforeResource.id == request.resourceID,
            beforeResource.revision == request.resourceRevision
        else {
            pendingSudoApprovalGrants.removeValue(forKey: requestID)
            _ = try? await requestService.transition(id: requestID, to: .expired)
            return failure(
                messageID: messageID,
                code: "request_resource_changed",
                message: "The resource changed after this request was approved."
            )
        }

        let enrollment = try await attachSudoCredential(
            alias: alias,
            protectedPayload: protectedPayload,
            messageID: messageID
        )
        guard enrollment.status == .completed else { return enrollment }

        let afterDocument = try await vault.readDocument()
        let afterResource = try ResourceRegistry(resources: afterDocument.resources).resource(
            alias: alias)
        guard afterResource.id == request.resourceID,
            afterResource.revision == request.resourceRevision + 1
        else {
            pendingSudoApprovalGrants.removeValue(forKey: requestID)
            _ = try? await requestService.transition(id: requestID, to: .expired)
            return failure(
                messageID: messageID,
                code: "request_resource_changed",
                message: "The resource changed while sudo setup was completing."
            )
        }

        guard grant.expiresAt > Date(),
            grant.monotonicDeadlineNanoseconds > DispatchTime.now().uptimeNanoseconds
        else {
            pendingSudoApprovalGrants.removeValue(forKey: requestID)
            _ = try? await requestService.transition(id: requestID, to: .expired)
            return failure(
                messageID: messageID,
                code: "approval_session_expired",
                message: "The authenticated sudo approval session expired."
            )
        }

        pendingSudoApprovalGrants.removeValue(forKey: requestID)
        let result = try await executionService.runApproved(
            requestID: requestID,
            grant: grant,
            expectedResourceRevision: afterResource.revision
        )
        return BrokerReply(
            messageID: messageID,
            status: .completed,
            data: ["decision": .string("approved"), "execution": Self.jsonProjection(result)]
        )
    }

    private func sudoCredentialState(requestID: UUID) async throws -> String? {
        guard let request = await requestService.get(id: requestID), request.privilege == .sudo
        else { return nil }
        guard let alias = await requestService.resourceAlias(requestID: requestID) else {
            throw ExecutionServiceError.requestNotFound
        }
        let document = try await vault.readDocument()
        let resource = try ResourceRegistry(resources: document.resources).resource(alias: alias)
        guard let credentialID = resource.sudoRef,
            document.credentialReferences.contains(where: {
                $0.id == credentialID && $0.health == .ready
            })
        else { return "missing" }
        return "ready"
    }

    private static func jsonProjection(
        _ request: ExecutionRequest,
        resourceAlias: ResourceAlias?,
        messageID: UUID
    )
        -> BrokerReply
    {
        var data: [String: JSONValue] = [
            "request_id": .string(request.id.uuidString),
            "state": .string(request.state.rawValue),
            "resource": resourceAlias.map { .string($0.rawValue) } ?? .null,
            "intent": .string(String(request.intent.prefix(1_024))),
        ]
        if let result = request.executionResult {
            data["execution"] = jsonProjection(result)
        }
        switch request.state {
        case .completed:
            return BrokerReply(messageID: messageID, status: .completed, data: data)
        case .denied, .failed, .timedOut, .cancelled, .expired:
            return BrokerReply(
                messageID: messageID,
                status: .failed,
                data: data,
                error: SAFAErrorPayload(
                    code: "request_\(request.state.rawValue)",
                    message: "The request ended in state \(request.state.rawValue).",
                    retryable: false
                )
            )
        default:
            return BrokerReply(messageID: messageID, status: .userActionRequired, data: data)
        }
    }

    private static func jsonProjection(_ result: ExecutionResult) -> JSONValue {
        .object([
            "termination": .string(terminationLabel(result.termination)),
            "remote_exit_code": result.remoteExitCode.map { .integer(Int64($0)) } ?? .null,
            "stdout": jsonProjection(result.stdout),
            "stderr": jsonProjection(result.stderr),
        ])
    }

    private static func jsonProjection(_ output: BoundedOutput) -> JSONValue {
        .object([
            "text": .string(output.text),
            "captured_bytes": .integer(Int64(output.capturedBytes)),
            "original_bytes": .integer(Int64(output.totalBytes ?? output.capturedBytes)),
            "truncated": .boolean(output.truncated),
        ])
    }

    /// `TerminationKind.cancel`'s raw value ("cancel") does not match the Agent CLI's existing
    /// string check ("cancelled", inherited from `ProcessTermination.cancelled`); translate at
    /// the boundary rather than touching either enum's raw values.
    private static func terminationLabel(_ termination: TerminationKind) -> String {
        termination == .cancel ? "cancelled" : termination.rawValue
    }

    private static func jsonProjection(_ grant: ApprovalGrant) -> JSONValue {
        .object([
            "id": .string(grant.id.uuidString),
            "privilege_ceiling": .string(grant.privilegeCeiling.rawValue),
            "state": .string(grant.state.rawValue),
            "uses": .integer(Int64(grant.uses)),
            "max_uses": grant.maxUses.map { .integer(Int64($0)) } ?? .null,
            "expires_at": .string(ISO8601DateFormatter().string(from: grant.expiresAt)),
        ])
    }

    private static func jsonProjection(_ presentation: ApprovalPresentation) -> [String:
        JSONValue]
    {
        [
            "request_id": .string(presentation.requestID.uuidString),
            "resource": .string(presentation.resourceAlias.rawValue),
            "privilege": .string(presentation.privilege.rawValue),
            "command": .string(presentation.commandDescription),
            "intent": .string(presentation.intent),
            "expected_effect": presentation.expectedEffect.map(JSONValue.string) ?? .null,
            "risk_level": .string(presentation.riskLevel.rawValue),
            "findings": .array(presentation.findings.map { .string($0.code) }),
        ]
    }

    private static func jsonProjection(
        _ resource: SafeResourceProjection,
        localClientAvailability: LocalClientAvailability
    ) -> JSONValue {
        .object([
            "alias": .string(resource.alias.rawValue),
            "transport": resource.transport.map { .string($0.rawValue) } ?? .null,
            "state": .string(resource.state.rawValue),
            "capabilities": .array(
                localClientAvailability.effectiveCapabilities(for: resource).map(JSONValue.string)
            ),
            "health": .string(resource.health.rawValue),
        ])
    }

    private func unsupported(messageID: UUID) -> BrokerReply {
        failure(
            messageID: messageID,
            code: "not_available_in_mvp",
            message: "This operation is not available in the diagnostic MVP."
        )
    }

    private func failure(
        messageID: UUID,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> BrokerReply {
        BrokerReply(
            messageID: messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code,
                message: message,
                retryable: false,
                details: details
            )
        )
    }
}
