import Dispatch
@preconcurrency import Foundation
import SAFADomain
import SAFAProtocol

enum TrustedLocalSetupClientError: Error, Equatable, Sendable {
    case unavailable
    case invalidReply
    case timedOut
    case brokerRejected(String)
}

struct TrustedApprovalPresentation: Sendable {
    let resourceAlias: String
    let privilege: String
    let command: String
    let intent: String
    let expectedEffect: String?
    let riskLevel: String
    let findings: [String]
    let sudoCredentialState: String?
    let approvalState: String
}

enum TrustedApprovalDecisionResult: Sendable {
    case denied
    case sudoCredentialRequired
    case approved(terminationSummary: String)
}

protocol TrustedLocalSetupClient: Sendable {
    func begin(alias: ResourceAlias) async throws -> UUID
    func commit(sessionID: UUID, payload: ProtectedResourceSetupPayload) async throws
    func attachSudo(alias: ResourceAlias, payload: ProtectedSudoCredentialPayload) async throws
    func removeSudo(alias: ResourceAlias) async throws
    func approvalPresentation(requestID: UUID) async throws -> TrustedApprovalPresentation
    func decideApproval(
        requestID: UUID, approved: Bool, scope: ApprovalScope?
    ) async throws -> TrustedApprovalDecisionResult
    func completeSudoApproval(
        requestID: UUID, payload: ProtectedSudoCredentialPayload
    ) async throws -> TrustedApprovalDecisionResult
}

struct XPCTrustedLocalSetupClient: TrustedLocalSetupClient {
    func begin(alias: ResourceAlias) async throws -> UUID {
        let reply = try await send(.beginPrivateSetup(resourceAlias: alias))
        guard reply.status == .completed,
            case let .string(value) = reply.data["setup_session_id"],
            let sessionID = UUID(uuidString: value)
        else {
            throw Self.error(for: reply)
        }
        return sessionID
    }

    func commit(sessionID: UUID, payload: ProtectedResourceSetupPayload) async throws {
        let reply = try await send(
            .commitPrivateSetup(
                sessionID: sessionID,
                protectedPayload: try CanonicalCodec.encode(payload)
            )
        )
        guard reply.status == .completed else { throw Self.error(for: reply) }
    }

    func attachSudo(alias: ResourceAlias, payload: ProtectedSudoCredentialPayload) async throws {
        let reply = try await send(
            .attachSudoCredential(
                resourceAlias: alias,
                protectedPayload: try CanonicalCodec.encode(payload)
            )
        )
        guard reply.status == .completed else { throw Self.error(for: reply) }
    }

    func removeSudo(alias: ResourceAlias) async throws {
        let reply = try await send(.removeSudoCredential(resourceAlias: alias))
        guard reply.status == .completed else { throw Self.error(for: reply) }
    }

    func approvalPresentation(requestID: UUID) async throws -> TrustedApprovalPresentation {
        let reply = try await send(.getApprovalPresentation(requestID: requestID))
        guard reply.status == .completed,
            case let .string(resourceAlias)? = reply.data["resource"],
            case let .string(privilege)? = reply.data["privilege"],
            case let .string(command)? = reply.data["command"],
            case let .string(intent)? = reply.data["intent"],
            case let .string(riskLevel)? = reply.data["risk_level"]
        else {
            throw Self.error(for: reply)
        }
        let expectedEffect: String? = {
            guard case let .string(value)? = reply.data["expected_effect"] else { return nil }
            return value
        }()
        let findings: [String] = {
            guard case let .array(values)? = reply.data["findings"] else { return [] }
            return values.compactMap {
                guard case let .string(value) = $0 else { return nil }
                return value
            }
        }()
        let sudoCredentialState: String? = {
            guard case let .string(value)? = reply.data["sudo_credential_state"] else {
                return nil
            }
            return value
        }()
        let approvalState: String = {
            guard case let .string(value)? = reply.data["approval_state"] else {
                return "awaiting_user_presence"
            }
            return value
        }()
        return TrustedApprovalPresentation(
            resourceAlias: resourceAlias,
            privilege: privilege,
            command: command,
            intent: intent,
            expectedEffect: expectedEffect,
            riskLevel: riskLevel,
            findings: findings,
            sudoCredentialState: sudoCredentialState,
            approvalState: approvalState
        )
    }

    func decideApproval(
        requestID: UUID, approved: Bool, scope: ApprovalScope?
    ) async throws -> TrustedApprovalDecisionResult {
        let reply = try await send(
            .decideApproval(requestID: requestID, approved: approved, scope: scope))
        guard reply.status == .completed, case let .string(decision)? = reply.data["decision"]
        else {
            throw Self.error(for: reply)
        }
        guard decision != "denied" else { return .denied }
        if case .string("sudo_credential_required")? = reply.data["continuation"] {
            return .sudoCredentialRequired
        }
        return Self.approvedResult(reply)
    }

    func completeSudoApproval(
        requestID: UUID,
        payload: ProtectedSudoCredentialPayload
    ) async throws -> TrustedApprovalDecisionResult {
        let reply = try await send(
            .completeSudoApproval(
                requestID: requestID,
                protectedPayload: try CanonicalCodec.encode(payload)
            )
        )
        guard reply.status == .completed else { throw Self.error(for: reply) }
        return Self.approvedResult(reply)
    }

    private static func approvedResult(_ reply: BrokerReply) -> TrustedApprovalDecisionResult {
        var summary = "completed"
        if case let .object(execution)? = reply.data["execution"],
            case let .string(termination)? = execution["termination"]
        {
            let exitCode: String = {
                if case let .integer(code)? = execution["remote_exit_code"] { return "\(code)" }
                return "unknown"
            }()
            summary = "\(termination) (exit \(exitCode))"
        }
        return .approved(terminationSummary: summary)
    }

    private func send(_ operation: TrustedLocalOperation) async throws -> BrokerReply {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let now = Date()
        let message = TrustedLocalMessage(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(180)),
            operation: operation
        )
        let request = try CanonicalCodec.encode(message)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.trustedLocal)
            let box = TrustedSetupReplyBox(connection: connection, continuation: continuation)
            box.scheduleTimeout(after: 185)
            connection.remoteObjectInterface = NSXPCInterface(
                with: (any SAFATrustedLocalBrokerXPC).self
            )
            connection.setCodeSigningRequirement(requirement)
            connection.interruptionHandler = { box.fail(TrustedLocalSetupClientError.unavailable) }
            connection.invalidationHandler = { box.fail(TrustedLocalSetupClientError.unavailable) }
            connection.resume()
            guard
                let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                    box.fail(TrustedLocalSetupClientError.unavailable)
                }) as? any SAFATrustedLocalBrokerXPC
            else {
                box.fail(TrustedLocalSetupClientError.unavailable)
                return
            }
            proxy.sendTrustedLocalMessage(request) { data in
                do {
                    let reply = try CanonicalCodec.decode(
                        BrokerReply.self,
                        from: data,
                        maxBytes: 2 * 1_048_576
                    )
                    guard reply.protocolVersion == IPCHeader.currentVersion,
                        reply.messageID == message.header.messageID
                    else {
                        throw TrustedLocalSetupClientError.invalidReply
                    }
                    box.succeed(reply)
                } catch {
                    box.fail(error)
                }
            }
        }
    }

    private static func error(for reply: BrokerReply) -> TrustedLocalSetupClientError {
        .brokerRejected(reply.error?.code ?? "private_setup_failed")
    }
}

private final class TrustedSetupReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var connection: NSXPCConnection?
    private let continuation: CheckedContinuation<BrokerReply, any Error>

    init(
        connection: NSXPCConnection,
        continuation: CheckedContinuation<BrokerReply, any Error>
    ) {
        self.connection = connection
        self.continuation = continuation
    }

    func succeed(_ reply: BrokerReply) { finish(.success(reply)) }
    func fail(_ error: any Error) { finish(.failure(error)) }

    func scheduleTimeout(after interval: TimeInterval) {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + interval) {
            [weak self] in
            self?.fail(TrustedLocalSetupClientError.timedOut)
        }
    }

    private func finish(_ result: Result<BrokerReply, any Error>) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        let retainedConnection = connection
        connection = nil
        lock.unlock()
        retainedConnection?.invalidate()
        continuation.resume(with: result)
    }
}
