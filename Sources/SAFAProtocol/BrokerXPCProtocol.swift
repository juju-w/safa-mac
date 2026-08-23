import Foundation
import SAFADomain

public enum BrokerServiceNames {
    public static let agent = "dev.safa.broker.agent"
    public static let trustedLocal = "dev.safa.broker.trusted-local"
    public static let askPass = "dev.safa.broker.askpass"
}

@objc(SAFAAgentBrokerXPC)
public protocol SAFAAgentBrokerXPC {
    func sendAgentMessage(_ request: Data, reply: @escaping (Data) -> Void)
    func queryResourceDirectory(_ request: Data, reply: @escaping (Data) -> Void)
    func mutateResource(_ request: Data, reply: @escaping (Data) -> Void)
    func queryTopology(_ request: Data, reply: @escaping (Data) -> Void)
    func mutateTopology(_ request: Data, reply: @escaping (Data) -> Void)
}

@objc(SAFATrustedLocalBrokerXPC)
public protocol SAFATrustedLocalBrokerXPC {
    func sendTrustedLocalMessage(_ request: Data, reply: @escaping (Data) -> Void)
}

@objc(SAFAAskPassBrokerXPC)
public protocol SAFAAskPassBrokerXPC {
    func consumeCredential(_ request: Data, reply: @escaping (Data) -> Void)
}

public struct AskPassRequest: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let binding: String
    public let parentProcessID: Int32

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        binding: String,
        parentProcessID: Int32
    ) {
        self.protocolVersion = protocolVersion
        self.binding = binding
        self.parentProcessID = parentProcessID
    }
}

public struct AskPassReply: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let credential: Data?
    public let errorCode: String?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        credential: Data? = nil,
        errorCode: String? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.credential = credential
        self.errorCode = errorCode
    }
}

public struct IPCHeader: Codable, Equatable, Sendable {
    public static let currentVersion: UInt = 1

    public let protocolVersion: UInt
    public let messageID: UUID
    public let sentAt: Date
    public let deadline: Date

    public init(
        protocolVersion: UInt = Self.currentVersion,
        messageID: UUID = UUID(),
        sentAt: Date,
        deadline: Date
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.sentAt = sentAt
        self.deadline = deadline
    }
}

public enum AgentClientOperation: Codable, Equatable, Sendable {
    case runtimeStatus
    case listResources(state: ResourceState?)
    case submitExecution(
        resourceAlias: ResourceAlias,
        command: CommandSpec,
        privilege: AgentExecutionPrivilegeV2,
        intent: String,
        expectedEffect: String?,
        rollback: String?
    )
    case getRequest(id: UUID)
    case waitRequest(id: UUID, timeoutSeconds: UInt)
    case cancelRequest(id: UUID)
    case listGrants
    case revokeGrant(id: UUID)
    case listAudit(after: String?, limit: UInt)
    case verifyAudit
}

public enum TrustedLocalOperation: Codable, Equatable, Sendable {
    case beginPrivateSetup(resourceAlias: ResourceAlias)
    case commitPrivateSetup(sessionID: UUID, protectedPayload: Data)
    /// Attaches or replaces a sudo credential on an existing, already-active
    /// resource. Unlike `commitPrivateSetup`, this is a single-shot
    /// operation: there is no session, since it never creates a resource.
    case attachSudoCredential(resourceAlias: ResourceAlias, protectedPayload: Data)
    case removeSudoCredential(resourceAlias: ResourceAlias)
    case getApprovalPresentation(requestID: UUID)
    case decideApproval(requestID: UUID, approved: Bool, scope: ApprovalScope?)
    /// Finishes an already system-authenticated sudo approval whose resource did not yet
    /// have a verified sudo credential. The protected payload is accepted only while the
    /// broker holds the short-lived exact grant produced by `decideApproval`.
    case completeSudoApproval(requestID: UUID, protectedPayload: Data)
    case listSensitiveResourceDetails(resourceID: UUID)
    case rotateHostIdentity(resourceID: UUID, protectedPayload: Data)
    case exportRecovery(protectedOptions: Data)
    case importRecovery(protectedPackage: Data)
}

public struct AgentClientMessage: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let operation: AgentClientOperation

    public init(header: IPCHeader, operation: AgentClientOperation) {
        self.header = header
        self.operation = operation
    }
}

public struct TrustedLocalMessage: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let operation: TrustedLocalOperation

    public init(header: IPCHeader, operation: TrustedLocalOperation) {
        self.header = header
        self.operation = operation
    }
}

public enum BrokerReplyStatus: String, Codable, Sendable {
    case completed
    case userActionRequired = "user_action_required"
    case failed
}

public struct BrokerReply: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let messageID: UUID
    public let status: BrokerReplyStatus
    public let data: [String: JSONValue]
    public let error: SAFAErrorPayload?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        messageID: UUID,
        status: BrokerReplyStatus,
        data: [String: JSONValue] = [:],
        error: SAFAErrorPayload? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.status = status
        self.data = data
        self.error = error
    }
}
