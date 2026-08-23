import Foundation

public enum DomainValidationError: Error, Equatable, Sendable {
    case invalidResourceAlias
    case invalidCommand(String)
    case invalidTransition
}

public struct ResourceAlias: Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        let allowed =
            rawValue.range(
                of: "^[a-z0-9.-]{1,64}$",
                options: .regularExpression
            ) != nil
        guard allowed else { throw DomainValidationError.invalidResourceAlias }
        self.rawValue = rawValue
    }
}

public enum TransportKind: String, Codable, Sendable {
    case ssh
}

public struct ResourceEndpoint: Codable, Equatable, Sendable {
    public let scheme: String?
    public let host: String
    public let port: UInt16
    public let path: String?

    public init(
        scheme: String? = nil,
        host: String,
        port: UInt16 = 22,
        path: String? = nil
    ) {
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
    }
}

public enum ResourceState: String, Codable, Sendable {
    case draft
    case active
    case disabled
    case deleted

    public func canTransition(to next: Self) -> Bool {
        switch (self, next) {
        case (.draft, .active), (.active, .disabled), (.disabled, .active):
            true
        case (.draft, .deleted), (.active, .deleted), (.disabled, .deleted):
            true
        default:
            false
        }
    }
}

public enum HostIdentityStatus: String, Codable, Sendable {
    case trusted
    case changed
    case revoked
}

public enum HostVerificationMethod: String, Codable, Sendable {
    case manual
    case trustedImport = "trusted_import"
    case rotationApproval = "rotation_approval"
}

public struct HostIdentity: Codable, Equatable, Sendable {
    public let algorithm: String
    public let publicKey: Data
    public let fingerprint: String
    public let verifiedAt: Date
    public let verificationMethod: HostVerificationMethod
    public let status: HostIdentityStatus

    public init(
        algorithm: String,
        publicKey: Data,
        fingerprint: String,
        verifiedAt: Date,
        verificationMethod: HostVerificationMethod,
        status: HostIdentityStatus
    ) {
        self.algorithm = algorithm
        self.publicKey = publicKey
        self.fingerprint = fingerprint
        self.verifiedAt = verifiedAt
        self.verificationMethod = verificationMethod
        self.status = status
    }
}

public struct CredentialKind: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        let isLegacyIdentifier =
            rawValue.range(
                of: "^[a-z][a-z0-9_]{0,63}$",
                options: .regularExpression
            ) != nil
        guard NamespacedIdentifier.validate(rawValue, maximumLength: 64) || isLegacyIdentifier
        else {
            throw ResourceDirectoryValidationError.invalidIdentifier(rawValue)
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: String) {
        try? self.init(rawValue)
    }

    public init(from decoder: any Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static let sshSecureEnclaveKey = try! Self("ssh_secure_enclave_key")
    public static let sshPassword = try! Self("ssh_password")
    public static let sshOpenSSH = try! Self("ssh.open-ssh")
    public static let sudoPassword = try! Self("sudo_password")
    public static let databasePassword = try! Self("database.password")
    public static let objectStorageAccessKey = try! Self("object-storage.access-key")
    public static let apiToken = try! Self("service.api-token")
}

public enum CredentialAccessClass: String, Codable, Sendable {
    case automaticWithinPolicy = "automatic_within_policy"
    case userPresenceRequired = "user_presence_required"
}

public enum CredentialHealth: String, Codable, Sendable {
    case pending
    case ready
    case locked
    case invalid
    case reenrollRequired = "reenroll_required"
}

public struct CredentialReference: Codable, Equatable, Sendable {
    public let id: UUID
    public let kind: CredentialKind
    public let storageLocator: Data
    public let publicMaterial: String?
    public let securityDomains: Set<String>
    public let accessClass: CredentialAccessClass
    public let health: CredentialHealth
    public let createdAt: Date
    public let lastUsedAt: Date?

    public init(
        id: UUID,
        kind: CredentialKind,
        storageLocator: Data,
        publicMaterial: String? = nil,
        securityDomains: Set<String>,
        accessClass: CredentialAccessClass,
        health: CredentialHealth,
        createdAt: Date,
        lastUsedAt: Date? = nil
    ) {
        self.id = id
        self.kind = kind
        self.storageLocator = storageLocator
        self.publicMaterial = publicMaterial
        self.securityDomains = securityDomains
        self.accessClass = accessClass
        self.health = health
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
    }
}

public enum ResourceVerificationStatus: String, Codable, Sendable {
    case verified
    case failed
}

public struct ResourceVerification: Codable, Equatable, Sendable {
    public let status: ResourceVerificationStatus
    public let adapter: AccessMethodIdentifier
    public let checkedAt: Date

    public init(
        status: ResourceVerificationStatus,
        adapter: AccessMethodIdentifier,
        checkedAt: Date
    ) {
        self.status = status
        self.adapter = adapter
        self.checkedAt = checkedAt
    }
}

public struct Resource: Codable, Equatable, Sendable {
    public let id: UUID
    public let alias: ResourceAlias
    /// Optional on disk so vault documents created before the resource-directory
    /// upgrade continue to decode through legacy SSH-host defaults.
    public var profile: ResourceProfile?
    public var displayName: String?
    public let transport: TransportKind?
    public var endpoint: ResourceEndpoint?
    public var username: String?
    public var jumpRoute: [UUID]
    public var securityDomain: String
    public var hostIdentity: HostIdentity?
    /// Broker-owned proof that a non-SSH adapter reached the expected service.
    /// Optional for compatibility with vault documents written before service adapters existed.
    public var verification: ResourceVerification?
    public var authRef: UUID?
    public var sudoRef: UUID?
    public var policyRef: UUID?
    public var revision: UInt64
    public var state: ResourceState
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID,
        alias: ResourceAlias,
        resourceType: ResourceTypeIdentifier = .hostLinux,
        classification: ResourceClassification? = nil,
        alternateAliases: [ResourceAlias] = [],
        accessMethods: [AccessMethodIdentifier] = [.ssh],
        metadata: [ResourceMetadataEntry] = [],
        relationships: [ResourceRelationship] = [],
        credentialBindings: [ResourceCredentialBinding] = [],
        displayName: String? = nil,
        transport: TransportKind? = .ssh,
        endpoint: ResourceEndpoint? = nil,
        username: String? = nil,
        jumpRoute: [UUID] = [],
        securityDomain: String,
        hostIdentity: HostIdentity? = nil,
        verification: ResourceVerification? = nil,
        authRef: UUID? = nil,
        sudoRef: UUID? = nil,
        policyRef: UUID? = nil,
        revision: UInt64 = 0,
        state: ResourceState = .draft,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.id = id
        self.alias = alias
        self.profile = ResourceProfile(
            classification: classification ?? .migratingLegacyType(resourceType),
            alternateAliases: alternateAliases,
            accessMethods: accessMethods,
            metadata: metadata,
            relationships: relationships,
            credentialBindings: credentialBindings
        )
        self.displayName = displayName
        self.transport = transport
        self.endpoint = endpoint
        self.username = username
        self.jumpRoute = jumpRoute
        self.securityDomain = securityDomain
        self.hostIdentity = hostIdentity
        self.verification = verification
        self.authRef = authRef
        self.sudoRef = sudoRef
        self.policyRef = policyRef
        self.revision = revision
        self.state = state
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public var resolvedResourceType: ResourceTypeIdentifier {
        profile?.resourceType ?? .hostLinux
    }

    public var resolvedClassification: ResourceClassification {
        profile?.classification ?? .host(platform: .linux)
    }

    public var resolvedKind: ResourceKindIdentifier {
        resolvedClassification.kind
    }

    public var resolvedTemplate: ResourceTemplateBinding {
        resolvedClassification.template
    }

    public var resolvedHostPlatform: HostPlatform? {
        resolvedClassification.hostPlatform
    }

    public var resolvedRoles: [ResourceRoleIdentifier] {
        resolvedClassification.roles
    }

    public var resolvedAlternateAliases: [ResourceAlias] {
        profile?.alternateAliases ?? []
    }

    public var resolvedAccessMethods: [AccessMethodIdentifier] {
        profile?.accessMethods ?? [AccessMethodIdentifier.ssh]
    }

    public var resolvedMetadata: [ResourceMetadataEntry] {
        profile?.metadata ?? []
    }

    public var resolvedRelationships: [ResourceRelationship] {
        profile?.relationships ?? []
    }

    public var resolvedCredentialBindings: [ResourceCredentialBinding] {
        profile?.credentialBindings ?? []
    }
}

public enum CommandMode: String, Codable, Sendable {
    case exec
    case shell
}

public enum StdinMode: String, Codable, Sendable {
    case none
    case brokerControlled = "broker_controlled"
    case boundedAgentData = "bounded_agent_data"
}

public struct CommandSpec: Codable, Equatable, Sendable {
    public let mode: CommandMode
    public let arguments: [String]?
    public let shellProgram: String?
    public let stdinMode: StdinMode
    public let tty: Bool
    public let workingDirectory: String?
    public let timeoutSeconds: UInt
    public let outputLimitBytes: UInt

    private init(
        mode: CommandMode,
        arguments: [String]?,
        shellProgram: String?,
        stdinMode: StdinMode,
        tty: Bool,
        workingDirectory: String?,
        timeoutSeconds: UInt,
        outputLimitBytes: UInt
    ) {
        self.mode = mode
        self.arguments = arguments
        self.shellProgram = shellProgram
        self.stdinMode = stdinMode
        self.tty = tty
        self.workingDirectory = workingDirectory
        self.timeoutSeconds = timeoutSeconds
        self.outputLimitBytes = outputLimitBytes
    }

    public static func exec(
        arguments: [String],
        stdinMode: StdinMode = .none,
        tty: Bool = false,
        workingDirectory: String? = nil,
        timeoutSeconds: UInt = 60,
        outputLimitBytes: UInt = 1_048_576
    ) throws -> Self {
        guard !arguments.isEmpty, arguments[0].utf8.count <= 4_096 else {
            throw DomainValidationError.invalidCommand("exec requires a bounded argument vector")
        }
        return Self(
            mode: .exec,
            arguments: arguments,
            shellProgram: nil,
            stdinMode: stdinMode,
            tty: tty,
            workingDirectory: workingDirectory,
            timeoutSeconds: timeoutSeconds,
            outputLimitBytes: outputLimitBytes
        )
    }

    public static func shell(
        program: String,
        stdinMode: StdinMode = .none,
        tty: Bool = false,
        workingDirectory: String? = nil,
        timeoutSeconds: UInt = 60,
        outputLimitBytes: UInt = 1_048_576
    ) throws -> Self {
        guard !program.isEmpty, program.utf8.count <= 65_536 else {
            throw DomainValidationError.invalidCommand("shell requires a bounded program")
        }
        return Self(
            mode: .shell,
            arguments: nil,
            shellProgram: program,
            stdinMode: stdinMode,
            tty: tty,
            workingDirectory: workingDirectory,
            timeoutSeconds: timeoutSeconds,
            outputLimitBytes: outputLimitBytes
        )
    }
}

public enum Privilege: String, Codable, Sendable {
    case user
    case sudo
}

public struct CallerIdentity: Codable, Equatable, Sendable {
    public let signingIdentifier: String
    public let teamIdentifier: String
    public let effectiveUserID: UInt32
    public let auditSessionID: UInt32
    public let agentSession: String?

    public init(
        signingIdentifier: String,
        teamIdentifier: String,
        effectiveUserID: UInt32,
        auditSessionID: UInt32,
        agentSession: String? = nil
    ) {
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.effectiveUserID = effectiveUserID
        self.auditSessionID = auditSessionID
        self.agentSession = agentSession
    }
}

public enum RequestState: String, Codable, Sendable {
    case created
    case evaluating
    case approvedByPolicy = "approved_by_policy"
    case awaitingApproval = "awaiting_approval"
    case approvedByUser = "approved_by_user"
    case denied
    case running
    case completed
    case failed
    case timedOut = "timed_out"
    case cancelled
    case expired

    public func canTransition(to next: Self) -> Bool {
        switch (self, next) {
        case (.created, .evaluating): true
        case (.evaluating, .approvedByPolicy), (.evaluating, .awaitingApproval),
            (.evaluating, .denied):
            true
        case (.awaitingApproval, .approvedByUser), (.awaitingApproval, .denied),
            (.awaitingApproval, .cancelled), (.awaitingApproval, .expired):
            true
        case (.approvedByPolicy, .running), (.approvedByPolicy, .cancelled),
            (.approvedByPolicy, .expired):
            true
        case (.approvedByUser, .running), (.approvedByUser, .cancelled),
            (.approvedByUser, .expired):
            true
        case (.running, .completed), (.running, .failed), (.running, .timedOut),
            (.running, .cancelled):
            true
        default: false
        }
    }
}

public struct ExecutionRequest: Codable, Equatable, Sendable {
    public let id: UUID
    public let caller: CallerIdentity
    public let resourceID: UUID
    public let resourceRevision: UInt64
    public let command: CommandSpec
    public let privilege: Privilege
    public let intent: String
    public let expectedEffect: String?
    public let rollback: String?
    public let fingerprint: String
    public var riskAssessmentID: UUID?
    public var state: RequestState
    public let createdAt: Date
    public let deadline: Date
    public var executionResult: ExecutionResult?

    public init(
        id: UUID,
        caller: CallerIdentity,
        resourceID: UUID,
        resourceRevision: UInt64,
        command: CommandSpec,
        privilege: Privilege,
        intent: String,
        expectedEffect: String? = nil,
        rollback: String? = nil,
        fingerprint: String,
        riskAssessmentID: UUID? = nil,
        state: RequestState = .created,
        createdAt: Date,
        deadline: Date,
        executionResult: ExecutionResult? = nil
    ) {
        self.id = id
        self.caller = caller
        self.resourceID = resourceID
        self.resourceRevision = resourceRevision
        self.command = command
        self.privilege = privilege
        self.intent = intent
        self.expectedEffect = expectedEffect
        self.rollback = rollback
        self.fingerprint = fingerprint
        self.riskAssessmentID = riskAssessmentID
        self.state = state
        self.createdAt = createdAt
        self.deadline = deadline
        self.executionResult = executionResult
    }
}

public enum RiskLevel: String, Codable, Sendable {
    case low
    case medium
    case high
    case critical
}

public enum RequiredApproval: String, Codable, Sendable {
    case none
    case userPresence = "user_presence"
    case explicitFullAccess = "explicit_full_access"
}

public struct Finding: Codable, Equatable, Sendable {
    public let code: String
    public let detail: String?

    public init(code: String, detail: String? = nil) {
        self.code = code
        self.detail = detail
    }
}

public struct RiskAssessment: Codable, Equatable, Sendable {
    public let id: UUID
    public let policyVersion: String
    public let level: RiskLevel
    public let findings: [Finding]
    public let requiredApproval: RequiredApproval
    public let agentReview: String?
    public let evaluatedAt: Date

    public init(
        id: UUID,
        policyVersion: String,
        level: RiskLevel,
        findings: [Finding],
        requiredApproval: RequiredApproval,
        agentReview: String? = nil,
        evaluatedAt: Date
    ) {
        self.id = id
        self.policyVersion = policyVersion
        self.level = level
        self.findings = findings
        self.requiredApproval = requiredApproval
        self.agentReview = agentReview
        self.evaluatedAt = evaluatedAt
    }
}

public enum ApprovalScope: Codable, Equatable, Sendable {
    case exact(fingerprint: String)
    case prefix(arguments: [String])
    case fullAccess
}

public enum GrantState: String, Codable, Sendable {
    case active
    case consumed
    case expired
    case revoked
    case invalidated
}

public struct ApprovalProof: Codable, Equatable, Sendable {
    public let method: String
    public let authenticatedAt: Date

    public init(method: String, authenticatedAt: Date) {
        self.method = method
        self.authenticatedAt = authenticatedAt
    }
}

public struct ApprovalGrant: Codable, Equatable, Sendable {
    public let id: UUID
    public let capabilityHash: String
    public let scope: ApprovalScope
    public let callerBinding: CallerIdentity
    public let resourceID: UUID
    public let resourceRevision: UInt64
    public let privilegeCeiling: Privilege
    public let policyVersion: String
    public let maxUses: UInt?
    public var uses: UInt
    public let issuedAt: Date
    public let expiresAt: Date
    public let monotonicDeadlineNanoseconds: UInt64
    public let approvalProof: ApprovalProof
    public var state: GrantState

    public init(
        id: UUID,
        capabilityHash: String,
        scope: ApprovalScope,
        callerBinding: CallerIdentity,
        resourceID: UUID,
        resourceRevision: UInt64,
        privilegeCeiling: Privilege,
        policyVersion: String,
        maxUses: UInt? = nil,
        uses: UInt = 0,
        issuedAt: Date,
        expiresAt: Date,
        monotonicDeadlineNanoseconds: UInt64,
        approvalProof: ApprovalProof,
        state: GrantState = .active
    ) {
        self.id = id
        self.capabilityHash = capabilityHash
        self.scope = scope
        self.callerBinding = callerBinding
        self.resourceID = resourceID
        self.resourceRevision = resourceRevision
        self.privilegeCeiling = privilegeCeiling
        self.policyVersion = policyVersion
        self.maxUses = maxUses
        self.uses = uses
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.monotonicDeadlineNanoseconds = monotonicDeadlineNanoseconds
        self.approvalProof = approvalProof
        self.state = state
    }
}

/// The immutable, system-authenticated rendering of a pending request that the trusted-local
/// approval flow shows the user before it will accept a decision. Contains nothing the Agent
/// did not already submit or that policy did not already compute — it exists to give the user
/// one unambiguous, non-scriptable view of exactly what they are approving, distinct from
/// anything the Agent could construct in chat.
public struct ApprovalPresentation: Codable, Equatable, Sendable {
    public let requestID: UUID
    public let resourceAlias: ResourceAlias
    public let privilege: Privilege
    public let commandDescription: String
    public let intent: String
    public let expectedEffect: String?
    public let riskLevel: RiskLevel
    public let findings: [Finding]

    public init(
        requestID: UUID,
        resourceAlias: ResourceAlias,
        privilege: Privilege,
        commandDescription: String,
        intent: String,
        expectedEffect: String?,
        riskLevel: RiskLevel,
        findings: [Finding]
    ) {
        self.requestID = requestID
        self.resourceAlias = resourceAlias
        self.privilege = privilege
        self.commandDescription = commandDescription
        self.intent = intent
        self.expectedEffect = expectedEffect
        self.riskLevel = riskLevel
        self.findings = findings
    }
}

public struct PolicyRule: Codable, Equatable, Sendable {
    public let code: String
    public let commandPrefix: [String]

    public init(code: String, commandPrefix: [String]) {
        self.code = code
        self.commandPrefix = commandPrefix
    }
}

public struct ExecutionLimits: Codable, Equatable, Sendable {
    public let maximumTimeoutSeconds: UInt
    public let maximumOutputBytes: UInt
    public let maximumConcurrentRequests: UInt
    public let allowsTTY: Bool

    public init(
        maximumTimeoutSeconds: UInt,
        maximumOutputBytes: UInt,
        maximumConcurrentRequests: UInt,
        allowsTTY: Bool
    ) {
        self.maximumTimeoutSeconds = maximumTimeoutSeconds
        self.maximumOutputBytes = maximumOutputBytes
        self.maximumConcurrentRequests = maximumConcurrentRequests
        self.allowsTTY = allowsTTY
    }
}

public struct Policy: Codable, Equatable, Sendable {
    public let id: UUID
    public let version: String
    public let automaticRules: [PolicyRule]
    public let approvalRules: [PolicyRule]
    public let denyRules: [PolicyRule]
    public let limits: ExecutionLimits

    public init(
        id: UUID,
        version: String,
        automaticRules: [PolicyRule],
        approvalRules: [PolicyRule],
        denyRules: [PolicyRule],
        limits: ExecutionLimits
    ) {
        self.id = id
        self.version = version
        self.automaticRules = automaticRules
        self.approvalRules = approvalRules
        self.denyRules = denyRules
        self.limits = limits
    }
}

public enum TerminationKind: String, Codable, Sendable {
    case exit
    case signal
    case timeout
    case cancel
    case transportFailure = "transport_failure"
}

public struct BoundedOutput: Codable, Equatable, Sendable {
    public let text: String
    public let encoding: String
    public let capturedBytes: UInt
    public let totalBytes: UInt?
    public let truncated: Bool

    public init(
        text: String,
        encoding: String = "utf-8",
        capturedBytes: UInt,
        totalBytes: UInt? = nil,
        truncated: Bool
    ) {
        self.text = text
        self.encoding = encoding
        self.capturedBytes = capturedBytes
        self.totalBytes = totalBytes
        self.truncated = truncated
    }
}

public struct ExecutionResult: Codable, Equatable, Sendable {
    public let startedAt: Date
    public let finishedAt: Date
    public let remoteExitCode: Int32?
    public let termination: TerminationKind
    public let stdout: BoundedOutput
    public let stderr: BoundedOutput
    public let transportError: String?
    public let redactionCount: UInt

    public init(
        startedAt: Date,
        finishedAt: Date,
        remoteExitCode: Int32? = nil,
        termination: TerminationKind,
        stdout: BoundedOutput,
        stderr: BoundedOutput,
        transportError: String? = nil,
        redactionCount: UInt = 0
    ) {
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.remoteExitCode = remoteExitCode
        self.termination = termination
        self.stdout = stdout
        self.stderr = stderr
        self.transportError = transportError
        self.redactionCount = redactionCount
    }
}

public enum AuditEventKind: String, Codable, Sendable {
    case request
    case decision
    case approval
    case execution
    case revocation
    case vault
    case integrity
    case package
}

public struct AuditEvent: Codable, Equatable, Sendable {
    public let sequence: UInt64
    public let id: UUID
    public let kind: AuditEventKind
    public let timestamp: Date
    public let requestID: UUID?
    public let grantID: UUID?
    public let actor: String
    public let resourceAlias: ResourceAlias?
    public let summary: [String: String]
    public let previousDigest: String?
    public let digest: String

    public init(
        sequence: UInt64,
        id: UUID,
        kind: AuditEventKind,
        timestamp: Date,
        requestID: UUID? = nil,
        grantID: UUID? = nil,
        actor: String,
        resourceAlias: ResourceAlias? = nil,
        summary: [String: String],
        previousDigest: String? = nil,
        digest: String
    ) {
        self.sequence = sequence
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.requestID = requestID
        self.grantID = grantID
        self.actor = actor
        self.resourceAlias = resourceAlias
        self.summary = summary
        self.previousDigest = previousDigest
        self.digest = digest
    }
}

public struct VaultDocument: Codable, Equatable, Sendable {
    public let schemaVersion: UInt
    public var resources: [Resource]
    public var credentialReferences: [CredentialReference]
    public var policies: [Policy]
    public var pendingRequests: [ExecutionRequest]
    public var activeGrants: [ApprovalGrant]
    public var settings: [String: String]
    public var appliedMigrations: [String]
    /// Broker-owned topology state. Optional so pre-topology vaults decode unchanged.
    public var topologyGraph: TopologyGraph?

    public init(
        schemaVersion: UInt,
        resources: [Resource],
        credentialReferences: [CredentialReference] = [],
        policies: [Policy] = [],
        pendingRequests: [ExecutionRequest] = [],
        activeGrants: [ApprovalGrant] = [],
        settings: [String: String] = [:],
        appliedMigrations: [String] = [],
        topologyGraph: TopologyGraph? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.resources = resources
        self.credentialReferences = credentialReferences
        self.policies = policies
        self.pendingRequests = pendingRequests
        self.activeGrants = activeGrants
        self.settings = settings
        self.appliedMigrations = appliedMigrations
        self.topologyGraph = topologyGraph
    }

    public static let empty = Self(schemaVersion: 1, resources: [])
}
