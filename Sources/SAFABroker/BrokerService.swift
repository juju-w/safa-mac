import Darwin
@preconcurrency import Foundation
import OSLog
import SAFACrypto
import SAFADomain
import SAFAProtocol

public enum BrokerDispatchError: Error, Equatable, Sendable {
    case malformedMessage
    case unsupportedProtocol
    case expired
}

public protocol AgentOperationHandling: Sendable {
    func handle(
        _ operation: AgentClientOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) async -> BrokerReply
}

public protocol TrustedLocalOperationHandling: Sendable {
    func handle(
        _ operation: TrustedLocalOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) async -> BrokerReply
}

public actor UnavailableBrokerHandler: AgentOperationHandling, TrustedLocalOperationHandling {
    public init() {}

    public func handle(
        _ operation: AgentClientOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) -> BrokerReply {
        switch operation {
        case .runtimeStatus:
            BrokerReply(
                messageID: messageID,
                status: .completed,
                data: ["broker": .string("ready"), "vault": .string("not_configured")]
            )
        default:
            unavailable(messageID: messageID)
        }
    }

    public func handle(
        _ operation: TrustedLocalOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) -> BrokerReply {
        unavailable(messageID: messageID)
    }

    private func unavailable(messageID: UUID) -> BrokerReply {
        BrokerReply(
            messageID: messageID,
            status: .userActionRequired,
            error: SAFAErrorPayload(
                code: "trusted_setup_required",
                message: "Complete setup through a trusted local, system-authenticated workflow.",
                retryable: false
            )
        )
    }
}

public actor BrokerRequestDispatcher {
    public static let maximumMessageBytes = 1_048_576
    public static let maximumClockSkew: TimeInterval = 300

    private let agentHandler: any AgentOperationHandling
    private let trustedHandler: any TrustedLocalOperationHandling
    private let resourceDirectoryHandler: any ResourceDirectoryHandling
    private let resourceMutationHandler: any ResourceMutationHandling
    private let topologyQueryHandler: any TopologyQueryHandling
    private let topologyMutationHandler: any TopologyMutationHandling
    private let log: SecurityLog

    public init(
        agentHandler: any AgentOperationHandling,
        trustedHandler: any TrustedLocalOperationHandling,
        resourceDirectoryHandler: any ResourceDirectoryHandling,
        resourceMutationHandler: any ResourceMutationHandling,
        topologyQueryHandler: any TopologyQueryHandling,
        topologyMutationHandler: any TopologyMutationHandling,
        log: SecurityLog = SecurityLog()
    ) {
        self.agentHandler = agentHandler
        self.trustedHandler = trustedHandler
        self.resourceDirectoryHandler = resourceDirectoryHandler
        self.resourceMutationHandler = resourceMutationHandler
        self.topologyQueryHandler = topologyQueryHandler
        self.topologyMutationHandler = topologyMutationHandler
        self.log = log
    }

    public func dispatchAgent(
        _ request: Data,
        caller: CallerIdentity,
        now: Date = Date()
    ) async -> Data {
        do {
            let message = try CanonicalCodec.decode(
                AgentClientMessage.self,
                from: request,
                maxBytes: Self.maximumMessageBytes
            )
            try validate(message.header, now: now)
            return try CanonicalCodec.encode(
                await agentHandler.handle(
                    message.operation,
                    caller: caller,
                    messageID: message.header.messageID
                )
            )
        } catch {
            log.invalidMessage(role: .agent, code: "invalid_message")
            return failureReply(messageID: UUID(), error: error)
        }
    }

    public func dispatchTrustedLocal(
        _ request: Data,
        caller: CallerIdentity,
        now: Date = Date()
    ) async -> Data {
        do {
            let message = try CanonicalCodec.decode(
                TrustedLocalMessage.self,
                from: request,
                maxBytes: Self.maximumMessageBytes
            )
            try validate(message.header, now: now)
            return try CanonicalCodec.encode(
                await trustedHandler.handle(
                    message.operation,
                    caller: caller,
                    messageID: message.header.messageID
                )
            )
        } catch {
            log.invalidMessage(role: .trustedLocal, code: "invalid_message")
            return failureReply(messageID: UUID(), error: error)
        }
    }

    public func dispatchResourceDirectory(
        _ request: Data,
        caller: CallerIdentity,
        now: Date = Date()
    ) async -> Data {
        do {
            let message = try CanonicalCodec.decode(
                ResourceDirectoryRequestV1.self,
                from: request,
                maxBytes: Self.maximumMessageBytes
            )
            try validate(message.header, now: now)
            return try CanonicalCodec.encode(
                await resourceDirectoryHandler.handle(message, caller: caller, now: now)
            )
        } catch {
            log.invalidMessage(role: .agent, code: "invalid_resource_directory_message")
            let code: String
            if case ProtocolCodecError.inputTooLarge = error {
                code = "message_too_large"
            } else if error as? BrokerDispatchError == .expired {
                code = "message_expired"
            } else {
                code = "invalid_message"
            }
            let reply = ResourceDirectoryReplyV1(
                messageID: UUID(),
                status: .failed,
                error: SAFAErrorPayload(
                    code: code,
                    message: "The broker rejected the resource directory request.",
                    retryable: false
                )
            )
            return (try? CanonicalCodec.encode(reply)) ?? Data()
        }
    }

    public func dispatchResourceMutation(
        _ request: Data,
        caller: CallerIdentity,
        now: Date = Date()
    ) async -> Data {
        do {
            let message = try CanonicalCodec.decode(
                ResourceMutationRequestV1.self,
                from: request,
                maxBytes: Self.maximumMessageBytes
            )
            try validate(message.header, now: now)
            return try CanonicalCodec.encode(
                await resourceMutationHandler.handle(message, caller: caller, now: now)
            )
        } catch {
            log.invalidMessage(role: .agent, code: "invalid_resource_mutation_message")
            let code: String
            if case ProtocolCodecError.inputTooLarge = error {
                code = "message_too_large"
            } else if error as? BrokerDispatchError == .expired {
                code = "message_expired"
            } else {
                code = "invalid_message"
            }
            let reply = ResourceMutationReplyV1(
                messageID: UUID(),
                status: .failed,
                error: SAFAErrorPayload(
                    code: code,
                    message: "The broker rejected the resource mutation request.",
                    retryable: false
                )
            )
            return (try? CanonicalCodec.encode(reply)) ?? Data()
        }
    }

    public func dispatchTopologyQuery(
        _ request: Data,
        caller: CallerIdentity,
        now: Date = Date()
    ) async -> Data {
        do {
            let message = try CanonicalCodec.decode(
                TopologyQueryRequestV1.self,
                from: request,
                maxBytes: Self.maximumMessageBytes
            )
            try validate(message.header, now: now)
            return try CanonicalCodec.encode(
                await topologyQueryHandler.query(message, caller: caller, now: now)
            )
        } catch {
            log.invalidMessage(role: .agent, code: "invalid_topology_query_message")
            let reply = TopologyQueryReplyV1(
                messageID: UUID(),
                status: .failed,
                error: SAFAErrorPayload(
                    code: dispatchErrorCode(error),
                    message: "The broker rejected the topology query.",
                    retryable: false
                )
            )
            return (try? CanonicalCodec.encode(reply)) ?? Data()
        }
    }

    public func dispatchTopologyMutation(
        _ request: Data,
        caller: CallerIdentity,
        now: Date = Date()
    ) async -> Data {
        do {
            let message = try CanonicalCodec.decode(
                TopologyMutationRequestV1.self,
                from: request,
                maxBytes: Self.maximumMessageBytes
            )
            try validate(message.header, now: now)
            return try CanonicalCodec.encode(
                await topologyMutationHandler.mutate(message, caller: caller, now: now)
            )
        } catch {
            log.invalidMessage(role: .agent, code: "invalid_topology_mutation_message")
            let reply = TopologyMutationReplyV1(
                messageID: UUID(),
                status: .failed,
                error: SAFAErrorPayload(
                    code: dispatchErrorCode(error),
                    message: "The broker rejected the topology mutation.",
                    retryable: false
                )
            )
            return (try? CanonicalCodec.encode(reply)) ?? Data()
        }
    }

    private func dispatchErrorCode(_ error: any Error) -> String {
        if case ProtocolCodecError.inputTooLarge = error { return "message_too_large" }
        if error as? BrokerDispatchError == .expired { return "message_expired" }
        return "invalid_message"
    }

    private func validate(_ header: IPCHeader, now: Date) throws {
        guard header.protocolVersion == IPCHeader.currentVersion else {
            throw BrokerDispatchError.unsupportedProtocol
        }
        guard
            header.deadline >= now,
            header.sentAt <= now.addingTimeInterval(Self.maximumClockSkew),
            header.sentAt >= now.addingTimeInterval(-Self.maximumClockSkew)
        else {
            throw BrokerDispatchError.expired
        }
    }

    private func failureReply(messageID: UUID, error: any Error) -> Data {
        let code: String
        if case ProtocolCodecError.inputTooLarge = error {
            code = "message_too_large"
        } else if error as? BrokerDispatchError == .expired {
            code = "message_expired"
        } else {
            code = "invalid_message"
        }
        let reply = BrokerReply(
            messageID: messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code,
                message: "The broker rejected the request.",
                retryable: false
            )
        )
        return (try? CanonicalCodec.encode(reply)) ?? Data()
    }
}

private final class ReplyBox: @unchecked Sendable {
    let value: (Data) -> Void

    init(_ value: @escaping (Data) -> Void) {
        self.value = value
    }
}

private final class AgentXPCExport: NSObject, SAFAAgentBrokerXPC, @unchecked Sendable {
    let dispatcher: BrokerRequestDispatcher
    let caller: CallerIdentity

    init(dispatcher: BrokerRequestDispatcher, caller: CallerIdentity) {
        self.dispatcher = dispatcher
        self.caller = caller
    }

    func sendAgentMessage(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            replyBox.value(await dispatcher.dispatchAgent(request, caller: caller))
        }
    }

    func queryResourceDirectory(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            replyBox.value(await dispatcher.dispatchResourceDirectory(request, caller: caller))
        }
    }

    func mutateResource(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            replyBox.value(await dispatcher.dispatchResourceMutation(request, caller: caller))
        }
    }

    func queryTopology(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            replyBox.value(await dispatcher.dispatchTopologyQuery(request, caller: caller))
        }
    }

    func mutateTopology(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            replyBox.value(await dispatcher.dispatchTopologyMutation(request, caller: caller))
        }
    }
}

private final class TrustedLocalXPCExport:
    NSObject, SAFATrustedLocalBrokerXPC, @unchecked Sendable
{
    let dispatcher: BrokerRequestDispatcher
    let caller: CallerIdentity

    init(dispatcher: BrokerRequestDispatcher, caller: CallerIdentity) {
        self.dispatcher = dispatcher
        self.caller = caller
    }

    func sendTrustedLocalMessage(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            replyBox.value(await dispatcher.dispatchTrustedLocal(request, caller: caller))
        }
    }
}

private final class AskPassXPCExport: NSObject, SAFAAskPassBrokerXPC, @unchecked Sendable {
    let bindingStore: ChildCredentialBindingStore
    let askPassProcessID: pid_t

    init(bindingStore: ChildCredentialBindingStore, askPassProcessID: pid_t) {
        self.bindingStore = bindingStore
        self.askPassProcessID = askPassProcessID
    }

    func consumeCredential(_ request: Data, reply: @escaping (Data) -> Void) {
        let replyBox = ReplyBox(reply)
        Task {
            let response: AskPassReply
            do {
                let decoded = try CanonicalCodec.decode(
                    AskPassRequest.self,
                    from: request,
                    maxBytes: 1_024
                )
                guard decoded.protocolVersion == IPCHeader.currentVersion,
                    decoded.binding.utf8.count <= 256,
                    decoded.parentProcessID > 0,
                    Self.parentProcessID(of: askPassProcessID) == decoded.parentProcessID,
                    Self.isSystemSSH(processID: decoded.parentProcessID)
                else {
                    throw ChildCredentialBindingError.childMismatch
                }
                response = AskPassReply(
                    credential: try bindingStore.consume(
                        token: decoded.binding,
                        childProcessID: decoded.parentProcessID
                    )
                )
            } catch {
                response = AskPassReply(errorCode: "child_binding_rejected")
            }
            replyBox.value((try? CanonicalCodec.encode(response)) ?? Data())
        }
    }

    private static func parentProcessID(of processID: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.stride
        let result = proc_pidinfo(processID, PROC_PIDTBSDINFO, 0, &info, Int32(size))
        guard result == size else { return nil }
        return pid_t(info.pbi_ppid)
    }

    private static func isSystemSSH(processID: pid_t) -> Bool {
        var buffer = [CChar](repeating: 0, count: 4_096)
        let count = proc_pidpath(processID, &buffer, UInt32(buffer.count))
        guard count > 0 else { return false }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self) == "/usr/bin/ssh"
    }
}

public final class BrokerListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let role: PeerRole
    private let validator: PeerValidator
    private let dispatcher: BrokerRequestDispatcher
    private let log: SecurityLog
    private let bindingStore: ChildCredentialBindingStore

    public init(
        role: PeerRole,
        validator: PeerValidator,
        dispatcher: BrokerRequestDispatcher,
        bindingStore: ChildCredentialBindingStore,
        log: SecurityLog = SecurityLog()
    ) {
        self.role = role
        self.validator = validator
        self.dispatcher = dispatcher
        self.bindingStore = bindingStore
        self.log = log
    }

    public func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        let caller: CallerIdentity
        do {
            caller = try validator.validate(
                XPCPeerIdentityReader.evidence(for: connection),
                as: role
            )
        } catch let error as PeerValidationError {
            log.peerRejected(role: role, reason: error)
            return false
        } catch {
            return false
        }

        switch role {
        case .agent:
            connection.exportedInterface = NSXPCInterface(with: (any SAFAAgentBrokerXPC).self)
            connection.exportedObject = AgentXPCExport(dispatcher: dispatcher, caller: caller)
        case .trustedLocal:
            connection.exportedInterface = NSXPCInterface(
                with: (any SAFATrustedLocalBrokerXPC).self
            )
            connection.exportedObject = TrustedLocalXPCExport(
                dispatcher: dispatcher,
                caller: caller
            )
        case .askPass:
            connection.exportedInterface = NSXPCInterface(with: (any SAFAAskPassBrokerXPC).self)
            connection.exportedObject = AskPassXPCExport(
                bindingStore: bindingStore,
                askPassProcessID: connection.processIdentifier
            )
        }
        connection.resume()
        return true
    }
}

public final class BrokerService: @unchecked Sendable {
    private let agentListener: NSXPCListener
    private let trustedListener: NSXPCListener
    private let askPassListener: NSXPCListener
    private let agentDelegate: BrokerListenerDelegate
    private let trustedDelegate: BrokerListenerDelegate
    private let askPassDelegate: BrokerListenerDelegate

    public init(
        validator: PeerValidator,
        dispatcher: BrokerRequestDispatcher,
        bindingStore: ChildCredentialBindingStore
    ) throws {
        agentListener = NSXPCListener(machServiceName: BrokerServiceNames.agent)
        trustedListener = NSXPCListener(machServiceName: BrokerServiceNames.trustedLocal)
        askPassListener = NSXPCListener(machServiceName: BrokerServiceNames.askPass)
        agentDelegate = BrokerListenerDelegate(
            role: .agent,
            validator: validator,
            dispatcher: dispatcher,
            bindingStore: bindingStore
        )
        trustedDelegate = BrokerListenerDelegate(
            role: .trustedLocal,
            validator: validator,
            dispatcher: dispatcher,
            bindingStore: bindingStore
        )
        askPassDelegate = BrokerListenerDelegate(
            role: .askPass,
            validator: validator,
            dispatcher: dispatcher,
            bindingStore: bindingStore
        )
        agentListener.delegate = agentDelegate
        trustedListener.delegate = trustedDelegate
        askPassListener.delegate = askPassDelegate
        agentListener.setConnectionCodeSigningRequirement(
            try validator.codeSigningRequirement(for: .agent)
        )
        trustedListener.setConnectionCodeSigningRequirement(
            try validator.codeSigningRequirement(for: .trustedLocal)
        )
        askPassListener.setConnectionCodeSigningRequirement(
            try validator.codeSigningRequirement(for: .askPass)
        )
    }

    public func run() async -> Never {
        agentListener.resume()
        trustedListener.resume()
        askPassListener.resume()
        while true {
            do {
                try await Task.sleep(for: .seconds(3_600))
            } catch {
                Foundation.exit(0)
            }
        }
    }
}

public enum BrokerRuntime {
    private static let startupLog = Logger(subsystem: "dev.safa.broker", category: "startup")

    public static func main() async -> Never {
        BrokerProcessEnvironment.reexecIfNeeded()
        BrokerProcessEnvironment.apply()
        let teamIdentifier: String
        do {
            teamIdentifier = try CodeSigningRequirement.currentTeamIdentifier()
        } catch {
            FileHandle.standardError.write(
                Data("safa-broker: a valid Developer Team signature is required\n".utf8)
            )
            Foundation.exit(45)
        }

        let policy = PeerValidationPolicy(
            brokerUserID: getuid(),
            auditSessionID: currentAuditSessionID(),
            teamIdentifier: teamIdentifier,
            agentSigningIdentifiers: ["dev.safa.cli"],
            trustedLocalSigningIdentifier: "dev.safa.trusted-local"
        )
        let bindingStore = ChildCredentialBindingStore()
        let keychain = DataProtectionKeychainStore()
        let applicationSupport: URL
        do {
            applicationSupport = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            ).appendingPathComponent("SAFA", isDirectory: true)
            try FileManager.default.createDirectory(
                at: applicationSupport,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            Foundation.exit(42)
        }
        let vault = EncryptedVault(
            fileURL: applicationSupport.appendingPathComponent("vault.json"),
            keyStore: keychain
        )
        do {
            _ = try await vault.load()
        } catch VaultError.notInitialized {
            do {
                _ = try await vault.initialize(document: .empty)
            } catch {
                startupLog.error(
                    "vault initialization failed: \(String(describing: error), privacy: .public)"
                )
                Foundation.exit(42)
            }
        } catch {
            startupLog.error(
                "vault load failed: \(String(describing: error), privacy: .public)"
            )
            Foundation.exit(42)
        }
        let askPassExecutable = BrokerRuntimePaths.askPassExecutable(
            bundleURL: Bundle.main.bundleURL,
            executableURL: Bundle.main.executableURL
        )
        let resourceStore = ResourceService(vault: vault, passwordStore: keychain)
        let topology = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: LocalAuthenticationUserPresenceAuthorizer(),
            authorizationReuseInterval: 300,
            mutationGate: resourceStore.mutationGate
        )
        let localClientAvailability = LocalClientAvailability.detected()
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: keychain,
            bindingStore: bindingStore,
            resourceService: resourceStore,
            localClientAdapter: LocalClientAdapter(availability: localClientAvailability),
            trustedSSHVerifier: TrustedSSHPasswordSetupVerifier(
                bindingStore: bindingStore,
                askPassExecutable: askPassExecutable,
                workingDirectory: applicationSupport.appendingPathComponent(
                    "runtime",
                    isDirectory: true
                )
            ),
            topologyReachabilityRecorder: topology,
            askPassExecutable: askPassExecutable,
            workingDirectory: applicationSupport.appendingPathComponent(
                "runtime", isDirectory: true)
        )
        let resourceDirectory = ResourceDirectoryService(
            vault: vault,
            disclosureAuthorizer: ResourceDisclosureAuthorizationService(
                userPresenceAuthorizer: LocalAuthenticationUserPresenceAuthorizer()
            ),
            localClientAvailability: localClientAvailability
        )
        let resourceMutation = ResourceMutationService(
            lifecycle: ResourceLifecycleService(
                resources: resourceStore,
                setup: OpenSSHResourceSetupService(
                    resources: resourceStore,
                    verifier: OpenSSHSetupVerifier(
                        workingDirectory: applicationSupport.appendingPathComponent(
                            "runtime",
                            isDirectory: true
                        )
                    )
                ),
                userPresenceAuthorizer: LocalAuthenticationUserPresenceAuthorizer(),
                authorizationReuseInterval: 300
            )
        )
        let dispatcher = BrokerRequestDispatcher(
            agentHandler: handler,
            trustedHandler: handler,
            resourceDirectoryHandler: resourceDirectory,
            resourceMutationHandler: resourceMutation,
            topologyQueryHandler: topology,
            topologyMutationHandler: topology
        )
        do {
            try await BrokerService(
                validator: PeerValidator(policy: policy),
                dispatcher: dispatcher,
                bindingStore: bindingStore
            ).run()
        } catch {
            Foundation.exit(45)
        }
    }

    private static func currentAuditSessionID() -> UInt32 {
        var information = auditinfo_addr()
        let result = getaudit_addr(
            &information,
            Int32(MemoryLayout<auditinfo_addr>.size)
        )
        guard result == 0 else { Foundation.exit(45) }
        return UInt32(bitPattern: information.ai_asid)
    }
}
