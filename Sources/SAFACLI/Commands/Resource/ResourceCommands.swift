import ArgumentParser
import Foundation
import SAFADomain
import SAFAProtocol

struct ResourceCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [
            ResourceListCommand.self,
            ResourceShowCommand.self,
            ResourceAddCommand.self,
            ResourceEditCommand.self,
            ResourceRemoveCommand.self,
            ResourceSudoCommand.self,
        ]
    )

    mutating func run() async throws {
        do {
            let reply = try await XPCBrokerAgentClient().queryResourceDirectory(action: .list)
            try finishDirectory(command: "resource.list", reply: reply)
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            try brokerFailure(command: "resource.list")
        }
    }
}

protocol ResourceDirectoryCommand: AgentCommand {}

extension AgentCommand {
    func finishDirectory(
        command: String,
        reply: ResourceDirectoryReplyV1,
        limit: Int = 100,
        fields: [AgentResourceListFieldV2] = AgentResourceListFieldV2.defaultFields
    ) throws {
        if command == "resource.list" {
            let total = reply.status == .completed ? reply.summaries.count : 0
            let rows =
                reply.status == .completed
                ? reply.summaries.prefix(limit).map(\.agentRow)
                : []
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: try AgentResourceListV2(
                        total: total,
                        truncated: total > rows.count,
                        resources: rows,
                        fields: fields
                    ),
                    error: reply.error?.agentError,
                    next: rows.isEmpty
                        ? []
                        : [
                            AgentNextCommandV2(
                                command: "safa resource show <alias>",
                                reason: "Inspect one safe resource summary",
                                safeForAgent: true
                            )
                        ]
                )
            )
            return
        }
        if let details = reply.details {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: AgentResourceDetailsPayloadV2(resource: details.agentDetails),
                    error: reply.error?.agentError
                )
            )
            return
        }
        if let summary = reply.summaries.first {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: AgentResourceSummaryPayloadV2(resource: summary.agentSummary),
                    error: reply.error?.agentError
                )
            )
            return
        }
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: reply.agentStatus,
                payload: AgentNoPayloadV2(),
                error: reply.error?.agentError
            )
        )
    }

    func finishMutation(command: String, reply: ResourceMutationReplyV1) throws {
        let protectedCommand: String
        if case let .string(value) = reply.error?.details["trusted_local_command"] {
            protectedCommand = value
        } else {
            protectedCommand = "complete resource setup in the trusted local workflow"
        }
        let next =
            reply.status == .userActionRequired
            ? [
                AgentNextCommandV2(
                    command: protectedCommand,
                    reason: reply.error?.message ?? "Local setup is required",
                    safeForAgent: false
                )
            ]
            : []
        if let summary = reply.summary {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: AgentResourceSummaryPayloadV2(resource: summary.agentSummary),
                    error: reply.error?.agentError,
                    next: next
                )
            )
            return
        }
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: reply.agentStatus,
                payload: AgentNoPayloadV2(),
                error: reply.error?.agentError,
                next: next
            )
        )
    }
}

private extension ResourceDirectoryReplyV1 {
    var agentStatus: AgentCLIStatusV2 {
        switch status {
        case .completed: .completed
        case .denied: .denied
        case .failed: .failed
        }
    }
}

private extension ResourceMutationReplyV1 {
    var agentStatus: AgentCLIStatusV2 {
        switch status {
        case .completed: .completed
        case .userActionRequired: .userActionRequired
        case .denied: .denied
        case .failed: .failed
        }
    }
}
struct ResourceSudoCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "sudo",
        abstract:
            "Inspect, enroll, verify, or remove a resource's protected sudo access.",
        discussion:
            "Status is a safe broker read. Lifecycle operations launch the separately signed safa-trusted-setup helper; password entry and macOS user-presence happen in the system terminal, and no protected value reaches the agent channel."
    )
    @Argument(completion: ResourceCLICompletion.resourceAliases) var alias: String
    @Flag(help: "Read safe sudo enrollment state without launching the trusted helper.")
    var status = false
    @Flag(help: "Require NOPASSWD sudo; never fall back to collecting a password.")
    var passwordless = false
    @Flag(help: "Remove the stored sudo credential.") var remove = false

    mutating func validate() throws {
        guard [status, passwordless, remove].filter({ $0 }).count <= 1 else {
            throw ValidationError("--status, --passwordless, and --remove are mutually exclusive.")
        }
    }

    func run() async throws {
        guard let target = try? ResourceAlias(alias) else {
            try invalidInvocation(
                command: "resource.sudo", message: "The resource alias is invalid.")
        }
        if status {
            do {
                let directory = try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .show,
                    alias: target
                )
                try finishSudoStatus(reply: directory)
            } catch let exit as ExitCode {
                throw exit
            } catch {
                try brokerFailure(command: "resource.sudo.status")
            }
            return
        }
        if !remove {
            do {
                let directory = try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .show,
                    alias: target
                )
                if try shouldSkipEnrollment(reply: directory) { return }
            } catch let exit as ExitCode {
                throw exit
            } catch {
                try brokerFailure(command: "resource.sudo")
            }
        }
        do {
            try await BundledTrustedResourceSetupLauncher().launchSudo(
                alias: target, passwordless: passwordless, remove: remove)
        } catch TrustedResourceSetupLauncherError.helperUnavailable {
            try finish(
                Self.runtimeFailure(
                    code: "runtime.trusted_helper_unavailable",
                    message: "The trusted local sudo enrollment helper is unavailable."
                )
            )
        } catch TrustedResourceSetupLauncherError.helperIdentityInvalid {
            try finish(
                Self.runtimeFailure(
                    code: "runtime.trusted_helper_identity_invalid",
                    message:
                        "The trusted local sudo enrollment helper failed identity verification."
                )
            )
        } catch TrustedResourceSetupLauncherError.setupIncomplete {
            try finish(
                Self.localActionRequired(
                    alias: target,
                    passwordless: passwordless,
                    remove: remove
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try finish(
                Self.runtimeFailure(
                    code: "runtime.trusted_helper_launch_failed",
                    message: "The trusted local sudo enrollment helper could not be launched."
                )
            )
            return
        }

        do {
            let directory = try await XPCBrokerAgentClient().queryResourceDirectory(
                action: .show,
                alias: target
            )
            try finishDirectory(command: "resource.sudo", reply: directory)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "resource.sudo")
        }
    }

    static func trustedLocalCommand(
        alias: ResourceAlias,
        passwordless: Bool,
        remove: Bool
    ) -> String {
        var arguments = ["safa", "resource", "sudo", alias.rawValue]
        if passwordless { arguments.append("--passwordless") }
        if remove { arguments.append("--remove") }
        return arguments.joined(separator: " ")
    }

    static func localActionRequired(
        alias: ResourceAlias,
        passwordless: Bool,
        remove: Bool
    ) -> AgentCLIResponseV2<AgentNoPayloadV2> {
        AgentCLIResponseV2(
            command: "resource.sudo",
            status: .userActionRequired,
            payload: AgentNoPayloadV2(),
            error: AgentCLIErrorV2(
                code: "sudo.enrollment_incomplete",
                message:
                    "Complete sudo credential enrollment in a trusted local terminal, then inspect the resource again.",
                retryable: true
            ),
            next: [
                AgentNextCommandV2(
                    command: trustedLocalCommand(
                        alias: alias,
                        passwordless: passwordless,
                        remove: remove
                    ),
                    reason: "A local user must complete the protected sudo credential flow",
                    safeForAgent: false
                )
            ]
        )
    }

    static func statusResponse(
        summary: ResourceSummaryV1,
        command: String = "resource.sudo.status",
        responseStatus: AgentCLIStatusV2 = .completed
    ) -> AgentCLIResponseV2<AgentSudoStatusV2> {
        let hasSudoCapability = summary.capabilities.contains("sudo")
        let accountIsRoot = booleanMetadata("host.account.is-root", in: summary)
        let state: String
        if accountIsRoot == true {
            state = "not_required"
        } else if !hasSudoCapability {
            state = "missing"
        } else if summary.sudoMode == nil {
            state = "invalid"
        } else {
            state = "ready"
        }
        let next =
            ["ready", "not_required"].contains(state)
            ? []
            : [
                AgentNextCommandV2(
                    command: "safa resource sudo \(summary.alias)",
                    reason: state == "missing"
                        ? "Enroll protected sudo access in a trusted local terminal"
                        : "Repair the incomplete sudo credential in a trusted local terminal",
                    safeForAgent: false
                )
            ]
        return AgentCLIResponseV2(
            command: command,
            status: responseStatus,
            payload: AgentSudoStatusV2(
                alias: summary.alias,
                state: state,
                mode: summary.sudoMode,
                accountIsRoot: accountIsRoot
            ),
            next: next
        )
    }

    static func rootAccountEnrollmentNoOp(
        summary: ResourceSummaryV1
    ) -> AgentCLIResponseV2<AgentSudoStatusV2>? {
        guard booleanMetadata("host.account.is-root", in: summary) == true else {
            return nil
        }
        return statusResponse(
            summary: summary,
            command: "resource.sudo",
            responseStatus: .noOp
        )
    }

    private static func booleanMetadata(
        _ key: String,
        in summary: ResourceSummaryV1
    ) -> Bool? {
        guard let entry = summary.metadata.first(where: { $0.key == key }),
            case let .boolean(value) = entry.value
        else {
            return nil
        }
        return value
    }

    private func finishSudoStatus(reply: ResourceDirectoryReplyV1) throws {
        guard reply.status == .completed else {
            try finish(
                AgentCLIResponseV2(
                    command: "resource.sudo.status",
                    status: reply.agentStatus,
                    payload: AgentNoPayloadV2(),
                    error: reply.error?.agentError
                )
            )
            return
        }
        guard let summary = reply.summaries.first else {
            try finish(Self.invalidBrokerReply(command: "resource.sudo.status"))
            return
        }
        try finish(Self.statusResponse(summary: summary))
    }

    private func shouldSkipEnrollment(reply: ResourceDirectoryReplyV1) throws -> Bool {
        guard reply.status == .completed else {
            try finish(
                AgentCLIResponseV2(
                    command: "resource.sudo",
                    status: reply.agentStatus,
                    payload: AgentNoPayloadV2(),
                    error: reply.error?.agentError
                )
            )
            return true
        }
        guard let summary = reply.summaries.first else {
            try finish(Self.invalidBrokerReply(command: "resource.sudo"))
            return true
        }
        guard let response = Self.rootAccountEnrollmentNoOp(summary: summary) else { return false }
        try finish(response)
        return true
    }

    private static func invalidBrokerReply(
        command: String
    ) -> AgentCLIResponseV2<AgentNoPayloadV2> {
        AgentCLIResponseV2(
            command: command,
            status: .failed,
            payload: AgentNoPayloadV2(),
            error: AgentCLIErrorV2(
                code: "runtime.invalid_broker_reply",
                message: "The signed local broker returned an incomplete sudo status.",
                retryable: false
            )
        )
    }

    private static func runtimeFailure(
        code: String,
        message: String
    ) -> AgentCLIResponseV2<AgentNoPayloadV2> {
        AgentCLIResponseV2(
            command: "resource.sudo",
            status: .failed,
            payload: AgentNoPayloadV2(),
            error: AgentCLIErrorV2(code: code, message: message, retryable: false)
        )
    }
}
