import ArgumentParser
import Foundation
import SAFAProtocol

struct RequestCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "request",
        abstract: "Inspect or wait on a submitted execution request awaiting trusted approval.",
        subcommands: [
            RequestGetCommand.self, RequestWaitCommand.self, RequestReviewCommand.self,
            RequestCancelCommand.self,
        ]
    )
}

/// Stable human entry point for the separately signed trusted-local helper. This command
/// carries only an opaque request id, cannot decide approval itself, and is deliberately
/// returned to Agents with `safe_for_agent: false`.
struct RequestReviewCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "review",
        abstract: "Review and authorize one immutable request in the trusted local workflow."
    )
    @Argument(help: "The request id returned by `safa exec`.") var id: String

    func run() async throws {
        guard let requestID = UUID(uuidString: id) else {
            try invalidInvocation(command: "request.review", message: "Not a valid request id.")
        }
        do {
            try await BundledTrustedResourceSetupLauncher().launchApproval(requestID: requestID)
            let reply = try await XPCBrokerAgentClient().send(.getRequest(id: requestID))
            try finishBrokerReply(command: "request.review", reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try finish(
                AgentCLIResponseV2(
                    command: "request.review",
                    status: .userActionRequired,
                    requestID: requestID,
                    payload: AgentNoPayloadV2(),
                    error: AgentCLIErrorV2(
                        code: "approval.incomplete",
                        message: "The trusted local review did not complete.",
                        retryable: true
                    ),
                    next: [
                        AgentNextCommandV2(
                            command: "safa request review \(requestID.uuidString.lowercased())",
                            reason: "Resume the trusted local review",
                            safeForAgent: false
                        )
                    ]
                )
            )
        }
    }
}

struct RequestGetCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "get")
    @Argument(help: "The request id returned by `safa exec`.") var id: String

    func run() async throws {
        guard let requestID = UUID(uuidString: id) else {
            try invalidInvocation(command: "request.get", message: "Not a valid request id.")
        }
        do {
            let reply = try await XPCBrokerAgentClient().send(.getRequest(id: requestID))
            try finishBrokerReply(command: "request.get", reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "request.get")
        }
    }
}

struct RequestWaitCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "wait")
    @Argument(help: "The request id returned by `safa exec`.") var id: String
    @Option(help: "How long to wait for a terminal state before returning.") var timeout: UInt = 60

    func run() async throws {
        guard let requestID = UUID(uuidString: id) else {
            try invalidInvocation(command: "request.wait", message: "Not a valid request id.")
        }
        do {
            let reply = try await XPCBrokerAgentClient().send(
                .waitRequest(id: requestID, timeoutSeconds: timeout))
            try finishBrokerReply(command: "request.wait", reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "request.wait")
        }
    }
}

struct RequestCancelCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "cancel")
    @Argument(help: "The request id returned by `safa exec`.") var id: String

    func run() async throws {
        guard let requestID = UUID(uuidString: id) else {
            try invalidInvocation(command: "request.cancel", message: "Not a valid request id.")
        }
        do {
            let reply = try await XPCBrokerAgentClient().send(.cancelRequest(id: requestID))
            try finishBrokerReply(command: "request.cancel", reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "request.cancel")
        }
    }
}
