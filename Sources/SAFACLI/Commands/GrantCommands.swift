import ArgumentParser
import Foundation
import SAFAProtocol

struct GrantCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "grant",
        abstract: "List or revoke active approval grants issued through trusted local approval.",
        subcommands: [GrantListCommand.self, GrantRevokeCommand.self]
    )
}

struct GrantListCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "list")

    func run() async throws {
        do {
            let reply = try await XPCBrokerAgentClient().send(.listGrants)
            try finishBrokerReply(command: "grant.list", reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "grant.list")
        }
    }
}

struct GrantRevokeCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "revoke")
    @Argument(help: "The grant id from `safa grant list`.") var id: String

    func run() async throws {
        guard let grantID = UUID(uuidString: id) else {
            try invalidInvocation(command: "grant.revoke", message: "Not a valid grant id.")
        }
        do {
            let reply = try await XPCBrokerAgentClient().send(.revokeGrant(id: grantID))
            try finishBrokerReply(command: "grant.revoke", reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "grant.revoke")
        }
    }
}
