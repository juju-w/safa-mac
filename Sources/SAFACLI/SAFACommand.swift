import ArgumentParser
import Foundation
import SAFADomain
import SAFAProtocol

@available(macOS 10.15, macCatalyst 13, iOS 13, tvOS 13, watchOS 6, *)
public struct SAFACommand: AsyncParsableCommand, AgentCommand {
    public static let configuration = CommandConfiguration(
        commandName: "safa",
        abstract: "Secure agent access for macOS",
        subcommands: [
            DoctorCommand.self, SetupCommand.self, ResourceCommand.self, TopologyCommand.self,
            ExecCommand.self, RequestCommand.self, GrantCommand.self,
        ]
    )

    public init() {}

    public static func runMain() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.count == 1, ["-v", "-V", "--version"].contains(arguments[0]) {
            print(RuntimeBuildMetadata.version)
            return
        }
        let parserArguments = arguments.prefix { $0 != "--" }
        if parserArguments.contains("--generate-completion-script")
            || parserArguments.contains("--experimental-dump-help")
        {
            emitUsageFailure(
                command: AgentCLIInvocation.command(arguments: arguments),
                message: "This Agent CLI does not expose completion or command-dump output."
            )
        }
        do {
            var command = try await asyncParseAsRoot(arguments)
            if var asyncCommand = command as? any AsyncParsableCommand {
                try await asyncCommand.run()
            } else {
                try command.run()
            }
        } catch let exitCode as ExitCode {
            exit(withError: exitCode)
        } catch {
            if exitCode(for: error).isSuccess {
                let response = AgentCLIResponseV2(
                    command: AgentCLIInvocation.command(arguments: arguments),
                    status: .completed,
                    payload: AgentHelpPayloadV2(text: message(for: error))
                )
                try? SAFACommand().emit(response)
                exit(withError: ExitCode.success)
            }
            emitUsageFailure(
                command: AgentCLIInvocation.command(arguments: arguments),
                message: message(for: error)
            )
        }
    }

    public mutating func run() async throws {
        do {
            let client = XPCBrokerAgentClient()
            let status = try await client.send(.runtimeStatus)
            let directory = try await client.queryResourceDirectory(action: .list)
            guard status.status == .completed, directory.status == .completed else {
                try brokerFailure(command: "home")
            }
            let total = directory.summaries.count
            let resources = directory.summaries.prefix(8).map(\.agentRow)
            let payload = AgentHomePayloadV2(
                binary: Self.displayBinaryPath(),
                description: "Securely discover and operate registered infrastructure by alias",
                broker: status.data.agentString(for: "broker") ?? "unknown",
                vault: status.data.agentString(for: "vault") ?? "unknown",
                resources: try AgentResourceListV2(
                    total: total,
                    truncated: total > resources.count,
                    resources: resources
                )
            )
            try finish(
                AgentCLIResponseV2(
                    command: "home",
                    status: .completed,
                    payload: payload,
                    next: [
                        AgentNextCommandV2(
                            command: "safa resource show <alias>",
                            reason: "Inspect one safe resource summary",
                            safeForAgent: true
                        ),
                        AgentNextCommandV2(
                            command: "safa topology show",
                            reason: "Inspect bounded logical relationships",
                            safeForAgent: true
                        ),
                    ]
                )
            )
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            try brokerFailure(command: "home")
        }
    }

    private static func emitUsageFailure(command: String, message: String) -> Never {
        let response = AgentCLIResponseV2(
            command: command,
            status: .failed,
            payload: AgentUsageFailureV2(validFlags: AgentCLIInvocation.validFlags(command)),
            error: AgentCLIErrorV2(
                code: "usage.invalid_invocation",
                message: message,
                retryable: false
            ),
            next: [AgentCLIInvocation.helpNext(command)]
        )
        try? SAFACommand().emit(response)
        exit(withError: ExitCode(AgentCLIProcessExitV2.usage.rawValue))
    }

    private static func displayBinaryPath() -> String {
        let path = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path == home { return "~" }
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }
}

struct DoctorCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "doctor")

    func run() async throws {
        do {
            try finishBrokerReply(
                command: "doctor", reply: try await XPCBrokerAgentClient().send(.runtimeStatus))
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "doctor")
        }
    }
}

struct ExecCommand: AsyncParsableCommand, AgentCommand {
    static let previewLimit: UInt = 65_536
    static let fullLimit: UInt = 1_048_576

    static let configuration = CommandConfiguration(commandName: "exec")
    @Argument(completion: ResourceCLICompletion.resourceAliases) var alias: String
    @Option var intent: String
    @Option(name: .customLong("expected-effect")) var expectedEffect: String?
    @Option var rollback: String?
    @Option var timeout: UInt = 60
    @Option(name: .customLong("output-limit")) var outputLimit: UInt = Self.previewLimit
    @Option var privilege: String = "user"
    @Flag var full = false
    @Argument(parsing: .postTerminator) var arguments: [String] = []

    func validate() throws {
        guard timeout > 0 else {
            throw ValidationError("--timeout must be greater than zero.")
        }
        guard full || (1...Self.fullLimit).contains(outputLimit) else {
            throw ValidationError("--output-limit must be between 1 and 1048576 bytes.")
        }
        guard !arguments.isEmpty else {
            throw ValidationError("A command is required after --.")
        }
        guard privilege == "user" || privilege == "sudo" else {
            throw ValidationError("--privilege must be either \"user\" or \"sudo\".")
        }
    }

    func run() async throws {
        let target = try ResourceAlias(alias)
        var commandArguments = arguments
        let resolvedPrivilege: Privilege
        if privilege == "sudo" {
            resolvedPrivilege = .sudo
            // A redundant `sudo` prefix on the command is harmless: strip it so the
            // Broker executes `sudo -S -- <command>` exactly once via SudoExecutor.
            if commandArguments.first == "sudo" {
                commandArguments.removeFirst()
            }
            guard !commandArguments.isEmpty else {
                throw ValidationError(
                    "A command is required after -- when --privilege sudo is used.")
            }
        } else {
            resolvedPrivilege = .user
        }
        let command = try CommandSpec.exec(
            arguments: commandArguments,
            timeoutSeconds: timeout,
            outputLimitBytes: full ? Self.fullLimit : outputLimit
        )
        do {
            try finishBrokerReply(
                command: "exec",
                reply: try await XPCBrokerAgentClient().send(
                    .submitExecution(
                        resourceAlias: target,
                        command: command,
                        privilege: resolvedPrivilege,
                        intent: intent,
                        expectedEffect: expectedEffect,
                        rollback: rollback
                    )
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "exec")
        }
    }
}
