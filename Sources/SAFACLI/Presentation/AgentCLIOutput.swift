import ArgumentParser
import Foundation
import SAFAProtocol

protocol AgentCommand {}

extension AgentCommand {
    func emit<Payload: AgentCLIToonPayload>(
        _ response: AgentCLIResponseV2<Payload>
    ) throws {
        let output = try AgentCLIToonPresenter().encode(response)
        FileHandle.standardOutput.write(Data(output.utf8))
        FileHandle.standardOutput.write(Data([0x0A]))
    }

    func finish<Payload: AgentCLIToonPayload>(
        _ response: AgentCLIResponseV2<Payload>,
        exit: AgentCLIProcessExitV2? = nil
    ) throws {
        try emit(response)
        let resolvedExit = exit ?? AgentCLIProcessExitV2.map(status: response.status)
        if resolvedExit != .success { throw ExitCode(resolvedExit.rawValue) }
    }

    func brokerFailure(command: String) throws -> Never {
        let response = AgentCLIResponseV2(
            command: command,
            status: .failed,
            payload: AgentNoPayloadV2(),
            error: AgentCLIErrorV2(
                code: "runtime.broker_unavailable",
                message: "The signed local broker is unavailable.",
                retryable: true
            )
        )
        try emit(response)
        throw ExitCode(AgentCLIProcessExitV2.failure.rawValue)
    }

    func invalidInvocation(command: String, message: String) throws -> Never {
        let response = AgentCLIResponseV2(
            command: command,
            status: .failed,
            payload: AgentUsageFailureV2(validFlags: AgentCLIInvocation.validFlags(command)),
            error: AgentCLIErrorV2(
                code: "usage.invalid_argument",
                message: message,
                retryable: false
            ),
            next: [AgentCLIInvocation.helpNext(command)]
        )
        try emit(response)
        throw ExitCode(AgentCLIProcessExitV2.usage.rawValue)
    }
}

enum AgentCLIInvocation {
    static func command(arguments: [String]) -> String {
        guard let first = arguments.first else { return "home" }
        guard !first.hasPrefix("-") else { return "home" }
        guard ["resource", "topology", "setup", "request", "grant"].contains(first),
            let second = arguments.dropFirst().first,
            !second.hasPrefix("-")
        else {
            return first
        }
        let verb = first == "resource" && second == "ls" ? "list" : second
        return "\(first).\(verb)"
    }

    static func validFlags(_ command: String) -> [String] {
        switch command {
        case "resource.list": ["--state", "--limit", "--fields", "--help"]
        case "resource.show": ["--details", "--help"]
        case "resource.add": ["--from-ssh-config", "--template", "--type", "--help"]
        case "resource.edit": ["--from-ssh-config", "--template", "--type", "--state", "--help"]
        case "resource.remove": ["--help"]
        case "resource.sudo": ["--status", "--passwordless", "--remove", "--help"]
        case "topology.show": ["--limit", "--fields", "--help"]
        case "topology.path", "topology.impact": ["--limit", "--help"]
        case "topology.link", "topology.unlink": ["--help"]
        case "exec":
            [
                "--intent", "--expected-effect", "--rollback", "--timeout", "--output-limit",
                "--privilege", "--full", "--help",
            ]
        case "request.get", "request.review", "request.cancel": ["--help"]
        case "request.wait": ["--timeout", "--help"]
        case "grant.list": ["--help"]
        case "grant.revoke": ["--help"]
        case "doctor", "setup.status", "setup.activate", "setup.deactivate": ["--help"]
        default: ["--help"]
        }
    }

    static func helpNext(
        _ command: String,
        arguments: [String] = []
    ) -> AgentNextCommandV2 {
        if command == "resource.sudo-status",
            arguments.count >= 3,
            !arguments[2].hasPrefix("-")
        {
            return AgentNextCommandV2(
                command: "safa resource sudo \(arguments[2]) --status",
                reason: "Use the nested sudo command to inspect safe credential state",
                safeForAgent: true
            )
        }
        let invocation =
            command == "home"
            ? "safa --help"
            : "safa \(command.replacingOccurrences(of: ".", with: " ")) --help"
        return AgentNextCommandV2(
            command: invocation,
            reason: "Read the complete local command reference",
            safeForAgent: true
        )
    }
}
