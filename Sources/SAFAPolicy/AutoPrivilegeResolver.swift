import Foundation
import SAFADomain

public struct AutoPrivilegeAccountObservation: Equatable, Sendable {
    public let isRoot: Bool?
    public let dockerAuthorized: Bool?
    public let observedAt: Date?

    public init(isRoot: Bool?, dockerAuthorized: Bool?, observedAt: Date?) {
        self.isRoot = isRoot
        self.dockerAuthorized = dockerAuthorized
        self.observedAt = observedAt
    }
}

public enum AutoPrivilegeUserReason: Equatable, Sendable {
    case rootAccount
    case dockerAuthorized
    case insufficientEvidence
    case commandNotEligible
}

public enum AutoPrivilegeCommandClass: Equatable, Sendable {
    case dockerRead
    case systemdMutation
}

public enum AutoPrivilegeDecision: Equatable, Sendable {
    case user(reason: AutoPrivilegeUserReason)
    case sudo(commandClass: AutoPrivilegeCommandClass)

    public var effectivePrivilege: Privilege {
        switch self {
        case .user: .user
        case .sudo: .sudo
        }
    }
}

/// Resolves explicit `auto` requests before policy evaluation. The resolver is intentionally a
/// closed full-vector classifier: unknown commands and uncertain observations stay at user
/// privilege, and remote execution output is never an input.
public struct AutoPrivilegeResolver: Sendable {
    public let maximumObservationAge: TimeInterval

    public init(maximumObservationAge: TimeInterval = 300) {
        self.maximumObservationAge = maximumObservationAge
    }

    public func resolve(
        command: CommandSpec,
        observation: AutoPrivilegeAccountObservation,
        now: Date
    ) -> AutoPrivilegeDecision {
        guard evidenceIsFreshAndConsistent(observation, now: now) else {
            return .user(reason: .insufficientEvidence)
        }

        if observation.isRoot == true {
            return .user(reason: .rootAccount)
        }
        guard command.mode == .exec, let arguments = command.arguments else {
            return .user(reason: .commandNotEligible)
        }

        switch classify(arguments) {
        case .dockerRead:
            if observation.dockerAuthorized == true {
                return .user(reason: .dockerAuthorized)
            }
            guard observation.isRoot == false, observation.dockerAuthorized == false else {
                return .user(reason: .insufficientEvidence)
            }
            return .sudo(commandClass: .dockerRead)
        case .systemdMutation:
            guard observation.isRoot == false else {
                return .user(reason: .insufficientEvidence)
            }
            return .sudo(commandClass: .systemdMutation)
        case nil:
            return .user(reason: .commandNotEligible)
        }
    }

    public func commandClass(for command: CommandSpec) -> AutoPrivilegeCommandClass? {
        guard command.mode == .exec, let arguments = command.arguments else { return nil }
        return classify(arguments)
    }

    private func evidenceIsFreshAndConsistent(
        _ observation: AutoPrivilegeAccountObservation,
        now: Date
    ) -> Bool {
        guard let observedAt = observation.observedAt else { return false }
        let age = now.timeIntervalSince(observedAt)
        guard age >= 0, age <= maximumObservationAge else { return false }
        if observation.isRoot == true, observation.dockerAuthorized == false { return false }
        return true
    }

    private func classify(_ arguments: [String]) -> AutoPrivilegeCommandClass? {
        if arguments.count == 3,
            arguments[0] == "systemctl",
            ["start", "stop", "restart", "reload"].contains(arguments[1]),
            arguments[2].range(
                of: "^[A-Za-z0-9@_.:-]{1,255}$",
                options: String.CompareOptions.regularExpression
            ) != nil
        {
            return .systemdMutation
        }
        switch arguments {
        case ["docker", "version"], ["docker", "ps"], ["docker", "ps", "--all"],
            ["docker", "ps", "--format", DiagnosticCommandPolicy.dockerPSFormat],
            [
                "docker", "stats", "--no-stream", "--format",
                DiagnosticCommandPolicy.dockerStatsFormat,
            ]:
            return .dockerRead
        default:
            return nil
        }
    }
}
