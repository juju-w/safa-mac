import Foundation
import SAFADomain

public enum PolicyDisposition: String, Equatable, Sendable {
    case automatic
    case approvalRequired = "approval_required"
    case denied
}

public struct PolicySecurityContext: Equatable, Sendable {
    public let vaultIntegrityVerified: Bool
    public let callerValidated: Bool
    public let hostIdentityTrusted: Bool
    public let platformSupported: Bool

    public init(
        vaultIntegrityVerified: Bool = true,
        callerValidated: Bool = true,
        hostIdentityTrusted: Bool = true,
        platformSupported: Bool = true
    ) {
        self.vaultIntegrityVerified = vaultIntegrityVerified
        self.callerValidated = callerValidated
        self.hostIdentityTrusted = hostIdentityTrusted
        self.platformSupported = platformSupported
    }
}

public struct PolicyEvaluation: Equatable, Sendable {
    public let policyVersion: String
    public let disposition: PolicyDisposition
    public let level: RiskLevel
    public let findings: [Finding]
    public let requiredApproval: RequiredApproval
    public let agentReview: String?

    init(
        policyVersion: String,
        disposition: PolicyDisposition,
        level: RiskLevel,
        findings: [Finding],
        requiredApproval: RequiredApproval,
        agentReview: String?
    ) {
        self.policyVersion = policyVersion
        self.disposition = disposition
        self.level = level
        self.findings = findings
        self.requiredApproval = requiredApproval
        self.agentReview = agentReview
    }

    public func riskAssessment(id: UUID, evaluatedAt: Date) -> RiskAssessment {
        RiskAssessment(
            id: id,
            policyVersion: policyVersion,
            level: level,
            findings: findings,
            requiredApproval: requiredApproval,
            agentReview: agentReview,
            evaluatedAt: evaluatedAt
        )
    }
}

public struct PolicyEngine: Sendable {
    private let canonicalizer: CommandCanonicalizer
    private let diagnosticPolicy: DiagnosticCommandPolicy

    public init(
        canonicalizer: CommandCanonicalizer = CommandCanonicalizer(),
        diagnosticPolicy: DiagnosticCommandPolicy = DiagnosticCommandPolicy()
    ) {
        self.canonicalizer = canonicalizer
        self.diagnosticPolicy = diagnosticPolicy
    }

    public func evaluate(
        command: CommandSpec,
        privilege: Privilege,
        policy: Policy,
        context: PolicySecurityContext = PolicySecurityContext(),
        agentReview: String? = nil
    ) throws -> PolicyEvaluation {
        let canonical = try canonicalizer.canonicalize(command)
        var accumulator = FindingAccumulator()
        var hardDeny = false
        var approvalRequired = false
        var maximumRisk = RiskRank.low

        func add(_ code: String, detail: String? = nil, risk: RiskRank) {
            accumulator.add(code: code, detail: detail)
            maximumRisk = max(maximumRisk, risk)
        }

        if !context.vaultIntegrityVerified {
            add("security.vault_integrity_failed", risk: .critical)
            hardDeny = true
        }
        if !context.callerValidated {
            add("security.caller_invalid", risk: .critical)
            hardDeny = true
        }
        if !context.hostIdentityTrusted {
            add("security.host_identity_untrusted", risk: .critical)
            hardDeny = true
        }
        if !context.platformSupported {
            add("security.platform_unsupported", risk: .critical)
            hardDeny = true
        }

        if command.timeoutSeconds == 0
            || command.timeoutSeconds > policy.limits.maximumTimeoutSeconds
        {
            add("policy.limit.timeout_exceeded", risk: .critical)
            hardDeny = true
        }
        if command.outputLimitBytes == 0
            || command.outputLimitBytes > policy.limits.maximumOutputBytes
        {
            add("policy.limit.output_exceeded", risk: .critical)
            hardDeny = true
        }
        if command.tty {
            add("command.tty", risk: .high)
            approvalRequired = true
            if !policy.limits.allowsTTY {
                add("policy.tty_forbidden", risk: .critical)
                hardDeny = true
            }
        }
        if command.stdinMode != .none {
            add("command.stdin", risk: .high)
            approvalRequired = true
        }
        if command.workingDirectory != nil {
            add("command.working_directory", risk: .medium)
            approvalRequired = true
        }

        let arguments = canonical.arguments
        let automaticRules = matching(policy.automaticRules, arguments: arguments)
        let approvalRules = matching(policy.approvalRules, arguments: arguments)
        let denyRules = matching(policy.denyRules, arguments: arguments)
        for rule in automaticRules {
            add("policy.automatic_rule", detail: rule.code, risk: .low)
        }
        for rule in approvalRules {
            add("policy.approval_rule", detail: rule.code, risk: .medium)
            approvalRequired = true
        }
        for rule in denyRules {
            add("policy.deny_rule", detail: rule.code, risk: .critical)
            hardDeny = true
        }

        let isAutomaticDiagnostic = diagnosticPolicy.allowsAutomaticExecution(command)
        if isAutomaticDiagnostic {
            add("policy.automatic_diagnostic", risk: .low)
        }

        if privilege == .sudo {
            add("command.sudo_requested", risk: .high)
            approvalRequired = true
        }

        let embedsSudo: Bool
        switch command.mode {
        case .exec:
            // A leading `sudo` in an exec command is a legitimate sudo request only when the
            // request is explicitly classified `privilege: sudo`. With `privilege: user`,
            // a leading `sudo` is a privilege-escalation attempt and must hard-deny.
            embedsSudo = arguments?.first.map(Self.executableName) == "sudo" && privilege != .sudo
        case .shell:
            // Shell mode embedding sudo anywhere is indirect escalation; hard-deny regardless.
            embedsSudo = tokenize(canonical.shellProgram ?? "").contains {
                $0.caseInsensitiveCompare("sudo") == .orderedSame
            }
        }
        if embedsSudo {
            add("command.embedded_sudo", risk: .critical)
            hardDeny = true
        }

        switch command.mode {
        case .exec:
            let values = arguments ?? []
            classify(tokens: values, rawProgram: values.joined(separator: " "), mode: .exec) {
                code, risk in
                add(code, risk: risk)
                approvalRequired = true
            }
            if !isAutomaticDiagnostic && automaticRules.isEmpty && approvalRules.isEmpty
                && denyRules.isEmpty
            {
                add("policy.no_automatic_rule", risk: .medium)
                approvalRequired = true
            }
        case .shell:
            add("command.shell", risk: .high)
            approvalRequired = true
            let program = canonical.shellProgram ?? ""
            classify(tokens: tokenize(program), rawProgram: program, mode: .shell) { code, risk in
                add(code, risk: risk)
                approvalRequired = true
            }
            if containsShellMetacharacter(program) {
                add("command.shell_metacharacter", risk: .high)
            }
            if program.contains("$(") || program.contains("`") {
                add("command.command_substitution", risk: .high)
            }
            if program.contains(">") || program.contains("<") {
                add("command.redirect", risk: .high)
            }
        }

        let disposition: PolicyDisposition
        let requiredApproval: RequiredApproval
        if hardDeny {
            disposition = .denied
            requiredApproval = .none
            maximumRisk = .critical
        } else if approvalRequired {
            disposition = .approvalRequired
            requiredApproval = .userPresence
        } else {
            disposition = .automatic
            requiredApproval = .none
        }

        return PolicyEvaluation(
            policyVersion: policy.version,
            disposition: disposition,
            level: maximumRisk.level,
            findings: accumulator.sortedFindings,
            requiredApproval: requiredApproval,
            agentReview: agentReview.map { String($0.prefix(2_048)) }
        )
    }

    private func matching(_ rules: [PolicyRule], arguments: [String]?) -> [PolicyRule] {
        guard let arguments else { return [] }
        return rules.filter { rule in
            !rule.commandPrefix.isEmpty
                && arguments.count >= rule.commandPrefix.count
                && Array(arguments.prefix(rule.commandPrefix.count)) == rule.commandPrefix
        }
    }

    private func classify(
        tokens: [String],
        rawProgram: String,
        mode: CommandMode,
        add: (String, RiskRank) -> Void
    ) {
        let lowerTokens = tokens.map { $0.lowercased() }
        let tokenSet = Set(lowerTokens)
        let lowerProgram = rawProgram.lowercased()
        let executableIndex =
            mode == .exec && lowerTokens.first.map(Self.executableName) == "sudo"
            ? 1 : 0
        let executable =
            lowerTokens.indices.contains(executableIndex)
            ? Self.executableName(lowerTokens[executableIndex]) : ""

        let interpreters: Set<String> = [
            "bash", "dash", "fish", "node", "perl", "powershell", "powershell.exe", "pwsh",
            "python", "python3", "ruby", "sh", "zsh",
        ]
        let hasInterpreter =
            mode == .shell
            ? !tokenSet.isDisjoint(with: interpreters)
            : interpreters.contains(executable)
        if hasInterpreter {
            add("command.interpreter", .high)
        }

        let encodedMarkers: Set<String> = [
            "-enc", "-encodedcommand", "base64", "base64.exe", "enc", "encodedcommand",
            "frombase64string",
        ]
        let hasEncodedPayload: Bool
        if mode == .shell {
            hasEncodedPayload =
                !tokenSet.isDisjoint(with: encodedMarkers)
                || lowerProgram.contains("base64")
                || lowerProgram.contains("frombase64string")
        } else {
            hasEncodedPayload =
                encodedMarkers.contains(executable)
                || (hasInterpreter && !tokenSet.isDisjoint(with: encodedMarkers))
        }
        if hasEncodedPayload {
            add("command.encoded_payload", .high)
        }

        let stateChangingCommands: Set<String> = [
            "apt", "apt-get", "chmod", "chown", "cp", "dnf", "install", "kill", "killall",
            "launchctl", "ln", "mv", "pkill", "rm", "tee", "yum",
        ]
        let dockerMutations: Set<String> = [
            "build", "compose", "create", "exec", "kill", "pause", "pull", "push", "rename",
            "restart", "rm", "run", "start", "stop", "unpause", "update",
        ]
        let systemdMutations: Set<String> = [
            "daemon-reload", "disable", "enable", "isolate", "kill", "mask", "reload",
            "restart", "start", "stop", "unmask",
        ]
        let semanticArguments = lowerTokens.dropFirst(executableIndex + 1)
        let isDockerMutation =
            executable == "docker"
            && semanticArguments.first.map(dockerMutations.contains) == true
        let isSystemdMutation =
            executable == "systemctl"
            && semanticArguments.first.map(systemdMutations.contains) == true
        let hasStateChangingExecutable =
            mode == .shell
            ? !tokenSet.isDisjoint(with: stateChangingCommands)
            : stateChangingCommands.contains(executable)
        if hasStateChangingExecutable || isDockerMutation || isSystemdMutation {
            add("command.state_changing", .high)
        }

        let destructiveCommands: Set<String> = [
            "dd", "fdisk", "halt", "mkfs", "poweroff", "reboot", "shutdown",
        ]
        let hasDestructiveExecutable =
            mode == .shell
            ? !tokenSet.isDisjoint(with: destructiveCommands)
            : destructiveCommands.contains(executable)
        let hasDestructivePattern: Bool
        if mode == .shell {
            hasDestructivePattern =
                lowerProgram.contains("rm -rf")
                || lowerProgram.contains("drop database")
                || lowerProgram.contains("drop table")
                || lowerProgram.contains("truncate table")
        } else {
            hasDestructivePattern =
                executable == "rm"
                && semanticArguments.contains(where: { $0 == "-rf" || $0 == "-fr" })
        }
        if hasDestructiveExecutable || hasDestructivePattern {
            add("command.destructive", .critical)
        }
    }

    private static func executableName(_ value: String) -> String {
        URL(fileURLWithPath: value).lastPathComponent.lowercased()
    }

    private func tokenize(_ program: String) -> [String] {
        program.components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { !$0.isEmpty }
    }

    private func containsShellMetacharacter(_ program: String) -> Bool {
        ["|", ";", "&&", "||", "`", "$("].contains { program.contains($0) }
    }
}

private struct FindingAccumulator {
    private var values: [String: Finding] = [:]

    mutating func add(code: String, detail: String?) {
        let key = code + "\u{0}" + (detail ?? "")
        values[key] = Finding(code: code, detail: detail)
    }

    var sortedFindings: [Finding] {
        values.values.sorted { lhs, rhs in
            if lhs.code != rhs.code { return lhs.code < rhs.code }
            return (lhs.detail ?? "") < (rhs.detail ?? "")
        }
    }
}

private enum RiskRank: Int, Comparable {
    case low
    case medium
    case high
    case critical

    static func < (lhs: RiskRank, rhs: RiskRank) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var level: RiskLevel {
        switch self {
        case .low: .low
        case .medium: .medium
        case .high: .high
        case .critical: .critical
        }
    }
}
