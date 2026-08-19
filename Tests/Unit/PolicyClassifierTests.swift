import Foundation
import SAFADomain
import SAFAPolicy
import Testing

@Suite("Deterministic execution policy")
struct PolicyClassifierTests {
    private let engine = PolicyEngine()

    @Test("bounded diagnostics remain automatic")
    func automaticDiagnostic() throws {
        for arguments in [
            ["uptime"],
            ["systemctl", "is-active", "docker"],
            ["docker", "version"],
            ["docker", "ps", "--format", DiagnosticCommandPolicy.dockerPSFormat],
        ] {
            let evaluation = try engine.evaluate(
                command: CommandSpec.exec(arguments: arguments),
                privilege: .user,
                policy: policy()
            )

            #expect(evaluation.disposition == .automatic)
            #expect(evaluation.level == .low)
            #expect(evaluation.requiredApproval == .none)
            #expect(evaluation.findings.map(\.code) == ["policy.automatic_diagnostic"])
            let assessment = evaluation.riskAssessment(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
                evaluatedAt: Date(timeIntervalSince1970: 1_800_000_000)
            )
            #expect(assessment.policyVersion == "test-v1")
            #expect(assessment.findings == evaluation.findings)
        }
    }

    @Test("unknown commands require approval instead of silently executing")
    func unknownCommand() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["journalctl", "-u", "api"]),
            privilege: .user,
            policy: policy()
        )

        #expect(evaluation.disposition == .approvalRequired)
        #expect(evaluation.level == .medium)
        #expect(evaluation.requiredApproval == .userPresence)
        #expect(evaluation.findings.map(\.code) == ["policy.no_automatic_rule"])
    }

    @Test("automatic rules cannot bypass stdin, working-directory, or destructive findings")
    func automaticRuleAuthorityCeiling() throws {
        let automatic = [PolicyRule(code: "custom", commandPrefix: ["custom-tool"])]
        let configured = policy(automatic: automatic)
        let commands = try [
            (
                CommandSpec.exec(
                    arguments: ["custom-tool", "read"],
                    stdinMode: .boundedAgentData
                ),
                ["command.stdin", "policy.automatic_rule"]
            ),
            (
                CommandSpec.exec(
                    arguments: ["custom-tool", "read"],
                    workingDirectory: "/tmp"
                ),
                ["command.working_directory", "policy.automatic_rule"]
            ),
        ]

        for (command, expectedFindings) in commands {
            let evaluation = try engine.evaluate(
                command: command,
                privilege: .user,
                policy: configured
            )
            #expect(evaluation.disposition == .approvalRequired)
            #expect(evaluation.findings.map(\.code) == expectedFindings)
        }

        let destructive = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["rm", "-rf", "/tmp/cache"]),
            privilege: .user,
            policy: policy(
                automatic: [PolicyRule(code: "cleanup", commandPrefix: ["rm"])]
            )
        )
        #expect(destructive.disposition == .approvalRequired)
        #expect(destructive.level == .critical)
        #expect(
            destructive.findings.map(\.code) == [
                "command.destructive", "command.state_changing", "policy.automatic_rule",
            ]
        )
    }

    @Test("inert exec arguments do not inherit executable semantics")
    func inertArguments() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(
                arguments: ["custom-tool", "python3", "rm", "base64", "$(still-data)"]
            ),
            privilege: .user,
            policy: policy(
                automatic: [PolicyRule(code: "custom", commandPrefix: ["custom-tool"])]
            )
        )

        #expect(evaluation.disposition == .automatic)
        #expect(evaluation.findings.map(\.code) == ["policy.automatic_rule"])
    }

    @Test("sudo inside command text cannot bypass the explicit privilege field")
    func embeddedSudo() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["sudo", "systemctl", "restart", "api"]),
            privilege: .user,
            policy: policy(
                automatic: [PolicyRule(code: "unsafe", commandPrefix: ["sudo"])]
            )
        )

        #expect(evaluation.disposition == .denied)
        #expect(evaluation.level == .critical)
        #expect(
            evaluation.findings.map(\.code) == [
                "command.embedded_sudo",
                "command.state_changing",
                "policy.automatic_rule",
            ]
        )
    }

    @Test("command substitution and encoded interpreter payloads are explicit")
    func obfuscatedShellFindings() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.shell(
                program: "powershell -EncodedCommand $(payload)"
            ),
            privilege: .user,
            policy: policy()
        )

        #expect(evaluation.disposition == .approvalRequired)
        #expect(
            evaluation.findings.map(\.code) == [
                "command.command_substitution",
                "command.encoded_payload",
                "command.interpreter",
                "command.shell",
                "command.shell_metacharacter",
            ]
        )
    }

    @Test("shell syntax, interpreters, encoded payloads, mutation, and sudo emit stable findings")
    func elevatedFindings() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.shell(
                program: "python3 -c 'import base64' | tee /etc/example > /dev/null"
            ),
            privilege: .sudo,
            policy: policy(),
            agentReview: "This is safe."
        )

        #expect(evaluation.disposition == .approvalRequired)
        #expect(evaluation.level == .high)
        #expect(evaluation.requiredApproval == .userPresence)
        #expect(
            evaluation.findings.map(\.code) == [
                "command.encoded_payload",
                "command.interpreter",
                "command.redirect",
                "command.shell",
                "command.shell_metacharacter",
                "command.state_changing",
                "command.sudo_requested",
            ]
        )
        #expect(evaluation.agentReview == "This is safe.")
    }

    @Test("deny overrides approval and automatic rules independent of rule order")
    func denyPrecedence() throws {
        let rules = [
            PolicyRule(code: "read", commandPrefix: ["tool"]),
            PolicyRule(code: "read-narrow", commandPrefix: ["tool", "inspect"]),
            PolicyRule(code: "operator", commandPrefix: ["tool", "inspect"]),
            PolicyRule(code: "operator-narrow", commandPrefix: ["tool", "inspect", "secret"]),
            PolicyRule(code: "blocked", commandPrefix: ["tool", "inspect", "secret"]),
            PolicyRule(code: "blocked-broad", commandPrefix: ["tool"]),
        ]
        let first = policy(
            automatic: [rules[0], rules[1]],
            approval: [rules[2], rules[3]],
            deny: [rules[4], rules[5]]
        )
        let second = policy(
            automatic: [rules[1], rules[0]],
            approval: [rules[3], rules[2]],
            deny: [rules[5], rules[4]]
        )
        let command = try CommandSpec.exec(arguments: ["tool", "inspect", "secret"])

        let a = try engine.evaluate(command: command, privilege: .user, policy: first)
        let b = try engine.evaluate(command: command, privilege: .user, policy: second)

        #expect(a.disposition == .denied)
        #expect(a.level == .critical)
        #expect(a.requiredApproval == .none)
        #expect(a.findings == b.findings)
        #expect(
            a.findings.map(\.code) == [
                "policy.approval_rule",
                "policy.approval_rule",
                "policy.automatic_rule",
                "policy.automatic_rule",
                "policy.deny_rule",
                "policy.deny_rule",
            ]
        )
        #expect(
            a.findings.map(\.detail) == [
                "operator", "operator-narrow", "read", "read-narrow", "blocked", "blocked-broad",
            ]
        )
    }

    @Test("security failures and hard limits deny even an automatic diagnostic")
    func hardDeny() throws {
        let context = PolicySecurityContext(
            vaultIntegrityVerified: false,
            callerValidated: true,
            hostIdentityTrusted: false,
            platformSupported: true
        )
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["uptime"]),
            privilege: .user,
            policy: policy(maximumTimeoutSeconds: 30),
            context: context,
            agentReview: "low risk"
        )

        #expect(evaluation.disposition == .denied)
        #expect(evaluation.level == .critical)
        #expect(evaluation.requiredApproval == .none)
        #expect(
            evaluation.findings.map(\.code) == [
                "policy.automatic_diagnostic",
                "policy.limit.timeout_exceeded",
                "security.host_identity_untrusted",
                "security.vault_integrity_failed",
            ]
        )
    }

    @Test(
        "sudo privilege never yields an automatic disposition, even for an otherwise-automatic diagnostic"
    )
    func sudoNeverAutomatic() throws {
        // A command that would be automatic at user privilege...
        let atUserPrivilege = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["uptime"]),
            privilege: .user,
            policy: policy()
        )
        #expect(atUserPrivilege.disposition == .automatic)

        // ...must never resolve to automatic (or to a "no approval needed"
        // outcome outside of an outright deny) once privilege is sudo. A
        // future change to PolicyEngine that special-cased sudo diagnostics
        // would silently reopen unattended privilege escalation.
        let atSudoPrivilege = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["uptime"]),
            privilege: .sudo,
            policy: policy()
        )
        #expect(atSudoPrivilege.disposition != .automatic)
        if atSudoPrivilege.disposition == .approvalRequired {
            #expect(atSudoPrivilege.requiredApproval == .userPresence)
        }
        #expect(atSudoPrivilege.findings.map(\.code).contains("command.sudo_requested"))
    }

    @Test("a direct sudo request at sudo privilege is approval-required, not denied")
    func directSudoRequestIsApprovalRequired() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["systemctl", "restart", "jellyfin"]),
            privilege: .sudo,
            policy: policy()
        )
        #expect(evaluation.disposition == PolicyDisposition.approvalRequired)
        #expect(evaluation.requiredApproval == RequiredApproval.userPresence)
        #expect(evaluation.findings.map { $0.code }.contains("command.sudo_requested"))
        #expect(!evaluation.findings.map { $0.code }.contains("command.embedded_sudo"))
    }

    @Test("a redundant sudo prefix at sudo privilege is tolerated, not hard-denied")
    func directSudoWithSudoPrefixIsApprovalRequired() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["sudo", "systemctl", "restart", "jellyfin"]),
            privilege: .sudo,
            policy: policy()
        )
        #expect(evaluation.disposition == PolicyDisposition.approvalRequired)
        #expect(!evaluation.findings.map { $0.code }.contains("command.embedded_sudo"))
    }

    @Test("a sudo prefix at user privilege is an escalation attempt and hard-denies")
    func userPrivilegeWithSudoPrefixHardDenies() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.exec(arguments: ["sudo", "systemctl", "restart", "jellyfin"]),
            privilege: .user,
            policy: policy()
        )
        #expect(evaluation.disposition == PolicyDisposition.denied)
        #expect(evaluation.findings.map { $0.code }.contains("command.embedded_sudo"))
    }

    @Test("shell mode embedding sudo hard-denies even at sudo privilege")
    func shellEmbeddingSudoHardDenies() throws {
        let evaluation = try engine.evaluate(
            command: CommandSpec.shell(program: "systemctl restart jellyfin; sudo whoami"),
            privilege: .sudo,
            policy: policy()
        )
        #expect(evaluation.disposition == PolicyDisposition.denied)
        #expect(evaluation.findings.map { $0.code }.contains("command.embedded_sudo"))
    }

    private func policy(
        automatic: [PolicyRule] = [],
        approval: [PolicyRule] = [],
        deny: [PolicyRule] = [],
        maximumTimeoutSeconds: UInt = 60
    ) -> Policy {
        Policy(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            version: "test-v1",
            automaticRules: automatic,
            approvalRules: approval,
            denyRules: deny,
            limits: ExecutionLimits(
                maximumTimeoutSeconds: maximumTimeoutSeconds,
                maximumOutputBytes: 1_048_576,
                maximumConcurrentRequests: 10,
                allowsTTY: false
            )
        )
    }
}
