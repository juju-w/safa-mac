import Foundation
import SAFADomain
import SAFAPolicy
import Testing

private let autoPrivilegeTestNow = Date(timeIntervalSince1970: 1_800_000_000)

struct AutoPrivilegeResolverTests {
    private let now = autoPrivilegeTestNow

    @Test("fresh root account always stays direct")
    func rootStaysDirect() throws {
        let decision = try AutoPrivilegeResolver().resolve(
            command: .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
            observation: .init(isRoot: true, dockerAuthorized: true, observedAt: now),
            now: now
        )

        #expect(decision == .user(reason: .rootAccount))
    }

    @Test("fresh Docker authorization keeps reviewed Docker reads direct")
    func dockerAuthorizedStaysDirect() throws {
        let decision = try AutoPrivilegeResolver().resolve(
            command: .exec(arguments: ["docker", "ps", "--all"]),
            observation: .init(isRoot: false, dockerAuthorized: true, observedAt: now),
            now: now
        )

        #expect(decision == .user(reason: .dockerAuthorized))
    }

    @Test("reviewed Docker read selects sudo only with fresh negative authorization evidence")
    func dockerUnauthorizedSelectsSudo() throws {
        let decision = try AutoPrivilegeResolver().resolve(
            command: .exec(arguments: ["docker", "ps", "--all"]),
            observation: .init(isRoot: false, dockerAuthorized: false, observedAt: now),
            now: now
        )

        #expect(decision == .sudo(commandClass: .dockerRead))
    }

    @Test("reviewed systemctl mutations select sudo for a fresh non-root account")
    func systemctlMutationSelectsSudo() throws {
        let decision = try AutoPrivilegeResolver().resolve(
            command: .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
            observation: .init(isRoot: false, dockerAuthorized: nil, observedAt: now),
            now: now
        )

        #expect(decision == .sudo(commandClass: .systemdMutation))
    }

    @Test(arguments: [
        AutoPrivilegeAccountObservation(isRoot: nil, dockerAuthorized: nil, observedAt: nil),
        AutoPrivilegeAccountObservation(
            isRoot: false,
            dockerAuthorized: false,
            observedAt: Date(timeIntervalSince1970: 1_799_999_000)
        ),
        AutoPrivilegeAccountObservation(
            isRoot: true, dockerAuthorized: false, observedAt: autoPrivilegeTestNow),
    ])
    func missingStaleOrContradictoryEvidenceNeverElevates(
        observation: AutoPrivilegeAccountObservation
    ) throws {
        let decision = try AutoPrivilegeResolver().resolve(
            command: .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
            observation: observation,
            now: now
        )

        #expect(decision == .user(reason: .insufficientEvidence))
    }

    @Test("unlisted vectors, shell mode, and near matches never elevate")
    func unlistedCommandsNeverElevate() throws {
        let observation = AutoPrivilegeAccountObservation(
            isRoot: false, dockerAuthorized: false, observedAt: now)
        let commands: [CommandSpec] = [
            try .exec(arguments: ["docker", "exec", "synthetic", "id"]),
            try .exec(arguments: ["docker", "ps", "--all", "--format", "{{json .}}"]),
            try .exec(arguments: ["systemctl", "restart", "media-synthetic", "--no-block"]),
            try .shell(program: "systemctl restart media-synthetic"),
        ]

        for command in commands {
            #expect(
                AutoPrivilegeResolver().resolve(
                    command: command, observation: observation, now: now)
                    == .user(reason: .commandNotEligible)
            )
        }
    }
}
