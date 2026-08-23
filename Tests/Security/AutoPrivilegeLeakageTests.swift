import Foundation
import SAFADomain
import SAFAPolicy
import Testing

@Suite("Auto privilege disclosure boundary")
struct AutoPrivilegeLeakageTests {
    @Test("100 resolver runs never echo command data or manufacture escalation from near matches")
    func hundredRunRegression() throws {
        let resolver = AutoPrivilegeResolver()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let observation = AutoPrivilegeAccountObservation(
            isRoot: false,
            dockerAuthorized: false,
            observedAt: now
        )

        for index in 0..<100 {
            let marker = "synthetic-private-marker-\(index)"
            let command = try CommandSpec.exec(
                arguments: ["docker", "exec", marker, "id"])
            let decision = resolver.resolve(
                command: command,
                observation: observation,
                now: now
            )
            let projection = String(reflecting: decision)

            #expect(decision == .user(reason: .commandNotEligible))
            #expect(!projection.contains(marker))
            #expect(!projection.contains("sudo"))
        }
    }
}
