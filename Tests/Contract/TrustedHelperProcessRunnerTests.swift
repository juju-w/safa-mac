import Darwin
import Foundation
import Testing

@testable import SAFACLI

@Suite("Trusted helper process runner")
struct TrustedHelperProcessRunnerTests {
    @Test("helper inherits the launcher's process group so controlling-TTY input stays foreground")
    func inheritsForegroundProcessGroup() async throws {
        let parentProcessGroup = getpgrp()
        let program = "test \"$(ps -o pgid= -p $$ | tr -d ' ')\" = \"$1\""
        let status = try await TrustedHelperProcessRunner().run(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", program, "safa-helper-test", String(parentProcessGroup)],
            environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        )

        #expect(status == 0)
    }
}
