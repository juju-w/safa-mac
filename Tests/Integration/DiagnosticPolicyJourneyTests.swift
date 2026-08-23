import Foundation
import SAFABroker
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@Suite("Diagnostic policy broker boundary")
struct DiagnosticPolicyJourneyTests {
    @Test(
        "commands that can disclose unrelated secrets never reach SSH automatically",
        arguments: [
            ["ps", "eww"],
            ["docker", "inspect", "api"],
            ["docker", "ps"],
            ["docker", "stats"],
            ["systemctl", "show", "api"],
            ["systemctl", "status", "api"],
        ]
    )
    func blocksSecretDisclosingForms(_ arguments: [String]) async throws {
        let resource = JourneyResourceFactory.active(alias: "nas.home")
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("must-not-run".utf8),
                stderr: Data(),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [resource])
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(Data("synthetic-password".utf8), id: resource.authRef!)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-policy-\(UUID().uuidString)")
        )

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: arguments),
                privilege: .user,
                intent: "Synthetic adversarial check",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: CallerIdentity(
                signingIdentifier: "dev.safa.cli",
                teamIdentifier: "TESTTEAM1",
                effectiveUserID: 501,
                auditSessionID: 77
            ),
            messageID: UUID()
        )

        // These commands are not on the automatic-diagnostic allowlist (they can disclose
        // another process's environment/secrets), so policy now requires trusted approval
        // instead of the old hard MVP denial — the security property under test (SSH is never
        // reached automatically) still holds either way.
        #expect(reply.status == .userActionRequired)
        #expect(reply.error?.code == "approval_required")
        #expect(reply.data["privilege"] == .string("user"))
        #expect(await runner.lastInvocation() == nil)
        #expect(
            !String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self).contains(
                "must-not-run"))
    }
}
