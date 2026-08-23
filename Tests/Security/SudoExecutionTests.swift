import Foundation
import SAFADomain
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@Suite("Sudo command composition and credential injection")
struct SudoExecutionTests {
    @Test("the remote command isolates the privileged child's stdin and never embeds the secret")
    func composesSudoArgumentsWithoutEmbeddingSecret() async throws {
        let secret = Data("must-not-appear-in-argv".utf8)
        let runner = FakeProcessRunner(result: Self.successResult())
        let executor = SudoExecutor(transport: SSHTransport(runner: runner))

        _ = try await executor.execute(
            resource: Self.resource(),
            command: try CommandSpec.exec(arguments: ["systemctl", "restart", "docker"]),
            primaryCredential: Self.openSSHCredential(),
            sudoSecret: secret,
            workingRoot: Self.workingRoot()
        )

        let invocation = try #require(await runner.lastInvocation())
        // The local `ssh` process receives the remote command as one POSIX-quoted string
        // (per-token quoted, then space-joined) rather than as separate local argv elements.
        let remoteCommand = try #require(invocation.arguments.last)
        #expect(
            remoteCommand
                == "'sudo' '-S' '-p' '' '--' '/bin/sh' '-c' 'exec \"$@\" </dev/null' 'safa-sudo-child' 'systemctl' 'restart' 'docker'"
        )
        let secretText = String(decoding: secret, as: UTF8.self)
        for argument in invocation.arguments {
            #expect(!argument.contains(secretText))
        }
        #expect(invocation.environment.values.allSatisfy { !$0.contains(secretText) })
    }

    @Test("a stored password cannot become stdin for a command that later becomes NOPASSWD")
    func storedPasswordNeverBecomesChildStdin() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let executor = SudoExecutor(transport: SSHTransport(runner: runner))

        _ = try await executor.execute(
            resource: Self.resource(),
            command: try CommandSpec.exec(arguments: ["sh", "-c", "cat"]),
            primaryCredential: Self.openSSHCredential(),
            sudoSecret: Data("stored-password".utf8),
            workingRoot: Self.workingRoot()
        )

        let invocation = try #require(await runner.lastInvocation())
        let remoteCommand = try #require(invocation.arguments.last)
        #expect(remoteCommand.contains("'exec \"$@\" </dev/null'"))
        #expect(remoteCommand.hasSuffix("'sh' '-c' 'cat'"))
    }

    @Test("the sudo secret reaches the remote command only through stdin, terminated by a newline")
    func secretDeliveredOnlyOnStdin() async throws {
        let secret = Data("synthetic-sudo-password".utf8)
        let runner = FakeProcessRunner(result: Self.successResult())
        let executor = SudoExecutor(transport: SSHTransport(runner: runner))

        _ = try await executor.execute(
            resource: Self.resource(),
            command: try CommandSpec.exec(arguments: ["true"]),
            primaryCredential: Self.openSSHCredential(),
            sudoSecret: secret,
            workingRoot: Self.workingRoot()
        )

        let invocation = try #require(await runner.lastInvocation())
        var expected = secret
        expected.append(0x0A)
        #expect(invocation.standardInput == expected)
    }

    @Test("passwordless sudo runs with no stdin payload at all")
    func passwordlessCarriesNoStdin() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let executor = SudoExecutor(transport: SSHTransport(runner: runner))

        _ = try await executor.execute(
            resource: Self.resource(),
            command: try CommandSpec.exec(arguments: ["true"]),
            primaryCredential: Self.openSSHCredential(),
            sudoSecret: nil,
            workingRoot: Self.workingRoot()
        )

        let invocation = try #require(await runner.lastInvocation())
        #expect(invocation.standardInput == nil)
        let remoteCommand = try #require(invocation.arguments.last)
        #expect(remoteCommand.contains("'-S'"))
    }

    @Test("a password-based primary login credential cannot carry a sudo secret on stdin")
    func passwordPrimaryCredentialRejectsStdinDelivery() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let executor = SudoExecutor(transport: SSHTransport(runner: runner))

        await #expect(throws: SudoExecutorError.primaryCredentialCannotCarrySudoSecret) {
            _ = try await executor.execute(
                resource: Self.resource(),
                command: try CommandSpec.exec(arguments: ["true"]),
                primaryCredential: .password(
                    childBinding: "synthetic-token",
                    askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass")
                ),
                sudoSecret: Data("synthetic".utf8),
                workingRoot: Self.workingRoot()
            )
        }
        #expect(await runner.lastInvocation() == nil)
    }

    private static func successResult() -> ProcessExecutionResult {
        ProcessExecutionResult(
            termination: .exit,
            exitCode: 0,
            stdout: Data(),
            stderr: Data(),
            startedAt: Date(timeIntervalSince1970: 1_700_000_000),
            finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }

    private static func openSSHCredential() -> SSHCredentialContext {
        .openSSH(identityFiles: [URL(fileURLWithPath: "/synthetic/id_ed25519")], identityAgent: nil)
    }

    private static func workingRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("safa-sudo-exec-\(UUID().uuidString)", isDirectory: true)
    }

    private static func resource() -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias("nas.home"),
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            ),
            authRef: UUID(),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }
}
