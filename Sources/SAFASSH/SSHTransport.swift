import Foundation
import SAFADomain
import SAFATransport

public struct SSHTransport: Sendable {
    private let runner: any ProcessRunning
    private let builder: SSHConfigurationBuilder

    public init(
        runner: any ProcessRunning = ProcessRunner(),
        builder: SSHConfigurationBuilder = SSHConfigurationBuilder()
    ) {
        self.runner = runner
        self.builder = builder
    }

    public func execute(
        resource: Resource,
        command: CommandSpec,
        credential: SSHCredentialContext,
        workingRoot: URL,
        didLaunch: (@Sendable (Int32) -> Void)? = nil,
        /// Bytes piped to the local `ssh` process's stdin, which OpenSSH
        /// forwards untouched to the remote command's stdin (no PTY is
        /// allocated). Only trusted, broker-internal callers may set this —
        /// it is unrelated to `CommandSpec.stdinMode`, which governs the
        /// Agent-facing execution path and never carries a payload of its
        /// own. Throws `SSHConfigurationError
        /// .stdinForwardingUnavailableForPasswordCredential` when combined
        /// with a `.password` login credential.
        remoteStandardInput: Data? = nil
    ) async throws -> ProcessExecutionResult {
        let prepared = try builder.prepare(
            resource: resource,
            command: command,
            credential: credential,
            rootDirectory: workingRoot,
            remoteStandardInput: remoteStandardInput
        )
        defer { try? FileManager.default.removeItem(at: prepared.rootDirectory) }
        let invocation = didLaunch.map(prepared.invocation.withLaunchHandler) ?? prepared.invocation
        return try await runner.run(invocation)
    }

    public func executeWindowsPowerShell(
        resource: Resource,
        encodedScript: String,
        credential: SSHCredentialContext,
        workingRoot: URL,
        timeoutSeconds: UInt,
        outputLimitBytes: UInt,
        didLaunch: (@Sendable (Int32) -> Void)? = nil
    ) async throws -> ProcessExecutionResult {
        let prepared = try builder.prepareWindowsPowerShell(
            resource: resource,
            encodedScript: encodedScript,
            credential: credential,
            rootDirectory: workingRoot,
            timeoutSeconds: timeoutSeconds,
            outputLimitBytes: outputLimitBytes
        )
        defer { try? FileManager.default.removeItem(at: prepared.rootDirectory) }
        let invocation = didLaunch.map(prepared.invocation.withLaunchHandler) ?? prepared.invocation
        return try await runner.run(invocation)
    }
}
