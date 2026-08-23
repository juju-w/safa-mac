import Foundation
import SAFADomain
import SAFATransport

public enum SudoExecutorError: Error, Equatable, Sendable {
    /// The resource's primary SSH login uses password authentication, which pins
    /// `StdinNull yes` on the underlying `ssh` invocation so the sudo secret has no channel
    /// to reach the remote `sudo -S` prompt. Mirrors `SudoCredentialVerificationError`'s same
    /// constraint for the verification-only probe.
    case primaryCredentialCannotCarrySudoSecret
    case unsupportedCommandMode
    case transportFailure
}

public protocol SudoExecuting: Sendable {
    /// Runs `command` with sudo privilege on `resource`. `sudoSecret` is `nil` only for a
    /// resource enrolled as passwordless (NOPASSWD) sudo; otherwise it is delivered on the
    /// remote command's stdin over the already-authenticated primary SSH channel and never
    /// appears in argv, an environment variable, a temporary file, or this call's own return
    /// value.
    func execute(
        resource: Resource,
        command: CommandSpec,
        primaryCredential: SSHCredentialContext,
        sudoSecret: Data?,
        workingRoot: URL,
        didLaunch: (@Sendable (Int32) -> Void)?
    ) async throws -> ProcessExecutionResult
}

/// Broker-internal only: reachable exclusively from `ExecutionService` after policy has
/// hard-required trusted approval for `privilege: .sudo` and a matching `ApprovalGrant` has
/// authorized this exact request. Composes and runs the real, Agent-submitted command under
/// sudo — as opposed to `SudoCredentialVerifier`, which only ever runs a fixed, output-free
/// probe during credential enrollment.
public struct SudoExecutor: SudoExecuting {
    private let transport: SSHTransport

    public init(transport: SSHTransport = SSHTransport()) {
        self.transport = transport
    }

    public func execute(
        resource: Resource,
        command: CommandSpec,
        primaryCredential: SSHCredentialContext,
        sudoSecret: Data?,
        workingRoot: URL,
        didLaunch: (@Sendable (Int32) -> Void)? = nil
    ) async throws -> ProcessExecutionResult {
        guard command.mode == .exec, let arguments = command.arguments, !arguments.isEmpty else {
            throw SudoExecutorError.unsupportedCommandMode
        }

        var remoteStandardInput: Data?
        if let sudoSecret {
            guard Self.canCarryStdin(primaryCredential) else {
                throw SudoExecutorError.primaryCredentialCannotCarrySudoSecret
            }
            var stdin = sudoSecret
            stdin.append(0x0A)
            remoteStandardInput = stdin
        }
        defer {
            if remoteStandardInput != nil {
                remoteStandardInput!.resetBytes(in: 0..<remoteStandardInput!.count)
            }
        }

        let sudoCommand = try CommandSpec.exec(
            arguments: Self.composeSudoArguments(originalArguments: arguments),
            stdinMode: command.stdinMode,
            tty: false,
            workingDirectory: command.workingDirectory,
            timeoutSeconds: command.timeoutSeconds,
            outputLimitBytes: command.outputLimitBytes
        )

        do {
            return try await transport.execute(
                resource: resource,
                command: sudoCommand,
                credential: primaryCredential,
                workingRoot: workingRoot,
                didLaunch: didLaunch,
                remoteStandardInput: remoteStandardInput
            )
        } catch let error as SudoExecutorError {
            throw error
        } catch {
            throw SudoExecutorError.transportFailure
        }
    }

    /// `-S` reads the password from stdin (a no-op if the account turns out to have NOPASSWD
    /// sudo, since no prompt is issued); `-p ''` suppresses sudo's prompt text. The fixed
    /// trusted shell wrapper redirects the privileged child's stdin to `/dev/null`. This is
    /// required because NOPASSWD sudo may leave the supplied password unread on stdin, and the
    /// Agent-selected child must never inherit those bytes. The original argument vector remains
    /// positional data and is never interpolated into the wrapper program.
    private static func composeSudoArguments(originalArguments: [String]) -> [String] {
        [
            "sudo", "-S", "-p", "", "--", "/bin/sh", "-c",
            "exec \"$@\" </dev/null", "safa-sudo-child",
        ] + originalArguments
    }

    private static func canCarryStdin(_ credential: SSHCredentialContext) -> Bool {
        switch credential {
        case .password:
            return false
        case .none, .secureEnclave, .openSSH:
            return true
        }
    }
}
