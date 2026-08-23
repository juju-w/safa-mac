import Foundation
import SAFADomain
import SAFASSH
import SAFATransport

public enum SudoCredentialVerificationError: Error, Equatable, Sendable {
    /// The resource's primary SSH login uses password authentication, which
    /// pins `StdinNull yes` on the underlying `ssh` invocation so the sudo
    /// secret has no channel to reach the remote `sudo -S` prompt. Sudo
    /// verification requires a key-based primary credential (`.sshOpenSSH`
    /// or a Secure Enclave key) so the local `ssh` process's stdin is free
    /// to carry the secondary secret over the already-authenticated channel.
    case primaryCredentialCannotCarrySudoSecret
    case transportFailure
}

public protocol SudoCredentialVerifying: Sendable {
    /// Confirms NOPASSWD sudo is configured for the resource's login account
    /// by running `sudo -n -k true`, which succeeds only if sudo would not
    /// need to prompt at all.
    func verifyPasswordless(
        resource: Resource,
        primaryCredential: SSHCredentialContext
    ) async throws -> Bool

    /// Confirms `sudoSecret` authenticates for sudo by running
    /// `sudo -k -S -p '' true` with the secret piped to the remote process's
    /// stdin over the primary SSH channel. Never writes the secret to argv,
    /// an environment variable, or a temporary file.
    func verifyPassword(
        resource: Resource,
        primaryCredential: SSHCredentialContext,
        sudoSecret: Data
    ) async throws -> Bool
}

/// Broker-internal only: reachable exclusively from the Touch ID-gated
/// trusted-local IPC path (`MVPBrokerHandler`), never from the Agent-facing
/// command execution path. It performs one bounded, output-free probe
/// command and nothing else.
public struct SudoCredentialVerifier: SudoCredentialVerifying {
    private let transport: SSHTransport
    private let workingDirectory: URL

    public init(
        transport: SSHTransport = SSHTransport(),
        workingDirectory: URL
    ) {
        self.transport = transport
        self.workingDirectory = workingDirectory
    }

    public func verifyPasswordless(
        resource: Resource,
        primaryCredential: SSHCredentialContext
    ) async throws -> Bool {
        let result = try await run(
            resource: resource,
            credential: primaryCredential,
            remoteStandardInput: nil,
            arguments: ["sudo", "-n", "-k", "true"]
        )
        return result.termination == .exit && result.exitCode == 0
    }

    public func verifyPassword(
        resource: Resource,
        primaryCredential: SSHCredentialContext,
        sudoSecret: Data
    ) async throws -> Bool {
        guard Self.canCarryStdin(primaryCredential) else {
            throw SudoCredentialVerificationError.primaryCredentialCannotCarrySudoSecret
        }
        var stdin = sudoSecret
        stdin.append(0x0A)
        defer { stdin.resetBytes(in: 0..<stdin.count) }
        let result = try await run(
            resource: resource,
            credential: primaryCredential,
            remoteStandardInput: stdin,
            // -k forces a fresh prompt so a cached ticket cannot report a
            // false positive; -p '' suppresses the prompt text so it never
            // pollutes stdout; -S reads the password from stdin.
            arguments: ["sudo", "-k", "-S", "-p", "", "true"]
        )
        return result.termination == .exit && result.exitCode == 0
    }

    private func run(
        resource: Resource,
        credential: SSHCredentialContext,
        remoteStandardInput: Data?,
        arguments: [String]
    ) async throws -> ProcessExecutionResult {
        do {
            return try await transport.execute(
                resource: resource,
                command: try CommandSpec.exec(
                    arguments: arguments,
                    timeoutSeconds: 12,
                    outputLimitBytes: 4_096
                ),
                credential: credential,
                workingRoot: workingDirectory.appendingPathComponent(
                    "sudo-verify-\(UUID().uuidString)",
                    isDirectory: true
                ),
                remoteStandardInput: remoteStandardInput
            )
        } catch {
            throw SudoCredentialVerificationError.transportFailure
        }
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
