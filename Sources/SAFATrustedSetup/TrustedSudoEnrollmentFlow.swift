import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

enum TrustedSudoEnrollmentError: Error, Equatable, Sendable {
    case authorizationDenied
    case invalidCredential
}

/// Mirrors `TrustedSSHEnrollmentFlow`'s shape: authorize with Touch ID first,
/// collect the secret only from the controlling TTY (never stdin), and hand
/// it to the broker as opaque protected bytes. The broker performs the SSH
/// verification and vault write; this flow never sees whether the secret was
/// accepted beyond the broker's completed/failed reply.
struct TrustedSudoEnrollmentFlow: Sendable {
    private let console: any TrustedSetupConsole
    private let authorizer: any UserPresenceAuthorizing
    private let client: any TrustedLocalSetupClient

    init(
        console: any TrustedSetupConsole,
        authorizer: any UserPresenceAuthorizing,
        client: any TrustedLocalSetupClient
    ) {
        self.console = console
        self.authorizer = authorizer
        self.client = client
    }

    func enroll(alias: ResourceAlias, passwordless: Bool) async throws {
        guard
            await authorizer.authorize(
                reason: "Configure protected sudo access for SAFA resource \(alias.rawValue)"
            )
        else {
            throw TrustedSudoEnrollmentError.authorizationDenied
        }

        if passwordless {
            try await verifyPasswordless(alias: alias)
            try await write("SAFA verified passwordless sudo for \(alias.rawValue).\n")
            return
        }

        do {
            try await verifyPasswordless(alias: alias)
            try await write("SAFA verified passwordless sudo for \(alias.rawValue).\n")
            return
        } catch let TrustedLocalSetupClientError.brokerRejected(code)
            where code == "sudo_credential_invalid"
        {
            // The broker has positively verified that NOPASSWD is unavailable.
            // Only this response permits collecting a password; transport and
            // verification failures must never be mistaken for a password prompt.
        }

        var secret = try await readSecret("Sudo password (hidden): ")
        defer { secret.resetBytes(in: 0..<secret.count) }
        guard !secret.isEmpty else { throw TrustedSudoEnrollmentError.invalidCredential }
        try await client.attachSudo(
            alias: alias,
            payload: ProtectedSudoCredentialPayload(secret: secret)
        )
        try await write("SAFA verified and stored the sudo credential for \(alias.rawValue).\n")
    }

    private func verifyPasswordless(alias: ResourceAlias) async throws {
        try await client.attachSudo(
            alias: alias,
            payload: ProtectedSudoCredentialPayload(passwordlessConfirmed: true)
        )
    }

    func remove(alias: ResourceAlias) async throws {
        guard
            await authorizer.authorize(
                reason: "Remove the protected sudo credential for SAFA resource \(alias.rawValue)"
            )
        else {
            throw TrustedSudoEnrollmentError.authorizationDenied
        }
        try await client.removeSudo(alias: alias)
        try await write("SAFA removed the sudo credential for \(alias.rawValue).\n")
    }

    private func readSecret(_ prompt: String) async throws -> Data {
        try await Task.detached(priority: .userInitiated) { [console] in
            try console.readSecret(prompt: prompt)
        }.value
    }

    private func write(_ text: String) async throws {
        try await Task.detached(priority: .userInitiated) { [console] in
            try console.write(text)
        }.value
    }
}
