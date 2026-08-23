import Foundation
import SAFACrypto
import SAFAProtocol

/// Renders the broker-computed presentation for a pending request, then relays the user's
/// decision. Unlike `TrustedSudoEnrollmentFlow`, the actual Touch ID/passcode gate for a "yes"
/// happens broker-side (`ApprovalService`), built from its own copy of this same request/risk
/// data — this flow's role is showing the user exactly what they are about to approve and
/// carrying their console-level decision, not authenticating them itself.
struct TrustedApprovalFlow: Sendable {
    private let console: any TrustedSetupConsole
    private let client: any TrustedLocalSetupClient

    init(console: any TrustedSetupConsole, client: any TrustedLocalSetupClient) {
        self.console = console
        self.client = client
    }

    func decide(requestID: UUID, approved: Bool) async throws {
        let presentation = try await client.approvalPresentation(requestID: requestID)
        try await render(presentation, decidingApproved: approved)

        let result: TrustedApprovalDecisionResult
        if approved, presentation.approvalState == "credential_required" {
            // LocalAuthentication already succeeded for this immutable request. Resume only
            // its short-lived broker-held grant; do not prompt a second time.
            result = .sudoCredentialRequired
        } else {
            result = try await client.decideApproval(
                requestID: requestID, approved: approved, scope: nil)
        }
        switch result {
        case .denied:
            try await write("SAFA denied request \(requestID.uuidString).\n")
        case .sudoCredentialRequired:
            let summary = try await completeFirstUseSudo(
                requestID: requestID,
                alias: presentation.resourceAlias
            )
            try await write("SAFA approved and ran request \(requestID.uuidString): \(summary)\n")
        case let .approved(summary):
            try await write(
                "SAFA approved and ran request \(requestID.uuidString): \(summary)\n")
        }
    }

    /// The user has already reviewed the exact command and passed broker-owned
    /// LocalAuthentication. Probe NOPASSWD first; only a positive "password required" result
    /// permits reading a remote sudo password from `/dev/tty`.
    private func completeFirstUseSudo(requestID: UUID, alias: String) async throws -> String {
        do {
            return try completionSummary(
                try await client.completeSudoApproval(
                    requestID: requestID,
                    payload: ProtectedSudoCredentialPayload(passwordlessConfirmed: true)
                )
            )
        } catch let TrustedLocalSetupClientError.brokerRejected(code)
            where code == "sudo_credential_invalid"
        {
            // The remote host was reached and positively rejected NOPASSWD. Transport,
            // identity, and verification failures never trigger secret input.
        }

        var secret = try await readSecret("Sudo password for \(alias) (hidden): ")
        defer { secret.resetBytes(in: 0..<secret.count) }
        guard !secret.isEmpty else { throw TrustedSudoEnrollmentError.invalidCredential }
        return try completionSummary(
            try await client.completeSudoApproval(
                requestID: requestID,
                payload: ProtectedSudoCredentialPayload(secret: secret)
            )
        )
    }

    private func completionSummary(
        _ result: TrustedApprovalDecisionResult
    ) throws -> String {
        guard case let .approved(summary) = result else {
            throw TrustedLocalSetupClientError.invalidReply
        }
        return summary
    }

    private func render(
        _ presentation: TrustedApprovalPresentation, decidingApproved: Bool
    ) async throws {
        var lines: [String] = []
        if presentation.privilege == "sudo" {
            lines.append("*** SUDO REQUEST \u{2014} this runs with root privilege ***")
        }
        lines.append("Resource: \(presentation.resourceAlias)")
        lines.append("Privilege: \(presentation.privilege)")
        lines.append("Command: \(presentation.command)")
        lines.append("Intent: \(presentation.intent)")
        if let expectedEffect = presentation.expectedEffect {
            lines.append("Expected effect: \(expectedEffect)")
        }
        lines.append("Risk: \(presentation.riskLevel)")
        if !presentation.findings.isEmpty {
            lines.append("Findings: \(presentation.findings.joined(separator: ", "))")
        }
        lines.append(
            decidingApproved
                ? presentation.approvalState == "credential_required"
                    ? "Approval authenticated; completing first-use sudo setup"
                    : "Deciding: approve (local authentication required next)"
                : "Deciding: deny")
        try await write(lines.joined(separator: "\n") + "\n")
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
