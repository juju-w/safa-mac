import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import Testing

@testable import SAFATrustedSetup

@Suite("Unified trusted sudo approval")
struct TrustedApprovalFlowTests {
    @Test("first use probes NOPASSWD, reads one hidden password, and completes without re-approval")
    func firstUseCompletesInOneFlow() async throws {
        let requestID = UUID()
        let secret = Data("synthetic-sudo-password".utf8)
        let console = ApprovalRecordingConsole(secrets: [secret])
        let client = ApprovalRecordingClient(
            presentation: Self.presentation(
                sudoCredentialState: "missing",
                approvalState: "awaiting_user_presence"
            ),
            decisionResult: .sudoCredentialRequired,
            completionResults: [
                .failure(.brokerRejected("sudo_credential_invalid")),
                .success(.approved(terminationSummary: "exit (exit 0)")),
            ]
        )

        try await TrustedApprovalFlow(console: console, client: client).decide(
            requestID: requestID,
            approved: true
        )

        #expect(await client.decisionCount == 1)
        #expect(await client.completionPayloads.count == 2)
        #expect(await client.completionPayloads[0].passwordlessConfirmed)
        #expect(await client.completionPayloads[1].secret == secret)
        #expect(console.secretReadCount == 1)
        #expect(console.renderedText.contains("Command: systemctl restart jellyfin"))
        #expect(console.renderedText.contains("SAFA approved and ran request"))
        #expect(!console.renderedText.contains("synthetic-sudo-password"))
    }

    @Test("an enrolled sudo credential needs only the one broker-owned approval")
    func readyCredentialDoesNotReadSecret() async throws {
        let console = ApprovalRecordingConsole()
        let client = ApprovalRecordingClient(
            presentation: Self.presentation(
                sudoCredentialState: "ready",
                approvalState: "awaiting_user_presence"
            ),
            decisionResult: .approved(terminationSummary: "exit (exit 0)")
        )

        try await TrustedApprovalFlow(console: console, client: client).decide(
            requestID: UUID(),
            approved: true
        )

        #expect(await client.decisionCount == 1)
        #expect(await client.completionPayloads.isEmpty)
        #expect(console.secretReadCount == 0)
    }

    @Test("an interrupted credential continuation resumes the authenticated exact grant")
    func resumesCredentialContinuationWithoutSecondDecision() async throws {
        let console = ApprovalRecordingConsole()
        let client = ApprovalRecordingClient(
            presentation: Self.presentation(
                sudoCredentialState: "missing",
                approvalState: "credential_required"
            ),
            decisionResult: .denied,
            completionResults: [
                .success(.approved(terminationSummary: "exit (exit 0)"))
            ]
        )

        try await TrustedApprovalFlow(console: console, client: client).decide(
            requestID: UUID(),
            approved: true
        )

        #expect(await client.decisionCount == 0)
        #expect(await client.completionPayloads.count == 1)
        #expect(console.secretReadCount == 0)
    }

    @Test("transport failure during NOPASSWD probe never opens a password prompt")
    func transportFailureDoesNotReadSecret() async {
        let console = ApprovalRecordingConsole(secrets: [Data("must-not-be-read".utf8)])
        let client = ApprovalRecordingClient(
            presentation: Self.presentation(
                sudoCredentialState: "missing",
                approvalState: "awaiting_user_presence"
            ),
            decisionResult: .sudoCredentialRequired,
            completionResults: [.failure(.brokerRejected("sudo_verification_failed"))]
        )

        await #expect(throws: TrustedLocalSetupClientError.self) {
            try await TrustedApprovalFlow(console: console, client: client).decide(
                requestID: UUID(),
                approved: true
            )
        }
        #expect(console.secretReadCount == 0)
    }

    private static func presentation(
        sudoCredentialState: String,
        approvalState: String
    ) -> TrustedApprovalPresentation {
        TrustedApprovalPresentation(
            resourceAlias: "media.home",
            privilege: "sudo",
            command: "systemctl restart jellyfin",
            intent: "Restart the media service",
            expectedEffect: "jellyfin restarts",
            riskLevel: "high",
            findings: ["command.sudo_requested"],
            sudoCredentialState: sudoCredentialState,
            approvalState: approvalState
        )
    }
}

private final class ApprovalRecordingConsole: TrustedSetupConsole, @unchecked Sendable {
    private let lock = NSLock()
    private var secrets: [Data]
    private var text = ""
    private var reads = 0

    init(secrets: [Data] = []) { self.secrets = secrets }

    var renderedText: String { lock.withLock { text } }
    var secretReadCount: Int { lock.withLock { reads } }

    func write(_ text: String) {
        lock.withLock { self.text += text }
    }

    func readSecret(prompt: String) -> Data {
        lock.withLock {
            text += prompt
            reads += 1
            return secrets.isEmpty ? Data() : secrets.removeFirst()
        }
    }
}

private actor ApprovalRecordingClient: TrustedLocalSetupClient {
    let presentationValue: TrustedApprovalPresentation
    let decisionResult: TrustedApprovalDecisionResult
    var completionResults: [Result<TrustedApprovalDecisionResult, TrustedLocalSetupClientError>]
    private(set) var decisionCount = 0
    private(set) var completionPayloads: [ProtectedSudoCredentialPayload] = []

    init(
        presentation: TrustedApprovalPresentation,
        decisionResult: TrustedApprovalDecisionResult,
        completionResults: [Result<TrustedApprovalDecisionResult, TrustedLocalSetupClientError>] =
            []
    ) {
        presentationValue = presentation
        self.decisionResult = decisionResult
        self.completionResults = completionResults
    }

    func approvalPresentation(requestID _: UUID) async throws -> TrustedApprovalPresentation {
        presentationValue
    }

    func decideApproval(
        requestID _: UUID,
        approved _: Bool,
        scope _: ApprovalScope?
    ) async throws -> TrustedApprovalDecisionResult {
        decisionCount += 1
        return decisionResult
    }

    func completeSudoApproval(
        requestID _: UUID,
        payload: ProtectedSudoCredentialPayload
    ) async throws -> TrustedApprovalDecisionResult {
        completionPayloads.append(payload)
        guard !completionResults.isEmpty else { throw TrustedLocalSetupClientError.unavailable }
        return try completionResults.removeFirst().get()
    }

    func begin(alias _: ResourceAlias) async throws -> UUID {
        throw TrustedLocalSetupClientError.unavailable
    }

    func commit(sessionID _: UUID, payload _: ProtectedResourceSetupPayload) async throws {
        throw TrustedLocalSetupClientError.unavailable
    }

    func attachSudo(alias _: ResourceAlias, payload _: ProtectedSudoCredentialPayload) async throws
    {
        throw TrustedLocalSetupClientError.unavailable
    }

    func removeSudo(alias _: ResourceAlias) async throws {
        throw TrustedLocalSetupClientError.unavailable
    }
}
