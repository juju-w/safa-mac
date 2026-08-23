import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATestFixtures
import Testing

@Suite("Sudo approval trust boundary")
struct SudoApprovalBoundaryTests {
    @Test("a protected payload cannot execute without a broker-held authenticated exact grant")
    func protectedPayloadAloneHasNoAuthority() async throws {
        let secret = Data("synthetic-secret-must-not-persist".utf8)
        let credentials = InMemoryPasswordSecretStore()
        let handler = MVPBrokerHandler(
            vault: InMemoryVaultDocumentStore(),
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            approvalAuthenticator: RejectingApprovalAuthenticator(),
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let reply = await handler.handle(
            .completeSudoApproval(
                requestID: UUID(),
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(secret: secret)
                )
            ),
            caller: CallerIdentity(
                signingIdentifier: "dev.safa.trusted-local",
                teamIdentifier: "TESTTEAM1",
                effectiveUserID: 501,
                auditSessionID: 77
            ),
            messageID: UUID()
        )

        #expect(reply.status == .failed)
        #expect(reply.error?.code == "approval_session_invalid")
        let serialized = String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self)
        #expect(!serialized.contains(String(decoding: secret, as: UTF8.self)))
    }
}

private struct RejectingApprovalAuthenticator: ApprovalAuthenticating {
    func authorize(reason _: String) async -> Bool { false }
}
