import Foundation
import SAFADomain
import Testing

@Suite("Sudo credential eligibility and secret validation")
struct SudoCredentialDomainTests {
    private static let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test("an active SSH resource with a primary credential is eligible")
    func eligibleResource() throws {
        let resource = try Self.resource(authRef: UUID())
        try SudoCredentialPolicy.ensureEligible(resource: resource)
    }

    @Test("a resource without a primary credential is rejected")
    func missingPrimaryCredential() throws {
        let resource = try Self.resource(authRef: nil)
        #expect(throws: SudoCredentialPolicyError.primaryCredentialRequired) {
            try SudoCredentialPolicy.ensureEligible(resource: resource)
        }
    }

    @Test("a disabled resource is rejected regardless of its credentials")
    func inactiveResource() throws {
        let resource = try Self.resource(authRef: UUID(), state: .disabled)
        #expect(throws: SudoCredentialPolicyError.resourceNotActive) {
            try SudoCredentialPolicy.ensureEligible(resource: resource)
        }
    }

    @Test("a resource without SSH among its access methods is rejected")
    func nonSSHResource() throws {
        let resource = try Self.resource(authRef: UUID(), accessMethods: [])
        #expect(throws: SudoCredentialPolicyError.sshAccessRequired) {
            try SudoCredentialPolicy.ensureEligible(resource: resource)
        }
    }

    @Test("empty, oversized, or control-character secrets are rejected")
    func invalidSecrets() {
        let oversized = Data(repeating: 0x41, count: SudoCredentialPolicy.maximumSecretBytes + 1)
        for secret in [Data(), oversized, Data([0x41, 0x0A]), Data([0x41, 0x0D]), Data([0x00])] {
            #expect(throws: SudoCredentialPolicyError.invalidSecret) {
                try SudoCredentialPolicy.validateSecret(secret)
            }
        }
    }

    @Test("an ordinary password-shaped secret validates")
    func validSecret() throws {
        try SudoCredentialPolicy.validateSecret(Data("correct horse battery staple".utf8))
    }

    private static func resource(
        authRef: UUID?,
        state: ResourceState = .active,
        accessMethods: [AccessMethodIdentifier] = [.ssh]
    ) throws -> Resource {
        Resource(
            id: UUID(),
            alias: try ResourceAlias("nas.home"),
            accessMethods: accessMethods,
            username: "operator",
            securityDomain: "resource.nas.home",
            authRef: authRef,
            state: state,
            createdAt: now,
            updatedAt: now
        )
    }
}
