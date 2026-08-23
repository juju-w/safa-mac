import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFATestFixtures
import Testing

@Suite("Sudo credential never leaks outside the password store")
struct SudoCredentialLeakageTests {
    @Test("the raw secret is never written to storageLocator or publicMaterial")
    func secretNeverInCredentialReference() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let secret = Data("must-not-leak-into-the-vault-document".utf8)
        let resource = try await resources.enrollSudoCredential(
            alias: alias, mode: .password(secret))

        let document = await vault.readDocument()
        let sudoReference = try #require(
            document.credentialReferences.first(where: { $0.id == resource.sudoRef })
        )
        #expect(sudoReference.storageLocator != secret)
        #expect(sudoReference.publicMaterial != String(decoding: secret, as: UTF8.self))

        let encodedDocument = try JSONEncoder().encode(document)
        #expect(encodedDocument.range(of: secret) == nil)
    }

    @Test("the secret is retrievable only through the password store, by credential id")
    func secretOnlyInPasswordStore() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let secret = Data("synthetic-sudo-secret".utf8)
        let resource = try await resources.enrollSudoCredential(
            alias: alias, mode: .password(secret))
        let sudoCredentialID = try #require(resource.sudoRef)

        #expect(await credentials.readSecret(id: sudoCredentialID) == secret)
    }

    @Test("rotating the sudo credential deletes the previous secret")
    func rotationDeletesPreviousSecret() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let first = Data("first-sudo-secret".utf8)
        let firstResource = try await resources.enrollSudoCredential(
            alias: alias,
            mode: .password(first)
        )
        let firstCredentialID = try #require(firstResource.sudoRef)

        let second = Data("second-sudo-secret".utf8)
        let secondResource = try await resources.enrollSudoCredential(
            alias: alias,
            mode: .password(second)
        )
        let secondCredentialID = try #require(secondResource.sudoRef)

        #expect(firstCredentialID != secondCredentialID)
        #expect(await credentials.readSecret(id: firstCredentialID) == nil)
        #expect(await credentials.readSecret(id: secondCredentialID) == second)
        let document = await vault.readDocument()
        #expect(!document.credentialReferences.contains(where: { $0.id == firstCredentialID }))
    }

    @Test("removing the sudo credential deletes its secret and clears sudoRef")
    func removalDeletesSecret() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let secret = Data("to-be-removed".utf8)
        let enrolled = try await resources.enrollSudoCredential(
            alias: alias, mode: .password(secret))
        let credentialID = try #require(enrolled.sudoRef)

        let removed = try await resources.removeSudoCredential(alias: alias)
        #expect(removed.sudoRef == nil)
        #expect(await credentials.readSecret(id: credentialID) == nil)
        let document = await vault.readDocument()
        #expect(!document.credentialReferences.contains(where: { $0.id == credentialID }))
    }

    @Test("an invalid secret is rejected before it ever reaches the password store")
    func invalidSecretNeverPersists() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        await #expect(throws: SudoCredentialPolicyError.invalidSecret) {
            try await resources.enrollSudoCredential(alias: alias, mode: .password(Data()))
        }
        let document = await vault.readDocument()
        #expect(!document.resources.contains(where: { $0.sudoRef != nil }))
    }

    @Test("passwordless enrollment stores no secret at all")
    func passwordlessStoresNoSecret() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let resource = try await resources.enrollSudoCredential(alias: alias, mode: .passwordless)
        let credentialID = try #require(resource.sudoRef)
        #expect(await credentials.readSecret(id: credentialID) == nil)
        let document = await vault.readDocument()
        let reference = try #require(document.credentialReferences.first { $0.id == credentialID })
        #expect(reference.storageLocator.isEmpty)
        #expect(reference.publicMaterial == "passwordless")
    }

    private static func addPrimaryResource(
        alias: ResourceAlias,
        resources: ResourceService
    ) async throws {
        try await resources.addProtectedResource(
            PrivateResourceDraft(
                alias: alias,
                endpoint: ResourceEndpoint(host: "host.invalid", port: 22),
                username: "operator",
                securityDomain: "resource.\(alias.rawValue)",
                hostIdentity: HostIdentity(
                    algorithm: "ssh-ed25519",
                    publicKey: Data([1, 2, 3]),
                    fingerprint: "SHA256:trusted",
                    verifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
                    verificationMethod: .manual,
                    status: .trusted
                )
            ),
            credential: Data("primary-ssh-password".utf8)
        )
    }
}
