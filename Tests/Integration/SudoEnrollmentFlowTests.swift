import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import Testing

@Suite("Enroll a host's sudo credential")
struct SudoEnrollmentFlowTests {
    private static let caller = CallerIdentity(
        signingIdentifier: "dev.safa.trusted-local",
        teamIdentifier: "TESTTEAM1",
        effectiveUserID: 501,
        auditSessionID: 78
    )

    @Test("a verified password is persisted and surfaces sudoRef on the resource")
    func verifiedPasswordPersists() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let sudoVerifier = RecordingSudoVerifier(passwordResult: true)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: resources,
            sudoVerifier: sudoVerifier,
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let secret = Data("synthetic-sudo-password".utf8)
        let reply = await handler.handle(
            .attachSudoCredential(
                resourceAlias: alias,
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(secret: secret)
                )
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        #expect(await sudoVerifier.observedSecrets == [secret])
        let resource = try await resources.resource(alias: alias)
        let sudoCredentialID = try #require(resource.sudoRef)
        #expect(await credentials.readSecret(id: sudoCredentialID) == secret)
        #expect(try await Self.sudoMode(alias: alias, vault: vault) == "password")
    }

    @Test("a rejected password verification persists nothing")
    func rejectedPasswordPersistsNothing() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let sudoVerifier = RecordingSudoVerifier(passwordResult: false)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: resources,
            sudoVerifier: sudoVerifier,
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let secret = Data("wrong-sudo-password".utf8)
        let reply = await handler.handle(
            .attachSudoCredential(
                resourceAlias: alias,
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(secret: secret)
                )
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.status == .failed)
        #expect(reply.error?.code == "sudo_credential_invalid")
        let resource = try await resources.resource(alias: alias)
        #expect(resource.sudoRef == nil)
    }

    @Test("passwordless enrollment succeeds when NOPASSWD sudo verifies")
    func passwordlessEnrollmentSucceeds() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)

        let sudoVerifier = RecordingSudoVerifier(passwordlessResult: true)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: resources,
            sudoVerifier: sudoVerifier,
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let reply = await handler.handle(
            .attachSudoCredential(
                resourceAlias: alias,
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(passwordlessConfirmed: true)
                )
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        let resource = try await resources.resource(alias: alias)
        let sudoCredentialID = try #require(resource.sudoRef)
        #expect(await credentials.readSecret(id: sudoCredentialID) == nil)
        let document = await vault.readDocument()
        let reference = try #require(
            document.credentialReferences.first { $0.id == sudoCredentialID }
        )
        #expect(reference.publicMaterial == "passwordless")
        #expect(try await Self.sudoMode(alias: alias, vault: vault) == "passwordless")
    }

    @Test("attaching sudo to an unregistered resource fails without touching the vault")
    func unknownResourceFails() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let sudoVerifier = RecordingSudoVerifier(passwordResult: true)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            sudoVerifier: sudoVerifier,
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let reply = await handler.handle(
            .attachSudoCredential(
                resourceAlias: try ResourceAlias("ghost.host"),
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(secret: Data("unused".utf8))
                )
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.status == .failed)
        #expect(reply.error?.code == "resource_not_found")
        #expect(await sudoVerifier.observedSecrets.isEmpty)
    }

    @Test("removing a sudo credential clears sudoRef and the stored secret")
    func removalClearsCredential() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let alias = try ResourceAlias("nas.home")
        try await Self.addPrimaryResource(alias: alias, resources: resources)
        try await resources.enrollSudoCredential(
            alias: alias,
            mode: .password(Data("synthetic-sudo-password".utf8))
        )

        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: resources,
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let reply = await handler.handle(
            .removeSudoCredential(resourceAlias: alias),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        let resource = try await resources.resource(alias: alias)
        #expect(resource.sudoRef == nil)
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

    private static func sudoMode(
        alias: ResourceAlias,
        vault: InMemoryVaultDocumentStore
    ) async throws -> String? {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let service = ResourceDirectoryService(
            vault: vault,
            disclosureAuthorizer: UnusedResourceDisclosureAuthorizer()
        )
        let reply = await service.handle(
            ResourceDirectoryRequestV1(
                header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
                action: .show,
                alias: alias
            ),
            caller: caller,
            now: now
        )
        return (try #require(reply.summaries.first)).sudoMode
    }
}

private struct UnusedResourceDisclosureAuthorizer: ResourceDisclosureAuthorizing {
    func authorize(alias _: ResourceAlias, now _: Date) async throws {
        Issue.record("show must not request detail disclosure authorization")
    }
}

private actor RecordingSudoVerifier: SudoCredentialVerifying {
    private let passwordResult: Bool
    private let passwordlessResult: Bool
    private(set) var observedSecrets: [Data] = []
    private(set) var passwordlessCallCount = 0

    init(passwordResult: Bool = false, passwordlessResult: Bool = false) {
        self.passwordResult = passwordResult
        self.passwordlessResult = passwordlessResult
    }

    func verifyPasswordless(
        resource: Resource,
        primaryCredential: SSHCredentialContext
    ) async throws -> Bool {
        passwordlessCallCount += 1
        return passwordlessResult
    }

    func verifyPassword(
        resource: Resource,
        primaryCredential: SSHCredentialContext,
        sudoSecret: Data
    ) async throws -> Bool {
        observedSecrets.append(sudoSecret)
        return passwordResult
    }
}
