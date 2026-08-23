import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@testable import SAFABroker

@Suite("Local HTTP resource execution")
struct LocalHTTPExecutionJourneyTests {
    @Test("reviewed curl inspection becomes ready only with every required property")
    func curlInspectionConformance() {
        let reviewed = CurlClientInspection(
            executable: true,
            applePlatformSigned: true,
            protocols: ["http", "https"],
            options: [
                "--config", "--connect-timeout", "--fail-with-body", "--max-time",
                "--no-progress-meter",
            ]
        )

        #expect(LocalClientAvailability(inspection: reviewed).http == .ready)
        #expect(
            LocalClientAvailability(
                inspection: CurlClientInspection(
                    executable: true,
                    applePlatformSigned: false,
                    protocols: reviewed.protocols,
                    options: reviewed.options
                )
            ).http == .unavailable
        )
        #expect(
            LocalClientAvailability(
                inspection: CurlClientInspection(
                    executable: true,
                    applePlatformSigned: true,
                    protocols: reviewed.protocols,
                    options: reviewed.options.subtracting(["--fail-with-body"])
                )
            ).http == .unavailable
        )
        #expect(
            LocalClientAvailability(
                inspection: CurlClientInspection(
                    executable: true,
                    applePlatformSigned: true,
                    protocols: ["http"],
                    options: reviewed.options
                )
            ).http == .unavailable
        )
    }

    @Test("unavailable HTTP client is reported by doctor and removes effective exec")
    func unavailableClientChangesRuntimeProjection() async throws {
        let resource = Self.httpResource()
        let sshResource = Self.sshResource()
        let availability = LocalClientAvailability(http: .unavailable)
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [resource, sshResource])
        )
        let runner = FakeProcessRunner(result: Self.successResult)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore(),
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            localProcessRunner: runner,
            localClientAdapter: LocalClientAdapter(availability: availability),
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )
        let directory = ResourceDirectoryService(
            vault: vault,
            disclosureAuthorizer: UnusedDisclosureAuthorizer(),
            localClientAvailability: availability
        )

        let doctor = await handler.handle(
            .runtimeStatus,
            caller: Self.caller,
            messageID: UUID()
        )
        let listed = await directory.handle(
            ResourceDirectoryRequestV1(
                header: IPCHeader(
                    sentAt: Date(timeIntervalSince1970: 1_700_000_000),
                    deadline: Date(timeIntervalSince1970: 1_700_000_030)
                ),
                action: .list
            ),
            caller: Self.caller
        )

        guard case let .string(httpClient)? = doctor.data["http_client"] else {
            Issue.record("doctor must report HTTP client readiness")
            return
        }
        #expect(httpClient == "unavailable")
        #expect(
            listed.summaries.first(where: { $0.alias == resource.alias.rawValue })?
                .capabilities.contains("exec") == false
        )
        #expect(
            listed.summaries.first(where: { $0.alias == sshResource.alias.rawValue })?
                .capabilities.contains("exec") == true
        )
    }

    @Test("anonymous direct plaintext HTTP remains a reviewed operation")
    func anonymousPlaintextHTTPIsAllowed() throws {
        let plan = try LocalClientAdapter(availability: LocalClientAvailability(http: .ready))
            .prepare(
                resource: Self.httpResource(scheme: "http"),
                command: try CommandSpec.exec(arguments: ["curl"]),
                privilege: .user,
                credential: nil
            )

        #expect(plan.invocation.executableURL.path == "/usr/bin/curl")
        #expect(
            String(decoding: try #require(plan.invocation.standardInput), as: UTF8.self)
                .contains("http://service.invalid:8443/health")
        )
    }

    @Test("registered HTTP resource executes through bounded local curl and becomes verified")
    func executesAndRecordsVerification() async throws {
        let credentialID = UUID()
        let secret = Data("synthetic-api-token".utf8)
        let resource = Self.httpResource(authRef: credentialID)
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: [Self.apiTokenReference(id: credentialID)]
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: credentialID)
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("healthy synthetic-api-token at service.invalid\n".utf8),
                stderr: Data(),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let resourceService = ResourceService(vault: vault, passwordStore: credentials)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: resourceService,
            transport: SSHTransport(runner: runner),
            localProcessRunner: runner,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-http-journey-\(UUID().uuidString)")
        )

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["curl"]),
                privilege: .user,
                intent: "Read the registered health endpoint",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller,
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        let invocation = try #require(await runner.lastInvocation())
        #expect(invocation.executableURL.path == "/usr/bin/curl")
        #expect(invocation.arguments == ["-q", "--config", "-"])
        #expect(invocation.environment == ["LC_ALL": "C"])
        let config = String(decoding: try #require(invocation.standardInput), as: UTF8.self)
        #expect(config.contains("https://service.invalid:8443/health"))
        #expect(config.contains("Authorization: Bearer synthetic-api-token"))

        let replyText = String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self)
        #expect(replyText.contains("healthy [REDACTED] at [REDACTED]"))
        #expect(!replyText.contains("synthetic-api-token"))
        #expect(!replyText.contains("service.invalid"))

        let updated = try #require(
            await vault.readDocument().resources.first(where: { $0.id == resource.id })
        )
        #expect(updated.verification?.status == .verified)
        #expect(updated.verification?.adapter == .http)
        #expect(updated.revision == resource.revision + 1)
    }

    static let caller = CallerIdentity(
        signingIdentifier: "dev.safa.cli",
        teamIdentifier: "TESTTEAM1",
        effectiveUserID: 501,
        auditSessionID: 77
    )

    static func httpResource(
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

    private static func sshResource() -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias("synthetic-host"),
            resourceType: .hostLinux,
            accessMethods: [.ssh],
            transport: .ssh,
            endpoint: ResourceEndpoint(scheme: "ssh", host: "host.invalid", port: 22),
            username: "operator",
            securityDomain: "synthetic",
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }

    static func apiTokenReference(id: UUID) -> CredentialReference {
        CredentialReference(
            id: id,
            kind: .apiToken,
            storageLocator: Data("synthetic-locator".utf8),
            securityDomains: ["synthetic"],
            accessClass: .automaticWithinPolicy,
            health: .ready,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
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

private struct UnusedDisclosureAuthorizer: ResourceDisclosureAuthorizing {
    func authorize(alias _: ResourceAlias, now _: Date) async throws {
        Issue.record("resource list must not request detail disclosure authorization")
    }
}
