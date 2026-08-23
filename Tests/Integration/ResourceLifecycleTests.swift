import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@testable import SAFABroker

@Suite("CLI resource lifecycle")
struct ResourceLifecycleTests {
    @Test("similar resource setup reuses a short approval but destructive state changes do not")
    func resourceSetupAuthorizationLease() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let config = ResolvedSSHConfig(
            endpoint: ResourceEndpoint(host: "synthetic.internal", port: 22),
            username: "operator"
        )
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: StaticSSHConfigResolver(value: config),
            userPresenceAuthorizer: authorizer,
            cooldown: 0,
            authorizationReuseInterval: 300
        )
        let mutation = ResourceMutationV1(
            sourceSSHConfigAlias: try ResourceAlias("synthetic-host"),
            resourceType: .hostLinux
        )
        let start = Date(timeIntervalSince1970: 1_700_000_000)

        _ = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("host.one"),
            mutation: mutation,
            now: start
        )
        _ = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("host.two"),
            mutation: mutation,
            now: start.addingTimeInterval(299)
        )
        _ = try await lifecycle.mutate(
            action: .remove,
            alias: ResourceAlias("host.one"),
            mutation: nil,
            now: start.addingTimeInterval(300)
        )
        _ = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("host.three"),
            mutation: mutation,
            now: start.addingTimeInterval(301)
        )

        #expect(
            await authorizer.reasons == [
                "Add SAFA resource host.one",
                "Remove SAFA resource host.one",
                "Add SAFA resource host.three",
            ])
    }

    @Test("denied user presence leaves the vault unchanged")
    func deniedMutationFailsClosed() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: false)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(throws: ResourceLifecycleError.denied) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("nas.home"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("home-nas"),
                    resourceType: .hostLinux
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await authorizer.reasons == ["Add SAFA resource nas.home"])
    }

    @Test("non-host resource types require an available trusted adapter before prompting")
    func nonHostImportIsRejectedBeforePrompt() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(
            throws: ResourceLifecycleError.adapterUnavailable("mysql")
        ) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("mysql.test"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("mysql-host"),
                    resourceType: .databaseMySQL
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await authorizer.reasons.isEmpty)
        #expect(await vault.readDocument().resources.isEmpty)
    }

    @Test("new SSH resources reject the retired NAS pseudo-platform")
    func retiredNASTypeIsRejectedBeforePrompt() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(
            throws: ResourceLifecycleError.unsupportedResourceType("host.nas")
        ) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("nas.home"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("home-nas"),
                    resourceType: ResourceTypeIdentifier("host.nas")
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await authorizer.reasons.isEmpty)
        #expect(await vault.readDocument().resources.isEmpty)
    }

    @Test("HTTP selects protected local setup while inert adapters fail before prompting")
    func serviceTemplateUsesTrustedSetup() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(
            throws: ResourceLifecycleError.trustedServiceSetupRequired("http")
        ) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("health-api"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("health-api"),
                    resourceType: .serviceHTTP,
                    templateID: .http
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await authorizer.reasons.isEmpty)
        #expect(await vault.readDocument().resources.isEmpty)

        await #expect(
            throws: ResourceLifecycleError.adapterUnavailable("mysql")
        ) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("mysql.test"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("mysql.test"),
                    resourceType: .databaseMySQL,
                    templateID: .mysql
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await authorizer.reasons.isEmpty)
    }

    @Test("mutation actions reject fields owned by a different mutation shape")
    func invalidMutationShapeFailsBeforePrompt() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(throws: ResourceLifecycleError.invalidRequest) {
            try await lifecycle.mutate(
                action: .disable,
                alias: ResourceAlias("nas.home"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("home-nas")
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        await #expect(throws: ResourceLifecycleError.invalidRequest) {
            try await lifecycle.mutate(
                action: .enable,
                alias: ResourceAlias("nas.home"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("home-nas")
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await authorizer.reasons.isEmpty)
    }

    @Test("approved add imports broker-resolved SSH settings as a draft")
    func approvedSSHConfigImport() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(
                        scheme: "ssh",
                        host: "nas.internal",
                        port: 2222
                    ),
                    username: "operator"
                )
            ),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let resource = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas"),
                resourceType: .hostLinux
            ),
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(resource.alias.rawValue == "nas.home")
        #expect(resource.resolvedResourceType == .hostLinux)
        #expect(resource.endpoint?.host == "nas.internal")
        #expect(resource.username == "operator")
        #expect(resource.state == .draft)
        #expect(resource.displayName == nil)
        #expect(resource.authRef == nil)
        #expect(resource.hostIdentity == nil)
    }

    @Test("approved add completes SSH setup in the same resource workflow")
    func approvedAddCompletesSetup() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let resolved = ResolvedSSHConfig(
            endpoint: ResourceEndpoint(host: "nas.internal", port: 2222),
            username: "operator"
        )
        let now = Date(timeIntervalSince1970: 1_700_000_010)
        let setup = try makeAcceptingOpenSSHSetup(
            resources: resources,
            resolved: resolved,
            now: now
        )
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: StaticSSHConfigResolver(value: resolved),
            setup: setup,
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let resource = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas"),
                resourceType: .hostLinux
            ),
            now: now
        )

        #expect(resource.state == .active)
        #expect(resource.authRef != nil)
        #expect(resource.hostIdentity?.status == .trusted)
        #expect(await authorizer.reasons == ["Add SAFA resource nas.home"])
    }

    @Test("a remediable add failure retains a resumable private draft")
    func failedAddRetainsDraft() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(host: "nas.internal", port: 2222),
                    username: "operator"
                )
            ),
            setup: FailingResourceSetup(error: .hostIdentityUnavailable),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(throws: ResourceSetupError.hostIdentityUnavailable) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("nas.home"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("home-nas"),
                    resourceType: .hostLinux
                ),
                now: Date(timeIntervalSince1970: 1_700_000_010)
            )
        }

        let retained = try await resources.resource(alias: ResourceAlias("nas.home"))
        #expect(retained.state == .draft)
        #expect(retained.authRef == nil)
        #expect(retained.hostIdentity == nil)
        #expect(await authorizer.reasons == ["Add SAFA resource nas.home"])
    }

    @Test("edit resumes and activates a retained SSH draft")
    func editResumesDraftSetup() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let resolved = ResolvedSSHConfig(
            endpoint: ResourceEndpoint(host: "nas.internal", port: 2222),
            username: "operator"
        )
        _ = try await resources.addDiscoveredResource(
            DiscoveredResourceDraft(
                alias: ResourceAlias("nas.home"),
                resourceType: .hostLinux,
                endpoint: resolved.endpoint,
                username: resolved.username,
                securityDomain: "local-ssh-config"
            )
        )
        let now = Date(timeIntervalSince1970: 1_700_000_010)
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: StaticSSHConfigResolver(value: resolved),
            setup: try makeAcceptingOpenSSHSetup(
                resources: resources,
                resolved: resolved,
                now: now
            ),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let resource = try await lifecycle.mutate(
            action: .edit,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas"),
                desiredState: .active
            ),
            now: now
        )

        #expect(resource.state == .active)
        #expect(resource.authRef != nil)
        #expect(await authorizer.reasons == ["Edit SAFA resource nas.home"])
    }

    @Test("Windows OpenSSH hosts use the same verified SSH lifecycle")
    func windowsSSHConfigImport() async throws {
        let vault = InMemoryVaultDocumentStore()
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(
                        scheme: "ssh",
                        host: "windows.internal",
                        port: 22
                    ),
                    username: "administrator"
                )
            ),
            userPresenceAuthorizer: LifecyclePresenceAuthorizer(result: true),
            cooldown: 0
        )

        let resource = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("windows.lab"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("windows-lab"),
                resourceType: .hostWindows
            ),
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(resource.resolvedResourceType == .hostWindows)
        #expect(resource.resolvedAccessMethods == [.ssh])
        #expect(resource.state == .draft)
        #expect(SafeResourceProjection(resource: resource).capabilities == ["exec"])
    }

    @Test("edit preserves the existing type unless type is explicitly supplied")
    func editPreservesType() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        _ = try await resources.addDiscoveredResource(
            DiscoveredResourceDraft(
                alias: ResourceAlias("nas.home"),
                resourceType: .hostLinux,
                endpoint: ResourceEndpoint(host: "nas.internal", port: 22),
                username: "operator",
                securityDomain: "local-ssh-config"
            )
        )
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(host: "nas.internal", port: 22),
                    username: "operator"
                )
            ),
            userPresenceAuthorizer: LifecyclePresenceAuthorizer(result: true),
            cooldown: 0
        )

        let edited = try await lifecycle.mutate(
            action: .edit,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas")
            ),
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )

        #expect(edited.resolvedResourceType == .hostLinux)
        #expect(edited.displayName == nil)
    }

    @Test("disable, re-enable, and remove are real authorized broker transactions")
    func disableEnableAndRemove() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        _ = try await resources.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("synthetic-password".utf8)
        )
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let disabled = try await lifecycle.mutate(
            action: .disable,
            alias: ResourceAlias("nas.home"),
            mutation: nil,
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )
        let enabled = try await lifecycle.mutate(
            action: .enable,
            alias: ResourceAlias("nas.home"),
            mutation: nil,
            now: Date(timeIntervalSince1970: 1_700_000_002)
        )
        let removed = try await lifecycle.mutate(
            action: .remove,
            alias: ResourceAlias("nas.home"),
            mutation: nil,
            now: Date(timeIntervalSince1970: 1_700_000_003)
        )

        #expect(disabled.state == .disabled)
        #expect(enabled.state == .active)
        #expect(removed.state == .deleted)
        #expect(
            await authorizer.reasons == [
                "Disable SAFA resource nas.home",
                "Enable SAFA resource nas.home",
                "Remove SAFA resource nas.home",
            ]
        )
    }

    @Test("edit owns disabling and re-enabling a resource")
    func editChangesResourceState() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        _ = try await resources.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("synthetic-password".utf8)
        )
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let disabled = try await lifecycle.mutate(
            action: .edit,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("nas.home"),
                desiredState: .disabled
            ),
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )
        let enabled = try await lifecycle.mutate(
            action: .edit,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("nas.home"),
                desiredState: .active
            ),
            now: Date(timeIntervalSince1970: 1_700_000_002)
        )

        #expect(disabled.state == .disabled)
        #expect(enabled.state == .active)
        #expect(
            await authorizer.reasons == [
                "Edit SAFA resource nas.home",
                "Edit SAFA resource nas.home",
            ]
        )
    }

    @Test("enable rejects resources that are not disabled")
    func enableRequiresDisabledResource() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        _ = try await resources.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("synthetic-password".utf8)
        )
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: LifecyclePresenceAuthorizer(result: true),
            cooldown: 0
        )

        await #expect(throws: DomainValidationError.invalidTransition) {
            try await lifecycle.mutate(
                action: .enable,
                alias: ResourceAlias("nas.home"),
                mutation: nil,
                now: Date(timeIntervalSince1970: 1_700_000_001)
            )
        }
    }

    @Test("OpenSSH effective config parser selects typed connection fields")
    func parseEffectiveSSHConfig() {
        let values = OpenSSHConfigResolver.parse(
            """
            host home-nas
            user operator
            hostname nas.internal
            port 2222
            identityfile ~/.ssh/id_ed25519
            """
        )

        #expect(values["hostname"] == "nas.internal")
        #expect(values["user"] == "operator")
        #expect(values["port"] == "2222")
    }

    @Test("OpenSSH agent sentinel resolves through the local SSH_AUTH_SOCK")
    func resolveOpenSSHAgentSentinel() {
        #expect(
            OpenSSHConfigResolver.identityAgent(
                "SSH_AUTH_SOCK",
                environment: ["SSH_AUTH_SOCK": "/tmp/synthetic-agent.sock"]
            ) == "/tmp/synthetic-agent.sock"
        )
        #expect(OpenSSHConfigResolver.identityAgent("none", environment: [:]) == nil)
    }

    @Test("OpenSSH setup rejects a session authenticated as a different remote user")
    func setupRejectsUnexpectedRemoteUser() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let resource = Resource(
            id: UUID(),
            alias: try ResourceAlias("nas.home"),
            endpoint: ResourceEndpoint(host: "nas.internal", port: 22),
            username: "operator",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .trustedImport,
                status: .trusted
            ),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("unexpected-user\n".utf8),
                stderr: Data(),
                startedAt: now,
                finishedAt: now,
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let verifier = OpenSSHSetupVerifier(
            transport: SSHTransport(runner: runner),
            workingDirectory: FileManager.default.temporaryDirectory
        )

        await #expect(throws: ResourceSetupError.accountVerificationFailed) {
            try await verifier.verify(
                resource: resource,
                locator: OpenSSHCredentialLocatorV1(
                    identityFiles: ["/synthetic/id_ed25519"],
                    identityAgent: nil
                ),
                observedAt: now
            )
        }
    }

    @Test("Windows OpenSSH setup verifies the account with whoami")
    func windowsSetupVerifier() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let resource = Resource(
            id: UUID(),
            alias: try ResourceAlias("windows.lab"),
            resourceType: .hostWindows,
            endpoint: ResourceEndpoint(host: "windows.internal", port: 22),
            username: "operator",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .trustedImport,
                status: .trusted
            ),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("WORKSTATION\\operator\r\n".utf8),
                stderr: Data(),
                startedAt: now,
                finishedAt: now,
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let verifier = OpenSSHSetupVerifier(
            transport: SSHTransport(runner: runner),
            workingDirectory: FileManager.default.temporaryDirectory,
            inventoryProbe: StaticHostInventoryProbe(platform: .windows)
        )

        let inventory = try await verifier.verify(
            resource: resource,
            locator: OpenSSHCredentialLocatorV1(
                identityFiles: ["/synthetic/id_ed25519"],
                identityAgent: nil
            ),
            observedAt: now
        )
        let invocation = try #require(await runner.lastInvocation())
        let remoteCommand = try #require(invocation.arguments.last)
        #expect(try decodeWindowsRemoteArguments(remoteCommand) == ["whoami"])
        #expect(inventory.platform == .windows)
    }

    @Test("POSIX inventory parser normalizes bounded hardware facts")
    func parsePOSIXInventory() throws {
        let observedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = try OpenSSHHostInventoryProbe.parsePOSIX(
            Data(
                """
                platform=linux
                architecture=x86_64
                os_version=Ubuntu 24.04 LTS
                kernel_release=6.8.0
                cpu_logical_count=64
                cpu_model=AMD EPYC 7543
                memory_total_bytes=274877906944
                storage_total_bytes=1099511627776
                storage_available_bytes=549755813888
                hardware_vendor=Supermicro
                hardware_model=H12SSL
                account_is_root=false
                docker_available=true
                docker_account_authorized=true
                docker_version=Docker version 27.1.1
                """.utf8
            ),
            observedAt: observedAt
        )

        #expect(snapshot.platform == .linux)
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.architecture" }?.value
                == .text("x86_64"))
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.cpu.logical-count" }?.value
                == .integer(64))
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.memory.total-bytes" }?.value
                == .byteCount(274_877_906_944))
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.account.is-root" }?.value
                == .boolean(false))
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.docker.account-authorized" }?.value
                == .boolean(true))
        #expect(snapshot.metadata.allSatisfy { $0.observedAt == observedAt })
    }

    @Test("Windows inventory parser accepts typed CIM JSON")
    func parseWindowsInventory() throws {
        let observedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = try OpenSSHHostInventoryProbe.parseWindows(
            Data(
                #"{"platform":"windows","architecture":"AMD64","os_version":"Windows Server 2022","kernel_release":"20348","cpu_model":"AMD EPYC","cpu_logical_count":32,"memory_total_bytes":137438953472,"storage_total_bytes":1099511627776,"storage_available_bytes":549755813888,"hardware_vendor":"Synthetic","hardware_model":"Server","docker_available":false,"docker_version":""}"#
                    .utf8
            ),
            observedAt: observedAt
        )

        #expect(snapshot.platform == .windows)
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.architecture" }?.value
                == .text("AMD64"))
        #expect(
            snapshot.metadata.first { $0.key.rawValue == "host.docker.available" }?.value
                == .boolean(false))
    }

    @Test("setup activates a draft with trusted known-host and OpenSSH references")
    func setupActivatesDraft() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try await resources.addDiscoveredResource(
            DiscoveredResourceDraft(
                alias: ResourceAlias("nas.home"),
                resourceType: .hostLinux,
                endpoint: ResourceEndpoint(host: "nas.internal", port: 2222),
                username: "operator",
                securityDomain: "local-ssh-config"
            )
        )
        let now = Date(timeIntervalSince1970: 1_700_000_010)
        let setup = OpenSSHResourceSetupService(
            resources: resources,
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(host: "nas.internal", port: 2222),
                    username: "operator"
                )
            ),
            knownHostResolver: StaticKnownHostResolver(
                value: HostIdentity(
                    algorithm: "ssh-ed25519",
                    publicKey: Data(repeating: 7, count: 32),
                    fingerprint: "SHA256:synthetic",
                    verifiedAt: now,
                    verificationMethod: .trustedImport,
                    status: .trusted
                )
            ),
            credentialSourceResolver: StaticCredentialSourceResolver(
                value: try OpenSSHCredentialLocatorV1(
                    identityFiles: ["/synthetic/id_ed25519"],
                    identityAgent: nil
                )
            ),
            verifier: AcceptingSetupVerifier()
        )
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: FailingSSHConfigResolver(),
            setup: setup,
            userPresenceAuthorizer: authorizer,
            cooldown: 10
        )

        let active = try await lifecycle.mutate(
            action: .setup,
            alias: draft.alias,
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas")
            ),
            now: now
        )
        let document = await vault.readDocument()
        let reference = try #require(
            document.credentialReferences.first(where: { $0.id == active.authRef })
        )

        #expect(active.state == .active)
        #expect(active.hostIdentity?.verificationMethod == .trustedImport)
        #expect(active.resolvedHostPlatform == .linux)
        #expect(active.resolvedMetadata.contains { $0.key.rawValue == "host.os.family" })
        #expect(reference.kind == .sshOpenSSH)
        #expect(reference.storageLocator != Data("/synthetic/id_ed25519".utf8))
        #expect(await authorizer.reasons == ["Set up SAFA resource nas.home"])
        let graph = try #require(document.topologyGraph)
        let runtime = try ResourceAlias("runtime.local")
        let observation = try #require(
            graph.edges.first(where: {
                $0.fromNodeID == graph.nodes.first(where: { $0.alias == runtime })?.id
                    && $0.relation == .canReach
                    && $0.toNodeID == active.id
            })
        )
        #expect(observation.layer == .observed)
        #expect(observation.verification == .verified)
        #expect(observation.observedAt == now)
    }

    @Test("resolver rejects an alias absent from explicit SSH Host declarations")
    func absentSSHConfigAliasIsRejected() async throws {
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("hostname missing.example\nuser operator\nport 22\n".utf8),
                stderr: Data(),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let resolver = OpenSSHConfigResolver(
            runner: runner,
            aliasChecker: StaticAliasChecker(result: false)
        )

        await #expect(throws: SSHConfigResolverError.aliasNotConfigured) {
            try await resolver.resolve(alias: ResourceAlias("missing.host"))
        }
        #expect(await runner.lastInvocation() == nil)
    }

    @Test("resource mutations serialize across actor reentrancy")
    func mutationsDoNotLoseUpdates() async throws {
        let vault = YieldingVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )

        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<32 {
                group.addTask {
                    _ = try await resources.addDiscoveredResource(
                        DiscoveredResourceDraft(
                            alias: ResourceAlias("node-\(index)"),
                            endpoint: ResourceEndpoint(host: "host-\(index).internal"),
                            username: "operator",
                            securityDomain: "synthetic"
                        )
                    )
                }
            }
            try await group.waitForAll()
        }

        #expect(await vault.readDocument().resources.count == 32)
    }

    @Test("SSH alias catalog follows bounded includes and ignores wildcard defaults")
    func explicitAliasCatalog() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("safa-config-\(UUID().uuidString)", isDirectory: true)
        let included = root.appendingPathComponent("config.d", isDirectory: true)
        try FileManager.default.createDirectory(at: included, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let config = root.appendingPathComponent("config")
        try Data("Include config.d/*\nHost *\n    ServerAliveInterval 30\n".utf8)
            .write(to: config)
        try Data("# Host commented\nHost home-nas storage\n    HostName nas.internal\n".utf8)
            .write(to: included.appendingPathComponent("hosts"))
        let checker = OpenSSHConfigAliasChecker(configURL: config)
        let configuredAlias = try ResourceAlias("home-nas")
        let missingAlias = try ResourceAlias("missing.host")

        #expect(await checker.contains(alias: configuredAlias))
        #expect(!(await checker.contains(alias: missingAlias)))
    }

    @Test("known-host import prefers Ed25519 and computes a readable fingerprint")
    func knownHostParser() throws {
        let ed25519 = Data(repeating: 7, count: 32)
        let rsa = Data(repeating: 8, count: 64)
        let parsed = try #require(
            OpenSSHKnownHostResolver.preferredKey(
                in: """
                    host ssh-rsa \(rsa.base64EncodedString())
                    host ssh-ed25519 \(ed25519.base64EncodedString())
                    """
            )
        )

        #expect(parsed.algorithm == "ssh-ed25519")
        #expect(parsed.publicKey == ed25519)
    }
}

private func decodeWindowsRemoteArguments(_ remoteCommand: String) throws -> [String] {
    let encodedScript = try #require(remoteCommand.split(separator: " ").last.map(String.init))
    let scriptData = try #require(Data(base64Encoded: encodedScript))
    let script = try #require(String(data: scriptData, encoding: .utf16LittleEndian))
    let prefix = "FromBase64String('"
    let payloadStart = try #require(script.range(of: prefix)?.upperBound)
    let payloadEnd = try #require(script[payloadStart...].range(of: "')")?.lowerBound)
    let payload = String(script[payloadStart..<payloadEnd])
    let argumentData = try #require(Data(base64Encoded: payload))
    return try JSONDecoder().decode([String].self, from: argumentData)
}

private struct StaticSSHConfigResolver: SSHConfigResolving {
    let value: ResolvedSSHConfig

    func resolve(alias _: ResourceAlias) async throws -> ResolvedSSHConfig { value }
}

private struct FailingSSHConfigResolver: SSHConfigResolving {
    func resolve(alias _: ResourceAlias) async throws -> ResolvedSSHConfig {
        throw SSHConfigResolverError.unavailable
    }
}

private struct StaticAliasChecker: SSHConfigAliasChecking {
    let result: Bool

    func contains(alias _: ResourceAlias) async -> Bool { result }
}

private struct StaticKnownHostResolver: OpenSSHKnownHostResolving {
    let value: HostIdentity

    func resolve(config _: ResolvedSSHConfig, now _: Date) async throws -> HostIdentity { value }
}

private struct StaticCredentialSourceResolver: OpenSSHCredentialSourceResolving {
    let value: OpenSSHCredentialLocatorV1

    func resolve(config _: ResolvedSSHConfig) async throws -> OpenSSHCredentialLocatorV1 { value }
}

private struct AcceptingSetupVerifier: OpenSSHSetupVerifying {
    func verify(
        resource _: Resource,
        locator _: OpenSSHCredentialLocatorV1,
        observedAt: Date
    ) async throws -> HostInventorySnapshot {
        HostInventorySnapshot(
            platform: .linux,
            metadata: [
                try ResourceMetadataEntry(
                    key: "host.os.family",
                    value: .text("linux"),
                    observedAt: observedAt
                )
            ]
        )
    }
}

private struct FailingResourceSetup: ResourceSetupHandling {
    let error: ResourceSetupError

    func setup(
        alias _: ResourceAlias,
        sourceSSHConfigAlias _: ResourceAlias,
        now _: Date
    ) async throws -> Resource {
        throw error
    }
}

private func makeAcceptingOpenSSHSetup(
    resources: ResourceService,
    resolved: ResolvedSSHConfig,
    now: Date
) throws -> OpenSSHResourceSetupService {
    OpenSSHResourceSetupService(
        resources: resources,
        sshConfigResolver: StaticSSHConfigResolver(value: resolved),
        knownHostResolver: StaticKnownHostResolver(
            value: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .trustedImport,
                status: .trusted
            )
        ),
        credentialSourceResolver: StaticCredentialSourceResolver(
            value: try OpenSSHCredentialLocatorV1(
                identityFiles: ["/synthetic/id_ed25519"],
                identityAgent: nil
            )
        ),
        verifier: AcceptingSetupVerifier()
    )
}

private struct StaticHostInventoryProbe: OpenSSHHostInventoryProbing {
    let platform: HostPlatform

    func probe(
        resource _: Resource,
        credential _: SSHCredentialContext,
        observedAt: Date,
        didLaunch _: (@Sendable (Int32) -> Void)?
    ) async throws -> HostInventorySnapshot {
        HostInventorySnapshot(
            platform: platform,
            metadata: [
                try ResourceMetadataEntry(
                    key: "host.os.family",
                    value: .text(platform.rawValue),
                    observedAt: observedAt
                )
            ]
        )
    }
}

private actor LifecyclePresenceAuthorizer: UserPresenceAuthorizing {
    private(set) var reasons: [String] = []
    private let result: Bool

    init(result: Bool) { self.result = result }

    func authorize(reason: String) async -> Bool {
        reasons.append(reason)
        return result
    }
}

private actor YieldingVaultDocumentStore: VaultDocumentStoring {
    private var document = VaultDocument.empty

    func readDocument() async -> VaultDocument {
        await Task.yield()
        return document
    }

    func writeDocument(_ document: VaultDocument) async {
        await Task.yield()
        self.document = document
    }
}
