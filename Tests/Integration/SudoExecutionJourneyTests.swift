import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@testable import SAFABroker

@Suite("Sudo execution journey")
struct SudoExecutionJourneyTests {
    @Test("auto keeps root at registered-account privilege")
    func autoRootStaysAtUserPrivilege() async throws {
        let observedAt = Date()
        let runner = FakeProcessRunner(result: Self.probeResult(root: true))
        let (resource, secret) = Self.resourceWithSudo(
            alias: "root.service",
            accountIsRoot: true,
            dockerAuthorized: true,
            observedAt: observedAt
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)
        let caller = Self.caller()

        let submission = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
                privilege: .auto,
                intent: "Restart a synthetic service",
                expectedEffect: "The service restarts",
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        let requestID = try #require(
            submission.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))
        let presentation = await handler.handle(
            .getApprovalPresentation(requestID: requestID),
            caller: caller,
            messageID: UUID()
        )

        #expect(submission.error?.code == "approval_required")
        #expect(submission.data.string(for: "privilege") == "user")
        #expect(submission.data.boolean(for: "review_agent_safe") == true)
        #expect(presentation.data.string(for: "privilege") == "user")
        #expect(await runner.invocationCount() == 1)
        #expect((await runner.lastInvocation()?.arguments.last ?? "").contains("account_is_root"))
    }

    @Test("auto keeps freshly Docker-authorized reads direct")
    func autoDockerAuthorizedStaysDirect() async throws {
        let observedAt = Date()
        let runner = FakeProcessRunner(results: [
            Self.probeResult(root: false, dockerAuthorized: true),
            Self.successResult(),
        ])
        let (resource, secret) = Self.resourceWithSudo(
            alias: "docker.worker",
            accountIsRoot: false,
            dockerAuthorized: true,
            observedAt: observedAt
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["docker", "version"]),
                privilege: .auto,
                intent: "Read Docker version",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller(),
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        #expect(await runner.invocationCount() == 2)
        #expect(!(await runner.lastInvocation()?.arguments.last ?? "").contains("'sudo'"))
    }

    @Test("auto sudo selection freezes one approval request before execution")
    func autoSudoRequiresImmutableApproval() async throws {
        let observedAt = Date()
        let runner = FakeProcessRunner(
            result: Self.probeResult(root: false, dockerAuthorized: nil))
        let (resource, secret) = Self.resourceWithSudo(
            alias: "standard.service",
            accountIsRoot: false,
            dockerAuthorized: false,
            observedAt: observedAt
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)
        let caller = Self.caller()

        let submission = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
                privilege: .auto,
                intent: "Restart a synthetic service",
                expectedEffect: "The service restarts",
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        let requestID = try #require(
            submission.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))
        let presentation = await handler.handle(
            .getApprovalPresentation(requestID: requestID),
            caller: caller,
            messageID: UUID()
        )

        #expect(submission.status == .userActionRequired)
        #expect(submission.error?.code == "approval_required")
        #expect(submission.data.string(for: "privilege") == "sudo")
        #expect(submission.data.boolean(for: "review_agent_safe") == true)
        #expect(presentation.data.string(for: "privilege") == "sudo")
        #expect(await runner.invocationCount() == 1)
        #expect((await runner.lastInvocation()?.arguments.last ?? "").contains("account_is_root"))
    }

    @Test("a fresh connection probe overrides stale stored account metadata")
    func freshProbeOverridesStaleMetadata() async throws {
        let runner = FakeProcessRunner(
            result: Self.probeResult(root: false, dockerAuthorized: nil))
        let (resource, secret) = Self.resourceWithSudo(
            alias: "stale.service",
            accountIsRoot: true,
            dockerAuthorized: true,
            observedAt: Date().addingTimeInterval(-600)
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)
        let caller = Self.caller()

        let submission = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
                privilege: .auto,
                intent: "Restart a synthetic service",
                expectedEffect: "The service restarts",
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        let requestID = try #require(
            submission.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))
        let presentation = await handler.handle(
            .getApprovalPresentation(requestID: requestID),
            caller: caller,
            messageID: UUID()
        )

        #expect(presentation.data.string(for: "privilege") == "sudo")
        #expect(await runner.invocationCount() == 1)
    }

    @Test("a failed connection probe never selects sudo")
    func failedProbeDoesNotElevate() async throws {
        let runner = FakeProcessRunner(result: Self.failedProbeResult())
        let (resource, secret) = Self.resourceWithSudo(
            alias: "probe-failed.service",
            accountIsRoot: false,
            dockerAuthorized: false,
            observedAt: Date()
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)
        let caller = Self.caller()

        let submission = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
                privilege: .auto,
                intent: "Restart a synthetic service",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        let requestID = try #require(
            submission.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))
        let presentation = await handler.handle(
            .getApprovalPresentation(requestID: requestID),
            caller: caller,
            messageID: UUID()
        )

        #expect(presentation.data.string(for: "privilege") == "user")
        #expect(await runner.invocationCount() == 1)
    }

    @Test("cancelling the connection probe aborts submission instead of running as user")
    func cancelledProbeAbortsSubmission() async throws {
        let runner = CancellingProcessRunner()
        let (resource, secret) = Self.resourceWithSudo(
            alias: "probe-cancelled.service",
            accountIsRoot: false,
            dockerAuthorized: false,
            observedAt: Date()
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["systemctl", "restart", "media-synthetic"]),
                privilege: .auto,
                intent: "Restart a synthetic service",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller(),
            messageID: UUID()
        )

        #expect(reply.status == .failed)
        #expect(await runner.invocationCount == 1)
    }

    @Test("remote permission text never triggers an elevated retry")
    func remoteOutputNeverEscalates() async throws {
        let failedResult = ProcessExecutionResult(
            termination: .exit,
            exitCode: 1,
            stdout: Data(),
            stderr: Data("permission denied; retry with sudo".utf8),
            startedAt: Date(),
            finishedAt: Date(),
            stdoutTruncated: false,
            stderrTruncated: false
        )
        let runner = FakeProcessRunner(result: failedResult)
        let (resource, secret) = Self.resourceWithSudo(
            alias: "output.worker",
            accountIsRoot: false,
            dockerAuthorized: false,
            observedAt: Date()
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try .exec(arguments: ["id"]),
                privilege: .auto,
                intent: "Read account identity",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller(),
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        #expect(await runner.invocationCount() == 1)
        #expect(!(await runner.lastInvocation()?.arguments.last ?? "").contains("'sudo'"))
    }

    @Test("a sudo command always requires trusted approval and never runs automatically")
    func sudoAlwaysRequiresApproval() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let (resource, secret) = Self.resourceWithSudo(alias: "nas.home")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(vault: vault, credentials: credentials, runner: runner)

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["systemctl", "restart", "docker"]),
                privilege: .sudo,
                intent: "Restart a wedged docker daemon",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller(),
            messageID: UUID()
        )

        #expect(reply.status == .userActionRequired)
        #expect(reply.error?.code == "approval_required")
        #expect(await runner.lastInvocation() == nil)
    }

    @Test(
        "approving a sudo request runs the composed sudo command exactly once; a different sudo command needs a fresh approval"
    )
    func approvalRunsExactlyOnce() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let (resource, secret) = Self.resourceWithSudo(alias: "nas.home")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(
            vault: vault, credentials: credentials, runner: runner,
            approvalAuthenticator: StubApprovalAuthenticator(decision: true)
        )
        let caller = Self.caller()

        let firstCommand = try CommandSpec.exec(arguments: ["systemctl", "restart", "docker"])
        let submitReply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: firstCommand,
                privilege: .sudo,
                intent: "Restart a wedged docker daemon",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        let requestID = try #require(
            submitReply.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))

        let presentationReply = await handler.handle(
            .getApprovalPresentation(requestID: requestID),
            caller: caller,
            messageID: UUID()
        )
        #expect(presentationReply.status == .completed)
        #expect(presentationReply.data.string(for: "privilege") == "sudo")
        #expect(presentationReply.data.string(for: "resource") == resource.alias.rawValue)

        let decisionReply = await handler.handle(
            .decideApproval(requestID: requestID, approved: true, scope: nil),
            caller: caller,
            messageID: UUID()
        )
        #expect(decisionReply.status == .completed)
        #expect(decisionReply.data.string(for: "decision") == "approved")

        let invocation = try #require(await runner.lastInvocation())
        let remoteCommand = try #require(invocation.arguments.last)
        #expect(
            remoteCommand
                == "'sudo' '-S' '-p' '' '--' '/bin/sh' '-c' 'exec \"$@\" </dev/null' 'safa-sudo-child' 'systemctl' 'restart' 'docker'"
        )
        let secretText = String(decoding: secret, as: UTF8.self)
        let serializedReply = String(
            decoding: try CanonicalCodec.encode(decisionReply), as: UTF8.self)
        #expect(!serializedReply.contains(secretText))

        // A second, different sudo command against the same resource must not be silently
        // authorized by the grant that was just consumed.
        let secondSubmitReply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["systemctl", "status", "docker"]),
                privilege: .sudo,
                intent: "Check whether the restart worked",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        #expect(secondSubmitReply.status == .userActionRequired)
        #expect(secondSubmitReply.error?.code == "approval_required")
    }

    @Test("denying a sudo request leaves it denied and never touches the transport")
    func denialNeverExecutes() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let (resource, secret) = Self.resourceWithSudo(alias: "nas.home")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(
            vault: vault, credentials: credentials, runner: runner,
            approvalAuthenticator: StubApprovalAuthenticator(decision: true)
        )
        let caller = Self.caller()

        let submitReply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["reboot"]),
                privilege: .sudo,
                intent: "Reboot the host",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: caller,
            messageID: UUID()
        )
        let requestID = try #require(
            submitReply.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))

        let decisionReply = await handler.handle(
            .decideApproval(requestID: requestID, approved: false, scope: nil),
            caller: caller,
            messageID: UUID()
        )
        #expect(decisionReply.status == .completed)
        #expect(decisionReply.data.string(for: "decision") == "denied")
        #expect(await runner.lastInvocation() == nil)
    }

    @Test("resource revision changes after approval submission fail closed before execution")
    func staleResourceRevisionNeverExecutes() async throws {
        let runner = FakeProcessRunner(result: Self.successResult())
        let (resource, secret) = Self.resourceWithSudo(alias: "nas.home")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: Self.credentialReferences(for: resource)
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(secret, id: resource.sudoRef!)
        let handler = Self.handler(
            vault: vault,
            credentials: credentials,
            runner: runner,
            approvalAuthenticator: StubApprovalAuthenticator(decision: true)
        )

        let submit = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["true"]),
                privilege: .sudo,
                intent: "Prove stale approvals cannot execute",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller(),
            messageID: UUID()
        )
        let requestID = try #require(
            submit.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))

        var changedDocument = await vault.readDocument()
        changedDocument.resources[0].revision += 1
        await vault.writeDocument(changedDocument)

        let decision = await handler.handle(
            .decideApproval(requestID: requestID, approved: true, scope: nil),
            caller: Self.caller(),
            messageID: UUID()
        )

        #expect(decision.status == .failed)
        #expect(decision.error?.code == "request_resource_changed")
        #expect(await runner.lastInvocation() == nil)
    }

    @Test(
        "first sudo use authenticates once, enrolls inside the approval flow, and runs the immutable request"
    )
    func firstUseEnrollsAndRunsAfterOneApproval() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let resource = Resource(
            id: UUID(),
            alias: try ResourceAlias("nas.home"),
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            ),
            authRef: UUID(),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        let runner = FakeProcessRunner(result: Self.successResult())
        let primaryReference = CredentialReference(
            id: resource.authRef!,
            kind: .sshOpenSSH,
            storageLocator: try CanonicalCodec.encode(
                OpenSSHCredentialLocatorV1(
                    identityFiles: ["/synthetic/id_ed25519"], identityAgent: nil)
            ),
            securityDomains: ["synthetic"],
            accessClass: .automaticWithinPolicy,
            health: .ready,
            createdAt: now
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: [primaryReference]
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        let verifier = FirstUseSudoVerifier(passwordResult: true, passwordlessResult: false)
        let authenticator = RecordingApprovalAuthenticator(decision: true)
        let handler = Self.handler(
            vault: vault,
            credentials: credentials,
            runner: runner,
            approvalAuthenticator: authenticator,
            sudoVerifier: verifier
        )

        let submitReply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["true"]),
                privilege: .sudo,
                intent: "Verify the first-use sudo workflow",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: Self.caller(),
            messageID: UUID()
        )

        #expect(submitReply.status == .userActionRequired)
        #expect(submitReply.error?.code == "approval_required")
        #expect(submitReply.data.boolean(for: "review_agent_safe") == false)
        let requestID = try #require(
            submitReply.data.string(for: "request_id").flatMap(UUID.init(uuidString:)))
        #expect(await runner.lastInvocation() == nil)

        let presentation = await handler.handle(
            .getApprovalPresentation(requestID: requestID),
            caller: Self.caller(),
            messageID: UUID()
        )
        #expect(presentation.data.string(for: "sudo_credential_state") == "missing")
        #expect(presentation.data.string(for: "approval_state") == "awaiting_user_presence")

        let approval = await handler.handle(
            .decideApproval(requestID: requestID, approved: true, scope: nil),
            caller: Self.caller(),
            messageID: UUID()
        )
        #expect(approval.status == .completed)
        #expect(approval.data.string(for: "continuation") == "sudo_credential_required")
        #expect(await authenticator.authorizationCount == 1)
        #expect(await runner.lastInvocation() == nil)

        // The trusted flow probes NOPASSWD before it is allowed to ask for a password.
        let passwordlessProbe = await handler.handle(
            .completeSudoApproval(
                requestID: requestID,
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(passwordlessConfirmed: true)
                )
            ),
            caller: Self.caller(),
            messageID: UUID()
        )
        #expect(passwordlessProbe.status == .failed)
        #expect(passwordlessProbe.error?.code == "sudo_credential_invalid")
        #expect(await verifier.passwordlessCallCount == 1)
        #expect(await runner.lastInvocation() == nil)

        let secret = Data("synthetic-first-use-password".utf8)
        let completion = await handler.handle(
            .completeSudoApproval(
                requestID: requestID,
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedSudoCredentialPayload(secret: secret)
                )
            ),
            caller: Self.caller(),
            messageID: UUID()
        )
        #expect(completion.status == .completed)
        #expect(completion.data.string(for: "decision") == "approved")
        #expect(await authenticator.authorizationCount == 1)
        #expect(await verifier.observedSecrets == [secret])
        #expect(await runner.lastInvocation() != nil)

        let document = await vault.readDocument()
        let updated = try #require(document.resources.first)
        let sudoCredentialID = try #require(updated.sudoRef)
        #expect(await credentials.readSecret(id: sudoCredentialID) == secret)
        let serialized = String(decoding: try CanonicalCodec.encode(completion), as: UTF8.self)
        #expect(!serialized.contains(String(decoding: secret, as: UTF8.self)))
    }

    // MARK: - Fixtures

    private static func handler(
        vault: any VaultDocumentStoring,
        credentials: any PasswordSecretStoring,
        runner: any ProcessRunning,
        approvalAuthenticator: (any ApprovalAuthenticating)? = nil,
        sudoVerifier: (any SudoCredentialVerifying)? = nil
    ) -> MVPBrokerHandler {
        MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            sudoVerifier: sudoVerifier,
            approvalAuthenticator: approvalAuthenticator,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-sudo-journey-\(UUID().uuidString)")
        )
    }

    private static func caller() -> CallerIdentity {
        CallerIdentity(
            signingIdentifier: "dev.safa.cli",
            teamIdentifier: "TESTTEAM1",
            effectiveUserID: 501,
            auditSessionID: 77
        )
    }

    private static func successResult() -> ProcessExecutionResult {
        ProcessExecutionResult(
            termination: .exit,
            exitCode: 0,
            stdout: Data(),
            stderr: Data(),
            startedAt: Date(timeIntervalSince1970: 1_700_000_000),
            finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }

    private static func probeResult(
        root: Bool,
        dockerAuthorized: Bool? = nil
    ) -> ProcessExecutionResult {
        let docker = dockerAuthorized.map(String.init) ?? "unknown"
        return ProcessExecutionResult(
            termination: .exit,
            exitCode: 0,
            stdout: Data(
                "account_is_root=\(root)\ndocker_account_authorized=\(docker)\n".utf8),
            stderr: Data(),
            startedAt: Date(timeIntervalSince1970: 1_700_000_000),
            finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }

    private static func failedProbeResult() -> ProcessExecutionResult {
        ProcessExecutionResult(
            termination: .timeout,
            exitCode: nil,
            stdout: Data(),
            stderr: Data(),
            startedAt: Date(timeIntervalSince1970: 1_700_000_000),
            finishedAt: Date(timeIntervalSince1970: 1_700_000_011),
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }

    /// A resource with an OpenSSH (key-based) primary login — required so the sudo secret can
    /// ride the already-authenticated channel's stdin — and a verified, ready sudo credential.
    private static func resourceWithSudo(
        alias: String,
        accountIsRoot: Bool? = nil,
        dockerAuthorized: Bool? = nil,
        observedAt: Date? = nil
    ) -> (resource: Resource, secret: Data) {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        var metadata: [ResourceMetadataEntry] = []
        if let accountIsRoot {
            metadata.append(
                try! ResourceMetadataEntry(
                    key: "host.account.is-root",
                    value: .boolean(accountIsRoot),
                    observedAt: observedAt
                ))
        }
        if let dockerAuthorized {
            metadata.append(
                try! ResourceMetadataEntry(
                    key: "host.docker.account-authorized",
                    value: .boolean(dockerAuthorized),
                    observedAt: observedAt
                ))
        }
        let resource = Resource(
            id: UUID(),
            alias: try! ResourceAlias(alias),
            metadata: metadata,
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            ),
            authRef: UUID(),
            sudoRef: UUID(),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        return (resource, Data("synthetic-sudo-password".utf8))
    }

    private static func credentialReferences(for resource: Resource) -> [CredentialReference] {
        let locator = try! OpenSSHCredentialLocatorV1(
            identityFiles: ["/synthetic/id_ed25519"], identityAgent: nil)
        return [
            CredentialReference(
                id: resource.authRef!,
                kind: .sshOpenSSH,
                storageLocator: try! CanonicalCodec.encode(locator),
                securityDomains: ["synthetic"],
                accessClass: .automaticWithinPolicy,
                health: .ready,
                createdAt: Date(timeIntervalSince1970: 1_700_000_000)
            ),
            CredentialReference(
                id: resource.sudoRef!,
                kind: .sudoPassword,
                storageLocator: Data(),
                securityDomains: ["synthetic"],
                accessClass: .userPresenceRequired,
                health: .ready,
                createdAt: Date(timeIntervalSince1970: 1_700_000_000)
            ),
        ]
    }
}

private actor CancellingProcessRunner: ProcessRunning {
    private(set) var invocationCount = 0

    func run(_: ProcessInvocation) async throws -> ProcessExecutionResult {
        invocationCount += 1
        throw CancellationError()
    }
}

private struct StubApprovalAuthenticator: ApprovalAuthenticating {
    let decision: Bool
    func authorize(reason _: String) async -> Bool { decision }
}

private actor RecordingApprovalAuthenticator: ApprovalAuthenticating {
    let decision: Bool
    private(set) var authorizationCount = 0

    init(decision: Bool) { self.decision = decision }

    func authorize(reason _: String) async -> Bool {
        authorizationCount += 1
        return decision
    }
}

private actor FirstUseSudoVerifier: SudoCredentialVerifying {
    let passwordResult: Bool
    let passwordlessResult: Bool
    private(set) var observedSecrets: [Data] = []
    private(set) var passwordlessCallCount = 0

    init(passwordResult: Bool, passwordlessResult: Bool) {
        self.passwordResult = passwordResult
        self.passwordlessResult = passwordlessResult
    }

    func verifyPasswordless(
        resource _: Resource,
        primaryCredential _: SSHCredentialContext
    ) async throws -> Bool {
        passwordlessCallCount += 1
        return passwordlessResult
    }

    func verifyPassword(
        resource _: Resource,
        primaryCredential _: SSHCredentialContext,
        sudoSecret: Data
    ) async throws -> Bool {
        observedSecrets.append(sudoSecret)
        return passwordResult
    }
}

extension Dictionary where Key == String, Value == JSONValue {
    fileprivate func string(for key: String) -> String? {
        guard case let .string(value)? = self[key] else { return nil }
        return value
    }

    fileprivate func boolean(for key: String) -> Bool? {
        guard case let .boolean(value)? = self[key] else { return nil }
        return value
    }
}
