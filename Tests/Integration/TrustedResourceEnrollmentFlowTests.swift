import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATransport
import Testing

@testable import SAFATrustedSetup

@Suite("Trusted no-GUI resource enrollment")
struct TrustedResourceEnrollmentFlowTests {
    @Test("HTTP enrollment keeps endpoint and optional token inside protected typed setup")
    func httpEnrollment() async throws {
        let token = Data("synthetic-api-token".utf8)
        let console = RecordingTrustedSetupConsole(
            secrets: [
                Data("https".utf8),
                Data("service.invalid".utf8),
                Data("8443".utf8),
                Data("/health".utf8),
                token,
            ]
        )
        let client = RecordingTrustedLocalSetupClient()

        try await TrustedHTTPEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            client: client
        ).enroll(alias: ResourceAlias("health-api"), resourceType: .serviceHTTP)

        let payload = try #require(await client.payload)
        #expect(payload.resourceType == ResourceTypeIdentifier.serviceHTTP.rawValue)
        #expect(payload.accessMethods == [AccessMethodIdentifier.http.rawValue])
        #expect(payload.scheme == "https")
        #expect(payload.host == "service.invalid")
        #expect(payload.port == 8443)
        #expect(payload.path == "/health")
        #expect(payload.credential == token)
        #expect(payload.credentialKind == CredentialKind.apiToken.rawValue)
        #expect(payload.credentialRole == ResourceCredentialRole.readOnly.rawValue)
        #expect(!console.renderedText.contains("service.invalid"))
        #expect(!console.renderedText.contains("synthetic-api-token"))
    }

    @Test("HTTP enrollment supports an empty optional token")
    func unauthenticatedHTTPEnrollment() async throws {
        let console = RecordingTrustedSetupConsole(
            secrets: [
                Data(),
                Data("service.invalid".utf8),
                Data(),
                Data(),
                Data(),
            ]
        )
        let client = RecordingTrustedLocalSetupClient()

        try await TrustedHTTPEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            client: client
        ).enroll(alias: ResourceAlias("health-api"), resourceType: .serviceHTTP)

        let payload = try #require(await client.payload)
        #expect(payload.scheme == "https")
        #expect(payload.port == 443)
        #expect(payload.path == "/")
        #expect(payload.credential == nil)
        #expect(payload.credentialKind == nil)
    }

    @Test("denied HTTP enrollment reads no protected field")
    func deniedHTTPEnrollment() async throws {
        let console = RecordingTrustedSetupConsole(secrets: [Data("must-not-be-read".utf8)])
        let client = RecordingTrustedLocalSetupClient()

        await #expect(throws: TrustedHTTPEnrollmentError.authorizationDenied) {
            try await TrustedHTTPEnrollmentFlow(
                console: console,
                authorizer: StaticUserPresenceAuthorizer(approved: false),
                client: client
            ).enroll(alias: ResourceAlias("health-api"), resourceType: .serviceHTTP)
        }

        #expect(console.secretReadCount == 0)
        #expect(await client.beginAliases.isEmpty)
    }

    @Test("host scan keeps endpoint and port out of child process arguments")
    func hostScanArgumentBoundary() async throws {
        let runner = RecordingHostScanProcessRunner(
            expectedHost: "host.invalid",
            expectedPort: 2222
        )
        let identity = try await SystemSSHHostKeyScanner(runner: runner).scan(
            host: "host.invalid",
            port: 2222,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let arguments = await runner.arguments
        #expect(arguments.first == "-F")
        #expect(arguments.suffix(2) == ["safa-setup-host", "true"])
        #expect(!arguments.contains("host.invalid"))
        #expect(!arguments.contains("2222"))
        #expect(await runner.configuration.contains("HostName host.invalid"))
        #expect(await runner.configuration.contains("Port 2222"))
        #expect(identity.algorithm == "ssh-ed25519")
    }

    @Test("password enrollment reaches the broker only through protected typed data")
    func passwordEnrollment() async throws {
        let secret = Data("synthetic-remote-password".utf8)
        let console = RecordingTrustedSetupConsole(
            secrets: [
                Data("host.invalid".utf8),
                Data("2222".utf8),
                Data("operator".utf8),
                Data("SHA256:trusted".utf8),
                secret,
            ]
        )
        let client = RecordingTrustedLocalSetupClient()
        let flow = TrustedSSHEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            scanner: StaticSSHHostKeyScanner(
                identity: HostIdentity(
                    algorithm: "ssh-ed25519",
                    publicKey: Data([1, 2, 3]),
                    fingerprint: "SHA256:trusted",
                    verifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
                    verificationMethod: .manual,
                    status: .trusted
                )
            ),
            client: client
        )

        try await flow.enroll(
            alias: ResourceAlias("nas.home"),
            resourceType: .hostLinux,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let captured = try #require(await client.payload)
        #expect(captured.host == "host.invalid")
        #expect(captured.port == 2222)
        #expect(captured.username == "operator")
        #expect(captured.credential == secret)
        #expect(captured.credentialKind == CredentialKind.sshPassword.rawValue)
        #expect(captured.hostFingerprint == "SHA256:trusted")
        let expectedAlias = try ResourceAlias("nas.home")
        #expect(await client.beginAliases == [expectedAlias])
        #expect(!console.renderedText.contains("synthetic-remote-password"))
        #expect(!console.renderedText.contains("host.invalid"))
        #expect(!console.renderedText.contains("SHA256:trusted"))
    }

    @Test("denied user presence collects no protected value")
    func deniedPresence() async throws {
        let console = RecordingTrustedSetupConsole(secrets: [Data("unused".utf8)])
        let scanner = CountingSSHHostKeyScanner()
        let client = RecordingTrustedLocalSetupClient()
        let flow = TrustedSSHEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: false),
            scanner: scanner,
            client: client
        )

        await #expect(throws: TrustedSSHEnrollmentError.authorizationDenied) {
            try await flow.enroll(alias: ResourceAlias("nas.home"), resourceType: .hostLinux)
        }
        #expect(console.secretReadCount == 0)
        #expect(await scanner.scanCount == 0)
        #expect(await client.beginAliases.isEmpty)
    }

    @Test("fingerprint mismatch sends neither password nor setup session")
    func fingerprintMismatch() async throws {
        let console = RecordingTrustedSetupConsole(
            secrets: [
                Data("host.invalid".utf8),
                Data("22".utf8),
                Data("operator".utf8),
                Data("SHA256:other".utf8),
                Data("must-not-be-read".utf8),
            ]
        )
        let client = RecordingTrustedLocalSetupClient()
        let flow = TrustedSSHEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            scanner: StaticSSHHostKeyScanner(
                identity: HostIdentity(
                    algorithm: "ssh-ed25519",
                    publicKey: Data([1]),
                    fingerprint: "SHA256:trusted",
                    verifiedAt: .now,
                    verificationMethod: .manual,
                    status: .trusted
                )
            ),
            client: client
        )

        await #expect(throws: TrustedSSHEnrollmentError.hostFingerprintMismatch) {
            try await flow.enroll(alias: ResourceAlias("nas.home"), resourceType: .hostLinux)
        }
        #expect(console.secretReadCount == 4)
        #expect(await client.beginAliases.isEmpty)
    }

    @Test("the trusted helper accepts no endpoint username or password options")
    func noProtectedCLIOptions() throws {
        for arguments in [
            ["resource", "add", "nas.home", "--host", "host.invalid"],
            ["resource", "add", "nas.home", "--username", "operator"],
            ["resource", "add", "nas.home", "--password", "secret"],
        ] {
            #expect(throws: (any Error).self) {
                _ = try TrustedSetupCommand.parseAsRoot(arguments)
            }
        }

        let http = try #require(
            try TrustedSetupCommand.parseAsRoot([
                "resource", "add", "health-api", "--type", "service.http",
            ]) as? TrustedResourceAddCommand
        )
        #expect(http.resourceType == ResourceTypeIdentifier.serviceHTTP.rawValue)
    }

    @Test("default sudo enrollment detects passwordless access without reading a secret")
    func sudoEnrollmentDetectsPasswordless() async throws {
        let console = RecordingTrustedSetupConsole(secrets: [Data("must-not-be-read".utf8)])
        let client = RecordingSudoSetupClient(results: [.success(())])
        let flow = TrustedSudoEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            client: client
        )

        try await flow.enroll(alias: ResourceAlias("nas.home"), passwordless: false)

        #expect(console.secretReadCount == 0)
        #expect(
            await client.payloads == [ProtectedSudoCredentialPayload(passwordlessConfirmed: true)])
        #expect(console.renderedText.contains("verified passwordless sudo"))
    }

    @Test("default sudo enrollment asks for a password only after NOPASSWD is rejected")
    func sudoEnrollmentFallsBackToPassword() async throws {
        let secret = Data("synthetic-sudo-password".utf8)
        let console = RecordingTrustedSetupConsole(secrets: [secret])
        let client = RecordingSudoSetupClient(
            results: [
                .failure(TrustedLocalSetupClientError.brokerRejected("sudo_credential_invalid")),
                .success(()),
            ]
        )
        let flow = TrustedSudoEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            client: client
        )

        try await flow.enroll(alias: ResourceAlias("nas.home"), passwordless: false)

        #expect(console.secretReadCount == 1)
        let payloads = await client.payloads
        #expect(payloads.count == 2)
        #expect(payloads[0] == ProtectedSudoCredentialPayload(passwordlessConfirmed: true))
        #expect(payloads[1] == ProtectedSudoCredentialPayload(secret: secret))
        #expect(!console.renderedText.contains("synthetic-sudo-password"))
    }

    @Test("verification failures never trigger a password prompt")
    func sudoEnrollmentDoesNotPromptAfterVerificationFailure() async throws {
        let console = RecordingTrustedSetupConsole(secrets: [Data("must-not-be-read".utf8)])
        let expected = TrustedLocalSetupClientError.brokerRejected("sudo_verification_failed")
        let client = RecordingSudoSetupClient(results: [.failure(expected)])
        let flow = TrustedSudoEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            client: client
        )

        await #expect(throws: expected) {
            try await flow.enroll(alias: ResourceAlias("nas.home"), passwordless: false)
        }
        #expect(console.secretReadCount == 0)
        #expect(await client.payloads.count == 1)
    }

    @Test("explicit passwordless enrollment never falls back to a password")
    func explicitPasswordlessEnrollmentDoesNotPrompt() async throws {
        let console = RecordingTrustedSetupConsole(secrets: [Data("must-not-be-read".utf8)])
        let expected = TrustedLocalSetupClientError.brokerRejected("sudo_credential_invalid")
        let client = RecordingSudoSetupClient(results: [.failure(expected)])
        let flow = TrustedSudoEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            client: client
        )

        await #expect(throws: expected) {
            try await flow.enroll(alias: ResourceAlias("nas.home"), passwordless: true)
        }
        #expect(console.secretReadCount == 0)
        #expect(await client.payloads.count == 1)
    }
}

private final class RecordingTrustedSetupConsole: TrustedSetupConsole, @unchecked Sendable {
    private let lock = NSLock()
    private var secrets: [Data]
    private(set) var renderedText = ""
    private(set) var secretReadCount = 0

    init(secrets: [Data]) {
        self.secrets = secrets
    }

    func write(_ text: String) throws {
        lock.withLock { renderedText += text }
    }

    func readSecret(prompt: String) throws -> Data {
        lock.withLock {
            renderedText += prompt
            secretReadCount += 1
            guard !secrets.isEmpty else { return Data() }
            return secrets.removeFirst()
        }
    }
}

private struct StaticUserPresenceAuthorizer: UserPresenceAuthorizing {
    let approved: Bool
    func authorize(reason _: String) async -> Bool { approved }
}

private struct StaticSSHHostKeyScanner: SSHHostKeyScanning {
    let identity: HostIdentity
    func scan(host _: String, port _: UInt16, now _: Date) async throws -> HostIdentity { identity }
}

private actor CountingSSHHostKeyScanner: SSHHostKeyScanning {
    private(set) var scanCount = 0
    func scan(host _: String, port _: UInt16, now _: Date) async throws -> HostIdentity {
        scanCount += 1
        throw TrustedSSHEnrollmentError.hostIdentityUnavailable
    }
}

private actor RecordingTrustedLocalSetupClient: TrustedLocalSetupClient {
    private(set) var beginAliases: [ResourceAlias] = []
    private(set) var payload: ProtectedResourceSetupPayload?

    func begin(alias: ResourceAlias) async throws -> UUID {
        beginAliases.append(alias)
        return UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    }

    func commit(sessionID _: UUID, payload: ProtectedResourceSetupPayload) async throws {
        self.payload = payload
    }

    func attachSudo(alias _: ResourceAlias, payload _: ProtectedSudoCredentialPayload) async throws
    {
        throw TrustedLocalSetupClientError.unavailable
    }

    func removeSudo(alias _: ResourceAlias) async throws {
        throw TrustedLocalSetupClientError.unavailable
    }

    func approvalPresentation(requestID _: UUID) async throws -> TrustedApprovalPresentation {
        throw TrustedLocalSetupClientError.unavailable
    }

    func decideApproval(
        requestID _: UUID, approved _: Bool, scope _: ApprovalScope?
    ) async throws -> TrustedApprovalDecisionResult {
        throw TrustedLocalSetupClientError.unavailable
    }

    func completeSudoApproval(
        requestID _: UUID, payload _: ProtectedSudoCredentialPayload
    ) async throws -> TrustedApprovalDecisionResult {
        throw TrustedLocalSetupClientError.unavailable
    }
}

private actor RecordingSudoSetupClient: TrustedLocalSetupClient {
    private var results: [Result<Void, TrustedLocalSetupClientError>]
    private(set) var payloads: [ProtectedSudoCredentialPayload] = []

    init(results: [Result<Void, TrustedLocalSetupClientError>]) {
        self.results = results
    }

    func attachSudo(
        alias _: ResourceAlias,
        payload: ProtectedSudoCredentialPayload
    ) async throws {
        payloads.append(payload)
        guard !results.isEmpty else { throw TrustedLocalSetupClientError.unavailable }
        try results.removeFirst().get()
    }

    func begin(alias _: ResourceAlias) async throws -> UUID {
        throw TrustedLocalSetupClientError.unavailable
    }

    func commit(sessionID _: UUID, payload _: ProtectedResourceSetupPayload) async throws {
        throw TrustedLocalSetupClientError.unavailable
    }

    func removeSudo(alias _: ResourceAlias) async throws {
        throw TrustedLocalSetupClientError.unavailable
    }

    func approvalPresentation(requestID _: UUID) async throws -> TrustedApprovalPresentation {
        throw TrustedLocalSetupClientError.unavailable
    }

    func decideApproval(
        requestID _: UUID,
        approved _: Bool,
        scope _: ApprovalScope?
    ) async throws -> TrustedApprovalDecisionResult {
        throw TrustedLocalSetupClientError.unavailable
    }

    func completeSudoApproval(
        requestID _: UUID, payload _: ProtectedSudoCredentialPayload
    ) async throws -> TrustedApprovalDecisionResult {
        throw TrustedLocalSetupClientError.unavailable
    }
}

private actor RecordingHostScanProcessRunner: ProcessRunning {
    private let expectedHost: String
    private let expectedPort: UInt16
    private(set) var arguments: [String] = []
    private(set) var configuration = ""

    init(expectedHost: String, expectedPort: UInt16) {
        self.expectedHost = expectedHost
        self.expectedPort = expectedPort
    }

    func run(_ invocation: ProcessInvocation) async throws -> ProcessExecutionResult {
        arguments = invocation.arguments
        let configPath = try #require(invocation.arguments.dropFirst().first)
        configuration = try String(contentsOfFile: configPath, encoding: .utf8)
        #expect(configuration.contains("HostName \(expectedHost)"))
        #expect(configuration.contains("Port \(expectedPort)"))
        let knownHosts = URL(fileURLWithPath: configPath).deletingLastPathComponent()
            .appendingPathComponent("known_hosts")
        let publicKey = Data([1, 2, 3]).base64EncodedString()
        try "safa-setup-host ssh-ed25519 \(publicKey)\n".write(
            to: knownHosts,
            atomically: true,
            encoding: .utf8
        )
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return ProcessExecutionResult(
            termination: .exit,
            exitCode: 255,
            stdout: Data(),
            stderr: Data("authentication intentionally unavailable".utf8),
            startedAt: now,
            finishedAt: now,
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }
}
